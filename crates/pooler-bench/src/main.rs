#![forbid(unsafe_code)]

//! Deterministic release-gate benchmarks for Pooler.
//!
//! The opaque benchmark uses a real Pooler HTTP listener and a local scripted
//! TCP upstream.  The semantic benchmark exercises the production Factory and
//! protocol codecs with a request larger than one MiB.  The stress workload is
//! deliberately deterministic: it exercises the same bounded codec path and
//! tracked-resource cleanup under a configurable number of concurrent clients,
//! with failures injected from the request index rather than wall-clock time.
//!
//! The full release workload is intentionally opt-in through the defaults
//! below.  `--short` is suitable for CI smoke checks and never changes the
//! invariants being measured.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use adapter_factory::{FactoryEventEncoder, FactoryLanguageModelDecoder};
use anyhow::{anyhow, bail, Context, Result};
use pooler_config::Config;
use pooler_http::{RuntimeResourceSnapshot, SseParser};
use pooler_protocol::{
    FinishReason, LossPolicy, OpenAiChatCodec, OpenAiChatEventDecoder, OpenAiChatEventEncoder,
    StreamEvent, StreamEventKind, Usage,
};
use pooler_server::HttpProxyServer;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const OPAQUE_BUDGET: Duration = Duration::from_millis(2);
const SEMANTIC_BUDGET: Duration = Duration::from_millis(5);
const SEMANTIC_REQUEST_BYTES: usize = 1024 * 1024;
const OPAQUE_REQUEST_BYTES: usize = 1024 * 1024;
const FULL_STRESS_DURATION_SECS: u64 = 15 * 60;
const FULL_STRESS_REQUESTS: usize = 10_000;
const FULL_STRESS_CLIENTS: usize = 100;
const FULL_FAILURE_PERCENT: u8 = 20;
const SHORT_OPAQUE_SAMPLES: usize = 100;
const SHORT_SEMANTIC_SAMPLES: usize = 10;
const SHORT_STRESS_DURATION_SECS: u64 = 5;
const SHORT_STRESS_REQUESTS: usize = 200;
const SHORT_STRESS_CLIENTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    All,
    Opaque,
    Semantic,
    Stress,
}

impl Mode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "all" => Ok(Self::All),
            "opaque" => Ok(Self::Opaque),
            "semantic" => Ok(Self::Semantic),
            "stress" => Ok(Self::Stress),
            _ => bail!("mode must be all, opaque, semantic, or stress"),
        }
    }

    const fn includes_opaque(self) -> bool {
        matches!(self, Self::All | Self::Opaque)
    }

    const fn includes_semantic(self) -> bool {
        matches!(self, Self::All | Self::Semantic)
    }

    const fn includes_stress(self) -> bool {
        matches!(self, Self::All | Self::Stress)
    }
}

#[derive(Clone, Debug)]
struct Settings {
    mode: Mode,
    short: bool,
    opaque_samples: usize,
    semantic_samples: usize,
    duration_secs: u64,
    requests: usize,
    clients: usize,
    failure_percent: u8,
    seed: u64,
    runs: usize,
    json: bool,
    output: Option<PathBuf>,
    enforce_budgets: bool,
}

impl Settings {
    fn parse() -> Result<Self> {
        let mut mode = Mode::All;
        let mut short = false;
        let mut opaque_samples = None;
        let mut semantic_samples = None;
        let mut duration_secs = None;
        let mut requests = None;
        let mut clients = None;
        let mut failure_percent = FULL_FAILURE_PERCENT;
        let mut seed = 0_u64;
        let mut runs = 1_usize;
        let mut json = false;
        let mut output = None;
        let mut enforce_budgets = false;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut index = 0;
        while index < args.len() {
            let argument = args[index].as_str();
            match argument {
                "--short" => short = true,
                "--json" => json = true,
                "--enforce-budgets" => enforce_budgets = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "--mode" => mode = Mode::parse(next_value(&args, &mut index, argument)?)?,
                "--opaque-samples" => {
                    opaque_samples = Some(parse_usize(next_value(&args, &mut index, argument)?)?)
                }
                "--semantic-samples" => {
                    semantic_samples = Some(parse_usize(next_value(&args, &mut index, argument)?)?)
                }
                "--duration-secs" => {
                    duration_secs = Some(parse_u64(next_value(&args, &mut index, argument)?)?)
                }
                "--requests" => {
                    requests = Some(parse_usize(next_value(&args, &mut index, argument)?)?)
                }
                "--clients" => {
                    clients = Some(parse_usize(next_value(&args, &mut index, argument)?)?)
                }
                "--failure-percent" => {
                    failure_percent = parse_u8(next_value(&args, &mut index, argument)?)?
                }
                "--seed" => seed = parse_u64(next_value(&args, &mut index, argument)?)?,
                "--runs" => runs = parse_usize(next_value(&args, &mut index, argument)?)?,
                "--output" => {
                    output = Some(PathBuf::from(next_value(&args, &mut index, argument)?))
                }
                other => bail!("unknown argument `{other}`; use --help for usage"),
            }
            index += 1;
        }

        let defaults = if short {
            (
                SHORT_OPAQUE_SAMPLES,
                SHORT_SEMANTIC_SAMPLES,
                SHORT_STRESS_DURATION_SECS,
                SHORT_STRESS_REQUESTS,
                SHORT_STRESS_CLIENTS,
            )
        } else {
            (
                1_000,
                100,
                FULL_STRESS_DURATION_SECS,
                FULL_STRESS_REQUESTS,
                FULL_STRESS_CLIENTS,
            )
        };
        let settings = Self {
            mode,
            short,
            opaque_samples: opaque_samples.unwrap_or(defaults.0),
            semantic_samples: semantic_samples.unwrap_or(defaults.1),
            duration_secs: duration_secs.unwrap_or(defaults.2),
            requests: requests.unwrap_or(defaults.3),
            clients: clients.unwrap_or(defaults.4),
            failure_percent,
            seed,
            runs: runs.max(1),
            json,
            output,
            enforce_budgets,
        };
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<()> {
        if self.opaque_samples == 0 {
            bail!("--opaque-samples must be greater than zero")
        }
        if self.semantic_samples == 0 {
            bail!("--semantic-samples must be greater than zero")
        }
        if self.duration_secs == 0 {
            bail!("--duration-secs must be greater than zero")
        }
        if self.requests == 0 {
            bail!("--requests must be greater than zero")
        }
        if self.clients == 0 {
            bail!("--clients must be greater than zero")
        }
        if self.failure_percent > 100 {
            bail!("--failure-percent must be between 0 and 100")
        }
        if self.enforce_budgets && !self.release_parameters_satisfied() {
            bail!("--enforce-budgets requires the full release workload: mode=all, no --short, at least 1000 opaque samples, at least 100 semantic samples, at least 900 seconds, at least 10000 requests, at least 100 clients, exactly 20% failures, and at least 3 runs")
        }
        Ok(())
    }

    fn release_parameters_satisfied(&self) -> bool {
        self.mode == Mode::All
            && !self.short
            && self.opaque_samples >= 1_000
            && self.semantic_samples >= 100
            && self.duration_secs >= FULL_STRESS_DURATION_SECS
            && self.requests >= FULL_STRESS_REQUESTS
            && self.clients >= FULL_STRESS_CLIENTS
            && self.failure_percent == FULL_FAILURE_PERCENT
            && self.runs >= 3
    }

    fn validate_provenance(&self, provenance: &ProvenanceReport) -> Result<()> {
        if !self.enforce_budgets {
            return Ok(());
        }
        if !provenance.worktree_clean {
            bail!("--enforce-budgets requires a clean worktree")
        }
        if provenance.build_profile != "release" {
            bail!("--enforce-budgets requires a release build")
        }
        Ok(())
    }
}

fn next_value<'a>(args: &'a [String], index: &mut usize, argument: &str) -> Result<&'a str> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{argument} requires a value"))
}

fn parse_usize(value: &str) -> Result<usize> {
    value
        .parse()
        .with_context(|| format!("invalid unsigned integer `{value}`"))
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .parse()
        .with_context(|| format!("invalid unsigned integer `{value}`"))
}

fn parse_u8(value: &str) -> Result<u8> {
    value
        .parse()
        .with_context(|| format!("invalid percentage `{value}`"))
}

fn print_help() {
    println!(
        "pooler-bench [options]\n\n  --mode <all|opaque|semantic|stress>\n  --short\n  --opaque-samples <n>\n  --semantic-samples <n>\n  --duration-secs <n>\n  --requests <n>\n  --clients <n>\n  --failure-percent <0..100>\n  --seed <n>\n  --runs <n>\n  --json\n  --output <path>\n  --enforce-budgets\n\nThe default stress workload is 900 seconds, 10,000 requests, 100 clients, and 20% deterministic failures. Use --short for CI smoke runs."
    );
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    provenance: ProvenanceReport,
    enforcement: EnforcementReport,
    mode: String,
    short: bool,
    seed: u64,
    runs: Vec<RunReport>,
    stress: Option<StressReport>,
    all_invariants_passed: bool,
}

#[derive(Debug, Serialize)]
struct ProvenanceReport {
    commit_sha: String,
    worktree_clean: bool,
    rustc_verbose_version: String,
    host_target: String,
    benchmark_target: String,
    host: String,
    build_profile: &'static str,
    command: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EnforcementReport {
    mode: &'static str,
    requested: bool,
    release_parameters_satisfied: bool,
    clean_worktree_required: bool,
    worktree_clean: bool,
    release_profile_required: bool,
    release_profile: bool,
}

#[derive(Debug, Serialize)]
struct RunReport {
    run: usize,
    opaque: Option<LatencyReport>,
    semantic: Option<LatencyReport>,
}

#[derive(Debug, Serialize)]
struct LatencyReport {
    samples: usize,
    payload_bytes: usize,
    p50_us: u64,
    p95_us: u64,
    max_us: u64,
    direct_p50_us: Option<u64>,
    direct_p95_us: Option<u64>,
    direct_max_us: Option<u64>,
    overhead_p50_us: Option<u64>,
    overhead_p95_us: Option<u64>,
    overhead_max_us: Option<u64>,
    budget_us: u64,
    budget_passed: bool,
}

#[derive(Debug, Serialize)]
struct StressReport {
    duration_secs: u64,
    configured_requests: usize,
    clients: usize,
    failure_percent: u8,
    seed: u64,
    failure_schedule: &'static str,
    failure_scope: &'static str,
    elapsed_ms: u128,
    duration_satisfied: bool,
    processed: usize,
    successful_streams: usize,
    injected_failures: usize,
    unexpected_failures: usize,
    panics: usize,
    timed_out: bool,
    max_in_flight: usize,
    expected_injected_upstream_failures: usize,
    scheduled_failure_requests: usize,
    issued_requests: usize,
    upstream_requests: usize,
    observed_logical_requests: usize,
    upstream_failures: usize,
    retries_after_injected_failure: usize,
    failovers: usize,
    cancellations_observed: usize,
    opaque_errors: usize,
    semantic_errors: usize,
    first_error: Option<String>,
    resources: ResourceReport,
    rss: RssReport,
    invariants: StressInvariants,
}

#[derive(Debug, Serialize)]
struct ResourceReport {
    source: &'static str,
    tasks: u64,
    permits: u64,
    refresh_leases: u64,
    temporary_files: u64,
    secret_material: u64,
    peak_tasks: u64,
    peak_permits: u64,
    peak_refresh_leases: u64,
    peak_temporary_files: u64,
    peak_secret_material: u64,
    zero_after_drain: bool,
}

#[derive(Debug, Serialize)]
struct RssReport {
    supported: bool,
    baseline_bytes: Option<u64>,
    post_drain_bytes: Option<u64>,
    delta_percent: Option<f64>,
    within_ten_percent: bool,
}

#[derive(Debug, Serialize)]
struct StressInvariants {
    no_panics: bool,
    no_deadlock: bool,
    no_incomplete_successful_streams: bool,
    deterministic_upstream_failures: bool,
    exact_configured_failure_rate: bool,
    processed_matches_issued: bool,
    all_issued_requests_observed: bool,
    upstream_attempt_accounting: bool,
    minimum_request_count: bool,
    duration_satisfied: bool,
    failover_observed: bool,
    cancellation_observed: bool,
    tracked_resources_zero: bool,
    rss_within_budget: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let settings = Settings::parse()?;
    let report = run(settings.clone()).await?;
    let serialized = serde_json::to_string_pretty(&report).context("serialize report")?;
    if let Some(path) = settings.output.as_deref() {
        std::fs::write(path, serialized.as_bytes())
            .with_context(|| format!("write benchmark report `{}`", path.display()))?;
    }
    if settings.json {
        println!("{serialized}");
    } else {
        print_summary(&report);
    }
    if settings.enforce_budgets && !report.all_invariants_passed {
        bail!("one or more benchmark or stress invariants failed")
    }
    Ok(())
}

async fn run(settings: Settings) -> Result<Report> {
    let provenance = ProvenanceReport::capture()?;
    settings.validate_provenance(&provenance)?;
    let mut runs = Vec::with_capacity(settings.runs);
    for run in 0..settings.runs {
        let opaque = if settings.mode.includes_opaque() {
            Some(run_opaque(settings.opaque_samples).await?)
        } else {
            None
        };
        let semantic = if settings.mode.includes_semantic() {
            Some(run_semantic(settings.semantic_samples)?)
        } else {
            None
        };
        runs.push(RunReport {
            run: run + 1,
            opaque,
            semantic,
        });
    }
    let stress = if settings.mode.includes_stress() {
        Some(run_stress(&settings).await?)
    } else {
        None
    };
    let all_invariants_passed = runs.iter().all(|run| {
        run.opaque
            .as_ref()
            .is_none_or(|report| report.budget_passed)
            && run
                .semantic
                .as_ref()
                .is_none_or(|report| report.budget_passed)
    }) && stress.as_ref().is_none_or(|report| {
        report.invariants.no_panics
            && report.invariants.no_deadlock
            && report.invariants.no_incomplete_successful_streams
            && report.invariants.deterministic_upstream_failures
            && report.invariants.exact_configured_failure_rate
            && report.invariants.processed_matches_issued
            && report.invariants.all_issued_requests_observed
            && report.invariants.upstream_attempt_accounting
            && report.invariants.minimum_request_count
            && report.invariants.duration_satisfied
            && report.invariants.failover_observed
            && report.invariants.cancellation_observed
            && report.invariants.tracked_resources_zero
            && report.invariants.rss_within_budget
    }) && (!settings.enforce_budgets
        || (provenance.worktree_clean && provenance.build_profile == "release"));
    let enforcement = EnforcementReport {
        mode: if settings.enforce_budgets {
            "release"
        } else {
            "advisory"
        },
        requested: settings.enforce_budgets,
        release_parameters_satisfied: settings.release_parameters_satisfied(),
        clean_worktree_required: settings.enforce_budgets,
        worktree_clean: provenance.worktree_clean,
        release_profile_required: settings.enforce_budgets,
        release_profile: provenance.build_profile == "release",
    };
    Ok(Report {
        schema_version: 2,
        provenance,
        enforcement,
        mode: mode_name(settings.mode).to_owned(),
        short: settings.short,
        seed: settings.seed,
        runs,
        stress,
        all_invariants_passed,
    })
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::All => "all",
        Mode::Opaque => "opaque",
        Mode::Semantic => "semantic",
        Mode::Stress => "stress",
    }
}

impl ProvenanceReport {
    fn capture() -> Result<Self> {
        let commit_sha = command_stdout("git", &["rev-parse", "HEAD"])?;
        let status = command_stdout(
            "git",
            &["status", "--porcelain=v1", "--untracked-files=normal"],
        )?;
        let rustc_verbose_version = command_stdout("rustc", &["-vV"])?;
        let host_target = rustc_verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .ok_or_else(|| anyhow!("rustc -vV did not report a host target"))?
            .to_owned();
        Ok(Self {
            commit_sha,
            worktree_clean: status.is_empty(),
            rustc_verbose_version,
            benchmark_target: host_target.clone(),
            host_target,
            host: host_description(),
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            command: std::env::args().collect(),
        })
    }
}

fn command_stdout(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("run `{program}` for benchmark provenance"))?;
    if !output.status.success() {
        bail!("`{program}` failed while collecting benchmark provenance")
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("`{program}` provenance output was not UTF-8"))
        .map(|value| value.trim().to_owned())
}

fn host_description() -> String {
    let base = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    #[cfg(unix)]
    {
        command_stdout("uname", &["-srm"]).unwrap_or(base)
    }
    #[cfg(not(unix))]
    {
        base
    }
}

fn print_summary(report: &Report) {
    for run in &report.runs {
        if let Some(opaque) = &run.opaque {
            println!(
                "run {} opaque: {} samples, raw_p95={}us, overhead_p95={}us (budget={}us, passed={})",
                run.run,
                opaque.samples,
                opaque.p95_us,
                opaque.overhead_p95_us.unwrap_or_default(),
                opaque.budget_us,
                opaque.budget_passed
            );
        }
        if let Some(semantic) = &run.semantic {
            println!(
                "run {} semantic: {} samples, p95={}us ({} bytes, budget={}us, passed={})",
                run.run,
                semantic.samples,
                semantic.p95_us,
                semantic.payload_bytes,
                semantic.budget_us,
                semantic.budget_passed
            );
        }
    }
    if let Some(stress) = &report.stress {
        println!(
            "stress: processed {}/{} in {}ms (success={}, upstream_failures={}, failovers={}, p={}), max_in_flight={}, resources_zero={}, rss_ok={}",
            stress.processed,
            stress.configured_requests,
            stress.elapsed_ms,
            stress.successful_streams,
            stress.upstream_failures,
            stress.failovers,
            stress.failure_percent,
            stress.max_in_flight,
            stress.invariants.tracked_resources_zero,
            stress.invariants.rss_within_budget
        );
    }
    println!("all invariants passed: {}", report.all_invariants_passed);
}

async fn run_opaque(samples: usize) -> Result<LatencyReport> {
    let response_body = Arc::new(vec![b'o'; OPAQUE_REQUEST_BYTES]);
    let upstream = EchoUpstream::start(Arc::clone(&response_body)).await?;
    let config = Config::from_yaml(
        "pooler-bench-opaque.yaml",
        &format!(
            "version: 2\nlisteners: {{bench: {{bind: 127.0.0.1:0}}}}\nupstreams: {{bench: {{url: http://{}}}}}\nroutes:\n  - id: opaque\n    listen: bench\n    match: {{method: POST, path: /bench}}\n    ingress: {{mode: opaque}}\n    response: {{mode: opaque}}\n    target: bench\n",
            upstream.address
        ),
    )?
    .compile()?;
    let server = HttpProxyServer::bind(config).await?;
    let address: SocketAddr = server
        .listener_addresses()
        .first()
        .ok_or_else(|| anyhow!("benchmark listener was not bound"))?
        .address()
        .parse()
        .context("parse benchmark listener address")?;
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };
    tokio::task::yield_now().await;

    let request_body = vec![b'i'; OPAQUE_REQUEST_BYTES];
    let mut matched_samples = Vec::with_capacity(samples);
    for _ in 0..samples {
        let direct =
            measure_opaque_request(upstream.address, &request_body, response_body.as_slice()).await;
        let pooled = measure_opaque_request(address, &request_body, response_body.as_slice()).await;
        match (direct, pooled) {
            (Ok(direct), Ok(pooled)) => {
                matched_samples.push(OpaqueLatencySample { direct, pooled });
            }
            (Err(error), _) | (Ok(_), Err(error)) => {
                stop_echo_and_server(&server, runner, upstream).await?;
                return Err(error);
            }
        }
    }
    server.drain(Duration::from_secs(5)).await?;
    runner.await.context("opaque server task panicked")??;
    upstream.stop().await?;
    Ok(latency_report_with_baseline(
        matched_samples,
        request_body.len(),
        OPAQUE_BUDGET,
    ))
}

async fn measure_opaque_request(
    address: SocketAddr,
    request_body: &[u8],
    expected_body: &[u8],
) -> Result<Duration> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).await?;
    let request = format!(
        "POST /bench HTTP/1.1\r\nHost: pooler-bench\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        request_body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(request_body).await?;
    let (status, body) = read_http_response(&mut stream).await?;
    if status != 200 || body.as_slice() != expected_body {
        bail!("opaque benchmark response mismatch: status={status}")
    }
    Ok(started.elapsed())
}

async fn stop_echo_and_server(
    server: &HttpProxyServer,
    runner: tokio::task::JoinHandle<Result<(), pooler_server::HttpProxyServerError>>,
    upstream: EchoUpstream,
) -> Result<()> {
    let _ = server.drain(Duration::from_secs(1)).await;
    let _ = runner.await;
    upstream.stop().await
}

fn run_semantic(samples: usize) -> Result<LatencyReport> {
    let body = semantic_request(SEMANTIC_REQUEST_BYTES)?;
    let decoder = FactoryLanguageModelDecoder::default();
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        semantic_translation(&decoder, &body)?;
        durations.push(started.elapsed());
    }
    Ok(latency_report(durations, body.len(), SEMANTIC_BUDGET))
}

fn semantic_translation(decoder: &FactoryLanguageModelDecoder, body: &[u8]) -> Result<()> {
    let decoded = decoder.decode(body, "pooler-bench-model")?;
    let encoded = OpenAiChatCodec::encode_request(&decoded.request, LossPolicy::Reject)?;
    if encoded.body.is_empty() {
        bail!("semantic request encoder returned an empty body")
    }

    let events = [
        StreamEvent::new(
            1,
            StreamEventKind::response_start(
                Some("pooler-bench-response".to_owned()),
                Some("pooler-bench-model".to_owned()),
            ),
        ),
        StreamEvent::new(2, StreamEventKind::text_delta("pooler-bench")).with_block_id("text"),
        StreamEvent::new(
            3,
            StreamEventKind::completion(FinishReason::Stop, Some(Usage::new(1, 1))),
        ),
    ];
    let mut chat_encoder = OpenAiChatEventEncoder::new();
    let mut chat_decoder = OpenAiChatEventDecoder::new();
    let factory_encoder = FactoryEventEncoder;
    let mut sse_parser = SseParser::new();
    for event in events {
        if let Some(chunk) = chat_encoder.encode_event(&event, LossPolicy::Reject)? {
            let semantic_events = chat_decoder.decode_chunk(&chunk.body)?;
            for semantic_event in semantic_events {
                let encoded = factory_encoder.encode_sse(&semantic_event, LossPolicy::Reject)?;
                sse_parser.feed(&encoded.body)?;
            }
        }
    }
    for semantic_event in chat_decoder.decode_data(b"[DONE]")? {
        let encoded = factory_encoder.encode_sse(&semantic_event, LossPolicy::Reject)?;
        sse_parser.feed(&encoded.body)?;
    }
    sse_parser.finish()?;
    Ok(())
}

fn semantic_request(target_bytes: usize) -> Result<Vec<u8>> {
    let text = "x".repeat(target_bytes);
    let value = json!({
        "prompt": [{
            "role": "user",
            "content": [{"type": "text", "text": text}]
        }]
    });
    let body = serde_json::to_vec(&value)?;
    if body.len() < target_bytes {
        bail!(
            "semantic request generator produced only {} bytes",
            body.len()
        )
    }
    Ok(body)
}

fn latency_report(
    mut durations: Vec<Duration>,
    payload_bytes: usize,
    budget: Duration,
) -> LatencyReport {
    durations.sort_unstable();
    let p50 = percentile(&durations, 0.50);
    let p95 = percentile(&durations, 0.95);
    let max = durations.last().copied().unwrap_or_default();
    LatencyReport {
        samples: durations.len(),
        payload_bytes,
        p50_us: micros(p50),
        p95_us: micros(p95),
        max_us: micros(max),
        direct_p50_us: None,
        direct_p95_us: None,
        direct_max_us: None,
        overhead_p50_us: None,
        overhead_p95_us: None,
        overhead_max_us: None,
        budget_us: micros(budget),
        budget_passed: p95 <= budget,
    }
}

#[derive(Clone, Copy)]
struct OpaqueLatencySample {
    direct: Duration,
    pooled: Duration,
}

fn latency_report_with_baseline(
    matched_samples: Vec<OpaqueLatencySample>,
    payload_bytes: usize,
    budget: Duration,
) -> LatencyReport {
    let mut pooled = matched_samples
        .iter()
        .map(|sample| sample.pooled)
        .collect::<Vec<_>>();
    pooled.sort_unstable();
    let mut report = latency_report(pooled.clone(), payload_bytes, budget);
    let mut direct = matched_samples
        .iter()
        .map(|sample| sample.direct)
        .collect::<Vec<_>>();
    direct.sort_unstable();
    let direct_p50 = percentile(&direct, 0.50);
    let direct_p95 = percentile(&direct, 0.95);
    let direct_max = direct.last().copied().unwrap_or_default();
    // Keep request pairing intact until the overhead distribution is built.
    // Subtracting independent marginal percentiles can hide a slow Pooler
    // request behind a different slow direct request.
    let mut overheads = matched_samples
        .iter()
        .map(|sample| sample.pooled.saturating_sub(sample.direct))
        .collect::<Vec<_>>();
    overheads.sort_unstable();
    let overhead_p50 = percentile(&overheads, 0.50);
    let overhead_p95 = percentile(&overheads, 0.95);
    let overhead_max = overheads.last().copied().unwrap_or_default();
    report.direct_p50_us = Some(micros(direct_p50));
    report.direct_p95_us = Some(micros(direct_p95));
    report.direct_max_us = Some(micros(direct_max));
    report.overhead_p50_us = Some(micros(overhead_p50));
    report.overhead_p95_us = Some(micros(overhead_p95));
    report.overhead_max_us = Some(micros(overhead_max));
    report.budget_passed = overhead_p95 <= budget;
    report
}

fn percentile(values: &[Duration], quantile: f64) -> Duration {
    if values.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((values.len() as f64) * quantile).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

async fn run_stress(settings: &Settings) -> Result<StressReport> {
    std::env::set_var("POOLER_BENCH_PRIMARY", "pooler-bench-primary");
    std::env::set_var("POOLER_BENCH_FALLBACK", "pooler-bench-fallback");
    let runtime = StressRuntime::start(settings).await?;
    let warmup_body = semantic_request(8 * 1024)?;
    // Exercise both real routes before recording the baseline. This warms the
    // listener, Hyper client, semantic queue, and allocator paths that the
    // mixed workload will use.
    let warmup_requests = settings.clients.max(8).saturating_mul(16);
    warmup_runtime(&runtime, &warmup_body, warmup_requests, settings.clients).await?;
    runtime.upstream.reset_workload_stats();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(settings.duration_secs);
    let successful_streams = Arc::new(AtomicUsize::new(0));
    let injected_requests = Arc::new(AtomicUsize::new(0));
    let unexpected_failures = Arc::new(AtomicUsize::new(0));
    let opaque_errors = Arc::new(AtomicUsize::new(0));
    let semantic_errors = Arc::new(AtomicUsize::new(0));
    let first_error = Arc::new(Mutex::new(None::<String>));
    let panics = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let next_request = Arc::new(AtomicUsize::new(0));
    let issued_requests = Arc::new(AtomicUsize::new(0));
    let stop_after = Arc::new(AtomicUsize::new(usize::MAX));
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();

    for _ in 0..settings.clients {
        let successful_streams = successful_streams.clone();
        let injected_requests = injected_requests.clone();
        let unexpected_failures = unexpected_failures.clone();
        let opaque_errors = opaque_errors.clone();
        let semantic_errors = semantic_errors.clone();
        let first_error = first_error.clone();
        let active = active.clone();
        let max_in_flight = max_in_flight.clone();
        let next_request = next_request.clone();
        let issued_requests = issued_requests.clone();
        let stop_after = stop_after.clone();
        let cancellation = cancellation.clone();
        let runtime = runtime.clone();
        let body = warmup_body.clone();
        let minimum_requests = settings.requests;
        tasks.spawn(async move {
            loop {
                if cancellation.is_cancelled() {
                    break;
                }
                let request = next_request.fetch_add(1, Ordering::AcqRel);
                if Instant::now() >= deadline {
                    let cohort_end = next_cohort_boundary(request.max(minimum_requests));
                    stop_after.fetch_min(cohort_end, Ordering::AcqRel);
                }
                if request >= stop_after.load(Ordering::Acquire) {
                    break;
                }
                issued_requests.fetch_add(1, Ordering::AcqRel);
                let current = active.fetch_add(1, Ordering::AcqRel).saturating_add(1);
                update_max(&max_in_flight, current);
                let result = runtime.send_mixed(request, &body).await;
                active.fetch_sub(1, Ordering::AcqRel);
                match result {
                    Ok(RequestOutcome::Success) => {
                        successful_streams.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(RequestOutcome::InjectedFailure) => {
                        injected_requests.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        unexpected_failures.fetch_add(1, Ordering::Relaxed);
                        let mut first = first_error
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if first.is_none() {
                            *first = Some(error.to_string());
                        }
                        if request % 2 == 0 {
                            opaque_errors.fetch_add(1, Ordering::Relaxed);
                        } else {
                            semantic_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
    }

    let baseline_wait = Duration::from_millis(
        settings
            .duration_secs
            .saturating_mul(1_000)
            .saturating_div(2)
            .max(100),
    );
    tokio::time::sleep(baseline_wait).await;
    let baseline = quiescent_rss().await;

    let join_timeout = Duration::from_secs(settings.duration_secs.saturating_add(30));
    let joined = tokio::time::timeout(join_timeout, async {
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    })
    .await;
    let timed_out = joined.is_err();
    if timed_out {
        cancellation.cancel();
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // Force one client disconnect while a real semantic upstream stream is
    // pending. The runtime must cancel its upstream task before drain.
    let cancellation_observed = runtime.send_cancellation().await.unwrap_or(false);
    runtime.server.drain(Duration::from_secs(5)).await?;
    let runner = runtime
        .runner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(runner) = runner {
        runner
            .await
            .context("Pooler stress server task panicked")??;
    }
    runtime.upstream.stop().await?;
    tokio::task::yield_now().await;
    let post_drain = quiescent_rss().await;
    let resources = ResourceReport::from(runtime.server.resource_snapshot());
    let rss = RssReport::from_values(baseline, post_drain);
    let upstream = runtime.upstream.stats();
    let processed = successful_streams.load(Ordering::Acquire)
        + injected_requests.load(Ordering::Acquire)
        + unexpected_failures.load(Ordering::Acquire);
    let duration_satisfied = started.elapsed() >= Duration::from_secs(settings.duration_secs);
    let observed_failures = upstream.failures.load(Ordering::Acquire);
    let failovers = upstream.fallback_after_failure.load(Ordering::Acquire);
    let retries_after_failure = upstream.retries_after_failure.load(Ordering::Acquire);
    let upstream_requests = upstream.requests.load(Ordering::Acquire);
    let issued = issued_requests.load(Ordering::Acquire);
    let issued_ids = (0..issued).collect::<BTreeSet<_>>();
    let expected_failure_ids =
        expected_failure_ids(issued, settings.seed, settings.failure_percent);
    let injected_failure_ids = upstream
        .injected_failure_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let exact_upstream_failures = deterministic_upstream_failures_match(
        &expected_failure_ids,
        &injected_failure_ids,
        observed_failures,
    );
    let seen_request_ids = upstream
        .seen_request_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let first_error = first_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let invariants = StressInvariants {
        no_panics: panics.load(Ordering::Acquire) == 0,
        no_deadlock: !timed_out,
        no_incomplete_successful_streams: unexpected_failures.load(Ordering::Acquire) == 0,
        deterministic_upstream_failures: exact_upstream_failures,
        exact_configured_failure_rate: (observed_failures as u128) * 100
            == (issued as u128) * u128::from(settings.failure_percent),
        processed_matches_issued: processed == issued,
        all_issued_requests_observed: seen_request_ids == issued_ids,
        upstream_attempt_accounting: upstream_requests
            == issued.saturating_add(retries_after_failure),
        minimum_request_count: processed >= settings.requests,
        duration_satisfied,
        failover_observed: failovers > 0,
        cancellation_observed,
        tracked_resources_zero: resources.zero_after_drain,
        rss_within_budget: rss.within_ten_percent,
    };
    Ok(StressReport {
        duration_secs: settings.duration_secs,
        configured_requests: settings.requests,
        clients: settings.clients,
        failure_percent: settings.failure_percent,
        seed: settings.seed,
        failure_schedule: "(seed + logical_request_index) mod 100 < failure_percent",
        failure_scope: "first actual upstream attempt for each issued logical request",
        elapsed_ms: started.elapsed().as_millis(),
        duration_satisfied,
        processed,
        successful_streams: successful_streams.load(Ordering::Acquire),
        injected_failures: injected_requests.load(Ordering::Acquire),
        unexpected_failures: unexpected_failures.load(Ordering::Acquire),
        panics: panics.load(Ordering::Acquire),
        timed_out,
        max_in_flight: max_in_flight.load(Ordering::Acquire),
        expected_injected_upstream_failures: expected_failure_ids.len(),
        scheduled_failure_requests: expected_failure_ids.len(),
        issued_requests: issued,
        upstream_requests,
        observed_logical_requests: seen_request_ids.len(),
        upstream_failures: observed_failures,
        retries_after_injected_failure: retries_after_failure,
        failovers,
        cancellations_observed: upstream.cancellations.load(Ordering::Acquire),
        opaque_errors: opaque_errors.load(Ordering::Acquire),
        semantic_errors: semantic_errors.load(Ordering::Acquire),
        first_error,
        resources,
        rss,
        invariants,
    })
}

async fn warmup_runtime(
    runtime: &StressRuntime,
    body: &[u8],
    requests: usize,
    clients: usize,
) -> Result<()> {
    let mut first = 0;
    while first < requests {
        let last = first.saturating_add(clients).min(requests);
        let mut batch = JoinSet::new();
        for request in first..last {
            let runtime = runtime.clone();
            let body = body.to_vec();
            batch.spawn(async move { runtime.send_mixed(request, &body).await });
        }
        while let Some(result) = batch.join_next().await {
            result.context("benchmark warmup task panicked")??;
        }
        first = last;
    }
    Ok(())
}

enum RequestOutcome {
    Success,
    InjectedFailure,
}

#[derive(Default)]
struct StressStats {
    requests: AtomicUsize,
    failures: AtomicUsize,
    fallback_after_failure: AtomicUsize,
    retries_after_failure: AtomicUsize,
    cancellations: AtomicUsize,
    injected_failure_ids: Mutex<BTreeSet<usize>>,
    failed_authorizations: Mutex<BTreeMap<usize, String>>,
    seen_request_ids: Mutex<BTreeSet<usize>>,
}

#[derive(Clone)]
struct StressUpstream {
    address: SocketAddr,
    cancellation: CancellationToken,
    task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    stats: Arc<StressStats>,
    opaque_body: Arc<Vec<u8>>,
}

impl StressUpstream {
    async fn start(seed: u64, failure_percent: u8) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let stats = Arc::new(StressStats::default());
        let opaque_body = Arc::new(vec![b'o'; OPAQUE_REQUEST_BYTES]);
        let semantic_body = Arc::new(factory_stream_body());
        let task_cancellation = cancellation.clone();
        let task_stats = Arc::clone(&stats);
        let task_opaque_body = Arc::clone(&opaque_body);
        let task_semantic_body = Arc::clone(&semantic_body);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = task_cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let Ok((stream, _)) = result else { break };
                        let stats = Arc::clone(&task_stats);
                        let opaque_body = Arc::clone(&task_opaque_body);
                        let semantic_body = Arc::clone(&task_semantic_body);
                        let cancellation = task_cancellation.clone();
                        connections.spawn(async move {
                            serve_stress_connection(
                                stream,
                                stats,
                                opaque_body,
                                semantic_body,
                                cancellation,
                                seed,
                                failure_percent,
                            )
                            .await;
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        let _ = result;
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            cancellation,
            task: Arc::new(Mutex::new(Some(task))),
            stats,
            opaque_body,
        })
    }

    fn stats(&self) -> Arc<StressStats> {
        Arc::clone(&self.stats)
    }

    fn reset_workload_stats(&self) {
        self.stats.requests.store(0, Ordering::Release);
        self.stats.failures.store(0, Ordering::Release);
        self.stats
            .fallback_after_failure
            .store(0, Ordering::Release);
        self.stats.retries_after_failure.store(0, Ordering::Release);
        self.stats.cancellations.store(0, Ordering::Release);
        self.stats
            .injected_failure_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.stats
            .failed_authorizations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.stats
            .seen_request_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    async fn stop(&self) -> Result<()> {
        self.cancellation.cancel();
        let task = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.await.context("stress upstream task panicked")?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct StressRuntime {
    server: HttpProxyServer,
    address: SocketAddr,
    runner: Arc<Mutex<Option<ServerTask>>>,
    upstream: StressUpstream,
}

type ServerTask = tokio::task::JoinHandle<Result<(), pooler_server::HttpProxyServerError>>;

impl StressRuntime {
    async fn start(settings: &Settings) -> Result<Self> {
        let upstream = StressUpstream::start(settings.seed, settings.failure_percent).await?;
        let config_text = format!(
            "version: 2\nlisteners: {{bench: {{bind: 127.0.0.1:0}}}}\nupstreams: {{bench: {{url: http://{}}}}}\naccounts:\n  primary: {{provider: bench, secret: env:POOLER_BENCH_PRIMARY}}\n  fallback: {{provider: bench, secret: env:POOLER_BENCH_FALLBACK}}\naccount_pools: {{pool: {{provider: bench, accounts: [primary, fallback]}}}}\npolicies:\n  pooled:\n    selection: {{strategy: round_robin}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, maximum_upstreams: 1, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}}\nroutes:\n  - id: opaque\n    listen: bench\n    match: {{method: POST, path: /bench/opaque}}\n    limits: {{max_request_body_bytes: 2097152, max_frame_bytes: 2097152}}\n    ingress: {{mode: opaque}}\n    response: {{mode: opaque}}\n    target: {{provider: bench, policy: pooled}}\n  - id: semantic\n    listen: bench\n    match: {{method: POST, path: /bench/semantic}}\n    limits: {{max_request_body_bytes: 2097152, max_frame_bytes: 2097152}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    target: {{provider: bench, policy: pooled}}\n",
            upstream.address
        );
        let config_text = config_text.replace(
            "  - id: semantic\n",
            "  - id: cancel\n    listen: bench\n    match: {method: POST, path: /bench/cancel}\n    limits: {max_request_body_bytes: 4096, max_frame_bytes: 4096}\n    ingress: {mode: opaque}\n    response: {mode: opaque}\n    target: {provider: bench, policy: pooled}\n  - id: semantic\n",
        );
        let config = match Config::from_yaml("pooler-bench-stress.yaml", &config_text) {
            Ok(config) => match config.compile() {
                Ok(config) => config,
                Err(error) => {
                    upstream.stop().await?;
                    return Err(error.into());
                }
            },
            Err(error) => {
                upstream.stop().await?;
                return Err(error.into());
            }
        };
        let server = match HttpProxyServer::bind(config).await {
            Ok(server) => server,
            Err(error) => {
                upstream.stop().await?;
                return Err(error.into());
            }
        };
        let address = server
            .listener_addresses()
            .first()
            .ok_or_else(|| anyhow!("stress listener was not bound"))?
            .address()
            .parse()
            .context("parse stress listener address")?;
        let server_for_task = server.clone();
        let runner = tokio::spawn(async move { server_for_task.run().await });
        tokio::task::yield_now().await;
        Ok(Self {
            server,
            address,
            runner: Arc::new(Mutex::new(Some(runner))),
            upstream,
        })
    }

    async fn send_mixed(&self, request: usize, semantic_body: &[u8]) -> Result<RequestOutcome> {
        if request % 2 == 0 {
            let body = vec![b'i'; OPAQUE_REQUEST_BYTES];
            let id = request.to_string();
            let response = send_http_request(
                self.address,
                "/bench/opaque",
                &body,
                &[("x-bench-id", id.as_str())],
            )
            .await?;
            if response.status == 429 {
                return Ok(RequestOutcome::InjectedFailure);
            }
            if response.status != 200
                || response.body.as_slice() != self.upstream.opaque_body.as_slice()
            {
                bail!("opaque stress stream did not preserve its terminal body")
            }
            return Ok(RequestOutcome::Success);
        } else {
            let id = request.to_string();
            let response = send_http_request(
                self.address,
                "/bench/semantic",
                semantic_body,
                &[
                    ("x-bench-id", id.as_str()),
                    ("idempotency-key", id.as_str()),
                    ("ai-language-model-specification-version", "3"),
                    ("ai-language-model-id", "pooler-bench-model"),
                    ("ai-language-model-streaming", "true"),
                    ("content-type", "application/json"),
                ],
            )
            .await?;
            if response.status == 429 {
                return Ok(RequestOutcome::InjectedFailure);
            }
            validate_factory_stream(response.status, &response.body)?;
        }
        Ok(RequestOutcome::Success)
    }

    async fn send_cancellation(&self) -> Result<bool> {
        let before = self.upstream.stats.cancellations.load(Ordering::Acquire);
        let mut stream = TcpStream::connect(self.address).await?;
        let body = b"cancel";
        let headers = format!(
            "POST /bench/cancel HTTP/1.1\r\nHost: pooler-bench\r\nConnection: close\r\nContent-Length: {}\r\nX-Bench-Cancel: 1\r\nContent-Type: application/octet-stream\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(body).await?;
        let _ = tokio::time::timeout(Duration::from_secs(2), read_until_headers(&mut stream)).await;
        drop(stream);
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if self.upstream.stats.cancellations.load(Ordering::Acquire) > before {
                    return true;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or(false);
        Ok(observed)
    }
}

async fn serve_stress_connection(
    mut stream: TcpStream,
    stats: Arc<StressStats>,
    opaque_body: Arc<Vec<u8>>,
    semantic_body: Arc<Vec<u8>>,
    cancellation: CancellationToken,
    seed: u64,
    failure_percent: u8,
) {
    let request =
        match tokio::time::timeout(Duration::from_secs(5), read_http_request(&mut stream)).await {
            Ok(Ok(request)) => request,
            _ => return,
        };
    let path = request_path(&request).unwrap_or_default();
    let request_id = request_header(&request, "x-bench-id")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let authorization = request_header(&request, "authorization").unwrap_or_default();
    if request_header(&request, "x-bench-cancel").is_some() {
        if write_cancellation_response(&mut stream, &semantic_body)
            .await
            .is_err()
        {
            stats.cancellations.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    if path != "/bench/semantic" && path != "/bench/opaque" {
        let _ = write_http_response(&mut stream, 404, "text/plain", b"not found").await;
        return;
    }
    stats.requests.fetch_add(1, Ordering::Relaxed);
    stats
        .seen_request_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(request_id);
    let marker = deterministic_failure(seed, request_id, failure_percent);
    let first_injected_attempt = marker
        && stats
            .injected_failure_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id);
    if first_injected_attempt {
        // Keep the synthetic failure credential-scoped: an unqualified 429 is
        // provider-scoped quota evidence and can make both benchmark accounts
        // transiently ineligible under concurrent selection. The zero-delay
        // authentication marker still exercises bounded credential failover.
        stats
            .failed_authorizations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id, authorization);
        stats.failures.fetch_add(1, Ordering::Relaxed);
        let body = br#"{"error":{"code":"invalid_api_key"}}"#;
        let _ = write_http_response_with_headers(
            &mut stream,
            429,
            "application/json",
            body,
            &[("X-Error-Code", "invalid_api_key"), ("Retry-After", "0")],
        )
        .await;
        return;
    }
    if marker {
        let failed_authorization = stats
            .failed_authorizations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id);
        if let Some(failed) = failed_authorization {
            stats.retries_after_failure.fetch_add(1, Ordering::Relaxed);
            if failed != authorization {
                stats.fallback_after_failure.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let result = match path.as_str() {
        "/bench/opaque" => {
            write_http_response(&mut stream, 200, "application/octet-stream", &opaque_body).await
        }
        "/bench/semantic" => {
            write_http_response(&mut stream, 200, "text/event-stream", &semantic_body).await
        }
        _ => write_http_response(&mut stream, 404, "text/plain", b"not found").await,
    };
    if result.is_err() && cancellation.is_cancelled() {
        stats.cancellations.fetch_add(1, Ordering::Relaxed);
    }
}

fn factory_stream_body() -> Vec<u8> {
    let chunks = [
        r#"data: {"id":"pooler-bench","model":"pooler-bench-model","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

"#,
        r#"data: {"id":"pooler-bench","model":"pooler-bench-model","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}

"#,
        r#"data: {"id":"pooler-bench","model":"pooler-bench-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}

"#,
        "data: [DONE]\n\n",
    ];
    chunks.concat().into_bytes()
}

fn request_path(request: &[u8]) -> Option<String> {
    std::str::from_utf8(request)
        .ok()?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

fn request_header(request: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(request).ok()?;
    text.lines().skip(1).find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write_http_response_with_headers(stream, status, content_type, body, &[]).await
}

async fn write_http_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    // Callers provide bare names and values; emit the field delimiter exactly
    // once at this boundary.
    for (name, value) in extra_headers {
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes()).await?;
    for chunk in body.chunks(4096) {
        stream.write_all(chunk).await?;
        if body.len() > 16 * 1024 {
            tokio::task::yield_now().await;
        }
    }
    Ok(())
}

async fn write_cancellation_response(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let first_event_end = body
        .windows(2)
        .position(|window| window == b"\n\n")
        .map_or(body.len(), |index| index + 2);
    let first = &body[..first_event_end];
    let repetitions = 128_usize;
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        first.len().saturating_mul(repetitions)
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(first).await?;
    for _ in 1..repetitions {
        tokio::time::sleep(Duration::from_millis(10)).await;
        stream.write_all(first).await?;
    }
    Ok(())
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn send_http_request(
    address: SocketAddr,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Result<HttpResponse> {
    let mut stream = TcpStream::connect(address).await?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: pooler-bench\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    let (status, body) = read_http_response(&mut stream).await?;
    Ok(HttpResponse { status, body })
}

fn validate_factory_stream(status: u16, body: &[u8]) -> Result<()> {
    if status != 200 {
        let code = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let diagnostic = match code.as_deref() {
            Some("upstream_error" | "upstream_timeout") => "pooler upstream request failure",
            Some("invalid_upstream_response") => "pooler semantic response failure",
            _ => "unclassified bounded response",
        };
        bail!("semantic stress request returned HTTP {status}: {diagnostic}")
    }
    let mut parser = SseParser::new();
    let events = parser.feed(body)?;
    let mut saw_done = false;
    let mut saw_finish = false;
    for event in events {
        if event.is_done() {
            saw_done = true;
        } else if serde_json::from_str::<Value>(&event.data)
            .ok()
            .is_some_and(|value| value.get("type").and_then(Value::as_str) == Some("finish"))
        {
            saw_finish = true;
        }
    }
    parser.finish()?;
    if !saw_done || !saw_finish {
        bail!(
            "semantic stream did not produce a finish event and [DONE]: status={status}, body_bytes={}",
            body.len()
        )
    }
    Ok(())
}

fn deterministic_failure(seed: u64, request: usize, percent: u8) -> bool {
    if percent == 0 {
        return false;
    }
    if percent == 100 {
        return true;
    }
    ((seed.wrapping_add(request as u64)) % 100) < u64::from(percent)
}

fn next_cohort_boundary(request: usize) -> usize {
    request
        .saturating_add(99)
        .saturating_div(100)
        .saturating_mul(100)
}

fn expected_failure_ids(requests: usize, seed: u64, percent: u8) -> BTreeSet<usize> {
    // Keep the verifier independent from `deterministic_failure`. A regression
    // in the upstream injector must not silently change its own oracle.
    (0..requests)
        .filter(|request| {
            percent == 100
                || (percent > 0 && seed.wrapping_add(*request as u64) % 100 < u64::from(percent))
        })
        .collect()
}

fn deterministic_upstream_failures_match(
    expected_ids: &BTreeSet<usize>,
    injected_ids: &BTreeSet<usize>,
    upstream_failures: usize,
) -> bool {
    upstream_failures == expected_ids.len() && injected_ids == expected_ids
}

fn update_max(value: &AtomicUsize, candidate: usize) {
    let mut current = value.load(Ordering::Relaxed);
    while candidate > current {
        match value.compare_exchange_weak(current, candidate, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl From<RuntimeResourceSnapshot> for ResourceReport {
    fn from(snapshot: RuntimeResourceSnapshot) -> Self {
        Self {
            source: "pooler_server.HttpProxyServer.resource_snapshot",
            tasks: snapshot.tasks,
            permits: snapshot.permits,
            refresh_leases: snapshot.refresh_leases,
            temporary_files: snapshot.temporary_files,
            secret_material: snapshot.secret_material,
            peak_tasks: snapshot.peak_tasks,
            peak_permits: snapshot.peak_permits,
            peak_refresh_leases: snapshot.peak_refresh_leases,
            peak_temporary_files: snapshot.peak_temporary_files,
            peak_secret_material: snapshot.peak_secret_material,
            zero_after_drain: snapshot.is_zero(),
        }
    }
}

impl RssReport {
    fn from_values(baseline: Option<u64>, post_drain: Option<u64>) -> Self {
        let delta_percent = baseline.zip(post_drain).map(|(baseline, post)| {
            if baseline == 0 {
                0.0
            } else {
                (post.saturating_sub(baseline) as f64 / baseline as f64) * 100.0
            }
        });
        Self {
            supported: baseline.is_some() && post_drain.is_some(),
            baseline_bytes: baseline,
            post_drain_bytes: post_drain,
            within_ten_percent: delta_percent.is_some_and(|delta| delta <= 10.0),
            delta_percent,
        }
    }
}

fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let contents = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = contents.lines().find(|line| line.starts_with("VmRSS:"))?;
        let value = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        Some(value.saturating_mul(1024))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

async fn quiescent_rss() -> Option<u64> {
    let mut samples = Vec::with_capacity(4);
    for _ in 0..4 {
        tokio::task::yield_now().await;
        if let Some(value) = current_rss_bytes() {
            samples.push(value);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    samples.into_iter().max()
}

struct EchoUpstream {
    address: SocketAddr,
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl EchoUpstream {
    async fn start(response: Arc<Vec<u8>>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = task_cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let Ok((mut stream, _)) = result else { break };
                        let response = Arc::clone(&response);
                        connections.spawn(async move {
                            if read_http_request(&mut stream).await.is_err() {
                                return;
                            }
                            let headers = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                response.len()
                            );
                            let _ = stream.write_all(headers.as_bytes()).await;
                            let _ = stream.write_all(&response).await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            cancellation,
            task,
        })
    }

    async fn stop(self) -> Result<()> {
        self.cancellation.cancel();
        self.task.await.context("echo upstream task panicked")?;
        Ok(())
    }
}

async fn read_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = read_until_headers(stream).await?;
    let header_end = find_header_end(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request headers are incomplete",
        )
    })?;
    let body_length = content_length(&bytes[..header_end]).unwrap_or(0);
    read_exactly(stream, &mut bytes, header_end + 4 + body_length).await?;
    Ok(bytes)
}

async fn read_http_response(stream: &mut TcpStream) -> io::Result<(u16, Vec<u8>)> {
    let mut bytes = read_until_headers(stream).await?;
    let header_end = find_header_end(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response headers are incomplete",
        )
    })?;
    let status = std::str::from_utf8(&bytes[..header_end])
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    let body_start = header_end + 4;
    let body = if let Some(body_length) = content_length(&bytes[..header_end]) {
        read_exactly(stream, &mut bytes, body_start + body_length).await?;
        bytes[body_start..body_start + body_length].to_vec()
    } else if transfer_encoding_chunked(&bytes[..header_end]) {
        let mut encoded = bytes.split_off(body_start);
        read_chunked_body(stream, &mut encoded).await?
    } else {
        let mut body = bytes.split_off(body_start);
        stream.read_to_end(&mut body).await?;
        body
    };
    Ok((status, body))
}

async fn read_until_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    while find_header_end(&bytes).is_none() {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP headers",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers exceed benchmark bound",
            ));
        }
    }
    Ok(bytes)
}

async fn read_exactly(
    stream: &mut TcpStream,
    bytes: &mut Vec<u8>,
    target: usize,
) -> io::Result<()> {
    let mut buffer = [0_u8; 4096];
    while bytes.len() < target {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP body",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(())
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

fn transfer_encoding_chunked(headers: &[u8]) -> bool {
    std::str::from_utf8(headers).is_ok_and(|headers| {
        headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value
                        .split(',')
                        .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
            })
        })
    })
}

async fn read_chunked_body(stream: &mut TcpStream, encoded: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = loop {
            if let Some(index) = encoded.windows(2).position(|window| window == b"\r\n") {
                break index;
            }
            read_more(stream, encoded).await?;
        };
        let line = encoded.drain(..line_end).collect::<Vec<_>>();
        encoded.drain(..2);
        let size_text = std::str::from_utf8(&line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            return Ok(decoded);
        }
        while encoded.len() < size + 2 {
            read_more(stream, encoded).await?;
        }
        decoded.extend_from_slice(&encoded[..size]);
        encoded.drain(..size + 2);
    }
}

async fn read_more(stream: &mut TcpStream, bytes: &mut Vec<u8>) -> io::Result<()> {
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer).await?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before chunked response completed",
        ));
    }
    bytes.extend_from_slice(&buffer[..read]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead_budget_uses_pooler_minus_direct_latency() {
        let report = latency_report_with_baseline(
            vec![
                OpaqueLatencySample {
                    pooled: Duration::from_millis(5),
                    direct: Duration::from_millis(2),
                },
                OpaqueLatencySample {
                    pooled: Duration::from_millis(6),
                    direct: Duration::from_millis(3),
                },
            ],
            OPAQUE_REQUEST_BYTES,
            Duration::from_millis(3),
        );
        assert_eq!(report.p95_us, 6_000);
        assert_eq!(report.direct_p95_us, Some(3_000));
        assert_eq!(report.overhead_p95_us, Some(3_000));
        assert!(report.budget_passed);
    }

    #[test]
    fn overhead_gate_rejects_false_pass_from_independent_percentiles() {
        let report = latency_report_with_baseline(
            vec![
                OpaqueLatencySample {
                    pooled: Duration::from_millis(100),
                    direct: Duration::from_millis(1),
                },
                OpaqueLatencySample {
                    pooled: Duration::from_millis(100),
                    direct: Duration::from_millis(100),
                },
            ],
            OPAQUE_REQUEST_BYTES,
            Duration::from_millis(1),
        );

        assert_eq!(report.p95_us, 100_000);
        assert_eq!(report.direct_p95_us, Some(100_000));
        assert_eq!(report.overhead_p95_us, Some(99_000));
        assert!(!report.budget_passed);
    }

    #[tokio::test]
    async fn injected_auth_failure_headers_parse_at_the_http_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("header test listener");
        let address = listener.local_addr().expect("header test address");
        let writer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("header test accept");
            write_http_response_with_headers(
                &mut stream,
                429,
                "application/json",
                br#"{"error":{"code":"invalid_api_key"}}"#,
                &[("X-Error-Code", "invalid_api_key"), ("Retry-After", "0")],
            )
            .await
            .expect("header test response");
        });

        let mut client = TcpStream::connect(address)
            .await
            .expect("header test connect");
        let response = read_until_headers(&mut client)
            .await
            .expect("header test response headers");
        writer.await.expect("header writer task");

        assert_eq!(
            request_header(&response, "X-Error-Code"),
            Some("invalid_api_key".to_owned())
        );
        assert_eq!(
            request_header(&response, "Retry-After"),
            Some("0".to_owned())
        );
        let headers =
            std::str::from_utf8(&response[..find_header_end(&response).expect("header boundary")])
                .expect("valid response headers");
        assert!(!headers.contains("X-Error-Code: : "));
        assert!(!headers.contains("Retry-After: : "));
    }

    fn release_settings() -> Settings {
        Settings {
            mode: Mode::All,
            short: false,
            opaque_samples: 1_000,
            semantic_samples: 100,
            duration_secs: FULL_STRESS_DURATION_SECS,
            requests: FULL_STRESS_REQUESTS,
            clients: FULL_STRESS_CLIENTS,
            failure_percent: FULL_FAILURE_PERCENT,
            seed: 0,
            runs: 3,
            json: false,
            output: None,
            enforce_budgets: true,
        }
    }

    #[test]
    fn enforced_benchmarks_reject_every_non_release_workload_dimension() {
        assert!(release_settings().validate().is_ok());

        let mut settings = release_settings();
        settings.mode = Mode::Stress;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.short = true;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.opaque_samples = 999;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.semantic_samples = 99;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.duration_secs = FULL_STRESS_DURATION_SECS - 1;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.requests = FULL_STRESS_REQUESTS - 1;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.clients = FULL_STRESS_CLIENTS - 1;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.failure_percent = FULL_FAILURE_PERCENT - 1;
        assert!(settings.validate().is_err());
        let mut settings = release_settings();
        settings.runs = 2;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn enforced_benchmarks_reject_dirty_or_non_release_provenance() {
        let provenance = |worktree_clean, build_profile| ProvenanceReport {
            commit_sha: "commit".to_owned(),
            worktree_clean,
            rustc_verbose_version: "rustc".to_owned(),
            host_target: "host".to_owned(),
            benchmark_target: "host".to_owned(),
            host: "host".to_owned(),
            build_profile,
            command: vec!["pooler-bench".to_owned()],
        };
        let settings = release_settings();

        assert!(settings
            .validate_provenance(&provenance(false, "release"))
            .is_err());
        assert!(settings
            .validate_provenance(&provenance(true, "debug"))
            .is_err());
        assert!(settings
            .validate_provenance(&provenance(true, "release"))
            .is_ok());
    }

    #[test]
    fn failure_verifier_rejects_marker_only_and_count_only_evidence() {
        let expected = expected_failure_ids(100, 0, 20);
        let wrong_ids = (80..100).collect::<BTreeSet<_>>();

        assert_eq!(expected, (0..20).collect());
        assert_eq!(expected_failure_ids(100, 90, 20), (10..30).collect());

        assert!(!deterministic_upstream_failures_match(
            &expected, &expected, 0
        ));
        assert!(!deterministic_upstream_failures_match(
            &expected,
            &wrong_ids,
            expected.len()
        ));
        assert!(deterministic_upstream_failures_match(
            &expected,
            &expected,
            expected.len()
        ));
    }

    #[test]
    fn resource_verifier_rejects_a_live_pooler_runtime_resource() {
        let snapshot = RuntimeResourceSnapshot {
            tasks: 1,
            peak_tasks: 1,
            ..RuntimeResourceSnapshot::default()
        };
        let report = ResourceReport::from(snapshot);

        assert_eq!(
            report.source,
            "pooler_server.HttpProxyServer.resource_snapshot"
        );
        assert!(!report.zero_after_drain);
    }

    #[test]
    fn rss_bound_requires_supported_quiescent_measurements() {
        assert!(RssReport::from_values(Some(100), Some(109)).within_ten_percent);
        assert!(!RssReport::from_values(Some(100), Some(111)).within_ten_percent);
        assert!(!RssReport::from_values(None, None).within_ten_percent);
    }
}
