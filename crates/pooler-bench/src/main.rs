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
    collections::BTreeSet,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use adapter_factory::{FactoryEventEncoder, FactoryLanguageModelDecoder};
use anyhow::{anyhow, bail, Context, Result};
use pooler_config::Config;
use pooler_http::SseParser;
use pooler_protocol::{
    FinishReason, LossPolicy, OpenAiChatCodec, OpenAiChatEventDecoder, OpenAiChatEventEncoder,
    StreamEvent, StreamEventKind, Usage,
};
use pooler_server::HttpProxyServer;
use pooler_testkit::{LeakCounters, LeakSnapshot};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
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
        if self.enforce_budgets && self.runs < 3 {
            bail!("--runs must be at least 3 when --enforce-budgets is enabled")
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
    mode: String,
    short: bool,
    seed: u64,
    runs: Vec<RunReport>,
    stress: Option<StressReport>,
    all_invariants_passed: bool,
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
    elapsed_ms: u128,
    duration_satisfied: bool,
    processed: usize,
    successful_streams: usize,
    injected_failures: usize,
    unexpected_failures: usize,
    panics: usize,
    timed_out: bool,
    max_in_flight: usize,
    expected_injected_failures: usize,
    marker_requests: usize,
    issued_requests: usize,
    upstream_requests: usize,
    upstream_failures: usize,
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
    tasks: u64,
    permits: u64,
    refresh_leases: u64,
    temporary_files: u64,
    secret_material: u64,
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
    deterministic_failure_count: bool,
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
            && report.invariants.deterministic_failure_count
            && report.invariants.minimum_request_count
            && report.invariants.duration_satisfied
            && report.invariants.failover_observed
            && report.invariants.cancellation_observed
            && report.invariants.tracked_resources_zero
            && report.invariants.rss_within_budget
    });
    Ok(Report {
        schema_version: 1,
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
            "version: 1\nlisteners: {{bench: {{bind: 127.0.0.1:0}}}}\nupstreams: {{bench: {{url: http://{}}}}}\nroutes:\n  - id: opaque\n    listen: bench\n    match: {{method: POST, path: /bench}}\n    ingress: {{mode: opaque}}\n    response: {{mode: opaque}}\n    target: bench\n",
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
    let mut durations = Vec::with_capacity(samples);
    let mut direct_durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let direct =
            measure_opaque_request(upstream.address, &request_body, response_body.as_slice()).await;
        let pooled = measure_opaque_request(address, &request_body, response_body.as_slice()).await;
        match (direct, pooled) {
            (Ok(direct), Ok(pooled)) => {
                direct_durations.push(direct);
                durations.push(pooled);
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
        durations,
        direct_durations,
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

fn latency_report_with_baseline(
    durations: Vec<Duration>,
    direct_durations: Vec<Duration>,
    payload_bytes: usize,
    budget: Duration,
) -> LatencyReport {
    let mut pooled = durations;
    pooled.sort_unstable();
    let mut report = latency_report(pooled.clone(), payload_bytes, budget);
    let mut direct = direct_durations;
    direct.sort_unstable();
    let direct_p50 = percentile(&direct, 0.50);
    let direct_p95 = percentile(&direct, 0.95);
    let direct_max = direct.last().copied().unwrap_or_default();
    // Compare like-for-like percentile measurements. Pairing independent TCP
    // samples makes scheduler noise dominate the hop cost; retaining both raw
    // distributions keeps the baseline auditable while this subtraction
    // estimates the Pooler-only p95 required by the architecture budget.
    let pooled_p50 = percentile(&pooled, 0.50);
    let pooled_p95 = percentile(&pooled, 0.95);
    let pooled_max = pooled.last().copied().unwrap_or_default();
    let overhead_p50 = pooled_p50.saturating_sub(direct_p50);
    let overhead_p95 = pooled_p95.saturating_sub(direct_p95);
    let overhead_max = pooled_max.saturating_sub(direct_max);
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
    let counters = LeakCounters::new();
    let semaphore = Arc::new(Semaphore::new(settings.clients));
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
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();

    for _ in 0..settings.clients {
        let counters = counters.clone();
        let semaphore = semaphore.clone();
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
        let cancellation = cancellation.clone();
        let runtime = runtime.clone();
        let body = warmup_body.clone();
        let minimum_requests = settings.requests;
        tasks.spawn(async move {
            let _task = counters.task();
            loop {
                if cancellation.is_cancelled() {
                    break;
                }
                let request = next_request.fetch_add(1, Ordering::AcqRel);
                if request >= minimum_requests && Instant::now() >= deadline {
                    break;
                }
                let permit = semaphore.acquire().await;
                let Ok(_permit) = permit else {
                    break;
                };
                let _tracked_permit = counters.permit();
                let _credential_lease = counters.refresh_lease();
                let _temporary_body = counters.temporary_file();
                let _secret = counters.secret_material();
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
    let _ = runtime.server.drain(Duration::from_secs(5)).await;
    let runner = runtime
        .runner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(runner) = runner {
        let _ = runner.await;
    }
    runtime.upstream.stop().await?;
    tokio::task::yield_now().await;
    let post_drain = quiescent_rss().await;
    let snapshot = counters.snapshot();
    let resources = ResourceReport::from(snapshot);
    let rss = RssReport::from_values(baseline, post_drain);
    let upstream = runtime.upstream.stats();
    let processed = successful_streams.load(Ordering::Acquire)
        + injected_requests.load(Ordering::Acquire)
        + unexpected_failures.load(Ordering::Acquire);
    let duration_satisfied = started.elapsed() >= Duration::from_secs(settings.duration_secs);
    let observed_failures = upstream.failures.load(Ordering::Acquire);
    let failovers = upstream.fallback_after_failure.load(Ordering::Acquire);
    let issued = issued_requests.load(Ordering::Acquire);
    let expected_markers = expected_markers(issued, settings.seed, settings.failure_percent);
    let marker_requests = upstream
        .marked_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    let first_error = first_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let invariants = StressInvariants {
        no_panics: panics.load(Ordering::Acquire) == 0,
        no_deadlock: !timed_out,
        no_incomplete_successful_streams: unexpected_failures.load(Ordering::Acquire) == 0,
        deterministic_failure_count: marker_requests == expected_markers,
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
        elapsed_ms: started.elapsed().as_millis(),
        duration_satisfied,
        processed,
        successful_streams: successful_streams.load(Ordering::Acquire),
        injected_failures: injected_requests.load(Ordering::Acquire),
        unexpected_failures: unexpected_failures.load(Ordering::Acquire),
        panics: panics.load(Ordering::Acquire),
        timed_out,
        max_in_flight: max_in_flight.load(Ordering::Acquire),
        expected_injected_failures: expected_markers,
        marker_requests,
        issued_requests: issued,
        upstream_requests: upstream.requests.load(Ordering::Acquire),
        upstream_failures: observed_failures,
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
    marked_primary: AtomicUsize,
    fallback_after_failure: AtomicUsize,
    cancellations: AtomicUsize,
    failed_ids: Mutex<BTreeSet<usize>>,
    marked_ids: Mutex<BTreeSet<usize>>,
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
        self.stats.marked_primary.store(0, Ordering::Release);
        self.stats
            .fallback_after_failure
            .store(0, Ordering::Release);
        self.stats.cancellations.store(0, Ordering::Release);
        self.stats
            .failed_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.stats
            .marked_ids
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
            "version: 1\nlisteners: {{bench: {{bind: 127.0.0.1:0}}}}\nupstreams: {{bench: {{url: http://{}}}}}\naccounts:\n  primary: {{provider: bench, secret: env:POOLER_BENCH_PRIMARY}}\n  fallback: {{provider: bench, secret: env:POOLER_BENCH_FALLBACK}}\naccount_pools: {{pool: {{accounts: [primary, fallback]}}}}\npolicies:\n  pooled:\n    selection: {{strategy: round_robin, account_pool: pool}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, maximum_providers: 1, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}}\nroutes:\n  - id: opaque\n    listen: bench\n    match: {{method: POST, path: /bench/opaque}}\n    limits: {{max_request_body_bytes: 2097152, max_frame_bytes: 2097152}}\n    ingress: {{mode: opaque}}\n    response: {{mode: opaque}}\n    target: {{provider: bench, policy: pooled}}\n  - id: semantic\n    listen: bench\n    match: {{method: POST, path: /bench/semantic}}\n    limits: {{max_request_body_bytes: 2097152, max_frame_bytes: 2097152}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    target: {{provider: bench, policy: pooled}}\n",
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
            if response.status == 500 {
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
    stats.requests.fetch_add(1, Ordering::Relaxed);
    let path = request_path(&request).unwrap_or_default();
    let request_id = request_header(&request, "x-bench-id")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let authorization = request_header(&request, "authorization").unwrap_or_default();
    let primary = authorization == "Bearer pooler-bench-primary";
    if request_header(&request, "x-bench-cancel").is_some() {
        if write_cancellation_response(&mut stream, &semantic_body)
            .await
            .is_err()
        {
            stats.cancellations.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    let marker = deterministic_failure(seed, request_id, failure_percent);
    if marker {
        stats
            .marked_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id);
    }
    if (path == "/bench/semantic" || path == "/bench/opaque") && primary && marker {
        stats.marked_primary.fetch_add(1, Ordering::Relaxed);
        stats.failures.fetch_add(1, Ordering::Relaxed);
        let body = br#"{"error":"deterministic benchmark failure"}"#;
        let _ = write_http_response_with_headers(
            &mut stream,
            if path == "/bench/semantic" { 429 } else { 500 },
            "application/json",
            body,
            &[("X-Error-Code", "insufficient_quota"), ("Retry-After", "0")],
        )
        .await;
        if path == "/bench/semantic" {
            stats
                .failed_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(request_id);
        }
        return;
    }
    if path == "/bench/semantic" && !primary && marker {
        let failed = stats
            .failed_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id);
        if failed {
            stats.fallback_after_failure.fetch_add(1, Ordering::Relaxed);
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
        bail!("semantic stress request returned HTTP {status}")
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

fn expected_markers(requests: usize, seed: u64, percent: u8) -> usize {
    (0..requests)
        .filter(|request| deterministic_failure(seed, *request, percent))
        .count()
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

impl From<LeakSnapshot> for ResourceReport {
    fn from(snapshot: LeakSnapshot) -> Self {
        Self {
            tasks: snapshot.tasks,
            permits: snapshot.permits,
            refresh_leases: snapshot.refresh_leases,
            temporary_files: snapshot.temporary_files,
            secret_material: snapshot.secret_material,
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
            vec![Duration::from_millis(5), Duration::from_millis(6)],
            vec![Duration::from_millis(2), Duration::from_millis(3)],
            OPAQUE_REQUEST_BYTES,
            Duration::from_millis(3),
        );
        assert_eq!(report.p95_us, 6_000);
        assert_eq!(report.direct_p95_us, Some(3_000));
        assert_eq!(report.overhead_p95_us, Some(3_000));
        assert!(report.budget_passed);
    }

    #[test]
    fn enforced_benchmarks_require_three_runs() {
        let mut settings = Settings {
            mode: Mode::Opaque,
            short: true,
            opaque_samples: 1,
            semantic_samples: 1,
            duration_secs: 1,
            requests: 1,
            clients: 1,
            failure_percent: 20,
            seed: 0,
            runs: 2,
            json: false,
            output: None,
            enforce_budgets: true,
        };
        assert!(settings.validate().is_err());
        settings.runs = 3;
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn rss_bound_requires_supported_quiescent_measurements() {
        assert!(RssReport::from_values(Some(100), Some(109)).within_ten_percent);
        assert!(!RssReport::from_values(Some(100), Some(111)).within_ten_percent);
        assert!(!RssReport::from_values(None, None).within_ten_percent);
    }
}
