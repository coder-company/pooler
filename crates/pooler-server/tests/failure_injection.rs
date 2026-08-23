use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use adapter_devin::{
    encode_connect_frame, proto, read_connect_trailer_error, ConnectDecoder, ConnectLimits,
};
use futures_util::{SinkExt, StreamExt};
use pooler_auth::{OAuthFuture, OAuthRefresher, OAuthTokenStore, OAuthTokens, SecretValue};
use pooler_config::{compile_yaml, CompiledConfig};
use pooler_http::{NativeRuntime, RuntimeResourceSnapshot};
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use pooler_testkit::{CancellationTracker, LeakCounters, LeakGuard};
use prost::Message;
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message as WebSocketMessage};
use tokio_util::sync::CancellationToken;

const CORPUS: &str = include_str!("../../../tests/failure-injection/corpus.json");
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_GRACE: Duration = Duration::from_millis(100);
const WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: u32,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    kind: String,
    boundary: String,
    outcome: Outcome,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    delay_millis: Option<u64>,
    commitment: String,
    expected_attempts: usize,
    expected_health_mutation: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Response,
    Cancelled,
    Error,
}

impl Case {
    fn assert_declared_contract(&self) {
        let (outcome, status) = match self.kind.as_str() {
            "connection_refused"
            | "tls_failure"
            | "partial_sse"
            | "invalid_utf8"
            | "missing_terminal_event"
            | "websocket_disconnect"
            | "truncated_connect"
            | "partial_connect" => (Outcome::Error, None),
            "slow_headers" | "fragmented_websocket" => (Outcome::Response, None),
            "downstream_disconnect" => (Outcome::Cancelled, None),
            "status_401_refresh" => (Outcome::Response, Some(401)),
            "status_429_recovery" => (Outcome::Response, Some(429)),
            "request_invalid" => (Outcome::Error, Some(400)),
            kind => panic!("{} has unsupported runtime fault kind {kind}", self.id),
        };
        assert_eq!(self.outcome, outcome, "{} declared outcome", self.id);
        assert_eq!(self.status, status, "{} declared status", self.id);
    }

    fn assert_outcome(&self, outcome: Outcome) {
        assert_eq!(self.outcome, outcome, "{} runtime outcome", self.id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_fault_corpus_runs_through_the_real_runtime() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("failure corpus JSON");
    assert_eq!(corpus.schema_version, 2);

    for case in corpus.cases {
        case.assert_declared_contract();
        eprintln!("running fault case {}", case.id);
        let counters = LeakCounters::new();
        execute_case(&case, counters.clone()).await;
        counters
            .assert_zero()
            .unwrap_or_else(|error| panic!("{} leaked resources: {error}", case.id));
    }
}

#[test]
fn runtime_case_rejects_unknown_fields() {
    let error = serde_json::from_str::<Case>(
        r#"{
            "id":"unknown-field",
            "kind":"connection_refused",
            "boundary":"http",
            "outcome":"error",
            "commitment":"before",
            "expected_attempts":2,
            "expected_health_mutation":"none",
            "unexpected":true
        }"#,
    )
    .expect_err("runtime case must reject unknown fields");
    assert!(error.to_string().contains("unknown field `unexpected`"));
}

#[tokio::test]
async fn fixture_drop_aborts_owned_task_handles() {
    let counters = LeakCounters::new();
    let config = compile_yaml(
        "fault-drop.yaml",
        "version: 1\nlisteners: {local: {bind: 127.0.0.1:0}}\nroutes: []\n",
    )
    .expect("drop-cleanup config compiles");
    let server = HttpProxyServer::bind(config)
        .await
        .expect("drop-cleanup server binds");
    let address = server.listener_addresses()[0]
        .address()
        .parse()
        .expect("drop-cleanup address parses");
    let probe = server.clone();
    let running = spawn_running_server(server, Some(address), Vec::new(), &counters);
    timeout(TEST_TIMEOUT, async {
        while probe.resource_snapshot().tasks == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Pooler fixture task starts");
    drop(running);
    timeout(TEST_TIMEOUT, async {
        while !probe.resource_snapshot().is_zero() || !counters.is_zero() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Pooler fixture drop aborts its runner");

    let upstream = spawn_http_upstream(HttpFault::Success, counters.clone(), None).await;
    assert!(!counters.is_zero(), "upstream task guard was not acquired");
    drop(upstream);
    timeout(TEST_TIMEOUT, async {
        while !counters.is_zero() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upstream fixture drop aborts its runner");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unix_listener_tracks_its_runtime_socket_until_shutdown() {
    use tokio::net::UnixStream;

    let counters = LeakCounters::new();
    let upstream = spawn_http_upstream(HttpFault::Success, counters.clone(), None).await;
    let directory = tempfile::tempdir().expect("Unix listener directory");
    let socket_path = directory.path().join("pooler.sock");
    let downstream_secret = TestSecret::new("unix-token", &counters);
    let yaml = format!(
        "version: 1\nlisteners:\n  local:\n    bind: unix:{}\nupstreams:\n  local:\n    url: http://{}\n    transport: {{connect_timeout: 500ms, request_timeout: 3s}}\nroutes:\n  - id: fault\n    listen: local\n    match: {{method: POST, path: /fault, content_types: [application/json]}}\n    downstream_auth: {{secret: {}}}\n    ingress: {{mode: patch}}\n    target: {{provider: local}}\n    response: {{mode: opaque}}\n",
        socket_path.display(),
        upstream.address,
        downstream_secret.reference(),
    );
    let config = compile_yaml("fault-unix.yaml", &yaml).expect("Unix fault config compiles");
    let server = HttpProxyServer::bind(config)
        .await
        .expect("Unix fault server binds");
    let bound = server.resource_snapshot();
    assert_eq!(
        bound.temporary_files, 1,
        "Unix socket is tracked while bound"
    );
    assert!(
        bound.peak_temporary_files > 0,
        "Unix listener did not record a temporary-file peak"
    );
    assert!(socket_path.exists(), "Unix socket was not created");
    let running = spawn_running_server(server, None, vec![downstream_secret], &counters);

    let mut client = UnixStream::connect(&socket_path)
        .await
        .expect("downstream connects to Unix listener");
    client
        .write_all(
            b"POST /fault HTTP/1.1\r\nHost: fault.test\r\nAuthorization: Bearer unix-token\r\nContent-Type: application/json\r\nIdempotency-Key: fault-unix\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await
        .expect("Unix request writes");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .expect("Unix response completes")
        .expect("Unix response bytes");
    assert_eq!(response_status(&response), 200);
    wait_for_attempts(&upstream.attempts, 1, "unix-listener").await;

    assert_eq!(upstream.stop().await, 1);
    let drained = running.stop().await;
    assert_eq!(
        drained.temporary_files, 0,
        "Unix socket guard remained live"
    );
    assert!(drained.peak_temporary_files > 0);
    assert!(!socket_path.exists(), "Unix socket remained after shutdown");
    counters
        .assert_zero()
        .expect("Unix listener test released every tracked resource");
}

async fn execute_case(case: &Case, counters: LeakCounters) {
    match case.kind.as_str() {
        "connection_refused" => execute_connection_refused(case, counters).await,
        "tls_failure" => execute_http_fault(case, HttpFault::TlsHandshake, counters).await,
        "slow_headers" => {
            execute_http_fault(
                case,
                HttpFault::SlowHeaders(Duration::from_millis(
                    case.delay_millis.expect("slow-header delay"),
                )),
                counters,
            )
            .await;
        }
        "downstream_disconnect" => execute_downstream_disconnect(case, counters).await,
        "status_401_refresh" => execute_native_refresh(case, counters).await,
        "status_429_recovery" => {
            execute_http_fault(case, HttpFault::QuotaThenSuccess, counters).await;
        }
        "request_invalid" => {
            execute_http_fault(case, HttpFault::InvalidRequest, counters).await;
        }
        "partial_sse" => execute_sse_fault(case, SseFault::Partial, counters).await,
        "invalid_utf8" => execute_sse_fault(case, SseFault::InvalidUtf8, counters).await,
        "missing_terminal_event" => {
            execute_sse_fault(case, SseFault::MissingTerminal, counters).await;
        }
        "fragmented_websocket" => execute_fragmented_websocket(case, counters).await,
        "websocket_disconnect" => execute_websocket_disconnect(case, counters).await,
        "truncated_connect" => execute_truncated_connect(case, counters).await,
        "partial_connect" => execute_partial_connect(case, counters).await,
        kind => panic!("{} has unsupported runtime fault kind {kind}", case.id),
    }
}

#[derive(Clone, Copy)]
enum HttpFault {
    TlsHandshake,
    SlowHeaders(Duration),
    QuotaThenSuccess,
    InvalidRequest,
    WaitForDownstream { after_headers: bool },
    Sse(SseFault),
    RefreshThenSuccess,
    Success,
}

#[derive(Clone, Copy)]
enum SseFault {
    Partial,
    InvalidUtf8,
    MissingTerminal,
}

struct RunningUpstream {
    address: SocketAddr,
    attempts: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl RunningUpstream {
    async fn stop(mut self) -> usize {
        self.cancellation.cancel();
        let mut task = self.task.take().expect("upstream task is present");
        let joined = match timeout(TEST_TIMEOUT, &mut task).await {
            Ok(joined) => joined,
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("upstream task did not stop");
            }
        };
        joined.expect("upstream task joins");
        self.attempts.load(Ordering::SeqCst)
    }
}

impl Drop for RunningUpstream {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn spawn_http_upstream(
    fault: HttpFault,
    counters: LeakCounters,
    cancellation_tracker: Option<CancellationTracker>,
) -> RunningUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fault upstream binds");
    let address = listener.local_addr().expect("fault upstream address");
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_task = Arc::clone(&attempts);
    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    let task_guard = counters.task();
    let task = tokio::spawn(async move {
        let _task_guard = task_guard;
        loop {
            let accepted = tokio::select! {
                () = stop.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (mut stream, _) = accepted.expect("fault upstream accepts");
            let _permit = counters.permit();
            let attempt = attempts_for_task.fetch_add(1, Ordering::SeqCst) + 1;
            serve_http_fault(&mut stream, fault, attempt, cancellation_tracker.as_ref()).await;
        }
    });
    RunningUpstream {
        address,
        attempts,
        cancellation,
        task: Some(task),
    }
}

async fn serve_http_fault(
    stream: &mut TcpStream,
    fault: HttpFault,
    attempt: usize,
    cancellation_tracker: Option<&CancellationTracker>,
) {
    if matches!(fault, HttpFault::TlsHandshake) {
        let mut byte = [0_u8; 1];
        let _ = timeout(TEST_TIMEOUT, stream.read(&mut byte)).await;
        return;
    }

    read_request(stream).await.expect("fault request bytes");
    match fault {
        HttpFault::TlsHandshake => unreachable!("TLS fault handled before HTTP parsing"),
        HttpFault::SlowHeaders(delay) => {
            sleep(delay).await;
            write_response(stream, 200, "OK", &[], b"ok").await;
        }
        HttpFault::QuotaThenSuccess => {
            if attempt == 1 {
                write_response(
                    stream,
                    429,
                    "Too Many Requests",
                    &[("X-Error-Code", "insufficient_quota"), ("Retry-After", "1")],
                    b"quota",
                )
                .await;
            } else {
                write_response(stream, 200, "OK", &[], b"ok").await;
            }
        }
        HttpFault::InvalidRequest => {
            write_response(
                stream,
                400,
                "Bad Request",
                &[("X-Error-Code", "invalid_request")],
                b"invalid",
            )
            .await;
        }
        HttpFault::WaitForDownstream { after_headers } => {
            if after_headers {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\ncommitted",
                    )
                    .await
                    .expect("committed response prefix");
            }
            let mut byte = [0_u8; 1];
            loop {
                match timeout(TEST_TIMEOUT, stream.read(&mut byte)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(_)) => {}
                    Err(_) => panic!("Pooler did not cancel the upstream connection"),
                }
            }
            if let Some(tracker) = cancellation_tracker {
                tracker.record_observed();
            }
        }
        HttpFault::Sse(fault) => write_sse_fault(stream, fault).await,
        HttpFault::RefreshThenSuccess => {
            if attempt == 1 {
                write_response(stream, 401, "Unauthorized", &[], b"").await;
            } else {
                write_response(stream, 200, "OK", &[], b"ok").await;
            }
        }
        HttpFault::Success => write_response(stream, 200, "OK", &[], b"ok").await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .await
        .expect("fault response headers");
    stream.write_all(body).await.expect("fault response body");
}

async fn write_sse_fault(stream: &mut TcpStream, fault: SseFault) {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("SSE response headers");
    stream
        .write_all(
            b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
        )
        .await
        .expect("SSE committed event");
    stream
        .write_all(
            b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{\"content\":\"committed\"},\"finish_reason\":null}]}\n\n",
        )
        .await
        .expect("SSE committed text event");
    sleep(Duration::from_millis(25)).await;
    match fault {
        SseFault::Partial => stream
            .write_all(b"data: {\"id\":")
            .await
            .expect("partial SSE event"),
        SseFault::InvalidUtf8 => stream
            .write_all(b"data: \xff\n\n")
            .await
            .expect("invalid UTF-8 SSE event"),
        SseFault::MissingTerminal => {}
    }
}

struct RunningServer {
    server: HttpProxyServer,
    address: Option<SocketAddr>,
    runner: Option<JoinHandle<Result<(), HttpProxyServerError>>>,
    secrets: Vec<TestSecret>,
}

impl RunningServer {
    fn tcp_address(&self) -> SocketAddr {
        self.address.expect("running server has a TCP listener")
    }

    async fn stop(mut self) -> RuntimeResourceSnapshot {
        self.server.begin_drain();
        let mut runner = self.runner.take().expect("Pooler task is present");
        let joined = match timeout(TEST_TIMEOUT, &mut runner).await {
            Ok(joined) => joined,
            Err(_) => {
                runner.abort();
                let _ = runner.await;
                panic!("Pooler did not drain");
            }
        };
        joined
            .expect("Pooler task joins")
            .expect("Pooler run succeeds");
        assert_eq!(self.server.active(), 0, "Pooler retained an active request");
        let resources = self.server.resource_snapshot();
        assert!(
            resources.is_zero(),
            "Pooler leaked resources: {resources:?}"
        );
        assert!(resources.peak_tasks > 0, "runtime tasks were not tracked");
        assert!(
            resources.peak_permits > 0,
            "request permits were not tracked"
        );
        self.secrets.clear();
        resources
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.server.begin_drain();
        if let Some(runner) = self.runner.take() {
            runner.abort();
        }
    }
}

async fn start_server(
    config: CompiledConfig,
    secrets: Vec<TestSecret>,
    counters: &LeakCounters,
) -> RunningServer {
    start_server_with_native(config, secrets, counters, None).await
}

async fn start_server_with_native(
    config: CompiledConfig,
    secrets: Vec<TestSecret>,
    counters: &LeakCounters,
    native: Option<Arc<NativeRuntime>>,
) -> RunningServer {
    let server = match native {
        Some(native) => HttpProxyServer::bind_with_native_runtime(config, native).await,
        None => HttpProxyServer::bind(config).await,
    }
    .expect("fault server binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("fault listener address")
        .address()
        .parse()
        .expect("fault listener address parses");
    spawn_running_server(server, Some(address), secrets, counters)
}

fn spawn_running_server(
    server: HttpProxyServer,
    address: Option<SocketAddr>,
    secrets: Vec<TestSecret>,
    counters: &LeakCounters,
) -> RunningServer {
    let runner_server = server.clone();
    let task_guard = counters.task();
    let runner = tokio::spawn(async move {
        let _task_guard = task_guard;
        runner_server.run().await
    });
    RunningServer {
        server,
        address,
        runner: Some(runner),
        secrets,
    }
}

fn pooled_config(
    upstream_url: &str,
    route: &str,
    counters: &LeakCounters,
) -> (CompiledConfig, Vec<TestSecret>) {
    let first = TestSecret::new("first-token", counters);
    let second = TestSecret::new("second-token", counters);
    let yaml = format!(
        "version: 1\nlisteners:\n  local:\n    bind: 127.0.0.1:0\nupstreams:\n  local:\n    url: {upstream_url}\n    transport: {{connect_timeout: 500ms, request_timeout: 3s}}\naccounts:\n  first: {{provider: local, secret: {}}}\n  second: {{provider: local, secret: {}}}\npolicies:\n  faults:\n    selection: {{strategy: ordered_fallback, accounts: [first, second]}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, maximum_providers: 2, statuses: [429, 500, 502, 503, 504], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s, maximum_elapsed: 3s, maximum_recovery_wait: 2s}}\nroutes:\n{route}\n",
        first.reference(),
        second.reference(),
    );
    let config = compile_yaml("fault-corpus.yaml", &yaml).expect("fault config compiles");
    (config, vec![first, second])
}

fn http_route() -> &'static str {
    "  - id: fault\n    listen: local\n    match: {method: POST, path: /fault, content_types: [application/json]}\n    ingress: {mode: patch}\n    target: {provider: local, policy: faults}\n    response: {mode: opaque}\n"
}

fn factory_route() -> &'static str {
    "  - id: fault\n    listen: local\n    match: {method: POST, path: /v3/ai/language-model, content_types: [application/json]}\n    ingress: {mode: semantic, decoder: decode.factory.language_model}\n    target: {provider: local, path: /v1/chat/completions, policy: faults}\n    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}\n    loss_policy: reject\n"
}

fn devin_route() -> &'static str {
    "  - id: fault\n    listen: local\n    match: {method: POST, path: /exa.api_server_pb.ApiServerService/GetChatMessage, content_types: [application/connect+proto]}\n    ingress: {mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}\n    target: {provider: local, path: /v1/chat/completions, policy: faults}\n    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}\n    loss_policy: reject\n"
}

async fn execute_http_fault(case: &Case, fault: HttpFault, counters: LeakCounters) {
    assert!(matches!(case.boundary.as_str(), "http" | "tls"));
    let upstream = spawn_http_upstream(fault, counters.clone(), None).await;
    let scheme = if matches!(fault, HttpFault::TlsHandshake) {
        "https"
    } else {
        "http"
    };
    let (config, secrets) = pooled_config(
        &format!("{scheme}://{}", upstream.address),
        http_route(),
        &counters,
    );
    let running = start_server(config, secrets, &counters).await;
    let response = send_http_request(
        running.tcp_address(),
        "/fault",
        "application/json",
        b"{}",
        true,
    )
    .await;

    match fault {
        HttpFault::SlowHeaders(_) | HttpFault::QuotaThenSuccess => {
            case.assert_outcome(Outcome::Response);
            assert_eq!(response_status(&response), 200, "{} response", case.id);
        }
        HttpFault::InvalidRequest => {
            case.assert_outcome(Outcome::Error);
            assert_eq!(
                response_status(&response),
                case.status.expect("invalid-request status"),
                "{} response",
                case.id
            );
            let decisions = running
                .server
                .pooling()
                .recent_decisions(16)
                .expect("invalid-request decisions");
            assert!(decisions.iter().any(|decision| {
                decision
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("failure=InvalidRequest"))
            }));
            assert!(decisions.iter().any(|decision| {
                decision
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("DoNotRetry"))
            }));
        }
        HttpFault::TlsHandshake => {
            case.assert_outcome(Outcome::Error);
            assert_eq!(response_status(&response), 502, "{} response", case.id);
        }
        _ => unreachable!("HTTP fault routed to a dedicated executor"),
    }

    wait_for_attempts(&upstream.attempts, case.expected_attempts, &case.id).await;
    let health = credential_cooldown_present(&running.server);
    assert_health(case, health);
    sleep(RETRY_GRACE).await;
    let attempts = upstream.stop().await;
    assert_eq!(attempts, case.expected_attempts, "{} attempts", case.id);
    running.stop().await;
}

async fn execute_connection_refused(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "http");
    case.assert_outcome(Outcome::Error);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve refused address");
    let address = listener.local_addr().expect("reserved address");
    drop(listener);
    let (config, secrets) = pooled_config(&format!("http://{address}"), http_route(), &counters);
    let running = start_server(config, secrets, &counters).await;
    let response = send_http_request(
        running.tcp_address(),
        "/fault",
        "application/json",
        b"{}",
        true,
    )
    .await;
    assert_eq!(response_status(&response), 502);
    let decisions = running
        .server
        .pooling()
        .recent_decisions(32)
        .expect("connection-refused decisions");
    let attempts = decisions
        .iter()
        .filter(|decision| {
            decision
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("failure=Network"))
        })
        .count();
    assert_eq!(attempts, case.expected_attempts, "{} attempts", case.id);
    assert_health(case, credential_cooldown_present(&running.server));
    running.stop().await;
}

async fn execute_downstream_disconnect(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "http");
    case.assert_outcome(Outcome::Cancelled);
    let tracker = CancellationTracker::new();
    let upstream = spawn_http_upstream(
        HttpFault::WaitForDownstream {
            after_headers: case.commitment == "after",
        },
        counters.clone(),
        Some(tracker.clone()),
    )
    .await;
    let (config, secrets) = pooled_config(
        &format!("http://{}", upstream.address),
        http_route(),
        &counters,
    );
    let running = start_server(config, secrets, &counters).await;
    let mut client = open_http_request(
        running.tcp_address(),
        "/fault",
        "application/json",
        b"{}",
        true,
    )
    .await;
    wait_for_attempts(&upstream.attempts, 1, &case.id).await;
    if case.commitment == "after" {
        let headers = read_headers(&mut client).await;
        assert_eq!(response_status(&headers), 200);
    }
    tracker.record_requested();
    drop(client);
    timeout(TEST_TIMEOUT, async {
        while tracker.observed() != 1 || running.server.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("downstream cancellation reaches upstream and releases the request");
    sleep(RETRY_GRACE).await;
    let attempts = upstream.stop().await;
    assert_eq!(attempts, case.expected_attempts, "{} attempts", case.id);
    assert!(tracker.all_requested_observed(), "{} cancellation", case.id);
    assert_health(case, credential_cooldown_present(&running.server));
    running.stop().await;
}

async fn execute_sse_fault(case: &Case, fault: SseFault, counters: LeakCounters) {
    assert_eq!(case.boundary, "sse");
    assert_eq!(case.commitment, "after");
    case.assert_outcome(Outcome::Error);
    let upstream = spawn_http_upstream(HttpFault::Sse(fault), counters.clone(), None).await;
    let (config, secrets) = pooled_config(
        &format!("http://{}", upstream.address),
        factory_route(),
        &counters,
    );
    let running = start_server(config, secrets, &counters).await;
    let body = br#"{"prompt":[{"role":"user","content":[{"type":"text","text":"fault"}]}]}"#;
    let response = send_http_request_with_headers(
        running.tcp_address(),
        "/v3/ai/language-model",
        "application/json",
        body,
        true,
        &[
            ("AI-Language-Model-Id", "gpt-test"),
            ("AI-Language-Model-Specification-Version", "3"),
        ],
    )
    .await;
    assert_eq!(response_status(&response), 200, "{} response", case.id);
    let response_body = decoded_http_body(&response);
    let response_body = String::from_utf8(response_body).expect("Factory error stream is UTF-8");
    assert!(
        response_body.contains("\"type\":\"error\"")
            && response_body.contains("\"code\":\"invalid_upstream_stream\"")
            && response_body.contains("data: [DONE]"),
        "{} did not emit an explicit terminal Factory error: {response_body}",
        case.id
    );
    assert!(
        !response_body.contains("\"type\":\"finish\""),
        "{} unexpectedly completed",
        case.id
    );
    wait_for_attempts(&upstream.attempts, case.expected_attempts, &case.id).await;
    sleep(RETRY_GRACE).await;
    let attempts = upstream.stop().await;
    assert_eq!(attempts, 1, "{} retried after SSE commitment", case.id);
    assert_health(case, credential_cooldown_present(&running.server));
    running.stop().await;
}

struct MockRefresher {
    calls: AtomicUsize,
    counters: LeakCounters,
}

impl OAuthRefresher for MockRefresher {
    fn refresh<'a>(
        &'a self,
        _refresh_token: &'a SecretValue,
        _cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let lease = self.counters.refresh_lease();
        Box::pin(async move {
            let _lease = lease;
            Ok(OAuthTokens::bearer("new-access", Some("new-refresh"), None))
        })
    }
}

async fn execute_native_refresh(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "http");
    case.assert_outcome(Outcome::Response);
    assert_eq!(case.status, Some(401), "{} refresh status", case.id);
    let upstream = spawn_http_upstream(HttpFault::RefreshThenSuccess, counters.clone(), None).await;
    let account_secret = TestSecret::new("unused-native-secret", &counters);
    let yaml = format!(
        "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  codex:\n    url: http://{}\n    native: {{kind: codex}}\n    oauth:\n      authorization_endpoint: https://oauth.example/authorize\n      token_endpoint: https://oauth.example/token\n      identity_endpoint: https://oauth.example/me\n      client_id: pooler-test\n      scopes: [openid]\naccounts:\n  account-a: {{provider: codex, secret: {}}}\npolicies:\n  faults:\n    selection: {{strategy: fill_first, accounts: [account-a]}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 1, statuses: [429], before_commit_only: true}}\nroutes:\n  - id: fault\n    listen: local\n    match: {{method: POST, path: /responses, content_types: [application/json]}}\n    ingress: {{mode: patch}}\n    target: {{provider: codex, policy: faults}}\n    response: {{mode: opaque}}\n",
        upstream.address,
        account_secret.reference(),
    );
    let config = compile_yaml("fault-refresh.yaml", &yaml).expect("refresh config compiles");
    let token_store = Arc::new(pooler_auth::MemoryOAuthTokenStore::new());
    let credential = pooler_auth::CredentialId::new("account-a").expect("native credential");
    token_store.insert(
        credential.clone(),
        OAuthTokens::bearer("old-access", Some("old-refresh"), None),
    );
    let refresher = Arc::new(MockRefresher {
        calls: AtomicUsize::new(0),
        counters: counters.clone(),
    });
    let native = Arc::new(
        NativeRuntime::with_codex_provider(token_store.clone(), "codex", refresher.clone())
            .with_account_id("account-a", "chatgpt-account-a"),
    );
    let running =
        start_server_with_native(config, vec![account_secret], &counters, Some(native)).await;
    let response = send_http_request(
        running.tcp_address(),
        "/responses",
        "application/json",
        br#"{"model":"gpt-test","input":"hello"}"#,
        false,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    wait_for_attempts(&upstream.attempts, case.expected_attempts, &case.id).await;
    assert_eq!(refresher.calls.load(Ordering::SeqCst), 1);
    let resources = running.server.resource_snapshot();
    assert!(resources.peak_refresh_leases > 0);
    assert!(resources.peak_secret_material > 0);
    let rotated = token_store
        .load(&credential)
        .await
        .expect("token store read")
        .expect("rotated token");
    assert_eq!(rotated.generation(), 1);
    assert_health(case, credential_cooldown_present(&running.server));
    sleep(RETRY_GRACE).await;
    let attempts = upstream.stop().await;
    assert_eq!(attempts, case.expected_attempts, "{} attempts", case.id);
    running.stop().await;
}

async fn execute_fragmented_websocket(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "websocket");
    assert_eq!(case.commitment, "after");
    case.assert_outcome(Outcome::Response);
    let upstream = spawn_websocket_upstream(WebSocketFault::Fragmented, counters.clone()).await;
    let (config, secrets) = websocket_config(upstream.address, &counters);
    let running = start_server(config, secrets, &counters).await;
    let mut client = websocket_handshake(running.tcp_address()).await;
    client
        .write_all(&client_frame(false, 0x1, b"frag"))
        .await
        .expect("first WebSocket fragment");
    client
        .write_all(&client_frame(true, 0x0, b"mented"))
        .await
        .expect("final WebSocket fragment");
    let (_, opcode, payload) = read_frame(&mut client).await;
    assert_eq!(opcode, 0x1);
    assert_eq!(payload, b"fragmented");
    drop(client);
    finish_websocket_case(case, upstream, running).await;
}

async fn execute_websocket_disconnect(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "websocket");
    assert_eq!(case.commitment, "after");
    case.assert_outcome(Outcome::Error);
    let upstream =
        spawn_websocket_upstream(WebSocketFault::DisconnectAfterUpgrade, counters.clone()).await;
    let (config, secrets) = websocket_config(upstream.address, &counters);
    let running = start_server(config, secrets, &counters).await;
    let mut client = websocket_handshake(running.tcp_address()).await;
    let mut header = [0_u8; 2];
    let read = timeout(TEST_TIMEOUT, client.read_exact(&mut header))
        .await
        .expect("WebSocket failure reaches downstream");
    if read.is_ok() {
        assert_eq!(header[0] & 0x0f, 0x8, "expected a WebSocket close frame");
    }
    drop(client);
    finish_websocket_case(case, upstream, running).await;
}

#[derive(Clone, Copy)]
enum WebSocketFault {
    Fragmented,
    DisconnectAfterUpgrade,
}

async fn spawn_websocket_upstream(
    fault: WebSocketFault,
    counters: LeakCounters,
) -> RunningUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("WebSocket upstream binds");
    let upstream_address = listener.local_addr().expect("WebSocket upstream address");
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_task = Arc::clone(&attempts);
    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    let task_guard = counters.task();
    let upstream_task = tokio::spawn({
        let counters = counters.clone();
        async move {
            let _task_guard = task_guard;
            loop {
                let accepted = tokio::select! {
                    () = stop.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let (stream, _) = accepted.expect("WebSocket upstream accepts");
                let _permit = counters.permit();
                attempts_for_task.fetch_add(1, Ordering::SeqCst);
                let mut socket = accept_async(stream).await.expect("WebSocket handshake");
                if matches!(fault, WebSocketFault::Fragmented) {
                    let message = socket
                        .next()
                        .await
                        .expect("fragmented message arrives")
                        .expect("fragmented message is valid");
                    assert_eq!(message.into_text().expect("text message"), "fragmented");
                    socket
                        .send(WebSocketMessage::Text("fragmented".into()))
                        .await
                        .expect("WebSocket echo");
                }
            }
        }
    });
    RunningUpstream {
        address: upstream_address,
        attempts,
        cancellation,
        task: Some(upstream_task),
    }
}

fn websocket_config(
    address: SocketAddr,
    counters: &LeakCounters,
) -> (CompiledConfig, Vec<TestSecret>) {
    pooled_config(
        &format!("ws://{address}"),
        "  - id: fault\n    listen: local\n    match: {method: GET, path: /socket, websocket: true}\n    target: {provider: local, path: /echo, policy: faults}\n",
        counters,
    )
}

async fn finish_websocket_case(case: &Case, upstream: RunningUpstream, running: RunningServer) {
    wait_for_attempts(&upstream.attempts, case.expected_attempts, &case.id).await;
    sleep(RETRY_GRACE).await;
    let actual_attempts = upstream.stop().await;
    assert_eq!(actual_attempts, 1, "{} retried after upgrade", case.id);
    assert_health(case, credential_cooldown_present(&running.server));
    running.stop().await;
}

async fn execute_truncated_connect(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "connect");
    case.assert_outcome(Outcome::Error);
    let upstream = spawn_http_upstream(HttpFault::Success, counters.clone(), None).await;
    let (config, secrets) = pooled_config(
        &format!("http://{}", upstream.address),
        devin_route(),
        &counters,
    );
    let running = start_server(config, secrets, &counters).await;
    let truncated = [0_u8, 0, 0, 0, 8, 1, 2];
    let response = send_http_request(
        running.tcp_address(),
        "/exa.api_server_pb.ApiServerService/GetChatMessage",
        "application/connect+proto",
        &truncated,
        false,
    )
    .await;
    assert_eq!(response_status(&response), 400);
    let error: serde_json::Value = serde_json::from_slice(&decoded_http_body(&response))
        .expect("local error is OpenAI-compatible JSON");
    assert_eq!(error["error"]["message"], "invalid request");
    assert_eq!(error["error"]["type"], "invalid_request_error");
    assert_eq!(error["error"]["code"], "invalid_request");
    sleep(RETRY_GRACE).await;
    let attempts = upstream.stop().await;
    assert_eq!(attempts, case.expected_attempts, "{} attempts", case.id);
    assert_health(case, credential_cooldown_present(&running.server));
    assert!(
        running
            .server
            .pooling()
            .recent_decisions(8)
            .expect("Connect decisions")
            .is_empty(),
        "invalid Connect input reached account selection"
    );
    running.stop().await;
}

async fn execute_partial_connect(case: &Case, counters: LeakCounters) {
    assert_eq!(case.boundary, "connect");
    assert_eq!(case.commitment, "after");
    case.assert_outcome(Outcome::Error);
    let upstream = spawn_http_upstream(
        HttpFault::Sse(SseFault::MissingTerminal),
        counters.clone(),
        None,
    )
    .await;
    let (config, secrets) = pooled_config(
        &format!("http://{}", upstream.address),
        devin_route(),
        &counters,
    );
    let running = start_server(config, secrets, &counters).await;
    let response = send_http_request_with_headers(
        running.tcp_address(),
        "/exa.api_server_pb.ApiServerService/GetChatMessage",
        "application/connect+proto",
        &valid_devin_request(),
        true,
        &[("Connect-Protocol-Version", "1")],
    )
    .await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_http_body(&response);
    let mut decoder = ConnectDecoder::new(ConnectLimits::default());
    let frames = decoder
        .push(&body)
        .expect("committed Connect frames decode");
    decoder.finish().expect("Connect frames are complete");
    assert!(!frames.is_empty(), "Connect response committed no frames");
    let terminal = frames
        .iter()
        .find(|frame| frame.is_end_stream())
        .expect("Connect fault emits a terminal error trailer");
    assert_eq!(
        read_connect_trailer_error(&terminal.payload).as_deref(),
        Some("Devin stream error upstream_stream: upstream semantic stream failed"),
        "{} terminal Connect error",
        case.id
    );
    wait_for_attempts(&upstream.attempts, case.expected_attempts, &case.id).await;
    sleep(RETRY_GRACE).await;
    let attempts = upstream.stop().await;
    assert_eq!(attempts, 1, "{} retried after Connect commitment", case.id);
    assert_health(case, credential_cooldown_present(&running.server));
    running.stop().await;
}

fn valid_devin_request() -> Vec<u8> {
    let request = proto::GetChatMessageRequest {
        metadata: Some(proto::Metadata::default()),
        chat_message_prompts: vec![proto::ChatMessagePrompt {
            source: proto::ChatMessageSource::User as i32,
            prompt: "fault".to_owned(),
            ..Default::default()
        }],
        chat_model_uid: "gpt-test".to_owned(),
        request_type: proto::ChatMessageRequestType::Cascade as i32,
        ..Default::default()
    };
    encode_connect_frame(&request.encode_to_vec(), false, false).expect("Connect request frame")
}

fn credential_cooldown_present(server: &HttpProxyServer) -> bool {
    let pooling = server.pooling();
    pooling
        .credential_health_states()
        .expect("credential health")
        .iter()
        .any(|health| health.failure_count > 0 && health.cooldown_until.is_some())
}

fn assert_health(case: &Case, credential_cooldown: bool) {
    let expected = case.expected_health_mutation == "credential_cooldown";
    assert_eq!(
        credential_cooldown, expected,
        "{} credential cooldown",
        case.id
    );
    if case.kind == "request_invalid" {
        assert!(
            !credential_cooldown,
            "invalid requests may not cool credentials"
        );
    }
}

async fn wait_for_attempts(attempts: &AtomicUsize, expected: usize, id: &str) {
    timeout(TEST_TIMEOUT, async {
        while attempts.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{id} did not reach {expected} attempts"));
}

async fn send_http_request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    idempotency_key: bool,
) -> Vec<u8> {
    send_http_request_with_headers(address, path, content_type, body, idempotency_key, &[]).await
}

async fn send_http_request_with_headers(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    idempotency_key: bool,
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut stream = open_http_request_with_headers(
        address,
        path,
        content_type,
        body,
        idempotency_key,
        extra_headers,
    )
    .await;
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("fault response completes")
        .expect("fault response bytes");
    response
}

async fn open_http_request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    idempotency_key: bool,
) -> TcpStream {
    open_http_request_with_headers(address, path, content_type, body, idempotency_key, &[]).await
}

async fn open_http_request_with_headers(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    idempotency_key: bool,
    extra_headers: &[(&str, &str)],
) -> TcpStream {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("downstream connect timeout")
        .expect("downstream connects");
    let idempotency = if idempotency_key {
        "Idempotency-Key: fault-corpus\r\n"
    } else {
        ""
    };
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: fault.test\r\nContent-Type: {content_type}\r\n{idempotency}"
    );
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    stream
        .write_all(request.as_bytes())
        .await
        .expect("fault request headers");
    stream.write_all(body).await.expect("fault request body");
    stream
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let body_start = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let content_length = bytes[..body_start]
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            let (name, value) = (&line[..colon], &line[colon + 1..]);
            name.eq_ignore_ascii_case(b"content-length")
                .then(|| {
                    std::str::from_utf8(value)
                        .ok()?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .flatten()
        })
        .unwrap_or(0);
    while bytes.len() < body_start + content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 256];
    timeout(TEST_TIMEOUT, async {
        loop {
            let read = stream.read(&mut chunk).await.expect("response headers");
            assert_ne!(read, 0, "connection closed before response headers");
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return;
            }
        }
    })
    .await
    .expect("response headers arrive");
    bytes
}

fn response_status(response: &[u8]) -> u16 {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("HTTP status line");
    std::str::from_utf8(&response[..line_end])
        .expect("HTTP status text")
        .split_whitespace()
        .nth(1)
        .expect("HTTP status")
        .parse()
        .expect("numeric HTTP status")
}

fn decoded_http_body(response: &[u8]) -> Vec<u8> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers");
    let headers = String::from_utf8_lossy(&response[..header_end]).to_ascii_lowercase();
    let body = &response[header_end + 4..];
    if headers.contains("transfer-encoding: chunked") {
        decode_complete_chunks(body)
    } else {
        body.to_vec()
    }
}

fn decode_complete_chunks(body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let Some(line_end) = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
        else {
            break;
        };
        let line_end = offset + line_end;
        let size = std::str::from_utf8(&body[offset..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
            .expect("HTTP chunk size");
        if size == 0 {
            break;
        }
        let data_start = line_end + 2;
        let data_end = data_start.saturating_add(size);
        if data_end.saturating_add(2) > body.len() {
            break;
        }
        decoded.extend_from_slice(&body[data_start..data_end]);
        offset = data_end + 2;
    }
    decoded
}

async fn websocket_handshake(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("WebSocket downstream connects");
    let request = format!(
        "GET /socket HTTP/1.1\r\nHost: fault.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {WEBSOCKET_KEY}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("WebSocket downstream handshake");
    let response = read_headers(&mut stream).await;
    assert_eq!(response_status(&response), 101);
    stream
}

fn client_frame(final_frame: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(if final_frame { 0x80 | opcode } else { opcode });
    let mask = [1_u8, 2, 3, 4];
    match payload.len() {
        0..=125 => frame.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    frame
}

async fn read_frame(stream: &mut TcpStream) -> (bool, u8, Vec<u8>) {
    let mut header = [0_u8; 2];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut header))
        .await
        .expect("WebSocket frame header")
        .expect("WebSocket frame header bytes");
    let final_frame = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    let mut length = u64::from(header[1] & 0x7f);
    if length == 126 {
        let mut extended = [0_u8; 2];
        stream
            .read_exact(&mut extended)
            .await
            .expect("WebSocket extended length");
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        stream
            .read_exact(&mut extended)
            .await
            .expect("WebSocket extended length");
        length = u64::from_be_bytes(extended);
    }
    let mut payload = vec![0_u8; usize::try_from(length).expect("WebSocket payload length")];
    stream
        .read_exact(&mut payload)
        .await
        .expect("WebSocket payload");
    (final_frame, opcode, payload)
}

struct TestSecret {
    file: tempfile::NamedTempFile,
    _temporary_file: LeakGuard,
    _secret_material: LeakGuard,
}

impl TestSecret {
    fn new(value: &str, counters: &LeakCounters) -> Self {
        let mut file = tempfile::Builder::new()
            .prefix("pooler-fault-secret-")
            .tempfile()
            .expect("fault secret creates exclusively");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
                .expect("fault secret permissions");
        }
        std::io::Write::write_all(file.as_file_mut(), value.as_bytes())
            .expect("fault secret writes");
        Self {
            file,
            _temporary_file: counters.temporary_file(),
            _secret_material: counters.secret_material(),
        }
    }

    fn reference(&self) -> String {
        format!("file:{}", self.file.path().display())
    }
}
