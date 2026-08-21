//! End-to-end coverage for the universal turnkey gateway preset.
//!
//! Every assertion here runs against a real `HttpProxyServer` bound to an
//! ephemeral port and a real loopback upstream. A route is only claimed as
//! mounted when a client request reaches that upstream through Pooler.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use pooler_auth::MemoryOAuthTokenStore;
use pooler_http::NativeRuntime;
use pooler_server::HttpProxyServer;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_tungstenite::{accept_async, tungstenite::Message};

/// The models this fake provider publishes. Every model a patch route selects
/// in this file must appear here, because an undeclared model is rejected
/// before the upstream call.
const MODEL_LIST: &[u8] = br#"{"data":[{"id":"gpt-4o"},{"id":"gpt-image-1"},{"id":"text-embedding-3-small"},{"id":"claude-sonnet-4"}]}"#;

/// One request line observed by the fake upstream.

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpstreamRequest {
    method: String,
    path: String,
    body: String,
}

/// A deterministic fake upstream.
///
/// The listener is owned for the whole lifetime of the proxy under test and is
/// stopped only after the proxy has drained, so the recorded request list is
/// exact rather than dependent on machine load.
struct FakeUpstream {
    address: SocketAddr,
    shutdown: Arc<Notify>,
    task: JoinHandle<Vec<UpstreamRequest>>,
}

impl FakeUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let address = listener.local_addr().expect("upstream address");
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(serve_upstream(listener, Arc::clone(&shutdown)));
        Self {
            address,
            shutdown,
            task,
        }
    }

    async fn finish(self) -> Vec<UpstreamRequest> {
        self.shutdown.notify_one();
        self.task.await.expect("upstream task")
    }
}

async fn serve_upstream(listener: TcpListener, shutdown: Arc<Notify>) -> Vec<UpstreamRequest> {
    let mut observed = Vec::new();
    loop {
        let accepted = tokio::select! {
            biased;
            accepted = listener.accept() => accepted,
            () = shutdown.notified() => break,
        };
        let (mut stream, _) = accepted.expect("upstream connection");
        let request = read_http_request(&mut stream).await;
        // The gateway upstream is declared with `known_provider`, so Pooler
        // derives a catalog source for it and discovers models from this
        // endpoint at startup. The patch routes can only select a model this
        // list contains, which is exactly the behaviour under test.
        let body: &[u8] = if request.path == "/v1/models" {
            MODEL_LIST
        } else {
            br#"{"ok":true}"#
        };
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("upstream response headers");
        stream
            .write_all(body)
            .await
            .expect("upstream response body");
        observed.push(request);
    }
    observed
}

/// A fake WebSocket upstream that echoes one text message.
async fn spawn_websocket_upstream() -> (SocketAddr, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("websocket upstream bind");
    let address = listener.local_addr().expect("websocket upstream address");
    let task = tokio::spawn(async move {
        let mut observed = Vec::new();
        let (stream, _) = listener.accept().await.expect("websocket upstream accepts");
        let mut socket = accept_async(stream).await.expect("websocket handshake");
        while let Some(message) = socket.next().await {
            match message.expect("websocket message") {
                Message::Text(text) => {
                    observed.push(text.to_string());
                    socket.send(Message::Text(text)).await.expect("echo");
                }
                Message::Close(frame) => {
                    let _ = socket.send(Message::Close(frame)).await;
                    break;
                }
                _ => {}
            }
        }
        observed
    });
    (address, task)
}

/// Compile the shipped preset the way an operator imports it, with the sample
/// endpoints replaced by loopback addresses.
fn gateway_config(
    directory: &TempDir,
    upstream: SocketAddr,
    websocket: SocketAddr,
) -> pooler_config::CompiledConfig {
    // An owner-private file reference keeps the fixture deterministic under a
    // parallel suite; a process-global environment variable would not be.
    // `NamedTempFile` creates the file owner-only, which the secret loader
    // requires.
    let mut secret_file =
        tempfile::NamedTempFile::new_in(directory.path()).expect("gateway secret file");
    secret_file
        .write_all(b"gateway-test-key")
        .expect("gateway secret contents");
    let (_, secret) = secret_file.keep().expect("gateway secret persists");
    let secret = secret.display();
    let path = directory.path().join("gateway.yaml");
    let mut file = std::fs::File::create(&path).expect("gateway config file");
    write!(
        file,
        "imports:\n  - preset: gateway\n    as: gateway\n    with:\n      bind: 127.0.0.1:0\n      upstream_url: http://{upstream}\n      websocket_url: ws://{websocket}\n      secret: 'file:{secret}'\n\nversion: 1\n"
    )
    .expect("gateway config contents");
    drop(file);
    pooler_config::Config::from_path(&path)
        .expect("gateway preset loads")
        .compile()
        .expect("gateway preset compiles")
}

/// Bind the gateway the way `pooler serve` does.
///
/// A `known_provider` upstream carries a native kind, so the server needs a
/// real native runtime; `HttpProxyServer::bind` installs a disabled one and
/// startup catalog discovery would fail authorization before any transport.
async fn bind_gateway(config: pooler_config::CompiledConfig) -> HttpProxyServer {
    let native = Arc::new(
        NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime"),
    );
    HttpProxyServer::bind_with_native_runtime(config, native)
        .await
        .expect("gateway binds")
}

/// Send one request through the proxy and return the raw downstream response.
async fn call(
    proxy: &str,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> String {
    let mut downstream = TcpStream::connect(proxy).await.expect("proxy connection");
    let content_type = content_type
        .map(|value| format!("content-type: {value}\r\n"))
        .unwrap_or_default();
    downstream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nhost: localhost\r\n{content_type}content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("downstream headers");
    downstream.write_all(body).await.expect("downstream body");
    let mut response = Vec::new();
    downstream
        .read_to_end(&mut response)
        .await
        .expect("downstream response");
    String::from_utf8_lossy(&response).to_string()
}

/// Every REST endpoint family the preset mounts for OpenAI, whose integration
/// documents `chat_completions`, `responses`, and `models`. The Anthropic and
/// Gemini surfaces belong to those providers and are covered by
/// `gateway_provider_auth.rs`.
const REST_FAMILIES: &[(&str, &str, Option<&str>, &str)] = &[
    ("GET", "/v1/models", None, ""),
    (
        "POST",
        "/v1/chat/completions",
        Some("application/json"),
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
    ),
    (
        "POST",
        "/v1/responses",
        Some("application/json"),
        r#"{"model":"gpt-4o","input":"hi"}"#,
    ),
    (
        "POST",
        "/v1/responses/compact",
        Some("application/json"),
        r#"{"model":"gpt-4o","response_id":"resp_1"}"#,
    ),
];

#[tokio::test]
async fn every_mounted_rest_family_reaches_the_upstream_through_the_gateway_preset() {
    let upstream = FakeUpstream::start().await;
    let (websocket_address, websocket_task) = spawn_websocket_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address, websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut responses = Vec::new();
    for (method, path, content_type, body) in REST_FAMILIES {
        let response = call(&proxy, method, path, *content_type, body.as_bytes()).await;
        responses.push((*method, *path, response));
    }

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let observed = upstream.finish().await;
    websocket_task.abort();

    for (method, path, response) in &responses {
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{method} {path} must be mounted, got: {response}"
        );
    }
    // Startup catalog discovery also calls this upstream, so assert presence
    // rather than an exact request count.
    for (method, path, _, _) in REST_FAMILIES {
        assert!(
            observed
                .iter()
                .any(|request| &request.method == method && &request.path == path),
            "{method} {path} must reach the upstream unrewritten; observed: {observed:?}"
        );
    }
}

#[tokio::test]
async fn the_gateway_preset_preserves_the_caller_body_and_rewrites_only_the_model() {
    let upstream = FakeUpstream::start().await;
    let (websocket_address, websocket_task) = spawn_websocket_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address, websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let response = call(
        &proxy,
        "POST",
        "/v1/chat/completions",
        Some("application/json"),
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"vendor_extension":{"keep":"me"}}"#,
    )
    .await;

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let observed = upstream.finish().await;
    websocket_task.abort();

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    // Startup catalog discovery is also in this list; select the chat request.
    let request = observed
        .iter()
        .find(|request| request.path == "/v1/chat/completions")
        .expect("the chat request reached the upstream");
    assert!(
        request.body.contains("\"vendor_extension\""),
        "an unknown caller field must survive a patch route: {}",
        request.body
    );
    assert!(
        request.body.contains("\"messages\""),
        "the caller's payload must survive: {}",
        request.body
    );
    assert!(
        request.body.contains("\"model\":\"gpt-4o\""),
        "the model must resolve to the requested target: {}",
        request.body
    );
}

#[tokio::test]
async fn the_gateway_preset_tunnels_a_responses_websocket() {
    let upstream = FakeUpstream::start().await;
    let (websocket_address, websocket_task) = spawn_websocket_upstream().await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address, websocket_address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{proxy}/v1/responses"))
        .await
        .expect("gateway accepts the WebSocket upgrade");
    client
        .send(Message::Text("hello".into()))
        .await
        .expect("client sends");
    let echoed = client.next().await.expect("echo").expect("echo message");
    client.close(None).await.expect("client closes");

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    let _ = upstream.finish().await;
    let observed = websocket_task.await.expect("websocket upstream task");

    assert_eq!(echoed.into_text().expect("text echo").as_str(), "hello");
    assert_eq!(
        observed,
        vec!["hello".to_owned()],
        "the frame must reach the WebSocket upstream"
    );
}

async fn read_http_request(stream: &mut TcpStream) -> UpstreamRequest {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.expect("request read");
        assert!(read > 0, "request closed before headers");
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
            })
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).await.expect("request body read");
            assert!(read > 0, "request closed before body");
            bytes.extend_from_slice(&chunk[..read]);
        }
        let mut start = headers.lines().next().expect("request line").split(' ');
        return UpstreamRequest {
            method: start.next().expect("method").to_owned(),
            path: start.next().expect("path").to_owned(),
            body: String::from_utf8_lossy(&bytes[header_end..]).to_string(),
        };
    }
}
