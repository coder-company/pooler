//! Wire-level credential placement for the gateway preset.
//!
//! A preset supplies the operator's protected credential reference. Where that
//! credential belongs is the provider's documented fact. These tests assert
//! what an upstream actually receives on the socket, not what configuration
//! says, and they assert the negative case too: a provider must never see a
//! credential header belonging to a different provider.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use pooler_auth::MemoryOAuthTokenStore;
use pooler_http::NativeRuntime;
use pooler_server::HttpProxyServer;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const SECRET: &str = "operator-chosen-key";

/// Every credential header Pooler knows how to place. A provider must receive
/// exactly one of these and never another provider's.
const CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "x-api-key", "x-goog-api-key"];

/// One request observed by the fake upstream, with its headers.
#[derive(Clone, Debug)]
struct UpstreamRequest {
    path: String,
    headers: Vec<(String, String)>,
}

impl UpstreamRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A fake upstream that answers model discovery and records inference requests.
///
/// The listener is owned for the whole proxy lifetime and stopped only after the
/// proxy has drained, so the recorded list is exact rather than load-dependent.
struct FakeProvider {
    address: SocketAddr,
    shutdown: Arc<Notify>,
    task: JoinHandle<Vec<UpstreamRequest>>,
}

impl FakeProvider {
    async fn start(discovery_path: &'static str, discovery_body: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let address = listener.local_addr().expect("upstream address");
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(serve(
            listener,
            discovery_path,
            discovery_body,
            Arc::clone(&shutdown),
        ));
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

async fn serve(
    listener: TcpListener,
    discovery_path: &'static str,
    discovery_body: &'static [u8],
    shutdown: Arc<Notify>,
) -> Vec<UpstreamRequest> {
    let mut observed = Vec::new();
    loop {
        let accepted = tokio::select! {
            biased;
            accepted = listener.accept() => accepted,
            () = shutdown.notified() => break,
        };
        let (mut stream, _) = accepted.expect("upstream connection");
        let request = read_request(&mut stream).await;
        let body: &[u8] = if request.path == discovery_path {
            discovery_body
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
            .expect("upstream headers");
        stream.write_all(body).await.expect("upstream body");
        observed.push(request);
    }
    observed
}

fn gateway_config(
    directory: &TempDir,
    provider: &str,
    upstream: SocketAddr,
) -> pooler_config::CompiledConfig {
    let mut secret_file = tempfile::NamedTempFile::new_in(directory.path()).expect("secret file");
    secret_file
        .write_all(SECRET.as_bytes())
        .expect("secret contents");
    let (_, secret) = secret_file.keep().expect("secret persists");
    let secret = secret.display();
    let path = directory.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!(
            "imports:\n  - preset: gateway\n    as: gw\n    with:\n      bind: 127.0.0.1:0\n      provider: {provider}\n      upstream_url: http://{upstream}\n      websocket_url: ws://{upstream}\n      secret: 'file:{secret}'\n\nversion: 1\n"
        ),
    )
    .expect("gateway config");
    pooler_config::Config::from_path(&path)
        .expect("gateway loads")
        .compile()
        .expect("gateway compiles")
}

async fn bind_gateway(config: pooler_config::CompiledConfig) -> HttpProxyServer {
    let native = Arc::new(
        NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime"),
    );
    HttpProxyServer::bind_with_native_runtime(config, native)
        .await
        .expect("gateway binds")
}

/// Drive one request through a gateway bound to `provider` and return every
/// request the upstream saw. `client_headers` are sent by the caller verbatim.
async fn exchange(
    provider: &str,
    discovery_path: &'static str,
    discovery_body: &'static [u8],
    path: &str,
    body: &[u8],
    client_headers: &str,
) -> Vec<UpstreamRequest> {
    let upstream = FakeProvider::start(discovery_path, discovery_body).await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, provider, upstream.address);
    let server = bind_gateway(config).await;
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut downstream = TcpStream::connect(&proxy).await.expect("proxy connection");
    downstream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n{client_headers}content-length: {}\r\nconnection: close\r\n\r\n",
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
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "{provider} {path}: {}",
        String::from_utf8_lossy(&response)
    );

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");
    upstream.finish().await
}

const OPENAI_MODELS: &[u8] = br#"{"data":[{"id":"gpt-4o"}]}"#;
const ANTHROPIC_MODELS: &[u8] = br#"{"data":[{"id":"claude-sonnet-4"}]}"#;
const GEMINI_MODELS: &[u8] = br#"{"models":[{"name":"models/gemini-2.5-pro","supportedGenerationMethods":["generateContent","streamGenerateContent","countTokens"]}]}"#;

/// Assert the request carried exactly one credential header, the documented
/// one, holding exactly the operator's secret.
fn assert_only_credential(request: &UpstreamRequest, expected: &str, value: &str) {
    assert_eq!(
        request.header(expected),
        Some(value),
        "{} must carry {expected}",
        request.path
    );
    for header in CREDENTIAL_HEADERS {
        if header.eq_ignore_ascii_case(expected) {
            continue;
        }
        assert_eq!(
            request.header(header),
            None,
            "{} must not carry {header}: {:?}",
            request.path,
            request.headers
        );
    }
}

#[tokio::test]
async fn a_bearer_provider_receives_only_the_configured_bearer_credential() {
    let observed = exchange(
        "openai",
        "/v1/models",
        OPENAI_MODELS,
        "/v1/chat/completions",
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        "",
    )
    .await;

    let request = observed
        .iter()
        .find(|request| request.path == "/v1/chat/completions")
        .expect("chat request reached the upstream");
    assert_only_credential(request, "authorization", &format!("Bearer {SECRET}"));
}

#[tokio::test]
async fn anthropic_receives_only_x_api_key_and_its_required_version_header() {
    let observed = exchange(
        "anthropic",
        "/v1/models",
        ANTHROPIC_MODELS,
        "/v1/messages",
        br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}"#,
        "",
    )
    .await;

    let request = observed
        .iter()
        .find(|request| request.path == "/v1/messages")
        .expect("messages request reached the upstream");
    assert_only_credential(request, "x-api-key", SECRET);
    assert_eq!(
        request.header("anthropic-version"),
        Some("2023-06-01"),
        "the provider's required version header must survive: {:?}",
        request.headers
    );
}

#[tokio::test]
async fn gemini_receives_only_its_documented_google_key_placement() {
    let observed = exchange(
        "google",
        "/v1beta/models",
        GEMINI_MODELS,
        "/v1beta/models/gemini-2.5-pro:generateContent",
        br#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
        "",
    )
    .await;

    let request = observed
        .iter()
        .find(|request| request.path.contains(":generateContent"))
        .expect("generateContent request reached the upstream");
    assert_only_credential(request, "x-goog-api-key", SECRET);
}

/// A caller must never be able to smuggle its own provider credential through
/// the gateway, and must never displace the configured one.
#[tokio::test]
async fn client_supplied_credential_headers_are_stripped_for_every_provider() {
    const SENTINELS: &str = "authorization: Bearer client-sentinel\r\nx-api-key: client-sentinel\r\nx-goog-api-key: client-sentinel\r\n";

    let openai = exchange(
        "openai",
        "/v1/models",
        OPENAI_MODELS,
        "/v1/chat/completions",
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#,
        SENTINELS,
    )
    .await;
    let request = openai
        .iter()
        .find(|request| request.path == "/v1/chat/completions")
        .expect("chat request");
    assert_only_credential(request, "authorization", &format!("Bearer {SECRET}"));

    let anthropic = exchange(
        "anthropic",
        "/v1/models",
        ANTHROPIC_MODELS,
        "/v1/messages",
        br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}"#,
        SENTINELS,
    )
    .await;
    let request = anthropic
        .iter()
        .find(|request| request.path == "/v1/messages")
        .expect("messages request");
    assert_only_credential(request, "x-api-key", SECRET);

    let google = exchange(
        "google",
        "/v1beta/models",
        GEMINI_MODELS,
        "/v1beta/models/gemini-2.5-pro:generateContent",
        br#"{"contents":[{"parts":[{"text":"hi"}]}]}"#,
        SENTINELS,
    )
    .await;
    let request = google
        .iter()
        .find(|request| request.path.contains(":generateContent"))
        .expect("generateContent request");
    assert_only_credential(request, "x-goog-api-key", SECRET);
}

/// The secret must not appear in rendered configuration.
#[tokio::test]
async fn the_credential_value_is_never_rendered() {
    let directory = TempDir::new().expect("config directory");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let path = directory.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!(
            "imports:\n  - preset: gateway\n    as: gw\n    with: {{bind: 127.0.0.1:0, provider: anthropic, upstream_url: 'http://{address}', secret: 'env:OPERATOR_KEY'}}\n\nversion: 1\n"
        ),
    )
    .expect("gateway config");

    let rendered = pooler_config::render_path(&path).expect("rendered gateway");
    assert!(rendered.contains("env:OPERATOR_KEY"));
    assert!(!rendered.contains(SECRET));
}

async fn read_request(stream: &mut TcpStream) -> UpstreamRequest {
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
            let read = stream.read(&mut chunk).await.expect("body read");
            assert!(read > 0, "request closed before body");
            bytes.extend_from_slice(&chunk[..read]);
        }
        let mut lines = headers.lines();
        let path = lines
            .next()
            .expect("request line")
            .split(' ')
            .nth(1)
            .expect("path")
            .to_owned();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        return UpstreamRequest { path, headers };
    }
}
