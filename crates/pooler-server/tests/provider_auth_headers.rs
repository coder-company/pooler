use std::{io::Write as _, net::SocketAddr, time::Duration};

use pooler_config::compile_yaml;
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIGURED_SECRET: &str = "configured-provider-secret";
const CLIENT_AUTHORIZATION: &str = "client-authorization-must-not-leak";
const CLIENT_X_API_KEY: &str = "client-x-api-key-must-not-leak";
const CLIENT_X_GOOG_API_KEY: &str = "client-x-goog-key-must-not-leak";
const CLIENT_API_KEY: &str = "client-api-key-must-not-leak";

#[tokio::test]
async fn non_native_oauth_account_fails_before_proxy_transport() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("OAuth upstream binds");
    let upstream_address = upstream.local_addr().expect("OAuth upstream address");
    let config = compile_yaml(
        "non-native-oauth-proxy.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  plain:\n    url: http://{upstream_address}\n    oauth:\n      authorization_endpoint: https://oauth.example/authorize\n      token_endpoint: https://oauth.example/token\n      client_id: pooler-test\n      scopes: [openid]\naccounts:\n  subscription:\n    provider: plain\n    auth_kind: oauth\npolicies:\n  oauth:\n    selection: {{strategy: fill_first, accounts: [subscription]}}\nroutes:\n  - id: oauth\n    listen: local\n    match: {{method: POST, path: /v1/chat/completions, content_types: [application/json]}}\n    ingress: {{mode: opaque}}\n    target: {{provider: plain, policy: oauth}}\n    response: {{mode: opaque}}\n"
        ),
    )
    .expect("non-native OAuth proxy config");
    let running = start_server(config).await;
    let response = send_semantic_request(
        running.address,
        "/v1/chat/completions",
        br#"{"model":"test","messages":[]}"#,
    )
    .await;
    assert_eq!(response_status(&response), 502);
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "non-native OAuth opened an upstream transport"
    );
    running.stop().await;
}

#[tokio::test]
async fn anthropic_semantic_route_injects_configured_x_api_key_only() {
    let upstream_body = serde_json::to_vec(&json!({
        "id":"msg-auth",
        "type":"message",
        "role":"assistant",
        "model":"claude-test",
        "content":[{"type":"text","text":"ok"}],
        "stop_reason":"end_turn",
        "stop_sequence":null,
        "usage":{"input_tokens":2,"output_tokens":1}
    }))
    .expect("Anthropic response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let mut secret_file = provider_secret_file();
    let config = anthropic_config(upstream_address, secret_file.path());
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "model":"claude-test",
        "max_tokens":64,
        "stream":false,
        "messages":[{"role":"user","content":"hello"}]
    }))
    .expect("Anthropic request JSON");
    let response = send_semantic_request(running.address, "/v1/messages", &request).await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_eq!(
        header_value(&upstream_request, "x-api-key"),
        Some(CONFIGURED_SECRET)
    );
    assert_eq!(header_value(&upstream_request, "authorization"), None);
    assert_eq!(header_value(&upstream_request, "x-goog-api-key"), None);
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_AUTHORIZATION));
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_X_API_KEY));
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_X_GOOG_API_KEY));

    running.stop().await;
    secret_file
        .as_file_mut()
        .flush()
        .expect("secret file remains valid");
}

#[tokio::test]
async fn gemini_semantic_route_injects_configured_x_goog_api_key_only() {
    let upstream_body = serde_json::to_vec(&json!({
        "responseId":"resp-auth",
        "modelVersion":"gemini-test",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"ok"}]},
            "finishReason":"STOP"
        }],
        "usageMetadata":{
            "promptTokenCount":2,
            "candidatesTokenCount":1,
            "totalTokenCount":3
        }
    }))
    .expect("Gemini response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let mut secret_file = provider_secret_file();
    let config = gemini_config(upstream_address, secret_file.path());
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "contents":[{"role":"user","parts":[{"text":"hello"}]}]
    }))
    .expect("Gemini request JSON");
    let response = send_semantic_request(
        running.address,
        "/v1beta/models/gemini-test:generateContent",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_eq!(
        header_value(&upstream_request, "x-goog-api-key"),
        Some(CONFIGURED_SECRET)
    );
    assert_eq!(header_value(&upstream_request, "authorization"), None);
    assert_eq!(header_value(&upstream_request, "x-api-key"), None);
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_AUTHORIZATION));
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_X_API_KEY));
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_X_GOOG_API_KEY));

    running.stop().await;
    secret_file
        .as_file_mut()
        .flush()
        .expect("secret file remains valid");
}

/// An Azure OpenAI deployment reached with configuration alone.
///
/// Azure names its credential header `api-key` and rejects a request that
/// omits `api-version`, neither of which any other provider in the repository
/// needs. Both come from the upstream declaration here, so a provider with the
/// same shape does not require an adapter.
#[tokio::test]
async fn azure_style_upstream_supplies_its_credential_header_and_required_query() {
    let upstream_body = serde_json::to_vec(&json!({
        "id":"chatcmpl-azure",
        "object":"chat.completion",
        "model":"gpt-4o",
        "choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]
    }))
    .expect("Azure response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let mut secret_file = provider_secret_file();
    let config = azure_config(upstream_address, secret_file.path());
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "model":"gpt-4o",
        "messages":[{"role":"user","content":"hello"}]
    }))
    .expect("Azure request JSON");

    let response = send_semantic_request(running.address, "/v1/chat/completions", &request).await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    let request_line = String::from_utf8_lossy(&upstream_request)
        .lines()
        .next()
        .expect("request line")
        .to_owned();
    assert_eq!(
        request_line,
        "POST /openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21 HTTP/1.1"
    );
    assert_eq!(
        header_value(&upstream_request, "api-key"),
        Some(CONFIGURED_SECRET),
        "the configured credential must replace the client's api-key header"
    );
    assert_eq!(header_value(&upstream_request, "authorization"), None);
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_API_KEY));
    assert!(!String::from_utf8_lossy(&upstream_request).contains(CLIENT_AUTHORIZATION));

    running.stop().await;
    secret_file
        .as_file_mut()
        .flush()
        .expect("secret file remains valid");
}

/// A caller that chose an `api-version` keeps it, because a configured query
/// parameter fills a gap rather than overriding a deliberate choice.
#[tokio::test]
async fn a_caller_supplied_query_parameter_survives_the_upstream_default() {
    let upstream_body = serde_json::to_vec(&json!({
        "id":"chatcmpl-azure",
        "object":"chat.completion",
        "model":"gpt-4o",
        "choices":[]
    }))
    .expect("Azure response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let mut secret_file = provider_secret_file();
    let config = azure_config(upstream_address, secret_file.path());
    let running = start_server(config).await;
    let request =
        serde_json::to_vec(&json!({"model":"gpt-4o","messages":[]})).expect("Azure request JSON");

    let response = send_semantic_request(
        running.address,
        "/v1/chat/completions?api-version=2025-01-01-preview",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    let request_line = String::from_utf8_lossy(&upstream_request)
        .lines()
        .next()
        .expect("request line")
        .to_owned();
    assert_eq!(
        request_line,
        "POST /openai/deployments/gpt-4o/chat/completions?api-version=2025-01-01-preview HTTP/1.1"
    );

    running.stop().await;
    secret_file
        .as_file_mut()
        .flush()
        .expect("secret file remains valid");
}

fn provider_secret_file() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("secret file");
    file.write_all(CONFIGURED_SECRET.as_bytes())
        .expect("write provider secret");
    file.flush().expect("flush provider secret");
    file
}

fn anthropic_config(
    upstream_address: SocketAddr,
    secret_path: &std::path::Path,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "anthropic-provider-auth.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  anthropic:\n    url: http://{upstream_address}\n    auth: {{kind: x-api-key, secret: 'file:{}'}}\nroutes:\n  - id: anthropic-auth\n    listen: local\n    match: {{method: POST, path: /v1/messages, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.anthropic.messages, encoder: encode.anthropic.messages}}\n    target: {{provider: anthropic, path: /v1/messages}}\n    response: {{mode: semantic, decoder: decode.anthropic.messages.events, encoder: encode.anthropic.messages.events}}\n    loss_policy: reject\n",
            secret_path.display()
        ),
    )
    .expect("Anthropic auth config")
}

fn gemini_config(
    upstream_address: SocketAddr,
    secret_path: &std::path::Path,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "gemini-provider-auth.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  gemini:\n    url: http://{upstream_address}\n    auth: {{kind: x-goog-api-key, secret: 'file:{}'}}\nroutes:\n  - id: gemini-auth\n    listen: local\n    match: {{method: POST, path: /v1beta/models/gemini-test:generateContent, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: gemini}}\n    response: {{mode: semantic, decoder: decode.gemini.generate_content.response, encoder: encode.gemini.generate_content.response}}\n    loss_policy: reject\n",
            secret_path.display()
        ),
    )
    .expect("Gemini auth config")
}

fn azure_config(
    upstream_address: SocketAddr,
    secret_path: &std::path::Path,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "azure-provider-auth.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  azure:\n    url: http://{upstream_address}\n    auth: {{kind: header, header: api-key, secret: 'file:{}'}}\n    query: {{api-version: '2024-10-21'}}\nroutes:\n  - id: azure-chat\n    listen: local\n    match: {{method: POST, path: /v1/chat/completions, content_types: [application/json]}}\n    ingress: {{mode: opaque}}\n    target: {{provider: azure, path: /openai/deployments/gpt-4o/chat/completions}}\n    response: {{mode: opaque}}\n",
            secret_path.display()
        ),
    )
    .expect("Azure auth config")
}

struct RunningServer {
    server: HttpProxyServer,
    address: SocketAddr,
    runner: JoinHandle<Result<(), HttpProxyServerError>>,
}

impl RunningServer {
    async fn stop(self) {
        self.server.begin_drain();
        timeout(TEST_TIMEOUT, self.runner)
            .await
            .expect("proxy drain timeout")
            .expect("proxy task")
            .expect("proxy succeeds");
    }
}

async fn start_server(config: pooler_config::CompiledConfig) -> RunningServer {
    let server = HttpProxyServer::bind(config).await.expect("proxy binds");
    let address = server.listener_addresses()[0]
        .address()
        .parse()
        .expect("proxy address");
    let runner_server = server.clone();
    let runner = tokio::spawn(async move { runner_server.run().await });
    RunningServer {
        server,
        address,
        runner,
    }
}

async fn spawn_upstream(
    content_type: &'static str,
    body: Vec<u8>,
) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let request = read_request(&mut stream).await.expect("upstream request");
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("response headers");
        stream.write_all(&body).await.expect("response body");
        request
    });
    (address, task)
}

async fn send_semantic_request(address: SocketAddr, path: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: provider-auth-test\r\nContent-Type: application/json\r\nAuthorization: Bearer {CLIENT_AUTHORIZATION}\r\nX-Api-Key: {CLIENT_X_API_KEY}\r\nX-Goog-Api-Key: {CLIENT_X_GOOG_API_KEY}\r\nApi-Key: {CLIENT_API_KEY}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("request headers");
    stream.write_all(body).await.expect("request body");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("proxy response timeout")
        .expect("proxy response");
    response
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
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
    let content_length = header_value(&bytes[..body_start], "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < body_start.saturating_add(content_length) {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

fn response_status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .expect("response UTF-8")
        .split_whitespace()
        .nth(1)
        .expect("response status")
        .parse()
        .expect("numeric status")
}

fn header_value<'a>(message: &'a [u8], name: &str) -> Option<&'a str> {
    let header_end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    std::str::from_utf8(&message[..header_end])
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            candidate
                .trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
}
