use std::{net::SocketAddr, time::Duration};

use pooler_config::compile_yaml;
use pooler_http::SseParser;
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn anthropic_unary_cache_warmup_preserves_json_mode_end_to_end() {
    let upstream_body = serde_json::to_vec(&json!({
        "id":"msg_warm","type":"message","role":"assistant","model":"claude-test",
        "content":[],"stop_reason":"max_tokens","stop_sequence":null,
        "usage":{
            "input_tokens":20,"output_tokens":0,"cache_creation_input_tokens":20
        },
        "service_tier":"standard"
    }))
    .expect("unary response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let running = start_server(anthropic_config(upstream_address)).await;
    let request = serde_json::to_vec(&json!({
        "model":"claude-test",
        "max_tokens":0,
        "stream":false,
        "system":[{
            "type":"text","text":"cache","cache_control":{"type":"ephemeral"}
        }],
        "messages":[{"role":"user","content":"warm cache"}]
    }))
    .expect("unary request JSON");
    let response = send_request(running.address, &request).await;
    assert_eq!(response_status(&response), 200);
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let body: Value =
        serde_json::from_slice(&decoded_response_body(&response)).expect("downstream unary JSON");
    assert_eq!(body["id"], "msg_warm");
    assert_eq!(body["content"], json!([]));
    assert_eq!(body["stop_reason"], "max_tokens");
    assert_eq!(body["usage"]["cache_creation_input_tokens"], 20);
    assert_eq!(body["service_tier"], "standard");

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert!(String::from_utf8_lossy(&upstream_request).starts_with("POST /v1/messages HTTP/1.1"));
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded unary JSON");
    assert_eq!(forwarded["stream"], false);
    assert_eq!(forwarded["max_tokens"], 0);
    running.stop().await;
}

#[tokio::test]
async fn anthropic_stream_request_remains_named_sse_end_to_end() {
    let upstream_body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_stream\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-test\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ANTHROPIC_STREAM_OK\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    )
    .as_bytes()
    .to_vec();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let running = start_server(anthropic_config(upstream_address)).await;
    let request = serde_json::to_vec(&json!({
        "model":"claude-test","max_tokens":1024,"stream":true,
        "messages":[{"role":"user","content":"stream"}]
    }))
    .expect("stream request JSON");
    let response = send_request(running.address, &request).await;
    assert_eq!(response_status(&response), 200);
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream Anthropic SSE");
    events.extend(parser.finish().expect("complete downstream SSE"));
    assert!(events.iter().any(|event| {
        event.event.as_deref() == Some("content_block_delta")
            && event.data.contains("ANTHROPIC_STREAM_OK")
    }));
    assert_eq!(
        events.last().and_then(|event| event.event.as_deref()),
        Some("message_stop")
    );

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded stream JSON");
    assert_eq!(forwarded["stream"], true);
    running.stop().await;
}

fn anthropic_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "anthropic-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: droid-anthropic\n    listen: local\n    match: {{method: POST, path: /v1/messages, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.anthropic.messages, encoder: encode.anthropic.messages}}\n    target: {{provider: local, path: /v1/messages}}\n    response: {{mode: semantic, decoder: decode.anthropic.messages.events, encoder: encode.anthropic.messages.events}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Anthropic runtime config")
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

async fn send_request(address: SocketAddr, body: &[u8]) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let headers = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: anthropic-test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    let content_length = String::from_utf8_lossy(&bytes[..body_start])
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);
    while bytes.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

fn response_status(response: &[u8]) -> u16 {
    String::from_utf8_lossy(response)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("response status")
}

fn response_headers(response: &[u8]) -> String {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers");
    String::from_utf8_lossy(&response[..end]).into_owned()
}

fn decoded_response_body(response: &[u8]) -> Vec<u8> {
    let start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("response body");
    decode_chunked(&response[start..])
}

fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let mut remaining = body;
    let mut decoded = Vec::new();
    while !remaining.is_empty() {
        let Some(line_end) = remaining.windows(2).position(|window| window == b"\r\n") else {
            return body.to_vec();
        };
        let Ok(size) =
            usize::from_str_radix(String::from_utf8_lossy(&remaining[..line_end]).trim(), 16)
        else {
            return body.to_vec();
        };
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        let end = start + size;
        if remaining.len() < end + 2 {
            return body.to_vec();
        }
        decoded.extend_from_slice(&remaining[start..end]);
        remaining = &remaining[end + 2..];
    }
    decoded
}

fn http_body(request: &[u8]) -> &[u8] {
    let start = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("request body");
    &request[start..]
}
