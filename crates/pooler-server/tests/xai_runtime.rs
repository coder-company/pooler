use std::{net::SocketAddr, time::Duration};

use adapter_xai::{
    XaiRealtimeEventDecoder, XaiRealtimeRequestCodec, XAI_CHAT_EVENT_DECODER,
    XAI_CHAT_EVENT_ENCODER, XAI_CHAT_REQUEST_DECODER, XAI_RESPONSES_EVENT_DECODER,
    XAI_RESPONSES_EVENT_ENCODER, XAI_RESPONSES_REQUEST_DECODER,
};
use futures_util::{SinkExt, StreamExt};
use pooler_config::compile_yaml;
use pooler_http::SseParser;
use pooler_protocol::{LossPolicy, StreamEventKind, StreamValidator};
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::{
    accept_hdr_async, connect_async,
    tungstenite::{handshake::server::Request, Message},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const REALTIME_REQUEST: &[u8] =
    include_bytes!("../../../fixtures/xai/responses-websocket-request.json");
const REALTIME_TEXT_EVENTS: &str =
    include_str!("../../../fixtures/xai/responses-websocket-text.jsonl");

#[tokio::test]
async fn xai_chat_rest_routes_semantically_and_restores_provider_fields() {
    let upstream_chunk = json!({
        "id":"chat-xai",
        "object":"chat.completion.chunk",
        "model":"grok-4.6",
        "service_tier":"priority",
        "system_fingerprint":"fp_xai",
        "choices":[{
            "index":0,
            "delta":{"role":"assistant","reasoning_content":"think","content":"XAI_CHAT_OK"},
            "finish_reason":"end_turn"
        }],
        "citations":["https://example.test/citation"],
        "output_files":[{"id":"file-xai"}],
        "usage":{
            "prompt_tokens":4,
            "completion_tokens":2,
            "total_tokens":6,
            "cost_in_usd_ticks":9,
            "num_sources_used":1,
            "prompt_tokens_details":{"text_tokens":3,"audio_tokens":1,"image_tokens":0},
            "completion_tokens_details":{
                "audio_tokens":0,
                "accepted_prediction_tokens":1,
                "rejected_prediction_tokens":0
            }
        }
    });
    let upstream_body = format!("data: {upstream_chunk}\n\ndata: [DONE]\n\n").into_bytes();
    let (upstream_address, upstream_task) =
        spawn_http_upstream("text/event-stream", upstream_body).await;
    let running = start_server(xai_rest_config(upstream_address, RestWire::Chat)).await;
    let request = serde_json::to_vec(&json!({
        "model":"grok-4.6",
        "messages":[{"role":"user","content":"hello"}],
        "stream":true,
        "service_tier":"priority",
        "search_parameters":{"mode":"auto"}
    }))
    .expect("xAI Chat request JSON");

    let response = send_request(running.address, "/v1/chat/completions", &request).await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream xAI Chat SSE");
    events.extend(parser.finish().expect("complete downstream xAI Chat SSE"));
    let chunks = events
        .iter()
        .filter(|event| event.data != "[DONE]")
        .map(|event| serde_json::from_str::<Value>(&event.data).expect("xAI Chat chunk JSON"))
        .collect::<Vec<_>>();
    assert!(chunks
        .iter()
        .any(|chunk| chunk["choices"][0]["delta"]["content"] == "XAI_CHAT_OK"));
    assert!(chunks
        .iter()
        .any(|chunk| chunk["choices"][0]["delta"]["reasoning_content"] == "think"));
    assert!(chunks
        .iter()
        .any(|chunk| chunk["service_tier"] == "priority"));
    assert!(chunks
        .iter()
        .any(|chunk| chunk["system_fingerprint"] == "fp_xai"));
    assert!(chunks
        .iter()
        .any(|chunk| chunk["citations"][0] == "https://example.test/citation"));
    assert!(chunks
        .iter()
        .any(|chunk| chunk["output_files"][0]["id"] == "file-xai"));
    assert!(chunks
        .iter()
        .any(|chunk| chunk["usage"]["cost_in_usd_ticks"] == 9));
    assert_eq!(
        events.iter().filter(|event| event.data == "[DONE]").count(),
        1
    );

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(&upstream_request, "/v1/chat/completions");
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded xAI Chat JSON");
    assert_eq!(forwarded["stream"], true);
    assert_eq!(forwarded["stream_options"]["include_usage"], true);
    assert_eq!(forwarded["search_parameters"]["mode"], "auto");
    running.stop().await;
}

#[tokio::test]
async fn xai_responses_rest_routes_named_sse_through_native_components() {
    let upstream_body = REALTIME_TEXT_EVENTS
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: Value = serde_json::from_str(line).expect("xAI Responses fixture JSON");
            let event = value["type"].as_str().expect("xAI event type");
            format!("event: {event}\ndata: {line}\n\n")
        })
        .collect::<String>()
        .into_bytes();
    let (upstream_address, upstream_task) =
        spawn_http_upstream("text/event-stream", upstream_body).await;
    let running = start_server(xai_rest_config(upstream_address, RestWire::Responses)).await;
    let request = serde_json::to_vec(&json!({
        "model":"grok-4.6",
        "input":"hello",
        "stream":true,
        "store":false,
        "frequency_penalty":0,
        "search_parameters":{"mode":"auto"}
    }))
    .expect("xAI Responses request JSON");

    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream xAI Responses SSE");
    events.extend(
        parser
            .finish()
            .expect("complete downstream xAI Responses SSE"),
    );
    assert!(events.iter().any(|event| {
        event.event.as_deref() == Some("response.output_text.delta") && event.data.contains("Hello")
    }));
    let completed = events
        .iter()
        .find(|event| event.event.as_deref() == Some("response.completed"))
        .expect("xAI Responses completion");
    let completed: Value =
        serde_json::from_str(&completed.data).expect("xAI Responses completion JSON");
    assert_eq!(completed["response"]["usage"]["cost_in_usd_ticks"], 42);
    assert_eq!(completed["response"]["usage"]["num_sources_used"], 1);
    assert!(!events.iter().any(|event| event.data == "[DONE]"));

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(&upstream_request, "/v1/responses");
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Responses JSON");
    assert_eq!(forwarded["stream"], true);
    assert_eq!(forwarded["store"], false);
    assert_eq!(forwarded["frequency_penalty"], 0);
    assert_eq!(forwarded["search_parameters"]["mode"], "auto");
    running.stop().await;
}

#[tokio::test]
async fn xai_responses_http_client_uses_semantic_realtime_websocket_upstream() {
    let (upstream_address, upstream_task) = spawn_xai_websocket_upstream().await;
    let running = start_server(xai_semantic_websocket_config(upstream_address)).await;
    let request = serde_json::to_vec(&json!({
        "model":"grok-4.6",
        "input":"hello",
        "stream":true,
        "store":false,
        "background":false,
        "search_parameters":{"mode":"auto"}
    }))
    .expect("xAI Responses request JSON");

    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream xAI realtime SSE");
    events.extend(parser.finish().expect("complete realtime SSE"));
    assert!(events.iter().any(|event| {
        event.event.as_deref() == Some("response.output_text.delta") && event.data.contains("Hello")
    }));
    assert!(events
        .iter()
        .any(|event| event.event.as_deref() == Some("response.completed")));

    let (path, upstream_request, openai_beta_present) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("xAI realtime upstream timeout")
        .expect("xAI realtime upstream task");
    assert_eq!(path, "/v1/responses");
    assert!(
        !openai_beta_present,
        "xAI must not receive OpenAI beta headers"
    );
    let upstream_request: Value =
        serde_json::from_slice(&upstream_request).expect("response.create JSON");
    assert_eq!(upstream_request["type"], "response.create");
    assert_eq!(upstream_request["model"], "grok-4.6");
    assert!(upstream_request.get("stream").is_none());
    assert!(upstream_request.get("background").is_none());
    assert_eq!(upstream_request["search_parameters"]["mode"], "auto");
    running.stop().await;
}

#[tokio::test]
async fn xai_responses_websocket_stays_raw_bounded_and_satisfies_codec_lifecycle() {
    let (upstream_address, upstream_task) = spawn_xai_websocket_upstream().await;
    let config = xai_websocket_config(upstream_address);
    let route = config
        .route("xai-responses-websocket")
        .expect("xAI WS route");
    assert_eq!(route.limits().max_frame_bytes, 8 * 1024 * 1024);
    assert_eq!(route.limits().max_queue_bytes, 8 * 1024 * 1024);
    assert_eq!(route.limits().max_queue_items, 64);
    assert_eq!(route.limits().request_timeout, None);
    let running = start_server(config).await;

    let url = format!("ws://{}/v1/responses", running.address);
    let (mut socket, response) = timeout(TEST_TIMEOUT, connect_async(&url))
        .await
        .expect("downstream WebSocket connect timeout")
        .expect("downstream WebSocket connects");
    assert_eq!(response.status(), 101);
    let encoded = XaiRealtimeRequestCodec::default()
        .encode_response_create(REALTIME_REQUEST, LossPolicy::Reject)
        .expect("xAI response.create request");
    socket
        .send(Message::Text(
            String::from_utf8(encoded.body.clone())
                .expect("xAI request UTF-8")
                .into(),
        ))
        .await
        .expect("send response.create");

    let mut decoder = XaiRealtimeEventDecoder::default();
    let mut validator = StreamValidator::default();
    let mut text = String::new();
    while let Some(message) = timeout(TEST_TIMEOUT, socket.next())
        .await
        .expect("xAI WebSocket event timeout")
    {
        match message.expect("xAI WebSocket message") {
            Message::Text(message) => {
                let decoded = decoder
                    .decode_message(message.as_bytes())
                    .expect("xAI realtime event contract");
                for event in decoded.semantic_events {
                    validator.accept(&event).expect("valid semantic lifecycle");
                    if let StreamEventKind::TextDelta { text: delta } = event.kind {
                        text.push_str(&delta);
                    }
                }
            }
            Message::Close(_) => break,
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .expect("xAI WebSocket pong"),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    decoder.finish().expect("terminal xAI realtime lifecycle");
    assert_eq!(text, "Hello from Grok.");

    let (path, upstream_request, openai_beta_present) = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("xAI WebSocket upstream timeout")
        .expect("xAI WebSocket upstream task");
    assert_eq!(path, "/v1/responses");
    assert!(
        !openai_beta_present,
        "xAI must not receive OpenAI beta headers"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&upstream_request).expect("upstream response.create JSON"),
        serde_json::from_slice::<Value>(&encoded.body).expect("encoded response.create JSON")
    );
    running.stop().await;
}

#[derive(Clone, Copy)]
enum RestWire {
    Chat,
    Responses,
}

fn xai_rest_config(upstream_address: SocketAddr, wire: RestWire) -> pooler_config::CompiledConfig {
    let (path, request_decoder, response_decoder, response_encoder) = match wire {
        RestWire::Chat => (
            "/v1/chat/completions",
            XAI_CHAT_REQUEST_DECODER,
            XAI_CHAT_EVENT_DECODER,
            XAI_CHAT_EVENT_ENCODER,
        ),
        RestWire::Responses => (
            "/v1/responses",
            XAI_RESPONSES_REQUEST_DECODER,
            XAI_RESPONSES_EVENT_DECODER,
            XAI_RESPONSES_EVENT_ENCODER,
        ),
    };
    compile_yaml(
        "xai-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{xai: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: xai-rest\n    listen: local\n    match: {{method: POST, path: {path}, content_types: [application/json], websocket: false}}\n    ingress: {{mode: semantic, decoder: {request_decoder}}}\n    target: {{provider: xai, path: {path}}}\n    response: {{mode: semantic, decoder: {response_decoder}, encoder: {response_encoder}}}\n    loss_policy: reject\n"
        ),
    )
    .expect("xAI REST runtime config")
}

fn xai_semantic_websocket_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "xai-semantic-websocket.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{xai: {{url: ws://{upstream_address}}}}}\nroutes:\n  - id: xai-responses-realtime\n    listen: local\n    match: {{method: POST, path: /v1/responses}}\n    ingress: {{mode: semantic, decoder: decode.xai.responses, encoder: encode.xai.responses}}\n    target: {{provider: xai, path: /v1/responses}}\n    response: {{mode: semantic, decoder: decode.xai.responses.events, encoder: encode.xai.responses.events}}\n"
        ),
    )
    .expect("xAI semantic WebSocket runtime config")
}

fn xai_websocket_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "xai-websocket.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{xai: {{url: ws://{upstream_address}}}}}\nroutes:\n  - id: xai-responses-websocket\n    listen: local\n    match: {{method: GET, path: /v1/responses, websocket: true}}\n    limits: {{max_frame_bytes: 8388608, max_queue_bytes: 8388608, max_queue_items: 64, request_timeout: null}}\n    ingress: {{mode: opaque}}\n    target: {{provider: xai, path: /v1/responses}}\n    response: {{mode: opaque}}\n"
        ),
    )
    .expect("xAI WebSocket runtime config")
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

async fn spawn_http_upstream(
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

async fn spawn_xai_websocket_upstream() -> (SocketAddr, JoinHandle<(String, Vec<u8>, bool)>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("xAI WebSocket upstream binds");
    let address = listener.local_addr().expect("xAI upstream address");
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("xAI upstream accepts");
        let mut path = String::new();
        let mut openai_beta_present = false;
        let mut socket = accept_hdr_async(stream, |request: &Request, response| {
            path = request.uri().path().to_owned();
            openai_beta_present = request.headers().contains_key("openai-beta");
            Ok(response)
        })
        .await
        .expect("xAI upstream handshake");
        let request = match timeout(TEST_TIMEOUT, socket.next())
            .await
            .expect("response.create timeout")
            .expect("response.create message")
            .expect("valid response.create message")
        {
            Message::Text(text) => text.as_bytes().to_vec(),
            other => panic!("expected response.create text message, got {other:?}"),
        };
        for line in REALTIME_TEXT_EVENTS
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            socket
                .send(Message::Text(line.to_owned().into()))
                .await
                .expect("xAI upstream event");
        }
        socket.close(None).await.expect("xAI upstream close");
        (path, request, openai_beta_present)
    });
    (address, task)
}

async fn send_request(address: SocketAddr, path: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: xai.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    while bytes.len() < body_start + content_length {
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

fn decoded_response_body(response: &[u8]) -> Vec<u8> {
    let body = http_body(response);
    if header_value(response, "transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(body)
    } else {
        body.to_vec()
    }
}

fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&body[..line_end])
                .expect("chunk size UTF-8")
                .split(';')
                .next()
                .expect("chunk size"),
            16,
        )
        .expect("hex chunk size");
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
    decoded
}

fn assert_request_line(request: &[u8], path: &str) {
    let end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("request line");
    assert_eq!(
        std::str::from_utf8(&request[..end]).expect("request line UTF-8"),
        format!("POST {path} HTTP/1.1")
    );
}

fn header_value<'a>(message: &'a [u8], name: &str) -> Option<&'a str> {
    message[..http_body_start(message)]
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(name.as_bytes())
                .then(|| std::str::from_utf8(&line[colon + 1..]).ok().map(str::trim))
                .flatten()
        })
}

fn http_body(message: &[u8]) -> &[u8] {
    &message[http_body_start(message)..]
}

fn http_body_start(message: &[u8]) -> usize {
    message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("HTTP header delimiter")
}
