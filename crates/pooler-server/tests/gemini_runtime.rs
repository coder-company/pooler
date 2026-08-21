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
async fn installed_droid_responses_shape_routes_through_semantic_runtime() {
    let response_id = "resp-droid";
    let message_id = "msg-droid";
    let created = json!({
        "type":"response.created",
        "response":{
            "id":response_id,"object":"response","model":"droid-model",
            "status":"in_progress","output":[],"usage":null
        }
    });
    let item_added = json!({
        "type":"response.output_item.added","output_index":0,
        "item":{"id":message_id,"type":"message","status":"in_progress","role":"assistant","content":[]}
    });
    let part_added = json!({
        "type":"response.content_part.added","item_id":message_id,
        "output_index":0,"content_index":0,
        "part":{"type":"output_text","text":"","annotations":[]}
    });
    let delta = json!({
        "type":"response.output_text.delta","item_id":message_id,
        "output_index":0,"content_index":0,"delta":"DROID_RUNTIME_OK"
    });
    let item_done = json!({
        "type":"response.output_item.done","output_index":0,
        "item":{
            "id":message_id,"type":"message","status":"completed","role":"assistant",
            "content":[{"type":"output_text","text":"DROID_RUNTIME_OK","annotations":[]}]
        }
    });
    let completed = json!({
        "type":"response.completed",
        "response":{
            "id":response_id,"object":"response","model":"droid-model",
            "status":"completed",
            "output":[],
            "usage":{
                "input_tokens":5,"input_tokens_details":{"cached_tokens":0},
                "output_tokens":2,"output_tokens_details":{"reasoning_tokens":0},
                "total_tokens":7
            }
        }
    });
    let upstream_body = [
        ("response.created", created),
        ("response.output_item.added", item_added),
        ("response.content_part.added", part_added),
        ("response.output_text.delta", delta),
        ("response.output_item.done", item_done),
        ("response.completed", completed),
    ]
    .into_iter()
    .map(|(name, value)| format!("event: {name}\ndata: {value}\n\n"))
    .collect::<String>()
    .into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let config = droid_config(upstream_address);
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "model":"droid-model",
        "instructions":"reply briefly",
        "input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],
        "tools":[{
            "type":"function","name":"Read","description":"read",
            "parameters":{"type":"object","properties":{},"additionalProperties":false},
            "strict":false
        }],
        "tool_choice":"auto",
        "parallel_tool_calls":true,
        "reasoning":{"effort":"low","summary":"auto"},
        "include":["reasoning.encrypted_content"],
        "prompt_cache_key":"droid-cache",
        "store":false,
        "stream":true
    }))
    .expect("Droid request JSON");
    let response = send_request(running.address, "/v1/responses", &request).await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream Responses SSE");
    events.extend(parser.finish().expect("complete Responses SSE"));
    assert!(events.iter().any(|event| {
        event.event.as_deref() == Some("response.output_text.delta")
            && event.data.contains("DROID_RUNTIME_OK")
    }));
    assert!(events
        .iter()
        .any(|event| event.event.as_deref() == Some("response.completed")));
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
    assert_eq!(forwarded["include"][0], "reasoning.encrypted_content");
    assert_eq!(forwarded["tools"][0]["name"], "Read");
    running.stop().await;
}

#[tokio::test]
async fn gemini_unary_routes_through_semantic_runtime() {
    let upstream_body = serde_json::to_vec(&json!({
        "responseId":"resp-unary",
        "modelVersion":"gemini-test",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"GEMINI_UNARY_OK"}]},
            "finishReason":"STOP"
        }],
        "usageMetadata":{
            "promptTokenCount":3,
            "candidatesTokenCount":2,
            "totalTokenCount":5
        }
    }))
    .expect("Gemini response JSON");
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_config(
        upstream_address,
        "/v1beta/models/gemini-test:generateContent",
    );
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "contents":[{"role":"user","parts":[{"text":"hello"}]}]
    }))
    .expect("Gemini request JSON");
    let response = send_request(
        running.address,
        "/v1beta/models/gemini-test:generateContent",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let body: Value =
        serde_json::from_slice(&decoded_response_body(&response)).expect("downstream Gemini JSON");
    assert_eq!(
        body["candidates"][0]["content"]["parts"][0]["text"],
        "GEMINI_UNARY_OK"
    );
    assert_eq!(body["candidates"][0]["finishReason"], "STOP");
    assert_eq!(body["usageMetadata"]["totalTokenCount"], 5);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/gemini-test:generateContent",
    );
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Gemini JSON");
    assert_eq!(forwarded["contents"][0]["parts"][0]["text"], "hello");
    running.stop().await;
}

#[tokio::test]
async fn gemini_stream_routes_named_sse_without_openai_done_marker() {
    let first = json!({
        "responseId":"resp-stream",
        "modelVersion":"gemini-test",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"GEMINI_STREAM_OK"}]}
        }]
    });
    let terminal = json!({
        "responseId":"resp-stream",
        "modelVersion":"gemini-test",
        "candidates":[{"index":0,"finishReason":"STOP"}],
        "usageMetadata":{
            "promptTokenCount":4,
            "candidatesTokenCount":3,
            "totalTokenCount":7
        }
    });
    let upstream_body = format!("data: {first}\n\ndata: {terminal}\n\n").into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let config = gemini_config(
        upstream_address,
        "/v1beta/models/gemini-test:streamGenerateContent",
    );
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "contents":[{"role":"user","parts":[{"text":"stream"}]}]
    }))
    .expect("Gemini request JSON");
    let response = send_request(
        running.address,
        "/v1beta/models/gemini-test:streamGenerateContent?alt=sse",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream Gemini SSE");
    events.extend(parser.finish().expect("complete downstream Gemini SSE"));
    assert!(events
        .iter()
        .any(|event| event.data.contains("GEMINI_STREAM_OK")));
    assert!(events
        .iter()
        .any(|event| event.data.contains("finishReason")));
    assert!(!events.iter().any(|event| event.data == "[DONE]"));

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/gemini-test:streamGenerateContent?alt=sse",
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_path_template_rewrites_model_alias_and_normalizes_stream_query() {
    let terminal = json!({
        "responseId":"resp-alias",
        "modelVersion":"private-gemini",
        "candidates":[{
            "index":0,
            "content":{"role":"model","parts":[{"text":"GEMINI_ALIAS_OK"}]},
            "finishReason":"STOP"
        }],
        "usageMetadata":{
            "promptTokenCount":4,
            "candidatesTokenCount":3,
            "totalTokenCount":7
        }
    });
    let upstream_body = format!("data: {terminal}\n\n").into_bytes();
    let (upstream_address, upstream_task) =
        spawn_upstream("text/event-stream", upstream_body).await;
    let config = gemini_alias_config(upstream_address);
    let running = start_server(config).await;
    let request = serde_json::to_vec(&json!({
        "systemInstruction":{"parts":[{"text":"Be concise."}]},
        "contents":[{"role":"user","parts":[{"text":"alias"}]}]
    }))
    .expect("Gemini alias request JSON");
    let response = send_request(
        running.address,
        "/v1beta/models/public-gemini:streamGenerateContent?trace=alias&alt=json",
        &request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    let body = decoded_response_body(&response);
    let mut parser = SseParser::new();
    let mut events = parser.feed(&body).expect("downstream alias SSE");
    events.extend(parser.finish().expect("complete downstream alias SSE"));
    assert!(events
        .iter()
        .any(|event| event.data.contains("GEMINI_ALIAS_OK")));

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/private-gemini:streamGenerateContent?trace=alias&key=server-key&alt=sse",
    );
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Gemini alias JSON");
    assert!(forwarded.get("model").is_none());
    assert!(forwarded["systemInstruction"].get("role").is_none());
    assert_eq!(
        forwarded["systemInstruction"]["parts"][0]["text"],
        "Be concise."
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_count_tokens_alias_rewrites_path_and_preserves_query_and_body() {
    let upstream_body = br#"{"totalTokens":3}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_same_wire_alias_config(
        upstream_address,
        "POST",
        "/v1beta/models/public-gemini:countTokens",
    );
    let running = start_server(config).await;
    let request = br#"{"contents":[{"parts":[{"text":"count me"}]}]}"#;

    let response = send_request(
        running.address,
        "/v1beta/models/public-gemini:countTokens?trace=count&alt=json",
        request,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded_response_body(&response)).expect("count response"),
        json!({"totalTokens":3})
    );

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/models/private-gemini:countTokens?trace=count&alt=json&key=server-key",
    );
    assert_eq!(http_body(&upstream_request), request);
    running.stop().await;
}

#[tokio::test]
async fn gemini_model_get_alias_rewrites_path_and_preserves_query() {
    let upstream_body = br#"{"name":"models/private-gemini"}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config =
        gemini_same_wire_alias_config(upstream_address, "GET", "/v1beta/models/public-gemini");
    let running = start_server(config).await;

    let response = send_method_request(
        running.address,
        "GET",
        "/v1beta/models/public-gemini?view=full",
        b"",
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_method_request_line(
        &upstream_request,
        "GET",
        "/v1beta/models/private-gemini?view=full&key=server-key",
    );
    running.stop().await;
}

#[tokio::test]
async fn gemini_interaction_alias_rewrites_body_and_preserves_query() {
    let upstream_body = br#"{"id":"int_123","status":"completed"}"#.to_vec();
    let (upstream_address, upstream_task) = spawn_upstream("application/json", upstream_body).await;
    let config = gemini_same_wire_alias_config(upstream_address, "POST", "/v1beta/interactions");
    let running = start_server(config).await;
    let request = br#"{"model":"public-gemini","input":"hello","stream":true}"#;

    let response = send_request(
        running.address,
        "/v1beta/interactions?trace=interaction",
        request,
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream timeout")
        .expect("upstream task");
    assert_request_line(
        &upstream_request,
        "/v1beta/interactions?trace=interaction&key=server-key",
    );
    let forwarded: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("forwarded Interaction JSON");
    assert_eq!(forwarded["model"], "private-gemini");
    assert_eq!(forwarded["input"], "hello");
    assert_eq!(forwarded["stream"], true);
    running.stop().await;
}

fn gemini_config(
    upstream_address: SocketAddr,
    downstream_path: &str,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "gemini-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: gemini\n    listen: local\n    match: {{method: POST, path: '{downstream_path}', content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local}}\n    response: {{mode: semantic, decoder: decode.gemini.generate_content.response, encoder: encode.gemini.generate_content.response}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Gemini runtime config")
}

fn gemini_same_wire_alias_config(
    upstream_address: SocketAddr,
    method: &str,
    downstream_path: &str,
) -> pooler_config::CompiledConfig {
    compile_yaml(
        "gemini-same-wire-alias-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}, query: {{key: server-key}}}}}}\nmodels:\n  - id: public-gemini\n    targets:\n      - {{provider: local, upstream_model: private-gemini, capabilities: [text, streaming, tools, function_calling], codecs: [decode.gemini.generate_content]}}\nroutes:\n  - id: gemini-same-wire-alias\n    listen: local\n    match: {{method: {method}, path: '{downstream_path}'}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local}}\n    response: {{mode: opaque}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Gemini same-wire alias config")
}

fn gemini_alias_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "gemini-alias-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}, query: {{key: server-key}}}}}}\nmodels:\n  - id: public-gemini\n    targets:\n      - {{provider: local, upstream_model: private-gemini, capabilities: [text, streaming], codecs: [decode.gemini.generate_content]}}\nroutes:\n  - id: gemini-alias\n    listen: local\n    match: {{method: POST, path_template: '/v1beta/models/{{model_action}}', content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.gemini.generate_content}}\n    target: {{provider: local, model_from: request.model}}\n    response: {{mode: semantic, decoder: decode.gemini.generate_content.response, encoder: encode.gemini.generate_content.response}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Gemini alias runtime config")
}

fn droid_config(upstream_address: SocketAddr) -> pooler_config::CompiledConfig {
    compile_yaml(
        "droid-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: droid-responses\n    listen: local\n    match: {{method: POST, path: /v1/responses, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.openai.responses}}\n    target: {{provider: local, path: /v1/responses}}\n    response: {{mode: semantic, decoder: decode.openai.responses.events, encoder: encode.openai.responses.events}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Droid runtime config")
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

async fn send_request(address: SocketAddr, path: &str, body: &[u8]) -> Vec<u8> {
    send_method_request(address, "POST", path, body).await
}

async fn send_method_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let content_type = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/json\r\n".to_owned()
    };
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: gemini-test\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n",
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

fn response_headers(response: &[u8]) -> String {
    String::from_utf8_lossy(&response[..http_body_start(response)]).into_owned()
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
    assert_method_request_line(request, "POST", path);
}

fn assert_method_request_line(request: &[u8], method: &str, path: &str) {
    let end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("request line");
    assert_eq!(
        std::str::from_utf8(&request[..end]).expect("request line UTF-8"),
        format!("{method} {path} HTTP/1.1")
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
