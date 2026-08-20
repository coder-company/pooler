use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

use adapter_devin::{encode_connect_frame, proto, ConnectDecoder, ConnectLimits};
use pooler_config::compile_yaml;
use pooler_http::{SseEvent, SseParser};
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use pooler_testkit::{normalize_json_value, Equivalence, Fixture, ScriptedChunk, ScriptedResult};
use prost::Message as _;
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityClaim {
    schema_version: u32,
    adapter: String,
    protocol: String,
    version: String,
    equivalence: String,
    exercised_capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DevinFixture {
    compatibility: CompatibilityClaim,
    id: String,
    client: ClientIdentity,
    equivalence: String,
    notes: String,
    request: DevinRequest,
    expected_openai_request: Value,
    expected_runtime_upstream_request: Value,
    runtime_upstream_sse: Vec<String>,
    expected_runtime_response: ExpectedDevinResponse,
}

#[derive(Debug, Deserialize)]
struct ClientIdentity {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct DevinRequest {
    model: String,
    cascade_id: String,
    execution_id: String,
    messages: Vec<DevinMessage>,
    tools: Vec<DevinTool>,
}

#[derive(Debug, Deserialize)]
struct DevinMessage {
    message_id: String,
    source: String,
    #[serde(default)]
    prompt: String,
    #[serde(default)]
    prompt_bytes: Option<usize>,
    #[serde(default)]
    tool_calls: Vec<DevinToolCall>,
    #[serde(default)]
    tool_call_id: String,
}

#[derive(Debug, Deserialize)]
struct DevinToolCall {
    id: String,
    name: String,
    arguments_json: String,
}

#[derive(Debug, Deserialize)]
struct DevinTool {
    name: String,
    json_schema_string: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedDevinResponse {
    text: String,
    stop_reason: String,
    input_tokens: u64,
    output_tokens: u64,
}

#[tokio::test]
async fn factory_current_fixture_replays_through_http_proxy_server() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/factory/fx-0.0.3-v4-current-client.json");
    let root: Value = serde_json::from_str(MANIFEST_FIXTURE).expect("Factory fixture JSON");
    let claim: CompatibilityClaim = serde_json::from_value(root["compatibility"].clone())
        .expect("typed Factory compatibility envelope");
    assert_claim(
        &claim,
        "factory",
        "language-model-v4",
        "fx-0.0.3",
        "event_semantic",
        &[
            "text",
            "function_tools",
            "streaming",
            "usage",
            "response_metadata",
            "v4_headers",
            "model_id_routing",
        ],
    );
    let fixture: Fixture = serde_json::from_value(root).expect("typed Factory fixture payload");
    assert_eq!(fixture.metadata.equivalence, Equivalence::EventSemantic);
    assert_eq!(fixture.metadata.id, "fx-0.0.3.factory.v4.pooler.2026-08-20");
    let downstream = fixture
        .downstream_request
        .as_ref()
        .expect("Factory downstream request");
    assert_eq!(
        header(downstream, "ai-language-model-specification-version"),
        "4"
    );
    assert_eq!(header(downstream, "ai-gateway-protocol-version"), "0.0.1");
    assert_eq!(header(downstream, "ai-language-model-id"), "gpt-5.6-sol");
    let factory_request: Value =
        serde_json::from_slice(&downstream.body).expect("Factory request JSON");
    assert_eq!(factory_request["tools"].as_array().map(Vec::len), Some(2));

    let ScriptedResult::Response(scripted_response) = fixture
        .upstream_script
        .first()
        .expect("Factory upstream response")
    else {
        panic!("Factory fixture must contain a response")
    };
    let upstream_body = scripted_sse_body(&scripted_response.chunks);
    let (upstream_address, upstream_task) = spawn_upstream(upstream_body).await;
    let config = compile_yaml(
        "factory-current-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nmodels:\n  - id: gpt-5.6-sol\n    targets:\n      - {{provider: local, upstream_model: gpt-5.6-sol, capabilities: [text, tools, function_calling, tool_choice, streaming], codecs: [decode.factory.language_model]}}\nroutes:\n  - id: factory-current\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: {{provider: local, path: /v1/chat/completions, model_from: request.model}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: degrade\n"
        ),
    )
    .expect("Factory runtime config");
    let running = start_server(config).await;

    let response = send_scripted_request(running.address, downstream).await;
    assert_eq!(
        response_status(&response),
        200,
        "Factory runtime response: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    let actual_events = parse_sse(&decoded_response_body(&response));
    assert_factory_events(&actual_events, &fixture.expected_downstream_chunks);

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("Factory upstream completes")
        .expect("Factory upstream task");
    assert_request_line(&upstream_request, "POST", "/v1/chat/completions");
    for stripped in [
        "ai-gateway-protocol-version",
        "ai-language-model-specification-version",
        "ai-language-model-id",
        "ai-language-model-streaming",
    ] {
        assert!(!has_header(&upstream_request, stripped));
    }
    let actual_upstream: Value = serde_json::from_slice(http_body(&upstream_request))
        .expect("Factory upstream request JSON");
    let expected_upstream: Value = serde_json::from_slice(
        &fixture
            .expected_upstream_request
            .as_ref()
            .expect("Factory expected upstream request")
            .body,
    )
    .expect("Factory expected upstream JSON");
    assert_eq!(
        normalize_json_value(actual_upstream),
        normalize_json_value(expected_upstream)
    );
    running.stop().await;
}

#[tokio::test]
async fn devin_current_tool_follow_up_replays_through_http_proxy_server() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/devin/current-client-tool-follow-up.json");
    let fixture: DevinFixture =
        serde_json::from_str(MANIFEST_FIXTURE).expect("typed Devin current-client fixture");
    assert_claim(
        &fixture.compatibility,
        "devin",
        "connect-rpc",
        "3000.4.16",
        "protobuf_semantic",
        &[
            "text",
            "function_tools",
            "streaming",
            "connect_rpc",
            "protobuf",
        ],
    );
    assert_eq!(
        fixture.id,
        "fx-devin-current-client-3000.4.16-tool-follow-up.v1"
    );
    assert_eq!(fixture.client.name, "Devin CLI");
    assert_eq!(fixture.client.version, "3000.4.16");
    assert_eq!(fixture.equivalence, "protobuf_semantic");
    assert!(fixture.notes.contains("follow-up shape"));
    assert!(fixture.notes.contains("initial tool-call response"));
    assert!(fixture.notes.contains("deterministic loopback data"));

    let connect_request = devin_connect_request(&fixture.request);
    let request_frame = encode_connect_frame(&connect_request.encode_to_vec(), false, false)
        .expect("Devin Connect request frame");
    let upstream_body = string_sse_body(&fixture.runtime_upstream_sse);
    let (upstream_address, upstream_task) = spawn_upstream(upstream_body).await;
    let config = compile_yaml(
        "devin-current-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: devin-current\n    listen: local\n    match: {{method: POST, path: /exa.api_server_pb.ApiServerService/GetChatMessage, content_types: [application/connect+proto]}}\n    ingress: {{mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}}\n    target: {{provider: local, path: /v1/chat/completions}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}}\n    loss_policy: reject\n"
        ),
    )
    .expect("Devin runtime config");
    let running = start_server(config).await;

    let response = send_request(
        running.address,
        "/exa.api_server_pb.ApiServerService/GetChatMessage",
        &[
            ("content-type", "application/connect+proto"),
            ("connect-protocol-version", "1"),
            ("connect-accept-encoding", "identity"),
        ],
        &request_frame,
    )
    .await;
    assert_eq!(
        response_status(&response),
        200,
        "Devin runtime response: {}; upstream_finished={}; decisions={:?}",
        String::from_utf8_lossy(&response),
        upstream_task.is_finished(),
        running
            .server
            .pooling()
            .recent_decisions(16)
            .expect("pooling decisions")
    );
    assert!(response_headers(&response)
        .to_ascii_lowercase()
        .contains("content-type: application/connect+proto"));
    assert_devin_response(
        &decoded_response_body(&response),
        &fixture.expected_runtime_response,
    );

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("Devin upstream completes")
        .expect("Devin upstream task");
    assert_request_line(&upstream_request, "POST", "/v1/chat/completions");
    for stripped in [
        "connect-protocol-version",
        "connect-content-encoding",
        "connect-accept-encoding",
    ] {
        assert!(!has_header(&upstream_request, stripped));
    }
    let actual_upstream: Value =
        serde_json::from_slice(http_body(&upstream_request)).expect("Devin upstream JSON");
    assert_eq!(
        normalize_json_value(actual_upstream.clone()),
        normalize_json_value(fixture.expected_runtime_upstream_request.clone())
    );
    let adapter_shape = &fixture.expected_openai_request;
    assert_eq!(adapter_shape["model"], fixture.request.model);
    assert_eq!(actual_upstream["model"], "gpt-5.6-sol-low");
    assert_eq!(actual_upstream["messages"][0]["role"], "assistant");
    assert_eq!(
        actual_upstream["messages"][0]["tool_calls"][0]["id"],
        "call-live-1"
    );
    assert_eq!(actual_upstream["messages"][1]["role"], "tool");
    assert_eq!(
        actual_upstream["messages"][1]["tool_call_id"],
        "call-live-1"
    );
    running.stop().await;
}

fn assert_claim(
    claim: &CompatibilityClaim,
    adapter: &str,
    protocol: &str,
    version: &str,
    equivalence: &str,
    capabilities: &[&str],
) {
    assert_eq!(claim.schema_version, 1);
    assert_eq!(claim.adapter, adapter);
    assert_eq!(claim.protocol, protocol);
    assert_eq!(claim.version, version);
    assert_eq!(claim.equivalence, equivalence);
    let actual = claim
        .exercised_capabilities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = capabilities.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), claim.exercised_capabilities.len());
}

fn devin_connect_request(fixture: &DevinRequest) -> proto::GetChatMessageRequest {
    let messages = fixture
        .messages
        .iter()
        .map(|message| {
            if let Some(prompt_bytes) = message.prompt_bytes {
                assert_eq!(message.prompt.len(), prompt_bytes);
            }
            let source = match message.source.as_str() {
                "system" => proto::ChatMessageSource::System,
                "tool" => proto::ChatMessageSource::Tool,
                source => panic!("unsupported Devin fixture source {source}"),
            };
            proto::ChatMessagePrompt {
                message_id: message.message_id.clone(),
                source: source as i32,
                prompt: message.prompt.clone(),
                tool_calls: message
                    .tool_calls
                    .iter()
                    .map(|call| proto::ChatToolCall {
                        id: call.id.clone(),
                        name: call.name.clone(),
                        arguments_json: call.arguments_json.clone(),
                        ..Default::default()
                    })
                    .collect(),
                tool_call_id: message.tool_call_id.clone(),
                ..Default::default()
            }
        })
        .collect();
    let tools = fixture
        .tools
        .iter()
        .map(|tool| proto::ChatToolDefinition {
            name: tool.name.clone(),
            json_schema_string: tool.json_schema_string.clone(),
            ..Default::default()
        })
        .collect();
    proto::GetChatMessageRequest {
        chat_model_uid: fixture.model.clone(),
        cascade_id: fixture.cascade_id.clone(),
        execution_id: fixture.execution_id.clone(),
        chat_message_prompts: messages,
        tools,
        tool_choice: Some(proto::ChatToolChoice {
            choice: Some(proto::chat_tool_choice::Choice::OptionName(
                "auto".to_owned(),
            )),
        }),
        ..Default::default()
    }
}

fn assert_devin_response(body: &[u8], expected: &ExpectedDevinResponse) {
    let expected_stop_reason = match expected.stop_reason.as_str() {
        "stop" => proto::StopReason::StopPattern,
        value => panic!("unsupported expected Devin stop reason {value}"),
    };
    let mut decoder = ConnectDecoder::with_gzip(ConnectLimits::default());
    let frames = decoder.push(body).expect("Devin Connect response frames");
    decoder.finish().expect("complete Devin Connect response");
    assert!(frames.last().is_some_and(|frame| frame.is_end_stream()));
    let mut text = String::new();
    let mut saw_stop = false;
    let mut saw_usage = false;
    for frame in frames.iter().filter(|frame| !frame.is_end_stream()) {
        let message = proto::GetChatMessageResponse::decode(frame.payload.as_slice())
            .expect("Devin response protobuf");
        text.push_str(&message.delta_text);
        saw_stop |= proto::StopReason::try_from(message.stop_reason)
            .is_ok_and(|reason| reason == expected_stop_reason);
        saw_usage |= message.usage.as_ref().is_some_and(|usage| {
            usage.input_tokens == expected.input_tokens
                && usage.output_tokens == expected.output_tokens
        });
    }
    assert_eq!(text, expected.text);
    assert!(saw_stop, "missing expected Devin stop reason");
    assert!(saw_usage, "missing expected Devin usage");
}

fn scripted_sse_body(chunks: &[ScriptedChunk]) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in chunks {
        let ScriptedChunk::Sse { event, data } = chunk else {
            panic!("current Factory fixture must contain only SSE chunks")
        };
        write_sse_event(&mut body, event.as_deref(), data);
    }
    body
}

fn string_sse_body(events: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    for data in events {
        write_sse_event(&mut body, None, data);
    }
    body
}

fn write_sse_event(output: &mut Vec<u8>, event: Option<&str>, data: &str) {
    if let Some(event) = event {
        output.extend_from_slice(format!("event: {event}\n").as_bytes());
    }
    for line in data.split('\n') {
        output.extend_from_slice(b"data: ");
        output.extend_from_slice(line.as_bytes());
        output.push(b'\n');
    }
    output.push(b'\n');
}

fn parse_sse(body: &[u8]) -> Vec<SseEvent> {
    let mut parser = SseParser::new();
    let mut events = parser.feed(body).expect("runtime Factory SSE");
    events.extend(parser.finish().expect("complete runtime Factory SSE"));
    events
}

fn assert_factory_events(actual: &[SseEvent], expected: &[ScriptedChunk]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        let ScriptedChunk::Sse { event, data } = expected else {
            panic!("expected Factory fixture chunk must be SSE")
        };
        assert_eq!(actual.event.as_deref(), event.as_deref());
        if actual.is_done() || data == "[DONE]" {
            assert_eq!(actual.data, *data);
        } else {
            let actual: Value = serde_json::from_str(&actual.data).expect("actual Factory JSON");
            let expected: Value = serde_json::from_str(data).expect("expected Factory JSON");
            assert_eq!(normalize_json_value(actual), normalize_json_value(expected));
        }
    }
    let event_types = actual
        .iter()
        .filter(|event| !event.is_done())
        .map(|event| {
            serde_json::from_str::<Value>(&event.data).expect("Factory event JSON")["type"]
                .as_str()
                .expect("Factory event type")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    for required in ["response-metadata", "text-delta", "finish"] {
        assert!(event_types.contains(required));
    }
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
            .expect("proxy drains")
            .expect("proxy task joins")
            .expect("proxy succeeds");
    }
}

async fn start_server(config: pooler_config::CompiledConfig) -> RunningServer {
    let server = HttpProxyServer::bind(config).await.expect("proxy binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("proxy listener")
        .address()
        .parse()
        .expect("proxy listener address");
    let runner_server = server.clone();
    let runner = tokio::spawn(async move { runner_server.run().await });
    RunningServer {
        server,
        address,
        runner,
    }
}

async fn spawn_upstream(body: Vec<u8>) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback upstream binds");
    let address = listener.local_addr().expect("loopback upstream address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let request = read_request(&mut stream).await.expect("upstream request");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("upstream response headers");
        stream
            .write_all(&body)
            .await
            .expect("upstream response body");
        request
    });
    (address, task)
}

async fn send_scripted_request(
    address: SocketAddr,
    request: &pooler_testkit::ScriptedRequest,
) -> Vec<u8> {
    let headers = request
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    send_request(address, &request.uri, &headers, &request.body).await
}

async fn send_request(
    address: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connection timeout")
        .expect("proxy connection");
    let mut request = format!("POST {path} HTTP/1.1\r\nHost: compatibility-test\r\n").into_bytes();
    for (name, value) in headers {
        request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    request.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    request.extend_from_slice(body);
    stream.write_all(&request).await.expect("proxy request");
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
        .expect("HTTP response is UTF-8")
        .split_whitespace()
        .nth(1)
        .expect("HTTP response status")
        .parse()
        .expect("numeric HTTP status")
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
        let size_text = std::str::from_utf8(&body[..line_end]).expect("chunk size UTF-8");
        let size = usize::from_str_radix(size_text.split(';').next().expect("chunk size"), 16)
            .expect("hex chunk size");
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        assert!(body.len() >= size + 2, "complete chunk");
        decoded.extend_from_slice(&body[..size]);
        assert_eq!(&body[size..size + 2], b"\r\n");
        body = &body[size + 2..];
    }
    decoded
}

fn assert_request_line(request: &[u8], method: &str, path: &str) {
    let line_end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("request line");
    let line = std::str::from_utf8(&request[..line_end]).expect("request line UTF-8");
    assert_eq!(line, format!("{method} {path} HTTP/1.1"));
}

fn has_header(message: &[u8], name: &str) -> bool {
    header_value(message, name).is_some()
}

fn header_value<'a>(message: &'a [u8], name: &str) -> Option<&'a str> {
    let headers = &message[..http_body_start(message)];
    headers.split(|byte| *byte == b'\n').find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|byte| *byte == b':')?;
        let header_name = &line[..colon];
        if !header_name.eq_ignore_ascii_case(name.as_bytes()) {
            return None;
        }
        std::str::from_utf8(&line[colon + 1..]).ok().map(str::trim)
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

fn header<'a>(request: &'a pooler_testkit::ScriptedRequest, name: &str) -> &'a str {
    request
        .headers
        .iter()
        .find(|(actual, _)| actual.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .expect("fixture header")
}
