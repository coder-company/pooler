use adapter_devin::{
    connect::{encode_connect_frame, ConnectDecoder},
    decode_model_response, encode_model_request,
    proto::{GetChatMessageRequest, GetChatMessageResponse, GetCliModelConfigsResponse},
    ConnectLimits, DevinChatEventDecoder, DevinIdentifiers,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pooler_protocol::{FinishReason, StreamEventKind};
use prost::Message;
use serde::Deserialize;

const TYPESCRIPT_RESPONSE: &str =
    include_str!("../../../fixtures/devin/protobuf/typescript-models-response.base64");
const RUST_REQUEST: &str =
    include_str!("../../../fixtures/devin/protobuf/rust-models-request.base64");
const CONNECT_FIXTURE: &str = include_str!("../../../fixtures/devin/connect/chat-stream.json");

#[derive(Debug, Deserialize)]
struct ConnectFixture {
    id: String,
    source: FixtureSource,
    equivalence: String,
    request_frame_base64: String,
    response_frames_base64: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureSource {
    repository: String,
    commit: String,
    paths: Vec<String>,
}

fn connect_fixture() -> ConnectFixture {
    serde_json::from_str(CONNECT_FIXTURE).expect("valid sanitized Devin fixture")
}

fn decode_base64(value: &str) -> Vec<u8> {
    STANDARD.decode(value.trim()).expect("valid base64 fixture")
}

fn decode_fragmented(input: &[u8]) -> Vec<adapter_devin::ConnectFrame> {
    let mut decoder = ConnectDecoder::with_gzip(ConnectLimits::default());
    let mut frames = Vec::new();
    for chunk in input.chunks(1) {
        frames.extend(decoder.push(chunk).expect("fragmented Connect input"));
    }
    decoder.finish().expect("complete Connect input");
    frames
}

#[test]
fn cross_language_model_fixtures_preserve_wire_bytes() {
    let request_bytes = decode_base64(RUST_REQUEST);
    assert_eq!(
        encode_model_request(Some("fixture"), None),
        request_bytes,
        "Rust-generated request fixture must remain byte-identical"
    );

    let response_bytes = decode_base64(TYPESCRIPT_RESPONSE);
    let response = GetCliModelConfigsResponse::decode(response_bytes.as_slice())
        .expect("TypeScript model response protobuf");
    let model = response
        .client_model_configs
        .first()
        .expect("fixture model");
    assert_eq!(model.model_uid, "fixture-model");
    assert_eq!(model.label, "Fixture Thinking");
    assert!(model.supports_images);
    assert_eq!(model.max_tokens, 4_096);
    assert_eq!(response.encode_to_vec(), response_bytes);

    let models = decode_model_response(
        &response_bytes,
        "https://models.example",
        ConnectLimits::default(),
    )
    .expect("adapter model response");
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].id, "fixture-model");
    assert_eq!(models[0].name, "Fixture Thinking");
    assert!(models[0].reasoning);
    assert_eq!(models[0].max_tokens, 4_096);
}

#[test]
fn connect_fixture_covers_fragmentation_gzip_tools_identifiers_and_usage() {
    let fixture = connect_fixture();
    assert_eq!(fixture.id, "fx-widevin-devin.connect.v1");
    assert_eq!(fixture.equivalence, "protobuf_semantic");
    assert_eq!(
        fixture.source.repository,
        "https://github.com/dante-teo/widevin"
    );
    assert_eq!(
        fixture.source.commit,
        "6c48392052caaecca820ec41df9d87ed818dfc21"
    );
    assert!(fixture
        .source
        .paths
        .iter()
        .any(|path| path == "rust/src/proto.rs"));

    let request_wire = decode_base64(&fixture.request_frame_base64);
    let request_frames = decode_fragmented(&request_wire);
    assert_eq!(request_frames.len(), 1);
    assert_eq!(
        request_frames[0].flags(),
        1,
        "request uses gzip compression"
    );
    let request = GetChatMessageRequest::decode(request_frames[0].payload.as_slice())
        .expect("fixture Devin request protobuf");
    assert_eq!(request.chat_model_uid, "fixture-model");
    assert_eq!(request.cascade_id, "cascade-1");
    assert_eq!(request.execution_id, "execution-1");
    assert_eq!(request.tools[0].name, "search");
    assert_eq!(request.chat_message_prompts[1].tool_calls[0].id, "call-1");
    assert_eq!(request.chat_message_prompts[2].tool_call_id, "call-1");
    assert_eq!(
        encode_connect_frame(&request.encode_to_vec(), true, false).expect("re-encode request"),
        request_wire,
        "protobuf and Connect request bytes must round-trip"
    );

    let response_wire = fixture
        .response_frames_base64
        .iter()
        .flat_map(|value| decode_base64(value))
        .collect::<Vec<_>>();
    let frames = decode_fragmented(&response_wire);
    assert_eq!(frames.len(), fixture.response_frames_base64.len());
    assert!(frames[..5].iter().all(|frame| frame.flags() == 1));
    assert!(frames
        .last()
        .is_some_and(|frame| frame.flags() == 2 && frame.is_end_stream()));

    let mut decoder = DevinChatEventDecoder::new(
        Some("fixture-model".into()),
        DevinIdentifiers {
            cascade_id: Some("cascade-1".into()),
            execution_id: Some("execution-1".into()),
        },
    );
    let mut events = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        if !frame.is_end_stream() {
            let message = GetChatMessageResponse::decode(frame.payload.as_slice())
                .expect("fixture Devin response protobuf");
            assert_eq!(
                encode_connect_frame(&message.encode_to_vec(), true, false)
                    .expect("re-encode response"),
                decode_base64(&fixture.response_frames_base64[index]),
                "protobuf and Connect response bytes must round-trip"
            );
        }
        events.extend(decoder.decode_frame(frame).expect("decode semantic frame"));
    }
    events.extend(decoder.finish().expect("finish semantic stream"));

    assert!(events.iter().any(|event| {
        matches!(
            event.kind,
            StreamEventKind::ResponseStart {
                response_id: Some(ref id),
                ..
            } if id == "execution-1"
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event.kind,
            StreamEventKind::ReasoningDelta { ref text } if text == "think"
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(event.kind, StreamEventKind::TextDelta { ref text } if text == "hello")
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event.kind,
            StreamEventKind::ToolCallStart { ref id, ref name }
                if id == "call-1" && name == "search"
        )
    }));
    let tool_arguments = events
        .iter()
        .filter_map(|event| match &event.kind {
            StreamEventKind::ToolCallDelta { id, arguments } if id == "call-1" => {
                Some(arguments.as_str())
            }
            _ => None,
        })
        .collect::<String>();
    assert_eq!(tool_arguments, r#"{"q":"x"}"#);
    assert!(events.iter().any(|event| {
        matches!(event.kind, StreamEventKind::ToolCallEnd { ref id } if id == "call-1")
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event.kind,
            StreamEventKind::Usage { ref usage }
                if usage.input_tokens == 2
                    && usage.output_tokens == 3
                    && usage.cached_input_tokens == Some(4)
                    && usage.details.get("cache_write_tokens") == Some(&5)
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::ToolCall,
                usage: Some(ref usage),
            } if usage.input_tokens == 2 && usage.output_tokens == 3
        )
    }));
}
