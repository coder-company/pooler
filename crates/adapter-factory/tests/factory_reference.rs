use pooler_http::{SseEvent, SseParser};
use pooler_protocol::{encode_chat_request, LossPolicy, OpenAiChatEventDecoder, StreamValidator};
use serde::Deserialize;
use serde_json::{json, Value};

use adapter_factory::{FactoryEventEncoder, FactoryLanguageModelDecoder};

#[derive(Debug, Deserialize)]
struct ReferenceFixture {
    id: String,
    source: String,
    equivalence: String,
    model_header: String,
    intentional_corrections: Vec<String>,
    factory_request: Value,
    expected_openai_request: Value,
    upstream_sse: Vec<String>,
    expected_factory_sse: Vec<String>,
    expected_pooler_factory_sse: Vec<String>,
}

fn load_fixture(source: &str) -> ReferenceFixture {
    serde_json::from_str(source).expect("valid sanitized Factory fixture")
}

fn parse_sse(frames: &[String]) -> Vec<SseEvent> {
    let mut parser = SseParser::new();
    let mut events = Vec::new();
    for frame in frames {
        events.extend(parser.feed(frame.as_bytes()).expect("valid SSE frame"));
    }
    events.extend(parser.finish().expect("complete SSE fixture"));
    events
}

fn source_projection(event: &SseEvent) -> Value {
    if event.is_done() {
        return Value::String("[DONE]".to_owned());
    }
    let mut value: Value = serde_json::from_str(&event.data).expect("JSON SSE data");
    if value["type"] == "response-metadata" {
        value
            .as_object_mut()
            .expect("response metadata object")
            .remove("id");
    }
    if value["type"] == "finish" {
        let usage = value["usage"]
            .as_object_mut()
            .expect("Factory finish usage object");
        usage
            .get_mut("inputTokens")
            .and_then(Value::as_object_mut)
            .expect("input token object")
            .remove("noCache");
        usage
            .get_mut("outputTokens")
            .and_then(Value::as_object_mut)
            .expect("output token object")
            .remove("text");
        usage.remove("totalTokens");
        value["finishReason"]
            .as_object_mut()
            .expect("finish reason object")
            .remove("raw");
    }
    value
}

fn semantic_sse_shape(frames: &[String]) -> Vec<Value> {
    parse_sse(frames)
        .iter()
        .map(|event| {
            if event.is_done() {
                Value::String("[DONE]".to_owned())
            } else {
                serde_json::from_str(&event.data).expect("JSON SSE data")
            }
        })
        .collect()
}

fn normalize_sampling_precision(mut value: Value) -> Value {
    let object = value.as_object_mut().expect("request object");
    for field in ["temperature", "top_p"] {
        if let Some(number) = object.get(field).and_then(Value::as_f64) {
            object.insert(field.to_owned(), serde_json::json!(number as f32));
        }
    }
    value
}

#[test]
fn replays_sanitized_factory_reference_request_and_stream() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/factory/factory-v3-text-reference.json");
    let fixture = load_fixture(MANIFEST_FIXTURE);
    assert_eq!(fixture.id, "factory.v3.text.reference");
    assert_eq!(
        fixture.source,
        "sanitized Factory V3 reference implementation"
    );
    assert_eq!(fixture.equivalence, "json_structural");
    for correction in [
        "factory_response_metadata_preserves_response_id",
        "factory_usage_includes_derived_no_cache_and_text_totals",
        "factory_finish_reason_uses_unified_only",
    ] {
        assert!(fixture
            .intentional_corrections
            .iter()
            .any(|actual| actual == correction));
    }

    let decoded = FactoryLanguageModelDecoder::default()
        .decode_value(&fixture.factory_request, fixture.model_header.clone())
        .expect("Factory request decodes");
    assert!(decoded.report.is_lossless());

    let encoded = encode_chat_request(&decoded.request, LossPolicy::Reject)
        .expect("Factory request encodes as OpenAI Chat");
    assert!(encoded.report.is_lossless());
    let mut openai_request: Value =
        serde_json::from_slice(&encoded.body).expect("encoded OpenAI request JSON");
    openai_request["stream"] = Value::Bool(true);
    openai_request["stream_options"] = json!({"include_usage": true});
    assert_eq!(
        normalize_sampling_precision(openai_request),
        normalize_sampling_precision(fixture.expected_openai_request.clone())
    );

    let upstream_events = parse_sse(&fixture.upstream_sse);
    assert_eq!(upstream_events.len(), 4);
    let mut decoder = OpenAiChatEventDecoder::new();
    let mut semantic_events = Vec::new();
    for event in &upstream_events {
        semantic_events.extend(
            decoder
                .decode_data(event.data.as_bytes())
                .expect("OpenAI stream chunk decodes"),
        );
    }

    let mut validator = StreamValidator::default();
    for event in &semantic_events {
        validator.accept(event).expect("semantic stream is valid");
    }
    assert!(validator.is_terminal());
    assert!(validator.is_drained());

    let factory_encoder = FactoryEventEncoder;
    let mut pooler_frames = Vec::new();
    for event in &semantic_events {
        pooler_frames.push(
            factory_encoder
                .encode_sse(event, LossPolicy::Reject)
                .expect("semantic event encodes as Factory SSE")
                .body,
        );
    }
    pooler_frames.push(b"data: [DONE]\n\n".to_vec());
    let actual_pooler_frames = pooler_frames
        .iter()
        .map(|frame| String::from_utf8(frame.clone()).expect("UTF-8 Factory frame"))
        .collect::<Vec<_>>();
    assert_eq!(
        semantic_sse_shape(&actual_pooler_frames),
        semantic_sse_shape(&fixture.expected_pooler_factory_sse)
    );

    let actual_source_shape: Vec<Value> = parse_sse(&actual_pooler_frames)
        .iter()
        .map(source_projection)
        .collect();
    let expected_source_shape: Vec<Value> = parse_sse(&fixture.expected_factory_sse)
        .iter()
        .map(source_projection)
        .collect();
    assert_eq!(actual_source_shape, expected_source_shape);
}
