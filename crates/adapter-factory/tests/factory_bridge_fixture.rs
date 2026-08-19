use std::collections::BTreeMap;

use adapter_factory::{
    FactoryEventEncoder, FactoryLanguageModelDecoder, FACTORY_LANGUAGE_MODEL_PATH, MODEL_ID_HEADER,
};
use pooler_protocol::{
    FinishReason, LossPolicy, OpenAiChatCodec, OpenAiChatEventDecoder, StreamEventKind,
    StreamValidator,
};
use pooler_testkit::{
    compare_requests, normalize_json_value, Equivalence, Fixture, ScriptedChunk, ScriptedRequest,
    ScriptedResult, ScriptedUpstream,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../fixtures/factory/fx-cliproxy-bridge-v3.json");

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("valid sanitized Factory fixture")
}

fn header<'a>(request: &'a ScriptedRequest, name: &str) -> &'a str {
    request
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .expect("fixture header")
}

fn json_body(request: &ScriptedRequest) -> Value {
    serde_json::from_slice(&request.body).expect("fixture JSON body")
}

fn semantic_stream(fixture: &Fixture) -> Vec<pooler_protocol::StreamEvent> {
    let mut decoder = OpenAiChatEventDecoder::new();
    let mut events = Vec::new();
    let ScriptedResult::Response(response) = &fixture.upstream_script[0] else {
        panic!("fixture must contain one scripted response")
    };
    for chunk in &response.chunks {
        let ScriptedChunk::Sse { data, .. } = chunk else {
            panic!("fixture stream must contain SSE data")
        };
        events.extend(
            decoder
                .decode_data(data.as_bytes())
                .expect("OpenAI stream chunk"),
        );
    }
    events
}

fn compare_event_chunks(expected: &[ScriptedChunk], actual: &[ScriptedChunk]) -> bool {
    expected.len() == actual.len()
        && expected.iter().zip(actual).all(|(expected, actual)| {
            let (
                ScriptedChunk::Sse {
                    event: expected_event,
                    data: expected_data,
                },
                ScriptedChunk::Sse {
                    event: actual_event,
                    data: actual_data,
                },
            ) = (expected, actual)
            else {
                return expected == actual;
            };
            expected_event == actual_event
                && normalize_json_value(
                    serde_json::from_str(expected_data).expect("expected Factory event JSON"),
                ) == normalize_json_value(
                    serde_json::from_str(actual_data).expect("actual Factory event JSON"),
                )
        })
}

#[tokio::test]
async fn replays_local_bridge_request_and_semantic_stream() {
    let fixture = fixture();
    assert_eq!(fixture.metadata.equivalence, Equivalence::EventSemantic);
    assert!(fixture
        .metadata
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("Local reference bridge")));

    let downstream = fixture
        .downstream_request
        .as_ref()
        .expect("Factory request");
    assert_eq!(downstream.uri, FACTORY_LANGUAGE_MODEL_PATH);
    let model = header(downstream, MODEL_ID_HEADER);
    let decoded = FactoryLanguageModelDecoder::default()
        .decode(&downstream.body, model)
        .expect("Factory request decodes");
    assert!(decoded.report.is_lossless());

    let encoded = OpenAiChatCodec::encode_request(&decoded.request, LossPolicy::Reject)
        .expect("semantic request encodes for OpenAI Chat");
    let expected_upstream = fixture
        .expected_upstream_request
        .as_ref()
        .expect("OpenAI bridge request");
    let mut expected_core = json_body(expected_upstream);
    let expected_object = expected_core.as_object_mut().expect("upstream object");
    assert_eq!(expected_object.remove("stream"), Some(Value::Bool(true)));
    assert_eq!(
        expected_object.remove("stream_options"),
        Some(serde_json::json!({"include_usage": true}))
    );
    let encoded_value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
    assert_eq!(
        normalize_json_value(encoded_value.clone()),
        normalize_json_value(expected_core)
    );
    let mut bridge_body = encoded_value;
    let bridge_object = bridge_body.as_object_mut().expect("encoded object");
    bridge_object.insert("stream".to_owned(), Value::Bool(true));
    bridge_object.insert(
        "stream_options".to_owned(),
        serde_json::json!({"include_usage": true}),
    );
    let bridge_request = ScriptedRequest::new("POST", "/v1/chat/completions")
        .with_header("accept", "application/json")
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_vec(&bridge_body).expect("bridge JSON"));
    assert!(compare_requests(
        &bridge_request,
        expected_upstream,
        Equivalence::JsonStructural
    )
    .is_equivalent());

    let upstream = ScriptedUpstream::with_script(fixture.upstream_script.clone());
    let response = upstream
        .execute(bridge_request.clone())
        .await
        .expect("scripted bridge response");
    assert_eq!(response.status, 200);
    assert_eq!(upstream.requests().len(), 1);
    assert!(compare_requests(
        &upstream.requests()[0],
        expected_upstream,
        Equivalence::JsonStructural
    )
    .is_equivalent());
    let events = semantic_stream(&Fixture {
        upstream_script: vec![ScriptedResult::Response(response)],
        ..fixture.clone()
    });
    let mut validator = StreamValidator::default();
    for event in &events {
        validator.accept(event).expect("valid semantic event order");
    }
    assert!(validator.is_terminal());
    assert!(validator.is_drained());
    assert!(events
        .iter()
        .any(|event| { matches!(event.kind, StreamEventKind::ReasoningDelta { .. }) }));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, StreamEventKind::TextDelta { .. })));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, StreamEventKind::ToolCallDelta { .. })));
    assert!(events.iter().any(|event| {
        matches!(
            event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::ToolCall,
                usage: Some(_),
            }
        )
    }));

    let encoded_events: Vec<_> = events
        .iter()
        .map(|event| {
            let encoded = FactoryEventEncoder
                .encode_json(event, LossPolicy::Reject)
                .expect("Factory event encodes");
            ScriptedChunk::sse(String::from_utf8(encoded.body).expect("JSON is UTF-8"))
        })
        .collect();
    assert!(!encoded_events.is_empty());
    assert!(compare_event_chunks(
        &fixture.expected_downstream_chunks,
        &encoded_events
    ));
    assert!(encoded_events.iter().any(|chunk| match chunk {
        ScriptedChunk::Sse { data, .. } => data.contains("reasoning-delta"),
        _ => false,
    }));
    assert!(encoded_events.iter().any(|chunk| match chunk {
        ScriptedChunk::Sse { data, .. } => data.contains("tool-input-delta"),
        _ => false,
    }));
    assert!(encoded_events.iter().any(|chunk| match chunk {
        ScriptedChunk::Sse { data, .. } => data.contains("\"type\":\"finish\""),
        _ => false,
    }));

    let mut extracted = BTreeMap::new();
    extracted.insert("model".to_owned(), model.to_owned());
    assert_eq!(fixture.extracted_fields, extracted);
}
