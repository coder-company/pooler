use adapter_factory::{
    FactoryEventEncoder, FactoryLanguageModelDecoder, GATEWAY_PROTOCOL_VERSION_HEADER,
    MODEL_ID_HEADER, SPECIFICATION_VERSION_HEADER, SPECIFICATION_VERSION_V4,
};
use pooler_http::{SseEvent, SseParser};
use pooler_protocol::{LossPolicy, OpenAiChatCodec, OpenAiChatEventDecoder, StreamValidator};
use pooler_testkit::{normalize_json_value, Equivalence, Fixture, ScriptedChunk, ScriptedResult};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../fixtures/factory/fx-0.0.3-v4-current-client.json");

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("valid current Factory fixture")
}

fn header<'a>(fixture: &'a Fixture, name: &str) -> &'a str {
    fixture
        .downstream_request
        .as_ref()
        .expect("downstream request")
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .expect("fixture header")
}

fn fixture_events(chunks: &[ScriptedChunk]) -> Vec<SseEvent> {
    chunks
        .iter()
        .map(|chunk| match chunk {
            ScriptedChunk::Sse { data, .. } => SseEvent::new(data),
            _ => panic!("fixture stream must contain SSE chunks"),
        })
        .collect()
}

#[test]
fn replays_current_fx_v4_request_and_stream() {
    let fixture = fixture();
    assert_eq!(fixture.metadata.equivalence, Equivalence::EventSemantic);
    assert!(fixture
        .metadata
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("fx/0.0.3")));
    assert_eq!(
        header(&fixture, SPECIFICATION_VERSION_HEADER),
        SPECIFICATION_VERSION_V4
    );
    assert_eq!(header(&fixture, GATEWAY_PROTOCOL_VERSION_HEADER), "0.0.1");
    let model = header(&fixture, MODEL_ID_HEADER);
    assert_eq!(model, "gpt-5.6-sol");

    let downstream = fixture
        .downstream_request
        .as_ref()
        .expect("downstream request");
    let decoded = FactoryLanguageModelDecoder::default()
        .decode(&downstream.body, model)
        .expect("V4 request decodes");
    assert!(decoded
        .report
        .dropped_optional_fields
        .iter()
        .any(|field| field == "tools[1]"));
    assert!(decoded.report.validate(LossPolicy::Reject).is_err());
    decoded
        .report
        .validate(LossPolicy::Degrade)
        .expect("preset degradation is explicit");

    let encoded = OpenAiChatCodec::encode_request(&decoded.request, LossPolicy::Degrade)
        .expect("request encodes for OpenAI Chat");
    let expected_upstream = fixture
        .expected_upstream_request
        .as_ref()
        .expect("expected upstream request");
    let mut actual: Value = serde_json::from_slice(&encoded.body).expect("encoded request JSON");
    let actual_object = actual.as_object_mut().expect("encoded request object");
    actual_object.insert("stream".to_owned(), Value::Bool(true));
    actual_object.insert(
        "stream_options".to_owned(),
        serde_json::json!({"include_usage": true}),
    );
    let expected: Value =
        serde_json::from_slice(&expected_upstream.body).expect("expected request JSON");
    assert_eq!(normalize_json_value(actual), normalize_json_value(expected));

    let ScriptedResult::Response(response) = &fixture.upstream_script[0] else {
        panic!("fixture must contain one upstream response")
    };
    let mut decoder = OpenAiChatEventDecoder::new();
    let mut semantic_events = Vec::new();
    for chunk in &response.chunks {
        let ScriptedChunk::Sse { data, .. } = chunk else {
            panic!("fixture stream must contain SSE chunks")
        };
        semantic_events.extend(
            decoder
                .decode_data(data.as_bytes())
                .expect("OpenAI event decodes"),
        );
    }
    let mut validator = StreamValidator::default();
    for event in &semantic_events {
        validator.accept(event).expect("semantic event order");
    }
    assert!(validator.is_terminal());
    assert!(validator.is_drained());

    let encoder = FactoryEventEncoder;
    let mut actual_chunks = semantic_events
        .iter()
        .map(|event| {
            let encoded = encoder
                .encode_sse(event, LossPolicy::Degrade)
                .expect("Factory V4 event encodes");
            let mut parser = SseParser::new();
            let events = parser.feed(&encoded.body).expect("encoded SSE");
            assert!(parser.finish().expect("complete encoded SSE").is_empty());
            events.into_iter().next().expect("one encoded SSE event")
        })
        .collect::<Vec<_>>();
    actual_chunks.push(SseEvent::new("[DONE]"));

    let expected_chunks = fixture_events(&fixture.expected_downstream_chunks);
    assert_eq!(actual_chunks.len(), expected_chunks.len());
    for (actual, expected) in actual_chunks.iter().zip(expected_chunks) {
        if actual.is_done() || expected.is_done() {
            assert_eq!(actual, &expected);
        } else {
            let actual_json: Value =
                serde_json::from_str(&actual.data).expect("actual Factory event JSON");
            let expected_json: Value =
                serde_json::from_str(&expected.data).expect("expected Factory event JSON");
            assert_eq!(
                normalize_json_value(actual_json),
                normalize_json_value(expected_json)
            );
        }
    }
}
