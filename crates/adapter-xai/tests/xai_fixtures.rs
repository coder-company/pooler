use adapter_xai::{
    XaiRealtimeEventDecoder, XaiRealtimeEventKind, XaiRealtimeRequestCodec, XaiRestAdapter,
};
use pooler_protocol::{FinishReason, LossPolicy, StreamEventKind, StreamValidator};
use serde_json::Value;

const CHAT_REQUEST: &[u8] = include_bytes!("../../../fixtures/xai/chat-completions-request.json");
const WEBSOCKET_REQUEST: &[u8] =
    include_bytes!("../../../fixtures/xai/responses-websocket-request.json");
const TEXT_EVENTS: &str = include_str!("../../../fixtures/xai/responses-websocket-text.jsonl");
const TOOL_EVENTS: &str = include_str!("../../../fixtures/xai/responses-websocket-tool.jsonl");
const ERROR_EVENT: &[u8] = include_bytes!("../../../fixtures/xai/responses-websocket-error.json");

#[test]
fn chat_fixture_retains_xai_provider_fields() {
    let decoded = XaiRestAdapter::default()
        .decode_chat_request(CHAT_REQUEST, LossPolicy::Reject)
        .expect("documented xAI Chat fixture");
    assert_eq!(decoded.request.model, "grok-4.6");
    assert_eq!(decoded.request.messages().count(), 2);
    let body: Value = serde_json::from_slice(&decoded.body).expect("prepared JSON");
    assert_eq!(body["search_parameters"]["mode"], "auto");
    assert_eq!(body["service_tier"], "priority");
    assert_eq!(body["reasoning_effort"], "medium");
    assert!(decoded.report.is_lossless());
}

#[test]
fn websocket_request_fixture_becomes_response_create() {
    let encoded = XaiRealtimeRequestCodec::default()
        .encode_response_create(WEBSOCKET_REQUEST, LossPolicy::Reject)
        .expect("documented xAI response.create fixture");
    let body: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
    assert_eq!(body["type"], "response.create");
    assert_eq!(body["store"], false);
    assert_eq!(
        encoded.previous_response_id.as_deref(),
        Some("resp_fixture_previous")
    );
    assert!(body.get("stream").is_none());
    assert!(body.get("background").is_none());
}

#[test]
fn websocket_text_fixture_produces_valid_semantic_stream() {
    let mut decoder = XaiRealtimeEventDecoder::default();
    let mut validator = StreamValidator::default();
    let mut text = String::new();
    let mut terminal_usage = None;
    for line in nonempty_lines(TEXT_EVENTS) {
        let decoded = decoder
            .decode_message(line.as_bytes())
            .expect("documented xAI text event");
        for event in decoded.semantic_events {
            validator.accept(&event).expect("valid semantic lifecycle");
            match event.kind {
                StreamEventKind::TextDelta { text: delta } => text.push_str(&delta),
                StreamEventKind::Completion { usage, .. } => terminal_usage = usage,
                _ => {}
            }
        }
    }
    decoder.finish().expect("terminal fixture");
    assert_eq!(text, "Hello from Grok.");
    let usage = terminal_usage.expect("terminal usage");
    assert_eq!(usage.input_tokens, 11);
    assert_eq!(usage.cached_input_tokens, Some(4));
    assert_eq!(usage.reasoning_tokens, Some(2));
    assert_eq!(usage.details.get("cost_in_usd_ticks"), Some(&42));
    assert_eq!(usage.details.get("num_sources_used"), Some(&1));
}

#[test]
fn websocket_tool_fixture_preserves_argument_fragments_and_tool_finish() {
    let mut decoder = XaiRealtimeEventDecoder::default();
    let mut validator = StreamValidator::default();
    let mut arguments = String::new();
    let mut finish_reason = None;
    for line in nonempty_lines(TOOL_EVENTS) {
        let decoded = decoder
            .decode_message(line.as_bytes())
            .expect("documented xAI tool event");
        for event in decoded.semantic_events {
            validator.accept(&event).expect("valid semantic lifecycle");
            match event.kind {
                StreamEventKind::ToolCallDelta {
                    arguments: delta, ..
                } => arguments.push_str(&delta),
                StreamEventKind::Completion {
                    finish_reason: reason,
                    ..
                } => finish_reason = Some(reason),
                _ => {}
            }
        }
    }
    decoder.finish().expect("terminal fixture");
    assert_eq!(arguments, r#"{"city":"Paris"}"#);
    assert_eq!(finish_reason, Some(FinishReason::ToolCall));
}

#[test]
fn websocket_error_fixture_is_terminal_and_not_retryable() {
    let mut decoder = XaiRealtimeEventDecoder::default();
    let decoded = decoder
        .decode_message(ERROR_EVENT)
        .expect("documented xAI error event");
    assert_eq!(decoded.kind, XaiRealtimeEventKind::Error);
    assert!(matches!(
        &decoded.semantic_events[0].kind,
        StreamEventKind::Failure { error }
            if error.code == "previous_response_not_found" && !error.retryable
    ));
    decoder.finish().expect("terminal error");
}

fn nonempty_lines(input: &str) -> impl Iterator<Item = &str> {
    input.lines().filter(|line| !line.trim().is_empty())
}
