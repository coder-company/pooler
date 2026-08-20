use adapter_anthropic::{
    AnthropicEventDecoder, AnthropicEventEncoder, AnthropicMessageCodec, AnthropicMessagesCodec,
};
use pooler_http::{SseEvent, SseParser};
use pooler_protocol::{ContentPart, FinishReason, InputItem, LossPolicy, StreamEventKind};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/droid-0.149.0-anthropic.json"))
        .expect("fixture JSON")
}

fn sse_event(value: &Value) -> SseEvent {
    SseEvent::new(serde_json::to_string(&value["data"]).expect("event data"))
        .with_event(value["event"].as_str().expect("event name"))
}

#[test]
fn sanitized_droid_request_preserves_native_anthropic_semantics() {
    let fixture = fixture();
    let request = serde_json::to_vec(&fixture["request"]).expect("request JSON");
    let decoded =
        AnthropicMessagesCodec::decode_request_with_report(&request).expect("decode request");
    assert!(decoded.report.is_lossless());
    assert!(matches!(
        &decoded.request.input[1],
        InputItem::Message(message)
            if matches!(&message.content[0], ContentPart::Reasoning(reasoning)
                if reasoning.signature.as_deref() == Some(b"synthetic-signature"))
            && matches!(&message.content[1], ContentPart::ToolCall(call)
                if call.id == "toolu_fixture")
    ));
    assert!(matches!(
        &decoded.request.input[2],
        InputItem::Message(message)
            if matches!(&message.content[0], ContentPart::ToolResult(result)
                if result.tool_call_id == "toolu_fixture")
    ));
    let encoded = AnthropicMessagesCodec::encode_request(&decoded.request, LossPolicy::Reject)
        .expect("lossless encode");
    let encoded: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
    assert_eq!(encoded["thinking"], fixture["request"]["thinking"]);
    assert_eq!(encoded["tool_choice"], fixture["request"]["tool_choice"]);
    assert_eq!(
        encoded["messages"][1]["content"][0]["tool_use_id"],
        "toolu_fixture"
    );
}

#[test]
fn sanitized_droid_sse_preserves_thinking_tool_usage_and_error() {
    let fixture = fixture();
    let mut decoder = AnthropicEventDecoder::new();
    let semantic = fixture["sse"]
        .as_array()
        .expect("SSE fixture")
        .iter()
        .flat_map(|event| {
            decoder
                .decode_sse_event(&sse_event(event))
                .expect("decode SSE")
        })
        .collect::<Vec<_>>();
    assert!(decoder.is_finished());
    assert!(semantic.iter().any(|event| matches!(
        &event.kind,
        StreamEventKind::ReasoningEnd { reasoning: Some(reasoning) }
            if reasoning.signature.as_deref() == Some(b"synthetic-signature")
    )));
    assert!(semantic.iter().any(|event| matches!(
        &event.kind,
        StreamEventKind::Completion {
            finish_reason: FinishReason::ToolCall,
            usage: Some(usage),
        } if usage.input_tokens == 21
            && usage.output_tokens == 12
            && usage.cached_input_tokens == Some(5)
    )));

    let mut encoder = AnthropicEventEncoder::new();
    let body = semantic
        .iter()
        .flat_map(|event| {
            encoder
                .encode_event(event, LossPolicy::Reject)
                .expect("encode SSE")
                .body
        })
        .collect::<Vec<_>>();
    let mut parser = SseParser::new();
    let encoded = parser.feed(&body).expect("parse encoded SSE");
    parser.finish().expect("complete encoded SSE");
    assert!(encoded.iter().any(|event| {
        event.event.as_deref() == Some("content_block_delta")
            && event.data.contains("signature_delta")
    }));
    assert_eq!(
        encoded.last().and_then(|event| event.event.as_deref()),
        Some("message_stop")
    );

    let mut error_decoder = AnthropicEventDecoder::new();
    let error = error_decoder
        .decode_sse_event(&sse_event(&fixture["error_sse"]))
        .expect("decode error");
    assert!(matches!(
        &error[0].kind,
        StreamEventKind::Failure { error }
            if error.code == "overloaded_error" && error.retryable
    ));
}

#[test]
fn sanitized_droid_unary_cache_warmup_round_trips_without_loss() {
    let fixture = fixture();
    let request = serde_json::to_vec(&fixture["cache_warmup_request"]).expect("request JSON");
    let decoded =
        AnthropicMessagesCodec::decode_request_with_report(&request).expect("decode warmup");
    assert!(decoded.report.is_lossless());
    assert_eq!(decoded.request.sampling.max_output_tokens, Some(0));
    let encoded = AnthropicMessagesCodec::encode_request(&decoded.request, LossPolicy::Reject)
        .expect("encode warmup");
    let encoded: Value = serde_json::from_slice(&encoded.body).expect("encoded request JSON");
    assert_eq!(encoded["max_tokens"], 0);
    assert_eq!(encoded["stream"], false);

    let response = serde_json::to_vec(&fixture["unary_response"]).expect("response JSON");
    let decoded = AnthropicMessageCodec::decode_response(&response).expect("decode unary");
    assert!(decoded.report.is_lossless());
    let encoded = AnthropicMessageCodec::encode_response(&decoded.events, LossPolicy::Reject)
        .expect("encode unary");
    let encoded: Value = serde_json::from_slice(&encoded.body).expect("encoded response JSON");
    assert_eq!(encoded["content"], serde_json::json!([]));
    assert_eq!(encoded["stop_reason"], "max_tokens");
    assert_eq!(encoded["usage"]["cache_creation_input_tokens"], 20);
    assert_eq!(encoded["service_tier"], "standard");
}
