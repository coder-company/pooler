use adapter_gemini::{
    parse_gemini_path, GeminiEventDecoder, GeminiEventEncoder, GeminiGenerateContentCodec,
    GeminiMethod,
};
use pooler_protocol::{
    ContentPart, FinishReason, LossPolicy, ReasoningEffort, Role, StreamEventKind, StreamValidator,
    ToolChoice,
};
use serde_json::Value;

const REQUEST: &[u8] = include_bytes!("fixtures/request-tools-thinking.json");
const STREAM_ONE: &[u8] = include_bytes!("fixtures/stream-thought-tool-1.json");
const STREAM_TWO: &[u8] = include_bytes!("fixtures/stream-thought-tool-2.json");
const STREAM_TOOL_PARTIAL_ONE: &[u8] = include_bytes!("fixtures/stream-tool-partial-1.json");
const STREAM_TOOL_PARTIAL_TWO: &[u8] = include_bytes!("fixtures/stream-tool-partial-2.json");
const UNARY: &[u8] = include_bytes!("fixtures/unary-text.json");
const UNARY_CANDIDATE_METADATA: &[u8] = include_bytes!("fixtures/unary-candidate-metadata.json");
const ERROR: &[u8] = include_bytes!("fixtures/error-resource-exhausted.json");
const LOSS_POLICIES: [LossPolicy; 3] = [
    LossPolicy::Reject,
    LossPolicy::Preserve,
    LossPolicy::Degrade,
];

#[test]
fn path_matcher_distinguishes_unary_and_streaming_methods() {
    let unary =
        parse_gemini_path("/v1beta/models/gemini-2.5-flash:generateContent").expect("unary path");
    assert_eq!(unary.model, "gemini-2.5-flash");
    assert_eq!(unary.method, GeminiMethod::GenerateContent);
    assert!(!unary.method.is_streaming());

    let stream = parse_gemini_path("/v1/models/gemini-3.1-pro:streamGenerateContent?alt=sse")
        .expect("stream path");
    assert_eq!(stream.model, "gemini-3.1-pro");
    assert_eq!(stream.method, GeminiMethod::StreamGenerateContent);
    assert!(stream.method.is_streaming());
    assert!(parse_gemini_path("/v1/models/x:countTokens").is_none());
    assert!(parse_gemini_path("/custom/models/x:generateContent").is_none());
    assert!(parse_gemini_path("/v1/models/team/x:generateContent").is_none());
}

#[test]
fn request_round_trip_keeps_tools_signatures_thinking_and_provider_fields() {
    let decoded = GeminiGenerateContentCodec::decode_request_with_report(REQUEST, "gemini-3.1-pro")
        .expect("decode request");
    assert_eq!(
        decoded.request.messages().next().expect("system").role,
        Role::System
    );
    assert_eq!(decoded.request.tools.len(), 1);
    assert_eq!(decoded.request.tools[0].name, "weather");
    assert_eq!(
        decoded.request.tool_choice,
        Some(ToolChoice::Tool {
            name: "weather".to_owned()
        })
    );
    let reasoning = decoded.request.reasoning.as_ref().expect("reasoning");
    assert_eq!(reasoning.effort, Some(ReasoningEffort::High));
    assert!(reasoning.include_summary);
    assert_eq!(
        decoded
            .request
            .cache
            .as_ref()
            .and_then(|cache| cache.key.as_deref()),
        Some("cachedContents/example")
    );
    let assistant = decoded
        .request
        .messages()
        .find(|message| message.role == Role::Assistant)
        .expect("assistant");
    let call = assistant
        .content
        .iter()
        .find_map(|part| match part {
            ContentPart::ToolCall(call) => Some(call),
            _ => None,
        })
        .expect("tool call");
    assert_eq!(call.id, "call-weather");
    assert!(!call.extensions.is_empty());

    for policy in LOSS_POLICIES {
        decoded
            .report
            .validate(policy)
            .expect("decoded request is lossless");
        let encoded = GeminiGenerateContentCodec::encode_request(&decoded.request, policy)
            .expect("encode request losslessly");
        assert_eq!(encoded.model, "gemini-3.1-pro");
        assert!(encoded.report.is_lossless());
        let value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
        assert!(value["systemInstruction"].get("role").is_none());
        assert_eq!(
            value["systemInstruction"]["parts"][0]["text"],
            "Be concise."
        );
        assert_eq!(
            value["contents"][1]["parts"][0]["thoughtSignature"],
            "c2lnLUE="
        );
        assert_eq!(
            value["contents"][2]["parts"][0]["functionResponse"]["name"],
            "weather"
        );
        assert_eq!(
            value["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            2048
        );
        assert_eq!(value["generationConfig"]["topK"], 20);
        assert!(value["safetySettings"].is_array());
        assert_eq!(value["tools"].as_array().expect("tools").len(), 2);
    }
}

#[test]
fn stream_decoder_emits_valid_thought_tool_usage_and_completion_lifecycles() {
    let mut decoder = GeminiEventDecoder::new();
    let mut events = decoder.decode_chunk(STREAM_ONE).expect("first chunk");
    events.extend(decoder.decode_chunk(STREAM_TWO).expect("final chunk"));
    assert!(decoder.finish().expect("finished").is_empty());

    let mut validator = StreamValidator::default();
    for event in &events {
        validator.accept(event).expect("valid semantic event");
    }
    assert!(validator.is_terminal());
    assert!(validator.is_drained());
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, StreamEventKind::ReasoningDelta { .. })));
    let tool_start = events
        .iter()
        .find(|event| matches!(event.kind, StreamEventKind::ToolCallStart { .. }))
        .expect("tool start");
    assert!(!tool_start.extensions.is_empty());
    let completion = events.last().expect("completion");
    match &completion.kind {
        StreamEventKind::Completion {
            finish_reason,
            usage: Some(usage),
        } => {
            assert_eq!(*finish_reason, FinishReason::ToolCall);
            assert_eq!(usage.input_tokens, 12);
            assert_eq!(usage.output_tokens, 4);
            assert_eq!(usage.reasoning_tokens, Some(6));
            assert_eq!(usage.cached_input_tokens, Some(2));
            assert_eq!(usage.details["tool_use_prompt_tokens"], 3);
            assert_eq!(usage.total_tokens, Some(22));
        }
        other => panic!("unexpected terminal event: {other:?}"),
    }
}

#[test]
fn stream_encoder_recreates_thought_signature_tool_call_and_final_usage() {
    let mut decoder = GeminiEventDecoder::new();
    let mut events = decoder.decode_chunk(STREAM_ONE).expect("first chunk");
    events.extend(decoder.decode_chunk(STREAM_TWO).expect("final chunk"));

    for policy in LOSS_POLICIES {
        let mut encoder = GeminiEventEncoder::new();
        let chunks = events
            .iter()
            .filter_map(|event| encoder.encode_event(event, policy).expect("encode event"))
            .map(|chunk| serde_json::from_slice::<Value>(&chunk.body).expect("chunk JSON"))
            .collect::<Vec<_>>();
        assert!(chunks.iter().any(|chunk| {
            chunk["candidates"][0]["content"]["parts"][0]["functionCall"]["name"] == "weather"
                && chunk["candidates"][0]["content"]["parts"][0]["thoughtSignature"]
                    == "c2lnLXN0cmVhbQ=="
        }));
        assert!(chunks.iter().any(|chunk| {
            chunk["candidates"][0]["groundingMetadata"]["webSearchQueries"][0] == "Paris weather"
                && chunk["candidates"][0]["safetyRatings"].is_array()
        }));
        assert!(chunks.iter().any(|chunk| {
            chunk["candidates"][0]["content"]["parts"][0]["executableCode"]["language"] == "PYTHON"
        }));
        assert!(chunks
            .iter()
            .all(|chunk| chunk.get("executableCode").is_none()));
        let final_chunk = chunks.last().expect("final chunk");
        assert_eq!(final_chunk["candidates"][0]["finishReason"], "STOP");
        assert_eq!(final_chunk["usageMetadata"]["thoughtsTokenCount"], 6);
    }
}

#[test]
fn repeated_stream_tool_fragments_form_one_merged_call() {
    let mut decoder = GeminiEventDecoder::new();
    let mut events = decoder
        .decode_chunk(STREAM_TOOL_PARTIAL_ONE)
        .expect("first partial tool chunk");
    assert!(!events
        .iter()
        .any(|event| matches!(event.kind, StreamEventKind::ToolCallStart { .. })));
    events.extend(
        decoder
            .decode_chunk(STREAM_TOOL_PARTIAL_TWO)
            .expect("terminal partial tool chunk"),
    );
    assert!(decoder.finish().expect("finished").is_empty());

    let starts = events
        .iter()
        .filter(|event| matches!(event.kind, StreamEventKind::ToolCallStart { .. }))
        .count();
    let ends = events
        .iter()
        .filter(|event| matches!(event.kind, StreamEventKind::ToolCallEnd { .. }))
        .count();
    assert_eq!(starts, 1);
    assert_eq!(ends, 1);
    let arguments = events
        .iter()
        .find_map(|event| match &event.kind {
            StreamEventKind::ToolCallDelta { arguments, .. } => Some(arguments),
            _ => None,
        })
        .expect("merged arguments");
    let arguments: Value = serde_json::from_str(arguments).expect("arguments JSON");
    assert_eq!(arguments["city"], "Paris");
    assert_eq!(arguments["units"], "metric");

    let mut validator = StreamValidator::default();
    for event in &events {
        validator.accept(event).expect("valid merged lifecycle");
    }
    assert!(validator.is_terminal());
    assert!(validator.is_drained());
}

#[test]
fn unary_response_round_trip_combines_text_parts_and_usage() {
    let events = GeminiGenerateContentCodec::decode_response(UNARY).expect("decode unary");
    let encoded = GeminiGenerateContentCodec::encode_response(&events, LossPolicy::Preserve)
        .expect("encode unary");
    let value: Value = serde_json::from_slice(&encoded.body).expect("response JSON");
    let parts = value["candidates"][0]["content"]["parts"]
        .as_array()
        .expect("parts");
    assert_eq!(parts[0]["text"], "hello ");
    assert_eq!(parts[1]["text"], "world");
    assert_eq!(value["candidates"][0]["finishReason"], "STOP");
    assert_eq!(value["usageMetadata"]["totalTokenCount"], 5);
}

#[test]
fn candidate_metadata_round_trips_under_every_loss_policy() {
    let input: Value =
        serde_json::from_slice(UNARY_CANDIDATE_METADATA).expect("candidate metadata fixture");
    let events = GeminiGenerateContentCodec::decode_response(UNARY_CANDIDATE_METADATA)
        .expect("decode candidate metadata");
    let completion = events.last().expect("completion");
    assert!(!completion.extensions.is_empty());

    for policy in LOSS_POLICIES {
        let encoded = GeminiGenerateContentCodec::encode_response(&events, policy)
            .expect("candidate metadata is preserved without loss");
        assert!(encoded.report.is_lossless());
        let output: Value = serde_json::from_slice(&encoded.body).expect("encoded response");
        let expected = &input["candidates"][0];
        let actual = &output["candidates"][0];
        for field in [
            "finishMessage",
            "tokenCount",
            "safetyRatings",
            "citationMetadata",
            "groundingMetadata",
            "groundingAttributions",
            "avgLogprobs",
            "logprobsResult",
            "urlContextMetadata",
        ] {
            assert_eq!(actual[field], expected[field], "candidate field {field}");
        }
    }
}

#[test]
fn provider_error_becomes_retryable_terminal_failure_with_details() {
    let mut decoder = GeminiEventDecoder::new();
    let events = decoder.decode_chunk(ERROR).expect("decode error");
    assert!(decoder.finish().expect("terminal").is_empty());
    assert_eq!(events.len(), 1);
    match &events[0].kind {
        StreamEventKind::Failure { error } => {
            assert_eq!(error.code, "RESOURCE_EXHAUSTED");
            assert!(error.retryable);
            assert!(error.details.is_some());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn multiple_candidates_are_rejected_instead_of_silently_dropping_one() {
    let input = br#"{
      "candidates":[
        {"index":0,"content":{"parts":[{"text":"one"}]}},
        {"index":1,"content":{"parts":[{"text":"two"}]}}
      ]
    }"#;
    let mut decoder = GeminiEventDecoder::new();
    let error = decoder
        .decode_chunk(input)
        .expect_err("multiple candidates");
    assert!(error.to_string().contains("one Gemini candidate"));
}

#[test]
fn multi_name_function_calling_config_round_trips_exactly() {
    let input = br#"{
      "contents":[{"role":"user","parts":[{"text":"Find it"}]}],
      "tools":[{"functionDeclarations":[
        {"name":"read","parametersJsonSchema":{"type":"object"}},
        {"name":"search","parametersJsonSchema":{"type":"object"}}
      ]}],
      "toolConfig":{"functionCallingConfig":{
        "mode":"ANY",
        "allowedFunctionNames":["read","search"]
      }}
    }"#;

    let decoded = GeminiGenerateContentCodec::decode_request_with_report(input, "gemini-test")
        .expect("decode request");
    decoded
        .report
        .validate(LossPolicy::Reject)
        .expect("lossless decode");
    let encoded = GeminiGenerateContentCodec::encode_request(&decoded.request, LossPolicy::Reject)
        .expect("lossless encode");
    let value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");

    assert_eq!(
        value["toolConfig"]["functionCallingConfig"],
        serde_json::json!({
            "mode":"ANY",
            "allowedFunctionNames":["read","search"]
        })
    );
}

#[test]
fn idless_function_history_does_not_gain_mismatched_wire_ids() {
    let input = br#"{
      "contents":[
        {"role":"model","parts":[{"functionCall":{
          "name":"lookup","args":{"query":"pooler"}
        }}]},
        {"role":"user","parts":[{"functionResponse":{
          "name":"lookup","response":{"result":"found"}
        }}]}
      ]
    }"#;

    let decoded = GeminiGenerateContentCodec::decode_request_with_report(input, "gemini-test")
        .expect("decode ID-less history");
    let encoded = GeminiGenerateContentCodec::encode_request(&decoded.request, LossPolicy::Reject)
        .expect("encode ID-less history");
    let value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");

    assert!(value["contents"][0]["parts"][0]["functionCall"]
        .get("id")
        .is_none());
    assert!(value["contents"][1]["parts"][0]["functionResponse"]
        .get("id")
        .is_none());
    assert_eq!(
        value["contents"][0]["parts"][0]["functionCall"]["name"],
        "lookup"
    );
    assert_eq!(
        value["contents"][1]["parts"][0]["functionResponse"]["response"]["result"],
        "found"
    );
}
