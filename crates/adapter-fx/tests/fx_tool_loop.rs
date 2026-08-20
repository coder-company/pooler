use std::convert::Infallible;

use adapter_factory::{
    GATEWAY_PROTOCOL_VERSION_HEADER, MODEL_ID_HEADER, SPECIFICATION_VERSION_HEADER,
    STREAMING_HEADER,
};
use adapter_fx::FxSemanticAdapter;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::{BodyExt, Full};
use pooler_config::compile_yaml;
use pooler_http::{SemanticAdapter, SseParser};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn replays_streaming_tool_call_and_follow_up() {
    const MANIFEST_FIXTURE: &str =
        include_str!("../../../fixtures/fx/fx-0.0.3-cliproxy-tool-loop.json");
    let fixture: Value = serde_json::from_str(MANIFEST_FIXTURE).expect("fx fixture JSON");
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["client"]["name"], "Vercel Labs fx");
    assert_eq!(fixture["client"]["version"], "0.0.3");
    assert_eq!(fixture["equivalence"], "event_semantic");

    let config = test_config();
    let route = config.route("fx-chat").expect("fx chat route");
    let headers = fixture_headers(&fixture);
    let adapter = FxSemanticAdapter;

    let initial = adapter
        .encode_request(
            route,
            &headers,
            &serde_json::to_vec(&fixture["initial_request"]).expect("initial JSON"),
        )
        .expect("initial request converts");
    assert_eq!(
        serde_json::from_slice::<Value>(&initial.body).expect("initial OpenAI JSON"),
        fixture["expected_initial_openai_request"]
    );

    let upstream = fixture["upstream_sse"]
        .as_array()
        .expect("upstream SSE array")
        .iter()
        .map(|event| format!("data: {}\n\n", event.as_str().expect("SSE data string")))
        .collect::<String>();
    let body = Full::new(Bytes::from(upstream))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let response = adapter
        .decode_response_with_request_headers(route, body, &headers, CancellationToken::new())
        .expect("fx response adapter");
    let response_bytes = response
        .body
        .collect()
        .await
        .expect("fx response stream")
        .to_bytes();
    let actual_events = parse_fx_events(&response_bytes);
    assert!(actual_events.iter().any(|event| {
        event["type"] == "reasoning-delta" && event["delta"] == "Checking the tool contract."
    }));
    assert_eq!(
        actual_events,
        fixture["expected_fx_events"]
            .as_array()
            .expect("expected fx events")
            .clone()
    );

    let follow_up = adapter
        .encode_request(
            route,
            &headers,
            &serde_json::to_vec(&fixture["follow_up_request"]).expect("follow-up JSON"),
        )
        .expect("tool result follow-up converts");
    let follow_up: Value = serde_json::from_slice(&follow_up.body).expect("follow-up OpenAI JSON");
    assert_eq!(follow_up, fixture["expected_follow_up_openai_request"]);
    assert_eq!(follow_up["messages"][3]["role"], "tool");
    assert_eq!(follow_up["messages"][3]["tool_call_id"], "call-1");
    assert_eq!(follow_up["messages"][3]["content"], "Pooler documentation");
}

#[tokio::test]
async fn preserves_upstream_model_metadata_without_inventing_capabilities() {
    const MODEL_FIXTURE: &str =
        include_str!("../../../fixtures/fx/fx-0.0.3-cliproxy-tool-loop.json");
    let fixture: Value = serde_json::from_str(MODEL_FIXTURE).expect("fx fixture JSON");
    let config = test_config();
    let route = config.route("fx-models").expect("fx models route");
    let adapter = FxSemanticAdapter;
    let encoded = adapter
        .encode_request(route, &HeaderMap::new(), b"")
        .expect("empty models request");
    assert!(encoded.body.is_empty());

    let body = Full::new(Bytes::from(
        serde_json::to_vec(&fixture["models_upstream"]).expect("models JSON"),
    ))
    .map_err(|never: Infallible| match never {})
    .boxed();
    let response = adapter
        .decode_response(route, body, CancellationToken::new())
        .expect("fx models response adapter");
    let body = response
        .body
        .collect()
        .await
        .expect("fx models response")
        .to_bytes();
    let models: Value = serde_json::from_slice(&body).expect("fx models JSON");
    let model = &models["data"][0];
    assert_eq!(model["id"], "gpt-test");
    assert_eq!(model["type"], "language");
    assert!(model.get("tags").is_none());
    assert!(model.get("reasoning_options").is_none());

    let declared = &models["data"][1];
    assert_eq!(declared["id"], "provider-declared");
    assert_eq!(declared["type"], "language");
    assert_eq!(declared["tags"], serde_json::json!(["provider-declared"]));
    assert_eq!(
        declared["reasoning_options"],
        serde_json::json!([{"type": "effort", "values": ["low"]}])
    );
    assert_eq!(declared["provider_metadata"]["trusted"], true);
}

#[tokio::test]
async fn body_model_hint_populates_metadata_without_upstream_echo() {
    let config = test_config();
    let route = config.route("fx-chat").expect("fx chat route");
    let adapter = FxSemanticAdapter;
    let request = serde_json::json!({
        "model": "body-model",
        "prompt": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello"}]
        }]
    });
    let encoded = adapter
        .encode_request(
            route,
            &HeaderMap::new(),
            &serde_json::to_vec(&request).expect("body-model request"),
        )
        .expect("body-model request converts");
    assert_eq!(
        encoded.response_hint.requested_model.as_deref(),
        Some("body-model")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded.body).expect("OpenAI request")["model"],
        "body-model"
    );

    let upstream = concat!(
        "data: {\"id\":\"chat-body-model\",\"choices\":[{\"index\":0,",
        "\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},",
        "\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,",
        "\"completion_tokens\":1,\"total_tokens\":2}}\n\n",
        "data: [DONE]\n\n"
    );
    let body = Full::new(Bytes::from_static(upstream.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let response = adapter
        .decode_response_with_hint(
            route,
            body,
            &HeaderMap::new(),
            &encoded.response_hint,
            CancellationToken::new(),
        )
        .expect("body-model response adapter");
    let bytes = response
        .body
        .collect()
        .await
        .expect("body-model response")
        .to_bytes();
    let events = parse_fx_events(&bytes);
    assert_eq!(events[0]["type"], "response-metadata");
    assert_eq!(events[0]["modelId"], "body-model");
}

#[test]
fn rejects_invalid_v4_header_contract_before_upstream() {
    let config = test_config();
    let route = config.route("fx-chat").expect("fx chat route");
    let mut headers = HeaderMap::new();
    headers.insert(SPECIFICATION_VERSION_HEADER, HeaderValue::from_static("4"));
    headers.insert(MODEL_ID_HEADER, HeaderValue::from_static("gpt-test"));
    headers.insert(STREAMING_HEADER, HeaderValue::from_static("true"));
    let error = FxSemanticAdapter
        .encode_request(route, &headers, br#"{"prompt":[]}"#)
        .expect_err("V4 requires the Gateway protocol header");
    assert!(error.to_string().contains("Gateway protocol version"));
}

fn test_config() -> pooler_config::CompiledConfig {
    compile_yaml(
        "fx-adapter-test.yaml",
        r#"
version: 1
listeners:
  local:
    bind: 127.0.0.1:0
upstreams:
  local:
    url: http://127.0.0.1:9
routes:
  - id: fx-chat
    listen: local
    match: {method: POST, path: /v3/ai/language-model}
    ingress: {mode: semantic, decoder: decode.fx.language_model}
    target: {provider: local, path: /v1/chat/completions}
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.fx.events}
    loss_policy: degrade
  - id: fx-models
    listen: local
    match: {method: GET, path: /coding-agent/v1/models}
    ingress: {mode: semantic, decoder: decode.fx.models.request}
    target: {provider: local, path: /v1/models}
    response: {mode: semantic, decoder: decode.openai.models, encoder: encode.fx.models}
    loss_policy: reject
"#,
    )
    .expect("fx adapter test config")
}

fn fixture_headers(fixture: &Value) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fixture["request_headers"]
        .as_object()
        .expect("fixture request headers")
    {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value.as_str().expect("header value")).expect("header value"),
        );
    }
    assert_eq!(
        headers[GATEWAY_PROTOCOL_VERSION_HEADER],
        HeaderValue::from_static("0.0.1")
    );
    headers
}

fn parse_fx_events(bytes: &[u8]) -> Vec<Value> {
    let mut parser = SseParser::new();
    let mut events = parser.feed(bytes).expect("fx SSE frames");
    events.extend(parser.finish().expect("complete fx SSE"));
    events
        .into_iter()
        .map(|event| {
            if event.is_done() {
                Value::String("[DONE]".to_owned())
            } else {
                serde_json::from_str(&event.data).expect("fx event JSON")
            }
        })
        .collect()
}
