use http::{header::HeaderValue, HeaderMap};
use pooler_observe::{RedactionPolicy, REDACTED_VALUE};
use serde_json::json;

#[test]
fn redaction_removes_nested_secrets_and_never_allows_secret_headers() {
    let policy = RedactionPolicy::strict();
    let value = json!({
        "request": {
            "api_key": "test-api-key-value",
            "nested": {"refreshToken": "test-refresh-token"},
            "safe": "visible"
        }
    });
    let sanitized = policy.sanitize_json(&value);
    assert_eq!(sanitized["request"]["api_key"], REDACTED_VALUE);
    assert_eq!(
        sanitized["request"]["nested"]["refreshToken"],
        REDACTED_VALUE
    );
    assert_eq!(sanitized["request"]["safe"], "visible");

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer test-api-key-value"),
    );
    headers.insert("x-request-id", HeaderValue::from_static("request-1"));
    let sanitized_headers = policy.sanitize_headers(&headers);
    assert_eq!(sanitized_headers["authorization"], REDACTED_VALUE);
    assert_eq!(sanitized_headers["x-request-id"], "request-1");
    assert!(!serde_json::to_string(&sanitized)
        .unwrap()
        .contains("test-api-key-value"));
    assert!(!serde_json::to_string(&sanitized_headers)
        .unwrap()
        .contains("test-api-key-value"));
}

#[test]
fn redaction_scans_free_text_and_bounds_deep_values() {
    let policy = RedactionPolicy::strict().with_max_depth(1);
    let sanitized = policy.sanitize_text("Authorization: Bearer test-api-key-value");
    assert_eq!(sanitized, "Authorization: [REDACTED] [REDACTED]");

    let value = json!({"outer": {"inner": {"token": "test-token-value"}}});
    let rendered = policy.sanitize_json(&value).to_string();
    assert!(!rendered.contains("test-token-value"));
    assert!(rendered.contains("DEPTH_LIMIT"));
}
