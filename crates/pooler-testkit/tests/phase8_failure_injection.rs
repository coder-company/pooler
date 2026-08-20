use std::collections::BTreeSet;

use serde::Deserialize;

const CORPUS: &str = include_str!("../../../tests/failure-injection/corpus.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: u32,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    kind: String,
    boundary: String,
    outcome: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    delay_millis: Option<u64>,
    commitment: String,
    expected_attempts: u32,
    expected_health_mutation: String,
}

#[test]
fn corpus_declares_the_complete_runtime_contract() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("failure corpus is valid JSON");
    assert_eq!(corpus.schema_version, 2);
    assert_eq!(corpus.cases.len(), 15);

    let ids: BTreeSet<_> = corpus.cases.iter().map(|case| case.id.as_str()).collect();
    assert_eq!(ids.len(), corpus.cases.len(), "case IDs must be unique");

    let required_kinds = [
        "connection_refused",
        "tls_failure",
        "slow_headers",
        "downstream_disconnect",
        "status_401_refresh",
        "status_429_recovery",
        "request_invalid",
        "partial_sse",
        "invalid_utf8",
        "missing_terminal_event",
        "fragmented_websocket",
        "websocket_disconnect",
        "truncated_connect",
        "partial_connect",
    ];
    for kind in required_kinds {
        assert!(
            corpus.cases.iter().any(|case| case.kind == kind),
            "missing failure kind {kind}"
        );
    }

    for boundary in ["http", "tls", "sse", "websocket", "connect"] {
        assert!(
            corpus.cases.iter().any(|case| case.boundary == boundary),
            "missing protocol boundary {boundary}"
        );
    }

    for case in &corpus.cases {
        assert!(
            matches!(case.commitment.as_str(), "before" | "after"),
            "{} has invalid commitment",
            case.id
        );
        assert!(
            matches!(case.outcome.as_str(), "response" | "cancelled" | "error"),
            "{} has invalid outcome",
            case.id
        );
        assert!(
            matches!(
                case.expected_health_mutation.as_str(),
                "none" | "credential_cooldown"
            ),
            "{} has invalid health mutation",
            case.id
        );
        if case.commitment == "after" {
            assert_eq!(
                case.expected_attempts, 1,
                "{} may not retry after commitment",
                case.id
            );
        }
    }

    let invalid = corpus
        .cases
        .iter()
        .find(|case| case.kind == "request_invalid")
        .expect("request-invalid case");
    assert_eq!(invalid.status, Some(400));
    assert_eq!(invalid.expected_attempts, 1);
    assert_eq!(invalid.expected_health_mutation, "none");

    let slow = corpus
        .cases
        .iter()
        .find(|case| case.kind == "slow_headers")
        .expect("slow-header case");
    assert_eq!(slow.delay_millis, Some(100));
}

#[test]
fn corpus_case_rejects_unknown_fields() {
    let mut value: serde_json::Value =
        serde_json::from_str(CORPUS).expect("failure corpus is valid JSON");
    value["cases"][0]
        .as_object_mut()
        .expect("failure case is an object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    let error = serde_json::from_value::<Corpus>(value)
        .expect_err("failure cases must reject unknown fields");
    assert!(error.to_string().contains("unknown field `unexpected`"));
}
