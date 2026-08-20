use std::collections::BTreeSet;
use std::time::Duration;

use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use pooler_testkit::{
    CancellationTracker, FakeClock, LeakCounters, ScriptedChunk, ScriptedError, ScriptedRequest,
    ScriptedResponse, ScriptedResult, ScriptedUpstream,
};

const CORPUS: &str = include_str!("../../../tests/failure-injection/corpus.json");

#[derive(Debug, Deserialize)]
struct Corpus {
    schema_version: u32,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    kind: String,
    outcome: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    delay_millis: Option<u64>,
    commitment: String,
}

#[tokio::test]
async fn corpus_is_complete_and_each_case_is_executable() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("failure corpus is valid JSON");
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.cases.len(), 12);

    let ids: BTreeSet<_> = corpus.cases.iter().map(|case| case.id.as_str()).collect();
    assert_eq!(ids.len(), corpus.cases.len(), "case IDs must be unique");

    let required = [
        "connection_refused",
        "tls_failure",
        "slow_headers",
        "downstream_disconnect",
        "status_401_refresh",
        "status_429_recovery",
        "partial_sse",
        "invalid_utf8",
        "missing_terminal_event",
        "fragmented_websocket",
        "truncated_connect",
    ];
    for kind in required {
        assert!(
            corpus.cases.iter().any(|case| case.kind == kind),
            "missing failure kind {kind}"
        );
    }
    assert!(corpus.cases.iter().any(|case| case.commitment == "before"));
    assert!(corpus.cases.iter().any(|case| case.commitment == "after"));
    assert!(corpus
        .cases
        .iter()
        .all(|case| matches!(case.commitment.as_str(), "before" | "after")));

    for case in corpus.cases {
        execute_case(&case).await;
    }
}

async fn execute_case(case: &Case) {
    let clock = FakeClock::new();
    let counters = LeakCounters::new();
    let upstream = ScriptedUpstream::with_clock(clock.clone()).with_counters(counters.clone());
    upstream.push(script_for(case));

    let cancellation = CancellationToken::new();
    let tracker = CancellationTracker::new();
    let request = ScriptedRequest::new("POST", "/failure-injection");
    let task = tokio::spawn({
        let upstream = upstream.clone();
        let cancellation = cancellation.clone();
        let tracker = tracker.clone();
        async move {
            upstream
                .execute_with_tracker(request, &cancellation, &tracker)
                .await
        }
    });

    if case.kind == "downstream_disconnect" {
        tokio::task::yield_now().await;
        cancellation.cancel();
    } else if let Some(delay_millis) = case.delay_millis {
        tokio::task::yield_now().await;
        clock.advance(Duration::from_millis(delay_millis));
        clock.run_until_idle().await;
    }

    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap_or_else(|_| panic!("failure case {} did not finish", case.id))
        .expect("failure case task did not panic");

    match case.outcome.as_str() {
        "response" => assert!(result.is_ok(), "{}: {result:?}", case.id),
        "cancelled" => assert_eq!(result, Err(ScriptedError::Cancelled), "{}", case.id),
        "error" => assert!(result.is_err(), "{} unexpectedly succeeded", case.id),
        outcome => panic!("{} has unknown outcome {outcome}", case.id),
    }
    if let Some(status) = case.status {
        if case.kind == "status_429_recovery" {
            assert!(matches!(result, Err(ScriptedError::RateLimited { .. })));
        } else {
            assert!(matches!(
                result,
                Err(ScriptedError::Status {
                    status: actual,
                    ..
                }) if actual == status
            ));
        }
    }
    assert_eq!(
        upstream.active_calls(),
        0,
        "{} left an active call",
        case.id
    );
    assert!(counters.is_zero(), "{} leaked tracked resources", case.id);
    if case.kind == "downstream_disconnect" {
        assert_eq!(
            tracker.snapshot().requested,
            1,
            "{} did not record cancellation",
            case.id
        );
    }
}

fn script_for(case: &Case) -> ScriptedResult {
    match case.kind.as_str() {
        "connection_refused" => ScriptedResult::error(ScriptedError::ConnectionRefused),
        "tls_failure" => ScriptedResult::error(ScriptedError::TlsHandshake),
        "slow_headers" => ScriptedResult::response(
            ScriptedResponse::ok()
                .with_chunk(ScriptedChunk::delay(Duration::from_millis(
                    case.delay_millis.unwrap_or(1),
                )))
                .with_chunk(ScriptedChunk::end()),
        ),
        "downstream_disconnect" => ScriptedResult::response(
            ScriptedResponse::ok().with_chunk(ScriptedChunk::delay(Duration::from_secs(60))),
        ),
        "status_401_refresh" => ScriptedResult::error(ScriptedError::status(401)),
        "status_429_recovery" => {
            ScriptedResult::error(ScriptedError::rate_limited(Some(Duration::from_millis(1))))
        }
        "partial_sse" => ScriptedResult::error(ScriptedError::InvalidResponse(
            "incomplete server-sent event".to_owned(),
        )),
        "invalid_utf8" => ScriptedResult::error(ScriptedError::InvalidResponse(
            "invalid UTF-8 upstream data".to_owned(),
        )),
        "missing_terminal_event" => ScriptedResult::error(ScriptedError::InvalidResponse(
            "stream ended without terminal event".to_owned(),
        )),
        "fragmented_websocket" => ScriptedResult::response(
            ScriptedResponse::ok()
                .with_chunk(ScriptedChunk::frame(1, false, b"fragment".to_vec()))
                .with_chunk(ScriptedChunk::frame(0, true, b"ed".to_vec())),
        ),
        "truncated_connect" => ScriptedResult::error(ScriptedError::InvalidResponse(
            "truncated Connect envelope".to_owned(),
        )),
        kind => panic!("unknown failure kind {kind}"),
    }
}
