//! Shared deterministic test infrastructure for Pooler.
//!
//! The testkit deliberately has no dependency on a Pooler runtime crate.  It can
//! therefore be used by protocol, adapter, policy, and end-to-end tests without
//! introducing dependency cycles.  The main pieces are:
//!
//! * [`FakeClock`] for advancing time without sleeping in wall-clock time;
//! * [`ScriptedUpstream`] and [`ScriptedChunk`] for deterministic failure and
//!   stream injection;
//! * [`Fixture`] and the normalization helpers for differential compatibility
//!   tests; and
//! * opt-in sanitized capture helpers that omit body content by default; and
//! * [`LeakCounters`] for proving that cancellation returns resources to zero.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod capture;
mod clock;
mod compatibility;
mod counters;
mod fixture;
mod upstream;

pub use capture::{
    capture_body, capture_fixture, capture_request, capture_response, write_captured_fixture,
    CaptureError, CaptureOptions, CapturedBody, CapturedChunk, CapturedFixture, CapturedRequest,
    CapturedResponse, CapturedResult, DEFAULT_MAX_CAPTURE_BODY_BYTES,
};
pub use clock::{Clock, FakeClock, SystemClock};
pub use compatibility::{
    load_compatibility_manifest, render_compatibility_matrix, CompatibilityEntry,
    CompatibilityError, CompatibilityManifest, CompatibilityStatus,
    COMPATIBILITY_MANIFEST_SCHEMA_VERSION,
};
pub use counters::{
    CancellationSnapshot, CancellationTracker, LeakCounters, LeakError, LeakGuard, LeakKind,
    LeakSnapshot, ResourceCounters, ResourceGuard,
};
pub use fixture::{
    compare_fixtures, compare_requests, compare_responses, normalize_chunks, normalize_fixture,
    normalize_headers, normalize_json, normalize_json_value, normalize_request, ConversionReport,
    Equivalence, EquivalenceKind, EquivalenceReport, ExpectedHealthMutation, Fixture,
    FixtureEquivalence, FixtureMetadata, HealthMutation, NormalizationError,
};
pub use upstream::{
    CallOutcome, ConnectChunk, Header, RecordedCall, ScriptedChunk, ScriptedError, ScriptedOutcome,
    ScriptedRequest, ScriptedResponse, ScriptedResult, ScriptedStream, ScriptedUpstream,
    UpstreamChunk, WebSocketChunk,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test]
    async fn fake_clock_releases_sleepers_only_after_advance() {
        let clock = FakeClock::new();
        let sleeper = tokio::spawn({
            let clock = clock.clone();
            async move {
                clock.sleep(Duration::from_secs(5)).await;
                clock.now()
            }
        });
        tokio::task::yield_now().await;
        assert!(!sleeper.is_finished());
        assert_eq!(
            clock.advance(Duration::from_secs(4)),
            Duration::from_secs(4)
        );
        clock.run_until_idle().await;
        assert!(!sleeper.is_finished());
        clock.advance(Duration::from_secs(1));
        clock.run_until_idle().await;
        assert_eq!(sleeper.await.expect("sleeper task"), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn scripted_upstream_records_requests_and_waits_on_fake_time() {
        let clock = FakeClock::new();
        let upstream =
            ScriptedUpstream::with_clock(clock.clone()).with_counters(LeakCounters::new());
        upstream.push(ScriptedResult::response(
            ScriptedResponse::ok()
                .with_chunk(ScriptedChunk::bytes("hello"))
                .with_chunk(ScriptedChunk::delay(Duration::from_secs(2)))
                .with_chunk(ScriptedChunk::end()),
        ));
        let request = ScriptedRequest::new("post", "/v1/test");
        let task = tokio::spawn({
            let upstream = upstream.clone();
            async move { upstream.execute(request).await }
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        clock.advance(Duration::from_secs(2));
        clock.run_until_idle().await;
        let response = task.await.expect("upstream task").expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(upstream.requests().len(), 1);
        assert_eq!(upstream.active_calls(), 0);
    }

    #[tokio::test]
    async fn cancellation_marks_call_and_releases_counter() {
        let clock = FakeClock::new();
        let counters = LeakCounters::new();
        let upstream = ScriptedUpstream::with_clock(clock.clone()).with_counters(counters.clone());
        upstream.push(ScriptedResult::response(
            ScriptedResponse::ok().with_chunk(ScriptedChunk::delay(Duration::from_secs(10))),
        ));
        let token = CancellationToken::new();
        let tracker = CancellationTracker::new();
        let task = tokio::spawn({
            let upstream = upstream.clone();
            let token = token.clone();
            let tracker = tracker.clone();
            async move {
                upstream
                    .execute_with_tracker(ScriptedRequest::new("GET", "/"), &token, &tracker)
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(counters.snapshot().tasks, 1);
        token.cancel();
        clock.run_until_idle().await;
        assert_eq!(
            task.await.expect("upstream task"),
            Err(ScriptedError::Cancelled)
        );
        assert_eq!(upstream.cancellation_count(), 1);
        assert_eq!(tracker.snapshot().requested, 1);
        assert!(counters.is_zero());
    }

    #[test]
    fn normalization_ignores_json_order_header_case_and_delays() {
        let left = ScriptedRequest::new("post", "/v1")
            .with_header("Content-Type", " application/json ")
            .with_body(br#"{ "b": 2, "a": [true, 1] }"#.to_vec());
        let right = ScriptedRequest::new("POST", "/v1")
            .with_header("content-type", "application/json")
            .with_body(br#"{"a":[true,1],"b":2}"#.to_vec());
        assert!(compare_requests(&left, &right, Equivalence::JsonStructural).is_equivalent());

        let expected = ScriptedResponse::ok().with_chunks([
            ScriptedChunk::delay(Duration::from_secs(1)),
            ScriptedChunk::sse("hello\r\nworld"),
        ]);
        let actual = ScriptedResponse::ok().with_chunk(ScriptedChunk::sse("hello\nworld"));
        assert!(compare_responses(&expected, &actual, Equivalence::EventSemantic).is_equivalent());
    }

    #[test]
    fn fixture_comparison_detects_extracted_field_mismatch() {
        let mut expected = Fixture::new("fixture", Equivalence::ByteLevel);
        expected
            .extracted_fields
            .insert("model".to_owned(), "gpt-test".to_owned());
        let mut actual = expected.clone();
        actual
            .extracted_fields
            .insert("model".to_owned(), "different-model".to_owned());

        let report = compare_fixtures(&expected, &actual);

        assert!(!report.is_equivalent());
        assert_eq!(report.differences, vec!["extracted_fields"]);
    }

    #[test]
    fn fixture_comparison_detects_upstream_script_mismatch() {
        let expected = Fixture::new("fixture", Equivalence::ByteLevel).with_upstream_script([
            ScriptedResult::response(
                ScriptedResponse::ok().with_chunk(ScriptedChunk::bytes("expected")),
            ),
        ]);
        let actual = Fixture::new("fixture", Equivalence::ByteLevel).with_upstream_script([
            ScriptedResult::response(
                ScriptedResponse::ok().with_chunk(ScriptedChunk::bytes("actual")),
            ),
        ]);

        let report = compare_fixtures(&expected, &actual);

        assert!(!report.is_equivalent());
        assert_eq!(report.differences, vec!["upstream_script"]);
    }

    #[test]
    fn fixture_comparison_normalizes_non_byte_level_upstream_scripts() {
        let expected = Fixture::new("fixture", Equivalence::EventSemantic).with_upstream_script([
            ScriptedResult::response(
                ScriptedResponse::ok()
                    .with_header("Content-Type", " text/event-stream ")
                    .with_chunks([
                        ScriptedChunk::delay(Duration::from_secs(1)),
                        ScriptedChunk::sse("hello\r\nworld"),
                    ]),
            ),
        ]);
        let actual = Fixture::new("fixture", Equivalence::EventSemantic).with_upstream_script([
            ScriptedResult::response(
                ScriptedResponse::ok()
                    .with_header("content-type", "text/event-stream")
                    .with_chunk(ScriptedChunk::sse("hello\nworld")),
            ),
        ]);

        assert!(compare_fixtures(&expected, &actual).is_equivalent());
    }

    #[test]
    fn leak_guard_reports_nonzero_and_returns_to_zero() {
        let counters = LeakCounters::new();
        let guard = counters.task();
        assert_eq!(counters.snapshot().tasks, 1);
        assert!(counters.assert_zero().is_err());
        guard.release();
        assert!(counters.assert_zero().is_ok());
    }
}
