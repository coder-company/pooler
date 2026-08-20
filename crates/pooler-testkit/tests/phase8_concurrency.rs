use std::time::Duration;

use pooler_testkit::{
    CancellationTracker, FakeClock, LeakCounters, ScriptedChunk, ScriptedRequest, ScriptedResponse,
    ScriptedResult, ScriptedUpstream,
};
use tokio_util::sync::CancellationToken;

const CONCURRENT_CALLS: usize = 100;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cancellation_returns_calls_and_resources_to_zero() {
    let clock = FakeClock::new();
    let counters = LeakCounters::new();
    let upstream = ScriptedUpstream::with_clock(clock).with_counters(counters.clone());
    for _ in 0..CONCURRENT_CALLS {
        upstream.push(ScriptedResult::response(
            ScriptedResponse::ok().with_chunk(ScriptedChunk::delay(Duration::from_secs(60))),
        ));
    }

    let cancellation = CancellationToken::new();
    let tracker = CancellationTracker::new();
    let mut tasks = Vec::with_capacity(CONCURRENT_CALLS);
    for index in 0..CONCURRENT_CALLS {
        let upstream = upstream.clone();
        let cancellation = cancellation.clone();
        let tracker = tracker.clone();
        let counters = counters.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = counters.permit();
            let _refresh_lease = counters.refresh_lease();
            let _temporary_file = counters.temporary_file();
            let _secret_material = counters.secret_material();
            upstream
                .execute_with_tracker(
                    ScriptedRequest::new("POST", format!("/concurrent/{index}")),
                    &cancellation,
                    &tracker,
                )
                .await
        }));
    }

    tokio::task::yield_now().await;
    cancellation.cancel();
    for task in tasks {
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled call did not finish")
            .expect("cancelled call task panicked");
        assert!(result.is_err());
    }

    assert_eq!(upstream.active_calls(), 0);
    assert_eq!(upstream.cancellation_count(), CONCURRENT_CALLS as u64);
    assert_eq!(tracker.snapshot().requested, CONCURRENT_CALLS as u64);
    assert!(
        counters.is_zero(),
        "tracked resources remain after cancellation"
    );
}
