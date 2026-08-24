use std::collections::VecDeque;
use std::future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pooler_core::{Capability, CapabilitySet, ModelId};
use pooler_model_catalog::{
    CatalogError, CatalogService, CatalogSourceConfig, DiscoveredModel, DiscoveryFailure,
    DiscoveryFailureKind, DiscoveryFuture, DiscoveryResponse, ModelDiscovery, ModelSelectionAction,
    RefreshConfig, RegisteredSource,
};

fn model(id: &str) -> DiscoveredModel {
    DiscoveredModel::new(
        ModelId::new(id).expect("valid test model"),
        CapabilitySet::from(Capability::Text),
    )
}

fn source(id: &str, provider: &str) -> pooler_model_catalog::CatalogSource {
    CatalogSourceConfig {
        id: id.to_owned(),
        provider: provider.to_owned(),
        ..CatalogSourceConfig::default()
    }
    .compile()
    .expect("valid source")
}

#[derive(Debug)]
struct SequenceDiscovery {
    responses: Mutex<VecDeque<Result<DiscoveryResponse, DiscoveryFailure>>>,
}

impl SequenceDiscovery {
    fn new(
        responses: impl IntoIterator<Item = Result<DiscoveryResponse, DiscoveryFailure>>,
    ) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl ModelDiscovery for SequenceDiscovery {
    fn discover(&self) -> DiscoveryFuture<'_> {
        let response = self
            .responses
            .lock()
            .expect("test response lock")
            .pop_front()
            .expect("test response available");
        Box::pin(future::ready(response))
    }
}

#[tokio::test]
async fn failed_refresh_retains_last_good_snapshot() {
    let discovery = Arc::new(SequenceDiscovery::new([
        Ok(DiscoveryResponse::new(vec![model("stable")])),
        Err(DiscoveryFailure::new("provider unavailable")),
    ]));
    let limits = RefreshConfig::default()
        .compile()
        .expect("default limits compile");
    let service = CatalogService::new(
        vec![RegisteredSource::new(
            source("provider.primary", "provider"),
            discovery,
        )],
        limits,
    )
    .expect("service builds");

    let report = service.refresh(100).await.expect("first refresh publishes");
    assert_eq!(report.generation(), 1);
    let good = service.snapshot();
    assert!(good.get("stable").is_some());

    let error = service
        .refresh(200)
        .await
        .expect_err("failed discovery does not publish");
    assert!(matches!(error, CatalogError::DiscoveryFailed { .. }));
    let retained = service.snapshot();
    assert_eq!(retained.generation(), 1);
    assert_eq!(retained.refreshed_at_unix_ms(), 100);
    assert_eq!(&*good, &*retained);
}

#[derive(Debug)]
struct ConcurrencyProbe {
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl ModelDiscovery for ConcurrencyProbe {
    fn discover(&self) -> DiscoveryFuture<'_> {
        Box::pin(async move {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(15)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(DiscoveryResponse::new(vec![model("shared")]))
        })
    }
}

#[tokio::test]
async fn refresh_enforces_discovery_concurrency_bound() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let sources = (0..6)
        .map(|index| {
            let discovery = Arc::new(ConcurrencyProbe {
                active: Arc::clone(&active),
                peak: Arc::clone(&peak),
            });
            RegisteredSource::new(
                source(
                    &format!("provider{index}.primary"),
                    &format!("provider-{index}"),
                ),
                discovery,
            )
        })
        .collect();
    // Generous on purpose: this test asserts the concurrency bound, so the
    // deadline must never turn machine load into a failure.
    let limits = RefreshConfig {
        timeout_ms: 60_000,
        max_concurrency: 2,
        ..RefreshConfig::default()
    }
    .compile()
    .expect("limits compile");
    let service = CatalogService::new(sources, limits).expect("service builds");

    let report = service.refresh(10).await.expect("refresh completes");
    assert_eq!(report.source_count(), 6);
    assert_eq!(report.model_count(), 1);
    assert_eq!(report.target_count(), 6);
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct NeverDiscovery;

impl ModelDiscovery for NeverDiscovery {
    fn discover(&self) -> DiscoveryFuture<'_> {
        Box::pin(future::pending())
    }
}

#[tokio::test]
async fn refresh_timeout_is_bounded_and_does_not_publish() {
    let limits = RefreshConfig {
        timeout_ms: 20,
        ..RefreshConfig::default()
    }
    .compile()
    .expect("limits compile");
    let service = CatalogService::new(
        vec![RegisteredSource::new(
            source("provider.primary", "provider"),
            Arc::new(NeverDiscovery),
        )],
        limits,
    )
    .expect("service builds");

    let error = service
        .refresh(10)
        .await
        .expect_err("deadline must terminate refresh");
    assert_eq!(error, CatalogError::RefreshTimedOut { timeout_ms: 20 });
    assert_eq!(service.snapshot().generation(), 0);
    assert!(service.snapshot().models().is_empty());
}

#[tokio::test]
async fn arbitrary_provider_failure_text_is_never_retained_or_rendered() {
    const SECRET: &str = "provider-secret-sentinel-should-never-render";
    let failure = DiscoveryFailure::new(SECRET);
    assert_eq!(failure.kind(), DiscoveryFailureKind::Provider);
    assert!(!failure.to_string().contains(SECRET));
    assert!(!format!("{failure:?}").contains(SECRET));

    let service = CatalogService::new(
        vec![RegisteredSource::new(
            source("provider.primary", "provider"),
            Arc::new(SequenceDiscovery::new([Err(failure)])),
        )],
        RefreshConfig::default().compile().expect("limits compile"),
    )
    .expect("service builds");
    let error = service.refresh(10).await.expect_err("discovery fails");
    assert!(!error.to_string().contains(SECRET));
    assert!(matches!(
        error,
        CatalogError::DiscoveryFailed {
            kind: DiscoveryFailureKind::Provider,
            ..
        }
    ));
}

#[tokio::test]
async fn complete_deadline_covers_high_work_merge_and_publication() {
    let models = (0..50_000)
        .rev()
        .map(|index| model(&format!("model-{index:05}")))
        .collect::<Vec<_>>();
    let service = CatalogService::new(
        vec![RegisteredSource::new(
            source("provider.primary", "provider"),
            Arc::new(SequenceDiscovery::new([Ok(DiscoveryResponse::new(models))])),
        )],
        RefreshConfig {
            timeout_ms: 1,
            max_models_per_source: 50_000,
            max_total_models: 50_000,
            max_merge_operations: 100_000,
            ..RefreshConfig::default()
        }
        .compile()
        .expect("high-work limits compile"),
    )
    .expect("service builds");

    let error = service
        .refresh(10)
        .await
        .expect_err("merge must share the complete refresh deadline");
    assert_eq!(error, CatalogError::RefreshTimedOut { timeout_ms: 1 });
    assert_eq!(service.snapshot().generation(), 0);
}

#[test]
fn account_bound_targets_and_signed_priorities_are_stable() {
    let make_source = |id: &str, account: Option<&str>, pool: Option<&str>, priority| {
        CatalogSourceConfig {
            id: id.to_owned(),
            provider: "shared-provider".to_owned(),
            account: account.map(str::to_owned),
            account_pool: pool.map(str::to_owned),
            priority,
            ..CatalogSourceConfig::default()
        }
        .compile()
        .expect("valid account-bound source")
    };
    let first = pooler_model_catalog::CatalogInput::new(
        make_source("shared.a", Some("account-a"), None, 20),
        DiscoveryResponse::new(vec![model("shared-model")]),
    );
    let second = pooler_model_catalog::CatalogInput::new(
        make_source("shared.b", Some("account-b"), None, 20),
        DiscoveryResponse::new(vec![model("shared-model")]),
    );
    let pooled = pooler_model_catalog::CatalogInput::new(
        make_source("shared.pool", None, Some("pool-a"), -5),
        DiscoveryResponse::new(vec![model("shared-model")]),
    );
    let merged = pooler_model_catalog::merge_discoveries(
        1,
        100,
        vec![first.clone(), second.clone(), pooled.clone()],
        RefreshConfig::default().compile().expect("limits"),
        &pooler_model_catalog::ModelOverrides::default(),
    )
    .expect("account-bound catalog merges");
    let targets = &merged.get("shared-model").expect("model").targets();
    assert_eq!(
        targets.len(),
        3,
        "authorized accounts and pools stay distinct"
    );
    assert_eq!(targets[0].priority(), 1);
    assert_eq!(targets[1].priority(), 1);
    assert_eq!(targets[2].priority(), 2);
    assert_eq!(targets[0].signed_priority(), 20);
    assert_eq!(targets[2].signed_priority(), -5);
    assert_eq!(targets[0].account(), Some("account-a"));
    assert_eq!(targets[1].account(), Some("account-b"));
    assert_eq!(targets[2].account_pool(), Some("pool-a"));
    assert_ne!(
        targets[0].binding().binding_id(),
        targets[1].binding().binding_id()
    );
    assert_eq!(targets[0].provenance()[0].account(), Some("account-a"));
    assert_eq!(targets[2].provenance()[0].account_pool(), Some("pool-a"));

    let repeat = pooler_model_catalog::merge_discoveries(
        1,
        100,
        vec![pooled, second, first],
        RefreshConfig::default().compile().expect("limits"),
        &pooler_model_catalog::ModelOverrides::default(),
    )
    .expect("repeat merge");
    assert_eq!(
        merged, repeat,
        "source order cannot change binding identity"
    );
}

#[tokio::test]
async fn typed_bulk_selection_preserves_explicit_exclusions_across_refresh() {
    let discovery = Arc::new(SequenceDiscovery::new([
        Ok(DiscoveryResponse::new(vec![model("keep"), model("remove")])),
        Ok(DiscoveryResponse::new(vec![model("keep"), model("remove")])),
        Ok(DiscoveryResponse::new(vec![model("keep"), model("remove")])),
    ]));
    let limits = RefreshConfig::default().compile().expect("limits");
    let service = CatalogService::new(
        vec![RegisteredSource::new(
            source("provider.selection", "provider"),
            discovery,
        )],
        limits,
    )
    .expect("service");

    service
        .exclude_model("provider.selection", "remove")
        .expect("explicit exclusion");
    service.refresh(1).await.expect("initial selection refresh");
    assert!(service.snapshot().get("keep").is_some());
    assert!(service.snapshot().get("remove").is_none());

    service
        .apply_selection("provider.selection", ModelSelectionAction::SelectNone)
        .expect("select none");
    service.refresh(2).await.expect("select none refresh");
    assert!(service.snapshot().models().is_empty());

    service
        .apply_selection("provider.selection", ModelSelectionAction::SelectAll)
        .expect("select all");
    service.refresh(3).await.expect("select all refresh");
    assert!(service.snapshot().get("keep").is_some());
    assert!(service.snapshot().get("remove").is_none());
    let state = service
        .selection_state("provider.selection")
        .expect("selection state");
    assert_eq!(state.action(), ModelSelectionAction::SelectAll);
    assert_eq!(
        state.explicit_exclusions(),
        &[pooler_core::ModelId::new("remove").expect("id")]
    );
}
