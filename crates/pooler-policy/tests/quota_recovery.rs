use std::collections::BTreeSet;
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use pooler_core::{CapabilitySet, CredentialId, ModelId};
use pooler_policy::{
    AffinityDecision, BindingKey, CommitmentState, CredentialRegistration, CredentialRegistry,
    ProviderNeutralQuotaClassifier, QuotaClassifier, QuotaObservation, QuotaProjectKey, QuotaScope,
    QuotaSignal, QuotaUnit, ReplayCheck, RetryContext, RetryDecision, RetryPolicy, RetryReason,
    RetryStopReason, SelectionRequest, SelectionStrategy,
};

fn account(
    credential: &str,
    provider: &str,
    project: &QuotaProjectKey,
    max_in_flight: Option<u32>,
) -> CredentialRegistration {
    let registration =
        CredentialRegistration::from_strings(credential, provider, "model", CapabilitySet::new())
            .expect("registration")
            .with_quota_project(project.clone());
    max_in_flight.map_or(registration.clone(), |limit| {
        registration
            .with_max_in_flight(limit)
            .expect("concurrency limit")
    })
}

fn selection(now: Instant) -> SelectionRequest {
    SelectionRequest::new(ModelId::new("model").expect("model"))
        .with_strategy(SelectionStrategy::OrderedFallback)
        .at(now)
}

fn recovery_policy() -> RetryPolicy {
    RetryPolicy::with_bounds(
        3,
        3,
        3,
        Duration::from_millis(10),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
        Duration::from_secs(1),
    )
    .expect("retry policy")
}

#[test]
fn project_exhaustion_rotates_atomically_rebinds_affinity_and_restores() {
    let registry = CredentialRegistry::new();
    let shared = QuotaProjectKey::new("shared-billing-project").expect("project");
    let alternate = shared.clone();
    for registration in [
        account("a", "provider-a", &shared, None),
        account("b", "provider-a", &shared, None),
        account("c", "provider-b", &alternate, None),
    ] {
        registry.register(registration).expect("register");
    }

    let now = Instant::now();
    let first_request = selection(now)
        .with_affinity_key("conversation", Duration::from_secs(300))
        .expect("affinity");
    let first = registry.select(first_request).expect("first account");
    assert_eq!(first.credential_id().as_str(), "a");

    let classified = ProviderNeutralQuotaClassifier::default().classify(
        &QuotaObservation::new(
            QuotaSignal::Exhausted,
            QuotaScope::Project,
            QuotaUnit::Credits,
        )
        .with_window(Some(10_000), Some(0))
        .with_reset_after(Duration::from_secs(3_600))
        .with_provider_code("project_budget_exhausted"),
        now,
    );
    let next_request = selection(now + Duration::from_millis(1))
        .with_affinity_key("conversation", Duration::from_secs(300))
        .expect("affinity")
        .with_attempt(2);
    let recovery = registry
        .recover_quota(
            first,
            &classified,
            next_request,
            &recovery_policy(),
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe())
                .with_used_targets(1, 1),
        )
        .expect("quota recovery");
    assert_eq!(
        recovery.retry_decision(),
        RetryDecision::Retry {
            delay: Duration::ZERO,
            retry_delay: Duration::ZERO,
            recovery_wait: Duration::ZERO,
            reason: RetryReason::AlternateCredential,
        }
    );
    let replacement = recovery.selection().expect("alternate account");
    assert_eq!(replacement.credential_id().as_str(), "c");
    assert!(matches!(
        replacement.explanation().affinity,
        AffinityDecision::Rebound { .. }
    ));
    drop(recovery);
    let affinity_match = registry
        .select(
            selection(now + Duration::from_millis(2))
                .with_affinity_key("conversation", Duration::from_secs(300))
                .expect("affinity"),
        )
        .expect("rebound affinity");
    assert_eq!(affinity_match.credential_id().as_str(), "c");
    assert!(matches!(
        affinity_match.explanation().affinity,
        AffinityDecision::Matched { .. }
    ));
    drop(affinity_match);

    let records = registry
        .quota_state_records(now + Duration::from_secs(1), 1_000_000)
        .expect("quota records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].scope(), QuotaScope::Project);

    let restored = CredentialRegistry::new();
    for registration in [
        account("a", "provider-a", &shared, None),
        account("b", "provider-a", &shared, None),
        account("c", "provider-b", &alternate, None),
    ] {
        restored.register(registration).expect("register");
    }
    for record in &records {
        assert!(restored
            .restore_quota_state(record, now + Duration::from_secs(2), 1_001_000)
            .expect("restore quota"));
    }
    let selected = restored
        .select(selection(now + Duration::from_secs(2)))
        .expect("restored quota filters shared project");
    assert_eq!(selected.credential_id().as_str(), "c");
}

#[test]
fn alternate_account_bypasses_reset_wait_but_commit_and_availability_still_bound_retry() {
    let project = QuotaProjectKey::new("project").expect("project");
    let now = Instant::now();
    let classified = ProviderNeutralQuotaClassifier::default().classify(
        &QuotaObservation::new(
            QuotaSignal::Exhausted,
            QuotaScope::Credential,
            QuotaUnit::Requests,
        )
        .with_reset_after(Duration::from_secs(3_600)),
        now,
    );

    let registry = CredentialRegistry::new();
    registry
        .register(account("a", "provider-a", &project, None))
        .expect("register a");
    registry
        .register(account("b", "provider-a", &project, None))
        .expect("register b");
    let failed = registry.select(selection(now)).expect("failed account");
    let recovery = registry
        .recover_quota(
            failed,
            &classified,
            selection(now).with_attempt(2),
            &recovery_policy(),
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe()),
        )
        .expect("recovery");
    assert_eq!(recovery.retry_decision().delay(), Duration::ZERO);
    assert_eq!(
        recovery
            .selection()
            .expect("alternate credential")
            .credential_id()
            .as_str(),
        "b"
    );

    let committed = CredentialRegistry::new();
    committed
        .register(account("a", "provider-a", &project, None))
        .expect("register a");
    committed
        .register(account("b", "provider-a", &project, None))
        .expect("register b");
    let failed = committed.select(selection(now)).expect("failed account");
    let stopped = committed
        .recover_quota(
            failed,
            &classified,
            selection(now).with_attempt(2),
            &recovery_policy(),
            RetryContext::new(1, CommitmentState::Committed, ReplayCheck::safe()),
        )
        .expect("stopped recovery");
    assert_eq!(
        stopped.retry_decision(),
        RetryDecision::DoNotRetry {
            reason: RetryStopReason::DownstreamCommitted,
        }
    );
    assert!(stopped.selection().is_none());

    let single = CredentialRegistry::new();
    single
        .register(account("only", "provider-a", &project, None))
        .expect("register");
    let failed = single.select(selection(now)).expect("failed account");
    let unavailable = single
        .recover_quota(
            failed,
            &classified,
            selection(now).with_attempt(2),
            &recovery_policy(),
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe()),
        )
        .expect("bounded recovery");
    assert_eq!(
        unavailable.retry_decision(),
        RetryDecision::DoNotRetry {
            reason: RetryStopReason::NoAlternateTarget,
        }
    );
    assert!(unavailable.no_eligible().is_some());
}

#[test]
fn concurrent_reservations_never_oversubscribe_accounts() {
    const WORKERS: usize = 32;
    let project = QuotaProjectKey::new("project").expect("project");
    let registry = Arc::new(CredentialRegistry::new());
    for credential in ["a", "b", "c"] {
        registry
            .register(account(credential, "provider", &project, Some(1)))
            .expect("register");
    }

    let start = Arc::new(Barrier::new(WORKERS + 1));
    let release = Arc::new(Barrier::new(WORKERS + 1));
    let (sender, receiver) = mpsc::channel();
    let now = Instant::now();
    let mut threads = Vec::new();
    for _ in 0..WORKERS {
        let registry = Arc::clone(&registry);
        let start = Arc::clone(&start);
        let release = Arc::clone(&release);
        let sender = sender.clone();
        threads.push(thread::spawn(move || {
            start.wait();
            let lease = registry
                .select(selection(now).with_strategy(SelectionStrategy::LeastInFlight))
                .ok();
            sender
                .send(
                    lease
                        .as_ref()
                        .map(|selection| selection.credential_id().to_string()),
                )
                .expect("send result");
            release.wait();
            drop(lease);
        }));
    }
    drop(sender);
    start.wait();
    let outcomes = receiver.iter().take(WORKERS).collect::<Vec<_>>();
    let successful = outcomes.into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(successful.len(), 3);
    let selected = successful.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(
        selected,
        BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()])
    );
    release.wait();
    for worker in threads {
        worker.join().expect("worker");
    }
    for credential in ["a", "b", "c"] {
        assert_eq!(
            registry
                .in_flight(&CredentialId::new(credential).expect("credential"))
                .expect("in-flight"),
            Some(0)
        );
    }
}

#[test]
fn stale_lease_cannot_release_a_reregistered_account_slot() {
    let project = QuotaProjectKey::new("project").expect("project");
    let registry = CredentialRegistry::new();
    let credential = CredentialId::new("account").expect("credential");
    registry
        .register(account("account", "provider", &project, Some(1)))
        .expect("register");
    let stale = registry
        .select(selection(Instant::now()))
        .expect("old lease");
    assert!(registry.unregister(&credential).expect("unregister"));
    registry
        .register(account("account", "provider", &project, Some(1)))
        .expect("reregister");
    let current = registry
        .select(selection(Instant::now()))
        .expect("new lease");
    drop(stale);
    assert_eq!(registry.in_flight(&credential).expect("in-flight"), Some(1));
    drop(current);
    assert_eq!(registry.in_flight(&credential).expect("in-flight"), Some(0));
}

#[test]
fn foreign_and_stale_leases_cannot_install_quota_state() {
    let project = QuotaProjectKey::new("project").expect("project");
    let now = Instant::now();
    let classified = ProviderNeutralQuotaClassifier::default().classify(
        &QuotaObservation::new(
            QuotaSignal::Exhausted,
            QuotaScope::Credential,
            QuotaUnit::Requests,
        ),
        now,
    );
    let first = CredentialRegistry::new();
    let second = CredentialRegistry::new();
    for registry in [&first, &second] {
        registry
            .register(account("a", "provider", &project, None))
            .expect("register");
    }
    let foreign = first.select(selection(now)).expect("foreign lease");
    let error = second
        .recover_quota(
            foreign,
            &classified,
            selection(now).with_attempt(2),
            &recovery_policy(),
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe()),
        )
        .expect_err("foreign lease");
    assert!(matches!(error, pooler_policy::SelectionError::ForeignLease));
    assert_eq!(
        first
            .in_flight(&CredentialId::new("a").expect("credential"))
            .expect("in-flight"),
        Some(0)
    );

    let stale = second.select(selection(now)).expect("stale lease");
    let credential = CredentialId::new("a").expect("credential");
    second.unregister(&credential).expect("unregister");
    second
        .register(account("a", "provider", &project, None))
        .expect("reregister");
    let error = second
        .recover_quota(
            stale,
            &classified,
            selection(now).with_attempt(2),
            &recovery_policy(),
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe()),
        )
        .expect_err("stale lease");
    assert!(matches!(error, pooler_policy::SelectionError::StaleLease));
    assert!(second.select(selection(now)).is_ok());
}

#[test]
fn unregister_removes_quota_with_no_remaining_subject_member() {
    let project = QuotaProjectKey::new("project").expect("project");
    let registry = CredentialRegistry::new();
    let credential = CredentialId::new("a").expect("credential");
    registry
        .register(account("a", "provider", &project, None))
        .expect("register");
    registry
        .mark_quota_exhausted(&credential, None)
        .expect("quota");
    assert!(registry.unregister(&credential).expect("unregister"));
    registry
        .register(account("a", "provider", &project, None))
        .expect("reregister");
    assert!(registry.select(selection(Instant::now())).is_ok());
}

#[test]
fn binding_quota_isolated_for_identical_account_ids() {
    let registry = CredentialRegistry::new();
    let first = CredentialRegistration::with_binding(
        BindingKey::new("target-a", "shared", "fingerprint-a").expect("binding"),
        pooler_core::ProviderId::new("provider-a").expect("provider"),
        ModelId::new("model").expect("model"),
        CapabilitySet::new(),
    )
    .expect("registration");
    let second = CredentialRegistration::with_binding(
        BindingKey::new("target-b", "shared", "fingerprint-b").expect("binding"),
        pooler_core::ProviderId::new("provider-b").expect("provider"),
        ModelId::new("model").expect("model"),
        CapabilitySet::new(),
    )
    .expect("registration");
    let first_binding = first.binding_key().clone();
    let second_binding = second.binding_key().clone();
    registry.register(first).expect("register first");
    registry.register(second).expect("register second");
    registry
        .mark_binding_quota_exhausted(&first_binding, None)
        .expect("exhaust first");

    let selected = registry
        .select(selection(Instant::now()))
        .expect("second binding remains eligible");
    assert_eq!(selected.binding_key(), &second_binding);
}
