//! Request-local account selection and mutable pooling state.
//!
//! The coordinator is intentionally small: immutable route plans stay in
//! [`CompiledConfig`], while this value owns only selection cursors, health,
//! affinity, and redacted decision persistence.  A coordinator is shared by
//! every listener serving one compiled configuration.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http::{header, HeaderMap};
use pooler_auth::SecretRef as AuthSecretRef;
use pooler_config::{
    AccountPlan, CompiledConfig, PolicyPlan, RoutePlan, SecretRef,
    SelectionStrategy as ConfigSelectionStrategy,
};
use pooler_core::{
    CapabilitySet, ConfigGeneration, CredentialId, ErrorClass, ModelId, ProviderId, RouteId,
};
use pooler_policy::{
    AffinityKey, CommitmentState, CooldownScope, CredentialRegistration, CredentialRegistry,
    FailureClassification, FailureClassifier, HealthMutation, HealthSubject, HttpFailureClassifier,
    ObservedFailure, ReplayCheck, RetryContext, RetryDecision, RetryPolicy, SelectionError,
    SelectionExplanation, SelectionLease, SelectionRequest,
};
use pooler_store::{
    CooldownState, CredentialHealthState, CredentialHealthStatus, CredentialState,
    DecisionCandidate, DecisionRecord, MemoryStore, SessionAffinity, Store,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// One selected upstream target and its short-lived account lease.
pub struct PoolSelection {
    upstream_id: Arc<str>,
    upstream_model: Option<Arc<str>>,
    account: Option<AccountPlan>,
    lease: Option<SelectionLease>,
    policy: Option<PolicyPlan>,
    explanation: Option<SelectionExplanation>,
    model: ModelId,
    provider: ProviderId,
    credential: Option<CredentialId>,
    affinity_key: Option<AffinityKey>,
    registry_key: Option<Arc<str>>,
}

impl std::fmt::Debug for PoolSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolSelection")
            .field("upstream_id", &self.upstream_id)
            .field("upstream_model", &self.upstream_model)
            .field("provider", &self.provider)
            .field("has_account", &self.account.is_some())
            .field("has_lease", &self.lease.is_some())
            .field("registry_key", &self.registry_key)
            .finish()
    }
}

impl PoolSelection {
    /// Selected upstream ID.
    #[must_use]
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }

    /// Model to place in an upstream semantic/JSON request, when model
    /// registry selection supplied one.
    #[must_use]
    pub fn upstream_model(&self) -> Option<&str> {
        self.upstream_model.as_deref()
    }

    /// Account secret reference, if an account rather than static upstream
    /// authentication was selected.
    #[must_use]
    pub fn account_secret(&self) -> Option<&SecretRef> {
        self.account.as_ref().map(AccountPlan::secret)
    }

    /// Whether this selection can participate in a retry policy.
    #[must_use]
    pub fn has_policy(&self) -> bool {
        self.policy.is_some()
    }

    /// Retry policy attached to this selection, if any.
    #[must_use]
    pub fn policy(&self) -> Option<&PolicyPlan> {
        self.policy.as_ref()
    }

    /// Selected model ID used for health and decisions.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.model
    }

    /// Selected provider ID used for health and decisions.
    #[must_use]
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Selected credential ID, when account pooling is active.
    #[must_use]
    pub fn credential(&self) -> Option<&CredentialId> {
        self.credential.as_ref()
    }

    /// Redacted selection explanation.
    #[must_use]
    pub fn explanation(&self) -> Option<&SelectionExplanation> {
        self.explanation.as_ref()
    }

    /// Return the lease so a response body can retain it until completion.
    pub(crate) fn take_lease(&mut self) -> Option<SelectionLease> {
        self.lease.take()
    }

    /// Return the affinity key used by this selection, if one was requested.
    #[must_use]
    pub fn affinity_key(&self) -> Option<&AffinityKey> {
        self.affinity_key.as_ref()
    }
}

/// A failure classification plus the retry decision made for one attempt.
#[derive(Clone, Debug)]
pub struct PoolFailure {
    pub classification: FailureClassification,
    pub mutation: HealthMutation,
    pub decision: RetryDecision,
}

/// Inputs for one pre-commit failure decision.
pub(crate) struct FailureInput<'a> {
    pub config: &'a CompiledConfig,
    pub route: &'a RoutePlan,
    pub selection: &'a PoolSelection,
    pub status: Option<u16>,
    pub provider_code: Option<String>,
    pub message: Option<String>,
    pub retry_after: Option<Duration>,
    pub replay: ReplayCheck,
    pub idempotency_key_present: bool,
    pub attempt: u32,
    pub credentials_used: u32,
    pub providers_used: u32,
    pub elapsed_retry_delay: Duration,
    pub elapsed_recovery_wait: Duration,
    pub started: Instant,
}

/// Runtime pooling errors are deliberately sanitized before they cross the
/// HTTP boundary.
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("invalid model identifier")]
    InvalidModel,
    #[error("invalid provider identifier")]
    InvalidProvider,
    #[error("invalid credential identifier")]
    InvalidCredential,
    #[error("model `{model}` is not configured")]
    UnknownModel { model: String },
    #[error("pool policy `{policy}` has no eligible account")]
    NoEligible { policy: String },
    #[error("pool state unavailable")]
    Store,
    #[error("selection state unavailable")]
    Selection,
}

/// Shared mutable account-pooling state for one compiled configuration.
#[derive(Clone)]
pub struct PoolingCoordinator {
    registries: Arc<BTreeMap<String, Arc<CredentialRegistry>>>,
    accounts: Arc<BTreeMap<String, AccountPlan>>,
    store: Arc<dyn Store>,
    request_sequence: Arc<AtomicU64>,
}

impl std::fmt::Debug for PoolingCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolingCoordinator")
            .field("registries", &self.registries.len())
            .field("accounts", &self.accounts.len())
            .finish_non_exhaustive()
    }
}

impl PoolingCoordinator {
    /// Build an in-memory coordinator. This preserves the legacy static
    /// upstream behavior when no accounts or policies are configured.
    pub fn new(config: &CompiledConfig) -> Result<Self, PoolError> {
        Self::with_store(config, Arc::new(MemoryStore::new()))
    }

    /// Build a coordinator backed by caller-selected mutable storage. SQLite
    /// callers can pass an `Arc<dyn Store>` here to retain account state over a
    /// process restart.
    pub fn with_store(config: &CompiledConfig, store: Arc<dyn Store>) -> Result<Self, PoolError> {
        let accounts = config
            .accounts()
            .values()
            .map(|account| (account.id().to_owned(), account.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut registries = BTreeMap::new();

        for model in config.models().values() {
            let registry = Arc::new(CredentialRegistry::new());
            register_model_accounts(&registry, model.id(), model.targets(), &accounts)?;
            registries.insert(model.id().to_owned(), registry);
        }
        for route in config.routes() {
            if route.target().policy().is_none() || route.target().model_source().is_some() {
                continue;
            }
            let key = route_registry_key(route.id());
            let registry = Arc::new(CredentialRegistry::new());
            register_route_accounts(&registry, route.id(), route.target().upstream(), &accounts)?;
            registries.insert(key, registry);
        }

        let coordinator = Self {
            registries: Arc::new(registries),
            accounts: Arc::new(accounts),
            store,
            request_sequence: Arc::new(AtomicU64::new(0)),
        };
        coordinator.restore_account_state(config)?;
        Ok(coordinator)
    }

    /// Number of persisted decisions, useful for diagnostics and tests.
    pub fn decision_count(&self) -> Result<usize, PoolError> {
        self.store
            .decisions()
            .map(|records| records.len())
            .map_err(|_| PoolError::Store)
    }

    /// Return recent redacted decisions for diagnostics and tests.
    pub fn recent_decisions(
        &self,
        limit: usize,
    ) -> Result<Vec<pooler_store::DecisionRecord>, PoolError> {
        self.store
            .recent_decisions(limit)
            .map_err(|_| PoolError::Store)
    }

    /// Select one target. The returned lease must remain alive until the
    /// response body is complete; callers may explicitly drop it on retry.
    pub fn select(
        &self,
        config: &CompiledConfig,
        route: &RoutePlan,
        model: Option<&str>,
        headers: &HeaderMap,
        attempt: u32,
        started: Instant,
    ) -> Result<PoolSelection, PoolError> {
        let policy = route
            .target()
            .policy()
            .and_then(|id| config.policies().get(id))
            .cloned();

        let (logical_model, static_upstream, static_model) =
            resolve_static_target(config, route, model)?;
        let Some(policy) = policy else {
            let provider = ProviderId::new(static_upstream.to_owned())
                .map_err(|_| PoolError::InvalidProvider)?;
            let model_id =
                ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
            return Ok(PoolSelection {
                upstream_id: Arc::from(static_upstream),
                upstream_model: static_model.map(Arc::from),
                account: None,
                lease: None,
                policy: None,
                explanation: None,
                model: model_id,
                provider,
                credential: None,
                affinity_key: None,
                registry_key: None,
            });
        };

        let registry_key = if model.is_some() {
            logical_model.to_owned()
        } else {
            route_registry_key(route.id())
        };
        let model_id =
            ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
        let Some(registry) = self.registries.get(&registry_key) else {
            self.record_no_eligible(
                route,
                model_id.as_str(),
                attempt,
                config.generation(),
                &policy,
                None,
            );
            return Err(PoolError::NoEligible {
                policy: policy.id().to_owned(),
            });
        };
        let mut request = SelectionRequest::new(model_id.clone())
            .with_strategy(config_strategy(policy.selection().strategy()))
            .with_route(RouteId::new(route.id()).map_err(|_| PoolError::Selection)?)
            .with_attempt(attempt)
            .with_generation(ConfigGeneration::new(config.generation()))
            .at(started);
        if let Some(allowed) = account_allow_list(config, &policy) {
            let ids = allowed
                .into_iter()
                .filter_map(|id| CredentialId::new(id).ok())
                .collect::<Vec<_>>();
            request = request.with_allowed_credentials(ids);
        }
        let affinity_key = affinity_value(&policy, headers)
            .and_then(|value| AffinityKey::new(value.as_bytes()).ok());
        if let Some(affinity) = policy.selection().affinity() {
            request = request.with_affinity_rebind(affinity.rebind());
            if let Some(value) = affinity_value(&policy, headers) {
                if let Ok(key) = AffinityKey::new(value.as_bytes()) {
                    request = request
                        .with_hashed_affinity_key(key.clone(), affinity.ttl())
                        .map_err(|_| PoolError::Selection)?;
                }
            }
        }

        let lease = match registry.select(request) {
            Ok(lease) => lease,
            Err(SelectionError::NoEligible { explanation, .. }) => {
                self.record_no_eligible(
                    route,
                    model_id.as_str(),
                    attempt,
                    config.generation(),
                    &policy,
                    Some(&explanation),
                );
                return Err(PoolError::NoEligible {
                    policy: policy.id().to_owned(),
                });
            }
            Err(_) => return Err(PoolError::Selection),
        };
        let registration = lease.registration().clone();
        let explanation = lease.explanation().clone();
        let provider = registration.provider().clone();
        let account_id = registration.credential().clone();
        let account = self.accounts.get(account_id.as_str()).cloned();
        let selected_model = config
            .models()
            .get(logical_model.as_str())
            .and_then(|plan| {
                plan.targets()
                    .iter()
                    .find(|target| target.provider() == provider.as_str())
            })
            .map(|target| target.upstream_model().to_owned())
            .or_else(|| static_model.map(str::to_owned));
        self.record_selection(
            route,
            &logical_model,
            attempt,
            config.generation(),
            &lease,
            selected_model.as_deref(),
        );
        Ok(PoolSelection {
            upstream_id: Arc::from(provider.as_str()),
            upstream_model: selected_model.map(Arc::from),
            account,
            lease: Some(lease),
            policy: Some(policy),
            explanation: Some(explanation),
            model: ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?,
            provider,
            credential: Some(account_id),
            affinity_key,
            registry_key: Some(Arc::from(registry_key)),
        })
    }

    /// Classify a pre-commit upstream failure, apply its health mutation, and
    /// decide whether the buffered request may be replayed.
    pub(crate) fn classify_failure(&self, input: FailureInput<'_>) -> PoolFailure {
        let FailureInput {
            config,
            route,
            selection,
            status,
            provider_code,
            message,
            retry_after,
            replay,
            idempotency_key_present,
            attempt,
            credentials_used,
            providers_used,
            elapsed_retry_delay,
            elapsed_recovery_wait,
            started,
        } = input;
        let classifier = HttpFailureClassifier;
        let mut classification = classifier.classify(&ObservedFailure {
            source: if status.is_some() {
                pooler_policy::FailureSource::Upstream
            } else {
                pooler_policy::FailureSource::Transport
            },
            status,
            provider_code,
            message,
            retry_after,
        });
        if selection.credential().is_some()
            && classification.classification.class == ErrorClass::CredentialQuotaExhausted
        {
            classification.credential_causation = pooler_policy::CredentialCausation::Proven;
        }
        let subject = HealthSubject {
            credential: selection.credential().cloned(),
            model: Some(selection.model().clone()),
            provider: Some(selection.provider().clone()),
            route: RouteId::new(route.id()).ok(),
        };
        let registry = self.registry_for(route, selection.model());
        let mutation = registry
            .map(|registry| registry.apply_failure(&classification, &subject, Instant::now()))
            .transpose()
            .ok()
            .flatten()
            .unwrap_or(HealthMutation::NoChange {
                reason: pooler_policy::HealthMutationReason::MissingCooldownTarget,
            });
        self.persist_failure(&classification, &subject, &mutation);

        let retry = selection.policy().map(|policy| {
            let retry_plan = policy.retry();
            let mut retry_policy = RetryPolicy::with_bounds(
                retry_plan.maximum_attempts(),
                retry_plan.maximum_credentials(),
                retry_plan.maximum_providers(),
                retry_plan.base_delay(),
                retry_plan.maximum_delay(),
                retry_plan.maximum_total_delay(),
                retry_plan
                    .maximum_recovery_wait()
                    .unwrap_or(retry_plan.maximum_total_delay()),
            )
            .unwrap_or_default();
            retry_policy = retry_policy.with_max_elapsed(retry_plan.maximum_elapsed());
            if status.is_some_and(|status| !retry_plan.allows_status(status)) {
                return RetryDecision::DoNotRetry {
                    reason: pooler_policy::RetryStopReason::ClassificationNotRetryable,
                };
            }
            let context = RetryContext::new(attempt, CommitmentState::Uncommitted, replay)
                .with_elapsed(started.elapsed())
                .with_used_targets(credentials_used, providers_used)
                .with_elapsed_retry_delay(elapsed_retry_delay)
                .with_elapsed_recovery_wait(elapsed_recovery_wait)
                .with_idempotency_key(idempotency_key_present);
            retry_policy.decide(&classification, context)
        });
        let decision = retry.unwrap_or(RetryDecision::DoNotRetry {
            reason: pooler_policy::RetryStopReason::ClassificationNotRetryable,
        });
        self.record_failure(
            route,
            selection,
            attempt,
            config.generation(),
            &classification,
            decision,
        );
        PoolFailure {
            classification,
            mutation,
            decision,
        }
    }

    /// Persist a newly selected affinity binding without storing raw keys.
    pub fn persist_affinity(&self, selection: &PoolSelection, now: Timestamp) {
        let Some(key) = selection.affinity_key() else {
            return;
        };
        let Some(credential) = selection.credential() else {
            return;
        };
        let Some(affinity) = selection
            .policy()
            .and_then(|policy| policy.selection().affinity())
        else {
            return;
        };
        let Some(registry_key) = selection.registry_key.as_deref() else {
            return;
        };
        let Some(expires_at) = now.checked_add(affinity.ttl().as_millis() as u64) else {
            return;
        };
        let binding = SessionAffinity::new(
            format!("{registry_key}|{}", key.as_str()),
            selection.provider().as_str(),
            credential.as_str(),
            selection
                .upstream_model()
                .unwrap_or(selection.model().as_str()),
            now,
            expires_at,
        );
        let _ = self.store.upsert_session_affinity(binding);
    }

    fn restore_account_state(&self, _config: &CompiledConfig) -> Result<(), PoolError> {
        for account in self.accounts.values() {
            let current = self
                .store
                .credential_state(account.id())
                .map_err(|_| PoolError::Store)?;
            let enabled = current
                .as_ref()
                .map_or(account.enabled(), |state| state.enabled);
            if current.is_none() {
                self.store
                    .upsert_credential_state(CredentialState::new(
                        account.id(),
                        account.provider(),
                        enabled,
                        timestamp_now(),
                    ))
                    .map_err(|_| PoolError::Store)?;
            }
            for registry in self.registries.values() {
                let id =
                    CredentialId::new(account.id()).map_err(|_| PoolError::InvalidCredential)?;
                registry
                    .set_enabled(&id, enabled)
                    .map_err(|_| PoolError::Selection)?;
                if let Some(health) = self
                    .store
                    .credential_health(account.id())
                    .map_err(|_| PoolError::Store)?
                {
                    if health.status == CredentialHealthStatus::Disabled {
                        let _ = registry.disable(id.clone());
                    }
                }
            }
        }
        self.restore_cooldowns()?;
        self.restore_affinities()?;
        Ok(())
    }

    fn restore_cooldowns(&self) -> Result<(), PoolError> {
        let now_wall = timestamp_now();
        let now_instant = Instant::now();
        for cooldown in self
            .store
            .cooldowns(now_wall)
            .map_err(|_| PoolError::Store)?
        {
            let remaining = cooldown.until.saturating_sub(now_wall);
            if remaining == 0 {
                continue;
            }
            let until = now_instant
                .checked_add(Duration::from_millis(remaining))
                .unwrap_or(now_instant);
            let Some((scope, registry_key)) = parse_cooldown_scope(&cooldown.scope, &cooldown.key)
            else {
                continue;
            };
            for (key, registry) in self.registries.iter() {
                if registry_key
                    .as_deref()
                    .is_some_and(|expected| expected != key.as_str())
                {
                    continue;
                }
                registry
                    .restore_cooldown(scope.clone(), until)
                    .map_err(|_| PoolError::Selection)?;
            }
        }
        Ok(())
    }

    fn restore_affinities(&self) -> Result<(), PoolError> {
        let now_wall = timestamp_now();
        let now_instant = Instant::now();
        for affinity in self
            .store
            .session_affinities(now_wall)
            .map_err(|_| PoolError::Store)?
        {
            let Some((registry_key, redacted_key)) = affinity.key.split_once('|') else {
                continue;
            };
            let remaining = affinity.expires_at.saturating_sub(now_wall);
            if remaining == 0 {
                continue;
            }
            let key = AffinityKey::from_redacted(redacted_key.to_owned())
                .map_err(|_| PoolError::Selection)?;
            let credential = CredentialId::new(affinity.credential_id)
                .map_err(|_| PoolError::InvalidCredential)?;
            let provider =
                ProviderId::new(affinity.provider_id).map_err(|_| PoolError::InvalidProvider)?;
            let model = self
                .registries
                .get(registry_key)
                .and_then(|registry| registry.registrations().ok())
                .and_then(|registrations| {
                    registrations
                        .into_iter()
                        .find(|registration| {
                            registration.credential() == &credential
                                && registration.provider() == &provider
                        })
                        .map(|registration| registration.model().clone())
                });
            let Some(model) = model else {
                continue;
            };
            let last_used = now_instant
                .checked_sub(Duration::from_millis(
                    now_wall.saturating_sub(affinity.last_used_at),
                ))
                .unwrap_or(now_instant);
            let expires = now_instant
                .checked_add(Duration::from_millis(remaining))
                .unwrap_or(now_instant);
            if let Some(registry) = self.registries.get(registry_key) {
                registry
                    .restore_affinity(key, credential, provider, model, last_used, expires)
                    .map_err(|_| PoolError::Selection)?;
            }
        }
        Ok(())
    }

    fn registry_for(&self, route: &RoutePlan, model: &ModelId) -> Option<Arc<CredentialRegistry>> {
        let key = if route.target().model_source().is_some() {
            model.as_str().to_owned()
        } else {
            route_registry_key(route.id())
        };
        self.registries.get(&key).cloned()
    }

    fn record_selection(
        &self,
        route: &RoutePlan,
        model: &str,
        attempt: u32,
        generation: u64,
        lease: &SelectionLease,
        upstream_model: Option<&str>,
    ) {
        let mut record =
            DecisionRecord::new(self.next_request_id(), route.id(), model, timestamp_now());
        record.attempt = attempt;
        record.configuration_generation = generation;
        record.selected_provider = Some(lease.registration().provider().to_string());
        record.selected_credential = Some(
            lease
                .explanation()
                .selected_credential_pseudonym()
                .map_or_else(|| "redacted".to_owned(), |value| value.as_str().to_owned()),
        );
        record.upstream_model = upstream_model.map(str::to_owned);
        record.candidates = lease
            .explanation()
            .candidates
            .iter()
            .map(|candidate| DecisionCandidate {
                provider_id: candidate.target.provider.to_string(),
                credential_id: Some(candidate.target.credential_pseudonym.as_str().to_owned()),
                score: candidate
                    .score
                    .map(|value| value as i64)
                    .unwrap_or_default(),
                eligible: candidate.is_eligible(),
                reason: (!candidate.filter_reasons.is_empty())
                    .then(|| format!("{:?}", candidate.filter_reasons)),
            })
            .collect();
        record.reason = Some("selected".to_owned());
        let _ = self.store.append_decision(record);
    }

    fn record_no_eligible(
        &self,
        route: &RoutePlan,
        model: &str,
        attempt: u32,
        generation: u64,
        policy: &PolicyPlan,
        explanation: Option<&SelectionExplanation>,
    ) {
        let mut record =
            DecisionRecord::new(self.next_request_id(), route.id(), model, timestamp_now());
        record.attempt = attempt;
        record.configuration_generation = generation;
        if let Some(explanation) = explanation {
            record.candidates = explanation
                .candidates
                .iter()
                .map(|candidate| DecisionCandidate {
                    provider_id: candidate.target.provider.to_string(),
                    credential_id: Some(candidate.target.credential_pseudonym.as_str().to_owned()),
                    score: candidate
                        .score
                        .map(|value| value as i64)
                        .unwrap_or_default(),
                    eligible: candidate.is_eligible(),
                    reason: (!candidate.filter_reasons.is_empty())
                        .then(|| format!("{:?}", candidate.filter_reasons)),
                })
                .collect();
        }
        record.reason = Some(format!(
            "no_eligible:policy={};affinity={:?}",
            policy.id(),
            explanation.map(|value| &value.affinity)
        ));
        let _ = self.store.append_decision(record);
    }

    fn record_failure(
        &self,
        route: &RoutePlan,
        selection: &PoolSelection,
        attempt: u32,
        generation: u64,
        classification: &FailureClassification,
        decision: RetryDecision,
    ) {
        let mut record = DecisionRecord::new(
            self.next_request_id(),
            route.id(),
            selection.model().as_str(),
            timestamp_now(),
        );
        record.attempt = attempt;
        record.configuration_generation = generation;
        record.selected_provider = Some(selection.provider().to_string());
        record.selected_credential = selection
            .explanation()
            .and_then(SelectionExplanation::selected_credential_pseudonym)
            .map(|value| value.as_str().to_owned());
        record.upstream_model = selection.upstream_model().map(str::to_owned);
        record.reason = Some(format!(
            "failure={:?};retry={:?};cooldown={:?}",
            classification.classification.class, decision, classification.cooldown
        ));
        let _ = self.store.append_decision(record);
    }

    fn persist_failure(
        &self,
        classification: &FailureClassification,
        subject: &HealthSubject,
        mutation: &HealthMutation,
    ) {
        let HealthMutation::CooldownApplied { scope, until } = mutation else {
            return;
        };
        let (scope_name, key) = cooldown_key(scope);
        let now_instant = Instant::now();
        let now_wall = timestamp_now();
        let until_ms = now_wall
            .saturating_add(until.saturating_duration_since(now_instant).as_millis() as u64);
        let mut cooldown = CooldownState::new(scope_name, key, until_ms, now_wall);
        cooldown.reason = Some(format!("{:?}", classification.classification.class));
        let _ = self.store.upsert_cooldown(cooldown);
        if let Some(credential) = subject.credential.as_ref() {
            if matches!(scope, CooldownScope::Credential(_)) {
                let _ = self.store.upsert_credential_health(CredentialHealthState {
                    credential_id: credential.to_string(),
                    status: CredentialHealthStatus::CoolingDown,
                    failure_count: 1,
                    cooldown_until: Some(unix_millis_from_instant(now_instant, *until)),
                    updated_at: now_wall,
                });
            }
        }
    }

    fn next_request_id(&self) -> String {
        let sequence = self
            .request_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        format!("pool-request-{sequence}")
    }
}

fn register_model_accounts(
    registry: &CredentialRegistry,
    model: &str,
    targets: &[pooler_config::ModelTargetPlan],
    accounts: &BTreeMap<String, AccountPlan>,
) -> Result<(), PoolError> {
    let model = ModelId::new(model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
    for account in accounts.values() {
        let Some(target) = targets
            .iter()
            .find(|target| target.provider() == account.provider())
        else {
            continue;
        };
        let registration = CredentialRegistration::from_strings(
            account.id(),
            account.provider(),
            model.as_str(),
            target.capabilities(),
        )
        .map_err(|_| PoolError::Selection)?
        .with_weight(account.weight())
        .map_err(|_| PoolError::Selection)?;
        let registration = match account.max_concurrency() {
            Some(max) => registration
                .with_max_in_flight(max)
                .map_err(|_| PoolError::Selection)?,
            None => registration,
        };
        registry
            .register(registration)
            .map_err(|_| PoolError::Selection)?;
    }
    Ok(())
}

fn register_route_accounts(
    registry: &CredentialRegistry,
    route_key: &str,
    upstream: &str,
    accounts: &BTreeMap<String, AccountPlan>,
) -> Result<(), PoolError> {
    let model = ModelId::new(route_key.to_owned()).map_err(|_| PoolError::InvalidModel)?;
    for account in accounts
        .values()
        .filter(|account| account.provider() == upstream)
    {
        let registration = CredentialRegistration::from_strings(
            account.id(),
            account.provider(),
            model.as_str(),
            CapabilitySet::new(),
        )
        .map_err(|_| PoolError::Selection)?
        .with_weight(account.weight())
        .map_err(|_| PoolError::Selection)?;
        let registration = match account.max_concurrency() {
            Some(max) => registration
                .with_max_in_flight(max)
                .map_err(|_| PoolError::Selection)?,
            None => registration,
        };
        registry
            .register(registration)
            .map_err(|_| PoolError::Selection)?;
    }
    Ok(())
}

fn resolve_static_target<'a>(
    config: &'a CompiledConfig,
    route: &'a RoutePlan,
    model: Option<&'a str>,
) -> Result<(String, &'a str, Option<&'a str>), PoolError> {
    if let Some(source) = route.target().model_source() {
        let model = model.ok_or(PoolError::InvalidModel)?;
        let plan = config
            .models()
            .get(model)
            .ok_or_else(|| PoolError::UnknownModel {
                model: model.to_owned(),
            })?;
        let target = plan.targets().first().ok_or(PoolError::UnknownModel {
            model: model.to_owned(),
        })?;
        let _ = source;
        return Ok((
            model.to_owned(),
            target.provider(),
            Some(target.upstream_model()),
        ));
    }
    Ok((
        model.unwrap_or(route.id()).to_owned(),
        route.target().upstream(),
        None,
    ))
}

fn route_registry_key(route: &str) -> String {
    format!("route:{route}")
}

fn config_strategy(strategy: ConfigSelectionStrategy) -> pooler_policy::SelectionStrategy {
    match strategy {
        ConfigSelectionStrategy::RoundRobin => pooler_policy::SelectionStrategy::RoundRobin,
        ConfigSelectionStrategy::SmoothWeightedRoundRobin => {
            pooler_policy::SelectionStrategy::SmoothWeightedRoundRobin
        }
        ConfigSelectionStrategy::FillFirst => pooler_policy::SelectionStrategy::FillFirst,
        ConfigSelectionStrategy::LeastInFlight => pooler_policy::SelectionStrategy::LeastInFlight,
        ConfigSelectionStrategy::HealthWeighted => pooler_policy::SelectionStrategy::HealthWeighted,
        ConfigSelectionStrategy::OrderedFallback => {
            pooler_policy::SelectionStrategy::OrderedFallback
        }
    }
}

fn account_allow_list(config: &CompiledConfig, policy: &PolicyPlan) -> Option<BTreeSet<String>> {
    let selection = policy.selection();
    if let Some(pool) = selection.account_pool().or(policy.account_pool()) {
        return config.account_pools().get(pool).map(|pool| {
            pool.accounts()
                .iter()
                .map(|account| account.to_string())
                .collect()
        });
    }
    if !selection.accounts().is_empty() {
        return Some(
            selection
                .accounts()
                .iter()
                .map(ToString::to_string)
                .collect(),
        );
    }
    None
}

fn affinity_value(policy: &PolicyPlan, headers: &HeaderMap) -> Option<String> {
    let key = policy.selection().affinity()?.key();
    if let Some(header_name) = key.strip_prefix("header:") {
        return headers
            .get(header_name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
    }
    match key {
        "request.session_id" | "semantic.session_id" | "devin.conversation_id" => headers
            .get("x-session-id")
            .or_else(|| headers.get("x-conversation-id"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        "devin.cascade_id" => headers
            .get("x-cascade-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        "devin.execution_id" => headers
            .get("x-execution-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        "openai.previous_response_id" => headers
            .get("x-previous-response-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        "anthropic.metadata" | "hash:selected_fields" => None,
        _ => None,
    }
}

fn cooldown_key(scope: &CooldownScope) -> (&'static str, String) {
    match scope {
        CooldownScope::Credential(id) => ("credential", id.to_string()),
        CooldownScope::CredentialModel { credential, model } => {
            ("credential_model", format!("{credential}:{model}"))
        }
        CooldownScope::Model(model) => ("model", model.to_string()),
        CooldownScope::Provider(provider) => ("provider", provider.to_string()),
        CooldownScope::ProviderModel { provider, model } => {
            ("provider_model", format!("{provider}:{model}"))
        }
        CooldownScope::Route(route) => ("route", route.to_string()),
    }
}

fn parse_cooldown_scope(scope: &str, key: &str) -> Option<(CooldownScope, Option<String>)> {
    let parse_id = |value: &str| ModelId::new(value.to_owned()).ok();
    match scope {
        "credential" => Some((
            CooldownScope::Credential(CredentialId::new(key.to_owned()).ok()?),
            None,
        )),
        "credential_model" => {
            let (credential, model) = key.split_once(':')?;
            Some((
                CooldownScope::CredentialModel {
                    credential: CredentialId::new(credential.to_owned()).ok()?,
                    model: parse_id(model)?,
                },
                None,
            ))
        }
        "model" => Some((CooldownScope::Model(parse_id(key)?), None)),
        "provider" => Some((
            CooldownScope::Provider(ProviderId::new(key.to_owned()).ok()?),
            None,
        )),
        "provider_model" => {
            let (provider, model) = key.split_once(':')?;
            Some((
                CooldownScope::ProviderModel {
                    provider: ProviderId::new(provider.to_owned()).ok()?,
                    model: parse_id(model)?,
                },
                None,
            ))
        }
        "route" => Some((
            CooldownScope::Route(RouteId::new(key.to_owned()).ok()?),
            Some(route_registry_key(key)),
        )),
        _ => None,
    }
}

pub(crate) fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

type Timestamp = u64;

fn unix_millis_from_instant(now: Instant, instant: Instant) -> Timestamp {
    timestamp_now().saturating_add(instant.saturating_duration_since(now).as_millis() as u64)
}

/// Apply one account secret to an outbound request.
pub(crate) fn apply_account_auth(
    headers: &mut HeaderMap,
    secret: Option<&SecretRef>,
) -> Result<bool, PoolError> {
    let Some(secret) = secret else {
        return Ok(false);
    };
    let reference = match secret {
        SecretRef::Env(name) => AuthSecretRef::Env(name.to_string()),
        SecretRef::File(path) => AuthSecretRef::File(path.as_ref().into()),
        SecretRef::Keyring { .. } | SecretRef::External(_) => return Err(PoolError::Store),
    };
    let value = reference.resolve().map_err(|_| PoolError::Store)?;
    if value.expose_secret().chars().any(char::is_whitespace) {
        return Err(PoolError::Store);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(7 + value.expose_bytes().len()));
    bytes.extend_from_slice(b"Bearer ");
    bytes.extend_from_slice(value.expose_bytes());
    let header = http::HeaderValue::from_bytes(&bytes).map_err(|_| PoolError::Store)?;
    headers.insert(header::AUTHORIZATION, header);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use pooler_config::compile_yaml;

    fn pooled_config(affinity: bool) -> CompiledConfig {
        let affinity = if affinity {
            "\n      affinity: {key: header:x-session, ttl: 10m, rebind: true}"
        } else {
            ""
        };
        compile_yaml(
            "pooling-test.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://127.0.0.1:1}}}}\naccounts:\n  first: {{provider: local, secret: env:POOLER_FIRST}}\n  second: {{provider: local, secret: env:POOLER_SECOND}}\naccount_pools:\n  pool: {{accounts: [first, second]}}\npolicies:\n  pooled:\n    selection:\n      strategy: ordered_fallback\n      account_pool: pool{affinity}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}}\nroutes:\n  - id: pooled\n    listen: local\n    target: {{provider: local, policy: pooled}}\n",
                affinity = affinity
            ),
        )
        .expect("pooling test config")
    }

    fn request_headers(session: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(session) = session {
            headers.insert("x-session", HeaderValue::from_str(session).expect("header"));
        }
        headers
    }

    #[test]
    fn malformed_upstream_request_does_not_cool_a_credential() {
        let config = pooled_config(false);
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let selection = coordinator
            .select(
                &config,
                route,
                None,
                &request_headers(None),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &selection,
            status: Some(400),
            provider_code: None,
            message: None,
            retry_after: None,
            replay: ReplayCheck::for_http_method("POST", false),
            idempotency_key_present: false,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert!(!failure.mutation.applied());
        assert!(!failure.decision.is_retry());
        let credential = selection.credential().expect("credential");
        assert!(coordinator
            .store
            .credential_health(credential.as_str())
            .expect("health lookup")
            .is_none());
    }

    #[test]
    fn provider_rate_limit_never_fakes_credential_causation() {
        let config = pooled_config(false);
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let first = coordinator
            .select(
                &config,
                route,
                None,
                &request_headers(None),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &first,
            status: Some(429),
            provider_code: Some("rate_limit".to_owned()),
            message: None,
            retry_after: Some(Duration::from_secs(30)),
            replay: ReplayCheck::for_http_method("POST", true),
            idempotency_key_present: true,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert_eq!(
            failure.classification.credential_causation,
            pooler_policy::CredentialCausation::Unknown
        );
        assert!(matches!(
            failure.mutation,
            HealthMutation::CooldownApplied {
                scope: pooler_policy::CooldownScope::Provider(_),
                ..
            }
        ));
        drop(first);
        assert!(matches!(
            coordinator.select(
                &config,
                route,
                None,
                &request_headers(None),
                2,
                Instant::now(),
            ),
            Err(PoolError::NoEligible { .. })
        ));
    }

    #[test]
    fn unavailable_affinity_target_rebinds_and_decision_is_explainable() {
        let config = pooled_config(true);
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let headers = request_headers(Some("session-1"));
        let first = coordinator
            .select(&config, route, None, &headers, 1, Instant::now())
            .expect("first selection");
        let first_credential = first.credential().expect("first credential").clone();
        let failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &first,
            status: Some(429),
            provider_code: Some("insufficient_quota".to_owned()),
            message: None,
            retry_after: Some(Duration::from_secs(30)),
            replay: ReplayCheck::for_http_method("POST", true),
            idempotency_key_present: true,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert!(failure.mutation.applied());
        drop(first);
        let second = coordinator
            .select(&config, route, None, &headers, 2, Instant::now())
            .expect("rebound selection");
        assert_ne!(second.credential(), Some(&first_credential));
        assert!(matches!(
            second
                .explanation()
                .map(|explanation| &explanation.affinity),
            Some(pooler_policy::AffinityDecision::Rebound { .. })
        ));
        assert!(coordinator.decision_count().expect("decision count") >= 2);
        assert!(coordinator
            .recent_decisions(4)
            .expect("recent decisions")
            .iter()
            .any(|record| record.reason.as_deref() == Some("selected")));
    }

    #[test]
    fn persisted_cooldown_and_affinity_rehydrate_with_real_expiry() {
        let config = pooled_config(true);
        let store = Arc::new(MemoryStore::new());
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let headers = request_headers(Some("session-restart"));
        let first = coordinator
            .select(&config, route, None, &headers, 1, Instant::now())
            .expect("first selection");
        let first_credential = first.credential().expect("credential").clone();
        coordinator.persist_affinity(&first, timestamp_now());
        let failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &first,
            status: Some(429),
            provider_code: Some("insufficient_quota".to_owned()),
            message: None,
            retry_after: Some(Duration::from_secs(30)),
            replay: ReplayCheck::for_http_method("POST", true),
            idempotency_key_present: true,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert!(failure.mutation.applied());
        drop(first);
        let now = timestamp_now();
        assert!(store
            .cooldowns(now)
            .expect("cooldowns")
            .iter()
            .any(|cooldown| cooldown.until > now));
        assert!(store
            .session_affinities(now)
            .expect("affinities")
            .iter()
            .any(|affinity| affinity.key.contains('|') && affinity.expires_at > now));

        let restarted =
            PoolingCoordinator::with_store(&config, store).expect("restart coordinator");
        let rebound = restarted
            .select(&config, route, None, &headers, 2, Instant::now())
            .expect("rehydrated selection");
        assert_ne!(rebound.credential(), Some(&first_credential));
        assert!(matches!(
            rebound
                .explanation()
                .map(|explanation| &explanation.affinity),
            Some(pooler_policy::AffinityDecision::Rebound { .. })
        ));
    }

    #[test]
    fn no_eligible_selection_is_persisted_as_a_decision() {
        let config = pooler_config::compile_yaml(
            "no-eligible.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  first: {provider: local, secret: env:POOLER_FIRST, enabled: false}
account_pools: {pool: {accounts: [first]}}
policies:
  pooled:
    selection: {strategy: ordered_fallback, account_pool: pool}
routes:
  - id: pooled
    listen: local
    target: {provider: local, policy: pooled}
"#,
        )
        .expect("config");
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("pooled").expect("route");
        assert!(matches!(
            coordinator.select(&config, route, None, &HeaderMap::new(), 1, Instant::now(),),
            Err(PoolError::NoEligible { .. })
        ));
        let decisions = coordinator.recent_decisions(1).expect("decision");
        assert!(decisions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("no_eligible:")));
        assert!(!decisions[0].candidates.is_empty());
    }
}
