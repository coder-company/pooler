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

use adapter_codex::CodexFailureClassifier;
use adapter_providers::AuthPlacement;
use http::HeaderMap;
use pooler_auth::SecretRef as AuthSecretRef;
use pooler_config::{
    AccountPlan, CompiledConfig, PolicyPlan, RoutePlan, SecretRef,
    SelectionStrategy as ConfigSelectionStrategy,
};
use pooler_core::{
    Capability, CapabilitySet, ConfigGeneration, CredentialId, ErrorClass, ModelDialect, ModelId,
    ProviderId, RouteId,
};
use pooler_model_catalog::{CatalogService, CatalogSnapshot};
use pooler_policy::{
    AffinityKey, CommitmentState, CooldownScope, CredentialRegistration, CredentialRegistry,
    FailureClassification, FailureClassifier, HealthMutation, HealthSubject, HttpFailureClassifier,
    ObservedFailure, PersistedQuotaSnapshot, ProviderNeutralQuotaClassifier, QuotaClassification,
    QuotaClassifier, QuotaObservation, QuotaProjectKey, QuotaScope, QuotaSignal, QuotaUnit,
    ReplayCheck, RetryContext, RetryDecision, RetryPolicy, SelectionError, SelectionExplanation,
    SelectionLease, SelectionRequest,
};
use pooler_store::{
    CooldownState, CredentialHealthState, CredentialHealthStatus, CredentialState,
    DecisionCandidate, DecisionRecord, MemoryStore, SessionAffinity, Store,
};
use thiserror::Error;

const TYPED_QUOTA_STORE_SCOPE: &str = "typed_quota_v1";

/// Request-local semantic information needed by account selection.
///
/// Raw identifiers are retained only until the selection decision is made;
/// [`AffinityKey`] hashes them before mutable state or diagnostics see them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelectionContext {
    model: Option<String>,
    required_capabilities: CapabilitySet,
    codec: Option<String>,
    affinity_values: BTreeMap<String, String>,
}

/// Attempt and monotonic-clock inputs for one selection operation.
#[derive(Clone, Copy, Debug)]
pub struct SelectionTiming {
    attempt: u32,
    started: Instant,
}

impl SelectionTiming {
    /// Construct request timing metadata.
    #[must_use]
    pub const fn new(attempt: u32, started: Instant) -> Self {
        Self { attempt, started }
    }
}

impl SelectionContext {
    /// Build selection requirements from a decoded semantic request.
    #[must_use]
    pub fn from_semantic_request(request: &pooler_protocol::SemanticRequest) -> Self {
        let mut context = Self::default();
        if !request.model.trim().is_empty() {
            context.model = Some(request.model.clone());
        }
        if !request.tools.is_empty() {
            context.require(Capability::Tools);
            context.require(Capability::FunctionCalling);
        }
        if request.tool_choice.is_some() {
            context.require(Capability::ToolChoice);
        }
        if request.reasoning.is_some() {
            context.require(Capability::Reasoning);
        }
        if request.continuation_id.is_some() {
            context.require(Capability::Continuation);
        }
        match request.response_format.as_ref() {
            Some(pooler_protocol::ResponseFormat::JsonObject) => {
                context.require(Capability::StructuredOutput);
            }
            Some(pooler_protocol::ResponseFormat::JsonSchema { .. }) => {
                context.require(Capability::StructuredOutput);
                context.require(Capability::JsonSchema);
            }
            Some(pooler_protocol::ResponseFormat::Text) | None => {}
        }
        for item in &request.input {
            context.require_input_capabilities(item);
        }
        if let Some(value) = request.session_id.as_deref() {
            context.with_affinity_value("request.session_id", value);
            context.with_affinity_value("semantic.session_id", value);
        }
        if let Some(value) = request.continuation_id.as_deref() {
            context.with_affinity_value("openai.previous_response_id", value);
        }
        context
    }

    /// Add a route-level requirement discovered by an adapter.
    pub const fn require(&mut self, capability: Capability) {
        self.required_capabilities.insert(capability);
    }

    /// Add a required codec identifier.
    pub fn with_codec(&mut self, codec: impl Into<String>) {
        let codec = codec.into();
        if !codec.trim().is_empty() {
            self.codec = Some(codec);
        }
    }

    /// Add one semantic affinity source.
    pub fn with_affinity_value(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.affinity_values.insert(key.into(), value);
        }
    }

    /// Required capabilities for this request.
    #[must_use]
    pub const fn required_capabilities(&self) -> CapabilitySet {
        self.required_capabilities
    }

    /// Public model identifier decoded from the request.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Required codec identifier, if the route has one.
    #[must_use]
    pub fn codec(&self) -> Option<&str> {
        self.codec.as_deref()
    }

    /// Look up a configured semantic affinity source.
    #[must_use]
    pub fn affinity_value(&self, key: &str) -> Option<&str> {
        self.affinity_values.get(key).map(String::as_str)
    }

    fn require_input_capabilities(&mut self, item: &pooler_protocol::InputItem) {
        use pooler_protocol::InputItem;

        match item {
            InputItem::Message(message) => {
                for content in &message.content {
                    self.require_content_capabilities(content);
                }
            }
            InputItem::ToolCall(_) | InputItem::ToolResult(_) => {
                self.require(Capability::Tools);
                self.require(Capability::FunctionCalling);
            }
            InputItem::Content(content) => self.require_content_capabilities(content),
            InputItem::Provider { .. } => {}
        }
    }

    fn require_content_capabilities(&mut self, content: &pooler_protocol::ContentPart) {
        use pooler_protocol::ContentPart;

        match content {
            ContentPart::Text { .. } => self.require(Capability::Text),
            ContentPart::Image { .. } => self.require(Capability::Images),
            ContentPart::File { .. } => self.require(Capability::Files),
            ContentPart::Audio { .. } => {
                self.require(Capability::Audio);
                self.require(Capability::InputAudio);
            }
            ContentPart::Reasoning(_) => self.require(Capability::Reasoning),
            ContentPart::ToolCall(_) | ContentPart::ToolResult(_) => {
                self.require(Capability::Tools);
                self.require(Capability::FunctionCalling);
            }
            ContentPart::Provider { .. } => {}
        }
    }
}

/// One selected upstream target and its short-lived account lease.
pub struct PoolSelection {
    upstream_id: Arc<str>,
    upstream_model: Option<Arc<str>>,
    dialect: ModelDialect,
    account: Option<AccountPlan>,
    lease: Option<SelectionLease>,
    policy: Option<PolicyPlan>,
    explanation: Option<SelectionExplanation>,
    model: ModelId,
    provider: ProviderId,
    credential: Option<CredentialId>,
    affinity_key: Option<AffinityKey>,
    registry_key: Option<Arc<str>>,
    selection_request: Option<SelectionRequest>,
}

impl std::fmt::Debug for PoolSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolSelection")
            .field("upstream_id", &self.upstream_id)
            .field("upstream_model", &self.upstream_model)
            .field("dialect", &self.dialect)
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

    /// Request-shaping deviations recorded for the selected upstream model.
    ///
    /// This is resolved after the account pool commits to a provider, so a
    /// failover to a different target carries that target's dialect rather
    /// than the one the first candidate would have used.
    #[must_use]
    pub const fn dialect(&self) -> ModelDialect {
        self.dialect
    }

    /// Account secret reference, if an account rather than static upstream
    /// authentication was selected.
    #[must_use]
    pub fn account_secret(&self) -> Option<&SecretRef> {
        self.account.as_ref().and_then(AccountPlan::secret)
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
#[derive(Debug)]
pub struct PoolFailure {
    pub classification: FailureClassification,
    pub mutation: HealthMutation,
    pub decision: RetryDecision,
    replacement: Option<PoolSelection>,
}

impl PoolFailure {
    /// Take the atomically reserved alternate selected for a quota retry.
    pub(crate) fn take_replacement(&mut self) -> Option<PoolSelection> {
        self.replacement.take()
    }
}

/// Inputs for one pre-commit failure decision.
pub(crate) struct FailureInput<'a> {
    pub config: &'a CompiledConfig,
    pub route: &'a RoutePlan,
    pub selection: &'a mut PoolSelection,
    pub status: Option<u16>,
    pub provider_code: Option<String>,
    pub message: Option<String>,
    pub native_codex: bool,
    pub quota_observations: &'a [QuotaObservation],
    pub retry_after: Option<Duration>,
    pub replay: ReplayCheck,
    pub commitment: CommitmentState,
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
    catalog: Option<Arc<CatalogService>>,
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
            register_route_accounts(
                &registry,
                route.id(),
                route.target().upstream(),
                route.target(),
                &accounts,
            )?;
            registries.insert(key, registry);
        }

        let coordinator = Self {
            registries: Arc::new(registries),
            accounts: Arc::new(accounts),
            store,
            request_sequence: Arc::new(AtomicU64::new(0)),
            catalog: None,
        };
        coordinator.restore_account_state(config)?;
        Ok(coordinator)
    }

    /// Rebuild the immutable registration view for a new configuration while
    /// retaining the same mutable store. Credential health, cooldowns,
    /// session affinity, decisions, and owner-selected enablement therefore
    /// survive a successful configuration generation swap.
    pub fn reconfigure(&self, config: &CompiledConfig) -> Result<Self, PoolError> {
        let mut coordinator = Self::with_store(config, Arc::clone(&self.store))?;
        coordinator.request_sequence = Arc::clone(&self.request_sequence);
        coordinator.catalog.clone_from(&self.catalog);
        Ok(coordinator)
    }

    /// Attach the atomically refreshed catalog used by request model selection.
    #[must_use]
    pub fn with_catalog(mut self, catalog: Arc<CatalogService>) -> Self {
        self.catalog = Some(catalog);
        self
    }

    /// Replace or clear the catalog attached to this coordinator.
    #[must_use]
    pub fn with_optional_catalog(mut self, catalog: Option<Arc<CatalogService>>) -> Self {
        self.catalog = catalog;
        self
    }

    /// Return the mutable state store shared by this coordinator.
    #[must_use]
    pub fn store(&self) -> Arc<dyn Store> {
        Arc::clone(&self.store)
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

    /// Return persisted credential enablement metadata for diagnostics.
    pub fn credential_states(&self) -> Result<Vec<pooler_store::CredentialState>, PoolError> {
        self.store.credential_states().map_err(|_| PoolError::Store)
    }

    /// Return persisted credential health metadata for diagnostics.
    pub fn credential_health_states(
        &self,
    ) -> Result<Vec<pooler_store::CredentialHealthState>, PoolError> {
        self.store
            .credential_health_states()
            .map_err(|_| PoolError::Store)
    }

    /// Return active provider/model/route cooldowns for diagnostics.
    pub fn cooldowns(&self) -> Result<Vec<pooler_store::CooldownState>, PoolError> {
        self.store
            .cooldowns(timestamp_now())
            .map_err(|_| PoolError::Store)
    }

    /// Disable one credential after provider evidence proves it needs
    /// interactive reauthorization. The state is persisted and removed from
    /// every model/route registry in this coordinator.
    pub fn disable_credential(&self, credential: &CredentialId) {
        let _ = self
            .store
            .set_credential_enabled(credential.as_str(), false, timestamp_now());
        for registry in self.registries.values() {
            let _ = registry.disable(credential.clone());
        }
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
        self.select_with_context(
            config,
            route,
            model,
            headers,
            &SelectionContext::default(),
            SelectionTiming::new(attempt, started),
        )
    }

    /// Select one target with decoded semantic requirements.
    pub fn select_with_context(
        &self,
        config: &CompiledConfig,
        route: &RoutePlan,
        model: Option<&str>,
        headers: &HeaderMap,
        context: &SelectionContext,
        timing: SelectionTiming,
    ) -> Result<PoolSelection, PoolError> {
        let policy = route
            .target()
            .policy()
            .and_then(|id| config.policies().get(id))
            .cloned();

        let requested_model =
            model.or_else(|| route.target().model_source().and_then(|_| context.model()));
        let catalog = self.catalog.as_ref().map(|catalog| catalog.snapshot());
        let (logical_model, static_upstream, static_model) =
            resolve_static_target(config, route, requested_model, catalog.as_deref())?;
        let Some(policy) = policy else {
            if selection_contract_is_declared(route, requested_model)
                && !target_satisfies_context(
                    config,
                    route,
                    requested_model,
                    &static_upstream,
                    context,
                    catalog.as_deref(),
                )
            {
                return Err(PoolError::Selection);
            }
            let provider =
                ProviderId::new(static_upstream.clone()).map_err(|_| PoolError::InvalidProvider)?;
            let model_id =
                ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
            let dialect = resolve_target_dialect(
                catalog.as_deref(),
                &logical_model,
                &static_upstream,
                static_model.as_deref(),
            );
            return Ok(PoolSelection {
                upstream_id: Arc::from(static_upstream),
                upstream_model: static_model.map(Arc::from),
                dialect,
                account: None,
                lease: None,
                policy: None,
                explanation: None,
                model: model_id,
                provider,
                credential: None,
                affinity_key: None,
                registry_key: None,
                selection_request: None,
            });
        };

        let registry_key = if requested_model.is_some() {
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
                timing.attempt,
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
            .with_attempt(timing.attempt)
            .with_generation(ConfigGeneration::new(config.generation()))
            .with_capabilities(required_capabilities_for_selection(
                route,
                requested_model,
                context,
            ))
            .at(timing.started);
        if let Some(codec) = required_codec_for_selection(route, requested_model, context) {
            request = request
                .with_codec(codec)
                .map_err(|_| PoolError::Selection)?;
        }
        if let Some(allowed) = account_allow_list(config, &policy) {
            let ids = allowed
                .into_iter()
                .filter_map(|id| CredentialId::new(id).ok())
                .collect::<Vec<_>>();
            request = request.with_allowed_credentials(ids);
        }
        let affinity_key = affinity_value(&policy, headers, context)
            .and_then(|value| AffinityKey::new(value.as_bytes()).ok());
        if let Some(affinity) = policy.selection().affinity() {
            request = request.with_affinity_rebind(affinity.rebind());
            if let Some(value) = affinity_value(&policy, headers, context) {
                if let Ok(key) = AffinityKey::new(value.as_bytes()) {
                    request = request
                        .with_hashed_affinity_key(key.clone(), affinity.ttl())
                        .map_err(|_| PoolError::Selection)?;
                }
            }
        }

        let selection_request = request.clone();
        let lease = match registry.select(request) {
            Ok(lease) => lease,
            Err(SelectionError::NoEligible { explanation, .. }) => {
                self.record_no_eligible(
                    route,
                    model_id.as_str(),
                    timing.attempt,
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
            .or(static_model);
        self.record_selection(
            route,
            &logical_model,
            timing.attempt,
            config.generation(),
            &lease,
            selected_model.as_deref(),
        );
        let dialect = resolve_target_dialect(
            catalog.as_deref(),
            &logical_model,
            provider.as_str(),
            selected_model.as_deref(),
        );
        Ok(PoolSelection {
            upstream_id: Arc::from(provider.as_str()),
            upstream_model: selected_model.map(Arc::from),
            dialect,
            account,
            lease: Some(lease),
            policy: Some(policy),
            explanation: Some(explanation),
            model: ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?,
            provider,
            credential: Some(account_id),
            affinity_key,
            registry_key: Some(Arc::from(registry_key)),
            selection_request: Some(selection_request),
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
            native_codex,
            quota_observations,
            retry_after,
            replay,
            commitment,
            idempotency_key_present,
            attempt,
            credentials_used,
            providers_used,
            elapsed_retry_delay,
            elapsed_recovery_wait,
            started,
        } = input;
        let quota_provider_code = provider_code.clone();
        let observed = ObservedFailure {
            source: if status.is_some() {
                pooler_policy::FailureSource::Upstream
            } else {
                pooler_policy::FailureSource::Transport
            },
            status,
            provider_code,
            message,
            retry_after,
        };
        let mut classification = if native_codex {
            CodexFailureClassifier::default().classify(&observed)
        } else {
            HttpFailureClassifier.classify(&observed)
        };
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
        let policy = selection.policy().cloned();
        let retry_policy = policy.as_ref().map(configured_retry_policy);
        let retry_context = RetryContext::new(attempt, commitment, replay)
            .with_elapsed(started.elapsed())
            .with_used_targets(credentials_used, providers_used)
            .with_elapsed_retry_delay(elapsed_retry_delay)
            .with_elapsed_recovery_wait(elapsed_recovery_wait)
            .with_idempotency_key(idempotency_key_present);
        let status_allows_retry = policy
            .as_ref()
            .is_some_and(|policy| status.is_none_or(|status| policy.retry().allows_status(status)));
        let now = Instant::now();
        let quotas = quota_classifications_for_failure(
            &classification,
            selection,
            quota_provider_code.as_deref(),
            retry_after,
            quota_observations,
            now,
        );
        let quota = quotas
            .iter()
            .filter(|quota| quota.exhausted(now))
            .max_by_key(|quota| quota.snapshot.reset_at);
        if let Some(typed) = quota.and_then(QuotaClassification::failure) {
            classification = typed.clone();
        }

        let mut replacement = None;
        let mut recovered = None;
        if status_allows_retry {
            if let (Some(registry), Some(quota), Some(retry_policy), Some(mut request)) = (
                registry.as_ref(),
                quota.as_ref(),
                retry_policy.as_ref(),
                selection.selection_request.clone(),
            ) {
                request.attempt = attempt.saturating_add(1);
                request.now = now;
                if let Some(credential) = selection.credential().cloned() {
                    request.excluded_credentials.insert(credential);
                }
                if let Some(lease) = selection.take_lease() {
                    if let Ok(recovery) = registry.recover_quota(
                        lease,
                        quota,
                        request.clone(),
                        retry_policy,
                        retry_context,
                    ) {
                        let mutation = recovery.health_mutation().clone();
                        let decision = recovery.retry_decision();
                        for observed in &quotas {
                            if let Some(credential) = selection.credential() {
                                let _ = registry.apply_quota_classification(credential, observed);
                            }
                            self.persist_quota_classification(selection, observed, registry, now);
                        }
                        replacement = recovery.into_selection().map(|lease| {
                            self.selection_from_recovery(config, route, selection, request, lease)
                        });
                        recovered = Some((mutation, decision));
                    }
                }
            }
        }

        let (mutation, decision) = recovered.unwrap_or_else(|| {
            if let (Some(registry), Some(credential)) = (registry.as_ref(), selection.credential())
            {
                for quota in &quotas {
                    let _ = registry.apply_quota_classification(credential, quota);
                    self.persist_quota_classification(selection, quota, registry, now);
                }
            }
            let mutation = registry
                .as_ref()
                .map(|registry| registry.apply_failure(&classification, &subject, now))
                .transpose()
                .ok()
                .flatten()
                .unwrap_or(HealthMutation::NoChange {
                    reason: pooler_policy::HealthMutationReason::MissingCooldownTarget,
                });
            let decision = if !status_allows_retry {
                RetryDecision::DoNotRetry {
                    reason: pooler_policy::RetryStopReason::ClassificationNotRetryable,
                }
            } else {
                retry_policy.as_ref().map_or(
                    RetryDecision::DoNotRetry {
                        reason: pooler_policy::RetryStopReason::ClassificationNotRetryable,
                    },
                    |retry_policy| retry_policy.decide(&classification, retry_context),
                )
            };
            (mutation, decision)
        });
        self.persist_failure(&classification, &subject, &mutation);
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
            replacement,
        }
    }

    fn selection_from_recovery(
        &self,
        config: &CompiledConfig,
        route: &RoutePlan,
        failed: &PoolSelection,
        request: SelectionRequest,
        lease: SelectionLease,
    ) -> PoolSelection {
        let registration = lease.registration().clone();
        let explanation = lease.explanation().clone();
        let provider = registration.provider().clone();
        let credential = registration.credential().clone();
        let upstream_model = config
            .models()
            .get(registration.model().as_str())
            .and_then(|model| {
                model
                    .targets()
                    .iter()
                    .find(|target| target.provider() == provider.as_str())
            })
            .map(|target| Arc::from(target.upstream_model()))
            .or_else(|| {
                (&provider == failed.provider())
                    .then(|| failed.upstream_model().map(Arc::from))
                    .flatten()
            });
        self.record_selection(
            route,
            registration.model().as_str(),
            request.attempt,
            config.generation(),
            &lease,
            upstream_model.as_deref(),
        );
        let dialect = resolve_target_dialect(
            self.catalog
                .as_ref()
                .map(|catalog| catalog.snapshot())
                .as_deref(),
            registration.model().as_str(),
            provider.as_str(),
            upstream_model.as_deref(),
        );
        PoolSelection {
            upstream_id: Arc::from(provider.as_str()),
            upstream_model,
            dialect,
            account: self.accounts.get(credential.as_str()).cloned(),
            lease: Some(lease),
            policy: failed.policy.clone(),
            explanation: Some(explanation),
            model: registration.model().clone(),
            provider,
            credential: Some(credential),
            affinity_key: failed.affinity_key.clone(),
            registry_key: failed.registry_key.clone(),
            selection_request: Some(request),
        }
    }

    fn persist_quota_classification(
        &self,
        failed: &PoolSelection,
        classification: &QuotaClassification,
        current: &Arc<CredentialRegistry>,
        now: Instant,
    ) {
        self.propagate_shared_quota(failed, classification, current);
        let now_wall = timestamp_now();
        for registry in self.registries.values() {
            let Ok(records) = registry.quota_state_records(now, now_wall) else {
                continue;
            };
            for record in records {
                let Some(until) = record.reset_at_unix_ms() else {
                    continue;
                };
                let Ok(reason) = serde_json::to_string(&record) else {
                    continue;
                };
                let Ok(key) = quota_store_key(&record) else {
                    continue;
                };
                let mut cooldown =
                    CooldownState::new(TYPED_QUOTA_STORE_SCOPE, key, until, now_wall);
                cooldown.reason = Some(reason);
                let _ = self.store.upsert_cooldown(cooldown);
            }
        }
    }

    fn propagate_shared_quota(
        &self,
        failed: &PoolSelection,
        classification: &QuotaClassification,
        current: &Arc<CredentialRegistry>,
    ) {
        if !matches!(
            classification.snapshot.scope,
            QuotaScope::Credential | QuotaScope::Project | QuotaScope::Provider
        ) {
            return;
        }
        let quota_project = failed
            .account
            .as_ref()
            .and_then(|account| account.quota_project())
            .and_then(|project| QuotaProjectKey::new(project).ok());
        for registry in self.registries.values() {
            if Arc::ptr_eq(registry, current) {
                continue;
            }
            let Ok(registrations) = registry.registrations() else {
                continue;
            };
            let matching = registrations.into_iter().find(|registration| {
                quota_registration_matches(
                    registration,
                    failed,
                    classification.snapshot.scope,
                    quota_project.as_ref(),
                )
            });
            if let Some(registration) = matching {
                let _ =
                    registry.set_quota_snapshot(registration.credential(), classification.snapshot);
            }
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
        self.restore_quota_states()?;
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

    fn restore_quota_states(&self) -> Result<(), PoolError> {
        let now_wall = timestamp_now();
        let now = Instant::now();
        for cooldown in self
            .store
            .cooldowns(now_wall)
            .map_err(|_| PoolError::Store)?
            .into_iter()
            .filter(|cooldown| cooldown.scope == TYPED_QUOTA_STORE_SCOPE)
        {
            let reason = cooldown.reason.as_deref().ok_or(PoolError::Store)?;
            let record: PersistedQuotaSnapshot =
                serde_json::from_str(reason).map_err(|_| PoolError::Store)?;
            if record.reset_at_unix_ms() != Some(cooldown.until) {
                return Err(PoolError::Store);
            }
            for registry in self.registries.values() {
                registry
                    .restore_quota_state(&record, now, now_wall)
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

fn configured_retry_policy(policy: &PolicyPlan) -> RetryPolicy {
    let retry = policy.retry();
    RetryPolicy::with_bounds(
        retry.maximum_attempts(),
        retry.maximum_credentials(),
        retry.maximum_providers(),
        retry.base_delay(),
        retry.maximum_delay(),
        retry.maximum_total_delay(),
        retry
            .maximum_recovery_wait()
            .unwrap_or(retry.maximum_total_delay()),
    )
    .unwrap_or_default()
    .with_max_elapsed(retry.maximum_elapsed())
}

fn quota_classifications_for_failure(
    failure: &FailureClassification,
    selection: &PoolSelection,
    provider_code: Option<&str>,
    retry_after: Option<Duration>,
    observations: &[QuotaObservation],
    now: Instant,
) -> Vec<QuotaClassification> {
    if selection.credential().is_none() {
        return Vec::new();
    }
    let classifier = ProviderNeutralQuotaClassifier::default();
    if !observations.is_empty() {
        return observations
            .iter()
            .cloned()
            .map(|mut observation| {
                if observation.scope == QuotaScope::Project
                    && selection
                        .account
                        .as_ref()
                        .and_then(AccountPlan::quota_project)
                        .is_none()
                    && selection.credential().is_some()
                {
                    observation.scope = QuotaScope::Credential;
                }
                classifier.classify(&observation, now)
            })
            .collect();
    }
    let project_scope = selection
        .account
        .as_ref()
        .and_then(AccountPlan::quota_project)
        .is_some()
        && provider_code.is_some_and(project_quota_marker);
    let (signal, scope) = match failure.classification.class {
        ErrorClass::CredentialQuotaExhausted => (
            QuotaSignal::Exhausted,
            if project_scope {
                QuotaScope::Project
            } else {
                QuotaScope::Credential
            },
        ),
        ErrorClass::ModelQuotaExhausted => (
            QuotaSignal::Exhausted,
            if project_scope {
                QuotaScope::ProjectModel
            } else {
                QuotaScope::CredentialModel
            },
        ),
        ErrorClass::ProviderRateLimited => (QuotaSignal::RateLimited, QuotaScope::Provider),
        _ => return Vec::new(),
    };
    let recovery = [failure.classification.recovery_after, retry_after]
        .into_iter()
        .flatten()
        .max();
    let mut observation =
        QuotaObservation::new(signal, scope, QuotaUnit::Requests).with_window(None, Some(0));
    if let Some(recovery) = recovery {
        observation = observation.with_reset_after(recovery);
    }
    if let Some(code) = provider_code {
        observation = observation.with_provider_code(code);
    }
    vec![classifier.classify(&observation, now)]
}

fn project_quota_marker(code: &str) -> bool {
    let code = code.to_ascii_lowercase();
    matches!(
        code.as_str(),
        "project_quota_exhausted"
            | "project_quota_exceeded"
            | "billing_project_quota_exhausted"
            | "billing_quota_exhausted"
            | "organization_quota_exhausted"
            | "tenant_quota_exhausted"
    )
}

fn quota_registration_matches(
    registration: &CredentialRegistration,
    failed: &PoolSelection,
    scope: QuotaScope,
    project: Option<&QuotaProjectKey>,
) -> bool {
    match scope {
        QuotaScope::Credential => failed
            .credential()
            .is_some_and(|credential| credential == registration.credential()),
        QuotaScope::Project => {
            registration.provider() == failed.provider() && registration.quota_project() == project
        }
        QuotaScope::Provider => registration.provider() == failed.provider(),
        QuotaScope::CredentialModel | QuotaScope::ProjectModel | QuotaScope::ProviderModel => false,
    }
}

fn quota_store_key(record: &PersistedQuotaSnapshot) -> Result<String, serde_json::Error> {
    serde_json::to_string(record)
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
        let registration = registration
            .with_codecs(target.codecs().iter().map(AsRef::as_ref))
            .map_err(|_| PoolError::Selection)?;
        let registration = with_account_quota_project(registration, account)?;
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
    target: &pooler_config::TargetPlan,
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
            target.capabilities(),
        )
        .map_err(|_| PoolError::Selection)?
        .with_weight(account.weight())
        .map_err(|_| PoolError::Selection)?;
        let registration = registration
            .with_codecs(target.codecs().iter().map(AsRef::as_ref))
            .map_err(|_| PoolError::Selection)?;
        let registration = with_account_quota_project(registration, account)?;
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

fn with_account_quota_project(
    registration: CredentialRegistration,
    account: &AccountPlan,
) -> Result<CredentialRegistration, PoolError> {
    let Some(project) = account.quota_project() else {
        return Ok(registration);
    };
    QuotaProjectKey::new(project)
        .map(|project| registration.with_quota_project(project))
        .map_err(|_| PoolError::Selection)
}

fn resolve_static_target(
    config: &CompiledConfig,
    route: &RoutePlan,
    model: Option<&str>,
    catalog: Option<&CatalogSnapshot>,
) -> Result<(String, String, Option<String>), PoolError> {
    if route.target().model_source().is_some() {
        let model = model.ok_or(PoolError::InvalidModel)?;
        if let Some(plan) = config.models().get(model) {
            let target = plan.targets().first().ok_or(PoolError::UnknownModel {
                model: model.to_owned(),
            })?;
            return Ok((
                model.to_owned(),
                target.provider().to_owned(),
                Some(target.upstream_model().to_owned()),
            ));
        }
        if let Some(target) = catalog
            .and_then(|catalog| catalog.get(model))
            .and_then(|model| model.targets().first())
        {
            return Ok((
                model.to_owned(),
                target.provider().to_string(),
                Some(target.upstream_model().to_string()),
            ));
        }
        return Err(PoolError::UnknownModel {
            model: model.to_owned(),
        });
    }
    Ok((
        model.unwrap_or(route.id()).to_owned(),
        route.target().upstream().to_owned(),
        None,
    ))
}

/// Resolve the dialect of the target the pool actually committed to.
///
/// A public model may map to several provider targets, and account failover can
/// commit to any of them, so the dialect is matched on the selected provider and
/// upstream model rather than taken from the first candidate. Statically
/// configured models carry no discovered facts and keep the protocol default.
fn resolve_target_dialect(
    catalog: Option<&CatalogSnapshot>,
    model: &str,
    provider: &str,
    upstream_model: Option<&str>,
) -> ModelDialect {
    let Some(upstream_model) = upstream_model else {
        return ModelDialect::DEFAULT;
    };
    catalog
        .and_then(|catalog| catalog.get(model))
        .and_then(|model| {
            model.targets().iter().find(|target| {
                target.provider().as_str() == provider
                    && target.upstream_model().as_str() == upstream_model
            })
        })
        .map_or(ModelDialect::DEFAULT, |target| target.dialect())
}

fn selection_contract_is_declared(route: &RoutePlan, model: Option<&str>) -> bool {
    model.is_some()
        || !route.target().capabilities().is_empty()
        || !route.target().codecs().is_empty()
}

fn required_capabilities_for_selection(
    route: &RoutePlan,
    model: Option<&str>,
    context: &SelectionContext,
) -> CapabilitySet {
    if selection_contract_is_declared(route, model) {
        context
            .required_capabilities()
            .union(route.target().capabilities())
    } else {
        route.target().capabilities()
    }
}

fn required_codec_for_selection<'a>(
    route: &RoutePlan,
    model: Option<&str>,
    context: &'a SelectionContext,
) -> Option<&'a str> {
    if selection_contract_is_declared(route, model) {
        context.codec()
    } else {
        None
    }
}

fn target_satisfies_context(
    config: &CompiledConfig,
    route: &RoutePlan,
    model: Option<&str>,
    static_upstream: &str,
    context: &SelectionContext,
    catalog: Option<&CatalogSnapshot>,
) -> bool {
    let (capabilities, codecs) = if let Some(model) = model {
        if let Some(plan) = config.models().get(model) {
            let Some(target) = plan
                .targets()
                .iter()
                .find(|target| target.provider() == static_upstream)
                .or_else(|| plan.targets().first())
            else {
                return false;
            };
            (target.capabilities(), target.codecs())
        } else {
            let Some(target) = catalog
                .and_then(|catalog| catalog.get(model))
                .and_then(|model| {
                    model
                        .targets()
                        .iter()
                        .find(|target| target.provider().as_str() == static_upstream)
                        .or_else(|| model.targets().first())
                })
            else {
                return false;
            };
            (target.capabilities(), &[][..])
        }
    } else {
        (route.target().capabilities(), route.target().codecs())
    };
    let required_capabilities = context
        .required_capabilities()
        .union(route.target().capabilities());
    capabilities.contains_all(required_capabilities)
        && context
            .codec()
            .is_none_or(|codec| codecs.iter().any(|value| value.as_ref() == codec))
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

fn affinity_value(
    policy: &PolicyPlan,
    headers: &HeaderMap,
    context: &SelectionContext,
) -> Option<String> {
    let key = policy.selection().affinity()?.key();
    if let Some(header_name) = key.strip_prefix("header:") {
        return headers
            .get(header_name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
    }
    match key {
        "request.session_id"
        | "semantic.session_id"
        | "devin.conversation_id"
        | "devin.cascade_id"
        | "devin.execution_id"
        | "openai.previous_response_id" => context
            .affinity_value(key)
            .map(str::to_owned)
            .or_else(|| semantic_header_value(key, headers)),
        "anthropic.metadata" | "hash:selected_fields" => None,
        _ => None,
    }
}

fn semantic_header_value(key: &str, headers: &HeaderMap) -> Option<String> {
    let header = match key {
        "request.session_id" | "semantic.session_id" | "devin.conversation_id" => {
            ["x-session-id", "x-conversation-id"]
                .into_iter()
                .find_map(|name| headers.get(name))
        }
        "devin.cascade_id" => headers.get("x-cascade-id"),
        "devin.execution_id" => headers.get("x-execution-id"),
        "openai.previous_response_id" => headers.get("x-previous-response-id"),
        _ => None,
    }?;
    header.to_str().ok().map(str::to_owned)
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

/// Apply one configured account secret using the upstream provider's auth kind.
pub fn apply_configured_account_auth(
    headers: &mut HeaderMap,
    secret: Option<&SecretRef>,
    configured_kind: Option<&str>,
) -> Result<bool, PoolError> {
    let Some(secret) = secret else {
        return Ok(false);
    };
    let reference = match secret {
        SecretRef::Env(name) => AuthSecretRef::Env(name.to_string()),
        SecretRef::File(path) => AuthSecretRef::File(path.as_ref().into()),
        SecretRef::Keyring { service, account } => AuthSecretRef::Keyring {
            service: service.to_string(),
            account: account.to_string(),
        },
    };
    let value = reference.resolve().map_err(|_| PoolError::Store)?;
    if value.expose_secret().chars().any(char::is_whitespace) {
        return Err(PoolError::Store);
    }
    let placement = AuthPlacement::from_configured_kind(configured_kind.unwrap_or("bearer_secret"))
        .map_err(|_| PoolError::Store)?;
    let authorization = placement
        .materialize(&value)
        .map_err(|_| PoolError::Store)?;
    authorization.apply_to(headers);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Barrier},
        thread,
    };

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

    fn project_quota_config() -> CompiledConfig {
        compile_yaml(
            "project-quota-test.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  first: {provider: local, secret: env:POOLER_FIRST, quota_project: shared-billing}
  second: {provider: local, secret: env:POOLER_SECOND, quota_project: shared-billing}
  third: {provider: local, secret: env:POOLER_THIRD, quota_project: alternate-billing}
account_pools:
  pool: {accounts: [first, second, third]}
policies:
  pooled:
    selection: {strategy: ordered_fallback, account_pool: pool}
    retry: {maximum_attempts: 3, maximum_credentials: 3, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}
routes:
  - id: pooled
    listen: local
    target: {provider: local, policy: pooled}
"#,
        )
        .expect("project quota config")
    }

    fn classify_quota_failure(
        coordinator: &PoolingCoordinator,
        config: &CompiledConfig,
        selection: &mut PoolSelection,
        commitment: CommitmentState,
        replay: ReplayCheck,
    ) -> PoolFailure {
        coordinator.classify_failure(FailureInput {
            config,
            route: config.route("pooled").expect("route"),
            selection,
            status: Some(429),
            provider_code: Some("project_quota_exhausted".to_owned()),
            message: None,
            native_codex: false,
            quota_observations: &[],
            retry_after: Some(Duration::from_secs(30)),
            replay,
            commitment,
            idempotency_key_present: true,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        })
    }

    #[test]
    fn selection_filters_model_capabilities_and_codecs_before_scoring() {
        let config = pooler_config::compile_yaml(
            "selection-requirements.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams:
  capable: {url: http://127.0.0.1:1}
  incomplete: {url: http://127.0.0.1:2}
accounts:
  capable: {provider: capable, secret: env:POOLER_CAPABLE}
  incomplete: {provider: incomplete, secret: env:POOLER_INCOMPLETE}
account_pools: {pool: {accounts: [capable, incomplete]}}
models:
  - id: public-model
    targets:
      - {provider: capable, upstream_model: capable-model, capabilities: [text, streaming], codecs: [decode.factory.language_model]}
      - {provider: incomplete, upstream_model: incomplete-model, capabilities: [streaming], codecs: [decode.other]}
policies:
  pooled:
    selection: {strategy: ordered_fallback, account_pool: pool}
routes:
  - id: model-route
    listen: local
    ingress: {mode: patch, inspectors: [inspect.openai.model]}
    target: {provider: capable, model_from: inspected.model, policy: pooled}
    response: {mode: opaque}
"#,
        )
        .expect("selection config");
        let route = config.route("model-route").expect("route");
        let mut semantic = pooler_protocol::SemanticRequest::new("public-model");
        semantic.push_message(pooler_protocol::Message::text(
            pooler_protocol::Role::User,
            "hello",
        ));
        let mut context = SelectionContext::from_semantic_request(&semantic);
        context.require(Capability::Streaming);
        context.with_codec("decode.factory.language_model");
        let selection = PoolingCoordinator::new(&config)
            .expect("coordinator")
            .select_with_context(
                &config,
                route,
                None,
                &HeaderMap::new(),
                &context,
                SelectionTiming::new(1, Instant::now()),
            )
            .expect("capable target selected");
        assert_eq!(selection.provider().as_str(), "capable");
        let candidates = selection
            .explanation()
            .expect("explanation")
            .candidates
            .iter()
            .find(|candidate| candidate.target.provider.as_str() == "incomplete")
            .expect("incomplete candidate");
        assert!(candidates
            .filter_reasons
            .iter()
            .any(|reason| matches!(reason, pooler_policy::FilterReason::MissingCapability(_))));
        assert!(candidates
            .filter_reasons
            .iter()
            .any(|reason| matches!(reason, pooler_policy::FilterReason::CodecUnavailable(_))));
    }

    #[test]
    fn static_target_contract_rejects_missing_capability_or_codec() {
        let config = pooler_config::compile_yaml(
            "static-selection-contract.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: semantic
    listen: local
    ingress: {mode: semantic, decoder: decode.factory.language_model}
    target: {provider: local, capabilities: [text], codecs: [decode.factory.language_model]}
    response: {mode: opaque}
"#,
        )
        .expect("static contract config");
        let route = config.route("semantic").expect("route");
        let mut semantic = pooler_protocol::SemanticRequest::new("public-model");
        semantic.push_message(pooler_protocol::Message::text(
            pooler_protocol::Role::User,
            "hello",
        ));
        let mut context = SelectionContext::from_semantic_request(&semantic);
        context.require(Capability::Streaming);
        context.with_codec("decode.other");
        let error = PoolingCoordinator::new(&config)
            .expect("coordinator")
            .select_with_context(
                &config,
                route,
                None,
                &HeaderMap::new(),
                &context,
                SelectionTiming::new(1, Instant::now()),
            )
            .expect_err("static target without requirements must not be selected");
        assert!(matches!(error, PoolError::Selection));
    }

    #[test]
    fn malformed_upstream_request_does_not_cool_a_credential() {
        let config = pooled_config(false);
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
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
            selection: &mut selection,
            status: Some(400),
            provider_code: None,
            message: None,
            native_codex: false,
            quota_observations: &[],
            retry_after: None,
            replay: ReplayCheck::for_http_method("POST", false),
            commitment: CommitmentState::Uncommitted,
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
        let mut first = coordinator
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
            selection: &mut first,
            status: Some(429),
            provider_code: Some("rate_limit".to_owned()),
            message: None,
            native_codex: false,
            quota_observations: &[],
            retry_after: Some(Duration::from_secs(30)),
            replay: ReplayCheck::for_http_method("POST", true),
            commitment: CommitmentState::Uncommitted,
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
        let mut first = coordinator
            .select(&config, route, None, &headers, 1, Instant::now())
            .expect("first selection");
        let first_credential = first.credential().expect("first credential").clone();
        let mut failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &mut first,
            status: Some(429),
            provider_code: Some("insufficient_quota".to_owned()),
            message: None,
            native_codex: false,
            quota_observations: &[],
            retry_after: Some(Duration::from_secs(30)),
            replay: ReplayCheck::for_http_method("POST", true),
            commitment: CommitmentState::Uncommitted,
            idempotency_key_present: true,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert!(failure.mutation.applied());
        let second = failure
            .take_replacement()
            .expect("quota recovery reserves the rebound selection");
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
        let mut first = coordinator
            .select(&config, route, None, &headers, 1, Instant::now())
            .expect("first selection");
        let first_credential = first.credential().expect("credential").clone();
        coordinator.persist_affinity(&first, timestamp_now());
        let failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &mut first,
            status: Some(429),
            provider_code: Some("insufficient_quota".to_owned()),
            message: None,
            native_codex: false,
            quota_observations: &[],
            retry_after: Some(Duration::from_secs(30)),
            replay: ReplayCheck::for_http_method("POST", true),
            commitment: CommitmentState::Uncommitted,
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

        let migrated = coordinator
            .reconfigure(&config)
            .expect("reconfigure coordinator");
        assert!(Arc::ptr_eq(&coordinator.store(), &migrated.store()));
        let rebound = migrated
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
    fn project_quota_uses_exact_config_group_and_restores_without_a_migration() {
        let config = project_quota_config();
        let store = Arc::new(MemoryStore::new());
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let mut failed = coordinator
            .select(&config, route, None, &HeaderMap::new(), 1, Instant::now())
            .expect("first project account");
        assert_eq!(failed.credential().map(CredentialId::as_str), Some("first"));

        let mut failure = classify_quota_failure(
            &coordinator,
            &config,
            &mut failed,
            CommitmentState::Uncommitted,
            ReplayCheck::safe(),
        );
        let replacement = failure
            .take_replacement()
            .expect("alternate project is reserved");
        assert_eq!(
            replacement.credential().map(CredentialId::as_str),
            Some("third")
        );
        drop(replacement);

        let persisted = store
            .cooldowns(timestamp_now())
            .expect("quota persistence")
            .into_iter()
            .filter(|state| state.scope == TYPED_QUOTA_STORE_SCOPE)
            .collect::<Vec<_>>();
        assert!(!persisted.is_empty());
        for state in &persisted {
            let record = state.reason.as_deref().expect("serialized quota record");
            assert!(!record.contains("shared-billing"));
            assert!(!record.contains("\"credential\":\"first\""));
        }

        let restarted =
            PoolingCoordinator::with_store(&config, store).expect("quota state restores");
        let selected = restarted
            .select(&config, route, None, &HeaderMap::new(), 2, Instant::now())
            .expect("restored project quota permits alternate project");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("third")
        );
    }

    #[test]
    fn remaining_high_regression_runtime_keeps_mixed_quota_dimensions() {
        let config = project_quota_config();
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let mut failed = coordinator
            .select(&config, route, None, &HeaderMap::new(), 1, Instant::now())
            .expect("first project account");
        let failed_credential = failed.credential().expect("credential").clone();
        let observations = [
            QuotaObservation::new(
                QuotaSignal::Snapshot,
                QuotaScope::Project,
                QuotaUnit::Requests,
            )
            .with_window(Some(100), Some(7))
            .with_reset_after(Duration::from_secs(2)),
            QuotaObservation::new(
                QuotaSignal::Exhausted,
                QuotaScope::Project,
                QuotaUnit::Tokens,
            )
            .with_window(Some(10_000), Some(0))
            .with_reset_after(Duration::from_secs(30)),
        ];
        let mut failure = coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &mut failed,
            status: Some(429),
            provider_code: Some("project_quota_exhausted".to_owned()),
            message: None,
            native_codex: false,
            quota_observations: &observations,
            retry_after: None,
            replay: ReplayCheck::safe(),
            commitment: CommitmentState::Uncommitted,
            idempotency_key_present: true,
            attempt: 1,
            credentials_used: 1,
            providers_used: 1,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert_eq!(
            failure
                .take_replacement()
                .expect("token exhaustion rotates projects")
                .credential()
                .map(CredentialId::as_str),
            Some("third")
        );
        let registry = coordinator
            .registry_for(route, failed.model())
            .expect("route registry");
        let mut snapshots = registry
            .quota_snapshots(&failed_credential, Instant::now())
            .expect("typed quota snapshots");
        snapshots.sort_by_key(|snapshot| snapshot.unit);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].unit, QuotaUnit::Requests);
        assert_eq!(snapshots[0].remaining, Some(7));
        assert_eq!(snapshots[1].unit, QuotaUnit::Tokens);
        assert_eq!(snapshots[1].remaining, Some(0));
    }

    #[test]
    fn quota_rotation_stays_inside_commit_and_replay_boundaries() {
        let config = project_quota_config();
        let route = config.route("pooled").expect("route");

        let committed = PoolingCoordinator::new(&config).expect("coordinator");
        let mut failed = committed
            .select(&config, route, None, &HeaderMap::new(), 1, Instant::now())
            .expect("selection");
        let mut failure = classify_quota_failure(
            &committed,
            &config,
            &mut failed,
            CommitmentState::Committed,
            ReplayCheck::safe(),
        );
        assert_eq!(
            failure.decision,
            RetryDecision::DoNotRetry {
                reason: pooler_policy::RetryStopReason::DownstreamCommitted,
            }
        );
        assert!(failure.take_replacement().is_none());

        let unsafe_replay = PoolingCoordinator::new(&config).expect("coordinator");
        let mut failed = unsafe_replay
            .select(&config, route, None, &HeaderMap::new(), 1, Instant::now())
            .expect("selection");
        let mut failure = classify_quota_failure(
            &unsafe_replay,
            &config,
            &mut failed,
            CommitmentState::Uncommitted,
            ReplayCheck::for_http_method("POST", false),
        );
        assert_eq!(
            failure.decision,
            RetryDecision::DoNotRetry {
                reason: pooler_policy::RetryStopReason::NotReplaySafe,
            }
        );
        assert!(failure.take_replacement().is_none());
    }

    #[test]
    fn concurrent_runtime_quota_failures_reserve_only_the_alternate_project() {
        const WORKERS: usize = 24;

        let config = Arc::new(project_quota_config());
        let coordinator = Arc::new(PoolingCoordinator::new(&config).expect("coordinator"));
        let ready = Arc::new(Barrier::new(WORKERS + 1));
        let (sender, receiver) = mpsc::channel();
        let mut workers = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let config = Arc::clone(&config);
            let coordinator = Arc::clone(&coordinator);
            let ready = Arc::clone(&ready);
            let sender = sender.clone();
            workers.push(thread::spawn(move || {
                let route = config.route("pooled").expect("route");
                let mut failed = coordinator
                    .select(&config, route, None, &HeaderMap::new(), 1, Instant::now())
                    .expect("initial account");
                assert_eq!(failed.credential().map(CredentialId::as_str), Some("first"));
                ready.wait();
                let mut failure = classify_quota_failure(
                    &coordinator,
                    &config,
                    &mut failed,
                    CommitmentState::Uncommitted,
                    ReplayCheck::safe(),
                );
                assert!(failure.decision.is_retry());
                let replacement = failure.take_replacement().unwrap_or_else(|| {
                    coordinator
                        .select(&config, route, None, &HeaderMap::new(), 2, Instant::now())
                        .expect("stale observation sees the installed project quota")
                });
                sender
                    .send(
                        replacement
                            .credential()
                            .expect("credential")
                            .as_str()
                            .to_owned(),
                    )
                    .expect("send result");
            }));
        }
        drop(sender);
        ready.wait();
        let selected = receiver.iter().take(WORKERS).collect::<Vec<_>>();
        assert_eq!(selected.len(), WORKERS);
        assert!(selected.iter().all(|credential| credential == "third"));
        for worker in workers {
            worker.join().expect("worker");
        }

        let final_selection = coordinator
            .select(
                &config,
                config.route("pooled").expect("route"),
                None,
                &HeaderMap::new(),
                2,
                Instant::now(),
            )
            .expect("post-recovery selection");
        assert_eq!(
            final_selection.credential().map(CredentialId::as_str),
            Some("third")
        );
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
