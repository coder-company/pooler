//! Request-local account selection and mutable pooling state.
//!
//! The coordinator is intentionally small: immutable route plans stay in
//! [`CompiledConfig`], while this value owns only selection cursors, health,
//! affinity, and redacted decision persistence.  A coordinator is shared by
//! every listener serving one compiled configuration.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use adapter_codex::CodexFailureClassifier;
use adapter_providers::{AuthPlacement, KimiAdapter};
use http::{HeaderMap, Uri};
use pooler_auth::SecretRef as AuthSecretRef;
use pooler_config::{
    AccountAuthKind, AccountPlan, CompiledConfig, PolicyPlan, RoutePlan, SecretRef,
    SelectionStrategy as ConfigSelectionStrategy, UpstreamPlan,
};
use pooler_core::{
    Capability, CapabilitySet, ConfigGeneration, CredentialId, ErrorClass, ModelDialect, ModelId,
    ModelProfile, ProviderId, RequestId, RouteId,
};
use pooler_model_catalog::{CatalogService, CatalogSnapshot, RequestOverlay};
use pooler_policy::{
    AffinityKey, BindingKey, CandidateFacts, CommitmentState, CooldownScope,
    CredentialRegistration, CredentialRegistry, FailureClassification, FailureClassifier,
    HealthMutation, HealthMutationReason, HealthSubject, HttpFailureClassifier, ObservedFailure,
    PersistedQuotaSnapshot, ProviderNeutralQuotaClassifier, QuotaClassification, QuotaClassifier,
    QuotaObservation, QuotaProjectKey, QuotaScope, QuotaSignal, QuotaUnit, ReplayCheck,
    RetryContext, RetryDecision, RetryPolicy, RetryStopReason, RetryTargetChange,
    RoutingRequirements, RoutingTelemetry, SelectionError, SelectionExplanation, SelectionLease,
    SelectionRequest, TelemetrySample,
};
use pooler_store::{
    ActivatedCredentialState, AffinityBindingIdentity, ConditionalCredentialMutation,
    CooldownState, CredentialConfigurationActivation, CredentialConfigurationIdentity,
    CredentialFingerprintRetirement, CredentialHealthState, CredentialHealthStatus,
    CredentialState, DecisionCandidate, DecisionRecord, MemoryStore, SessionAffinity, Store,
    StoreError,
};
use thiserror::Error;
use url::Url;

const TYPED_QUOTA_STORE_SCOPE: &str = "typed_quota_v1";
const MAX_DISABLED_MODELS: usize = 4_096;

/// The two historical streams written by the request lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceStream {
    /// Metadata-only request lifecycle events.
    RequestEvents,
    /// Metadata-only completed usage records.
    UsageRecords,
}

#[derive(Debug, Default)]
struct PersistenceStreamState {
    successful_writes: AtomicU64,
    lost_writes: AtomicU64,
    last_success_at_ms: AtomicU64,
    last_failure_at_ms: AtomicU64,
    last_failure_class: Mutex<Option<&'static str>>,
}

#[derive(Debug, Default)]
struct PersistenceStatusInner {
    enabled: AtomicBool,
    request_events: PersistenceStreamState,
    usage_records: PersistenceStreamState,
}

/// Bounded, process-local visibility into historical persistence.
///
/// This status intentionally stores only counters, timestamps, and a
/// fixed-vocabulary error class. It never retains storage error text, which
/// may contain paths or other operator-controlled values. The handle is
/// shared by all listeners serving one pooling coordinator.
#[derive(Clone, Debug, Default)]
pub struct PersistenceStatus {
    inner: Arc<PersistenceStatusInner>,
}

impl PersistenceStatus {
    /// Construct status for an enabled or disabled historical persistence
    /// stream. Pooler currently always mounts a store, but keeping this bit
    /// explicit lets management distinguish disabled persistence from an
    /// enabled store that has lost writes.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        let status = Self::default();
        status.inner.enabled.store(enabled, Ordering::Release);
        status
    }

    /// Record one successful write to a historical stream.
    pub fn record_success(&self, stream: PersistenceStream, recorded_at_ms: u64) {
        let state = self.stream(stream);
        state.successful_writes.fetch_add(1, Ordering::Relaxed);
        state
            .last_success_at_ms
            .store(recorded_at_ms, Ordering::Release);
    }

    /// Record one lost write using a fixed, redacted error class.
    pub fn record_failure(&self, stream: PersistenceStream, error: &StoreError) {
        let state = self.stream(stream);
        state.lost_writes.fetch_add(1, Ordering::Relaxed);
        state
            .last_failure_at_ms
            .store(timestamp_now(), Ordering::Release);
        *state
            .last_failure_class
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(store_error_class(error));
    }

    /// Return a redacted JSON snapshot suitable for management responses.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let request_events = self.stream_json(PersistenceStream::RequestEvents);
        let usage_records = self.stream_json(PersistenceStream::UsageRecords);
        let complete = self.inner.enabled.load(Ordering::Acquire)
            && request_events["complete"].as_bool().unwrap_or(false)
            && usage_records["complete"].as_bool().unwrap_or(false);
        serde_json::json!({
            "enabled": self.inner.enabled.load(Ordering::Acquire),
            "complete": complete,
            "request_events": request_events,
            "usage_records": usage_records,
        })
    }

    fn stream(&self, stream: PersistenceStream) -> &PersistenceStreamState {
        match stream {
            PersistenceStream::RequestEvents => &self.inner.request_events,
            PersistenceStream::UsageRecords => &self.inner.usage_records,
        }
    }

    fn stream_json(&self, stream: PersistenceStream) -> serde_json::Value {
        let state = self.stream(stream);
        let lost_writes = state.lost_writes.load(Ordering::Acquire);
        let last_success_at_ms = state.last_success_at_ms.load(Ordering::Acquire);
        let last_failure_at_ms = state.last_failure_at_ms.load(Ordering::Acquire);
        let last_failure_class = state
            .last_failure_class
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(str::to_owned);
        serde_json::json!({
            "complete": self.inner.enabled.load(Ordering::Acquire) && lost_writes == 0,
            "successful_writes": state.successful_writes.load(Ordering::Acquire),
            "lost_writes": lost_writes,
            "write_failures": lost_writes,
            "dropped_records": lost_writes,
            "last_success_at_ms": (last_success_at_ms != 0).then_some(last_success_at_ms),
            "last_failure_at_ms": (last_failure_at_ms != 0).then_some(last_failure_at_ms),
            "last_failure_class": last_failure_class,
        })
    }
}

fn store_error_class(error: &StoreError) -> &'static str {
    match error {
        StoreError::EmptyField { .. }
        | StoreError::InvalidRetention
        | StoreError::CredentialNotFound(_) => "validation",
        StoreError::DecisionIdExhausted
        | StoreError::RequestEventIdExhausted
        | StoreError::UsageRecordIdExhausted => "identifier_exhausted",
        StoreError::InvalidPath(_) | StoreError::UnsafePath(_) => "path",
        StoreError::Io(_) => "io",
        StoreError::Sqlite(_) => "database",
        StoreError::Serialization(_) => "serialization",
        StoreError::MasterKeyReferenceRejected
        | StoreError::MasterKeyUnavailable
        | StoreError::EmptyMasterKey
        | StoreError::EmptyCredentialPayload
        | StoreError::EncryptionRequired
        | StoreError::InvalidCredentialEnvelope
        | StoreError::UnsupportedCredentialEnvelopeVersion(_)
        | StoreError::UnsupportedCredentialEnvelopeAlgorithm
        | StoreError::WrongMasterKey
        | StoreError::CredentialEnvelopeAuthenticationFailed
        | StoreError::EncryptionFailed => "encryption",
        StoreError::CredentialRevisionConflict => "concurrency",
        StoreError::CredentialFingerprintConflict
        | StoreError::InvalidCredentialFingerprint
        | StoreError::InvalidAffinityBinding
        | StoreError::OwnerMismatch
        | StoreError::RecordExpired
        | StoreError::ManagementRevisionConflict
        | StoreError::ManagementCapacity
        | StoreError::ManagementSessionAlreadyExists
        | StoreError::OAuthFlowAlreadyExists
        | StoreError::OAuthFlowNotFound
        | StoreError::OAuthStateConflict
        | StoreError::ManagedSecretNotFound
        | StoreError::ManagedSecretRevisionConflict => "concurrency",
        StoreError::ManagedSecretEncryptionRequired => "encryption",
        StoreError::UnsupportedSchemaVersion(_) | StoreError::Migration { .. } => "migration",
        StoreError::LockPoisoned => "lock",
    }
}

/// Request-local semantic information needed by account selection.
///
/// Raw identifiers are retained only until the selection decision is made;
/// [`AffinityKey`] hashes them before mutable state or diagnostics see them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelectionContext {
    model: Option<String>,
    model_must_resolve: bool,
    required_capabilities: CapabilitySet,
    codec: Option<String>,
    affinity_values: BTreeMap<String, String>,
    routing: Option<RoutingRequirements>,
    fallback_depth: usize,
}

/// Attempt and monotonic-clock inputs for one selection operation.
#[derive(Clone, Copy, Debug)]
pub struct SelectionTiming {
    attempt: u32,
    _request_started: Instant,
}

impl SelectionTiming {
    /// Construct request timing metadata.
    #[must_use]
    pub const fn new(attempt: u32, request_started: Instant) -> Self {
        Self {
            attempt,
            _request_started: request_started,
        }
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

    /// Set the public model decoded by a provider-specific adapter.
    pub fn with_model(&mut self, model: impl Into<String>) {
        let model = model.into();
        if !model.trim().is_empty() {
            self.model = Some(model);
        }
    }

    /// Require the decoded model to resolve through the configured or
    /// discovered public model namespace before any upstream attempt.
    pub const fn require_known_model(&mut self) {
        self.model_must_resolve = true;
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

    /// Whether an adapter requires its decoded model to be a known public ID.
    #[must_use]
    pub const fn model_must_resolve(&self) -> bool {
        self.model_must_resolve
    }

    /// Required codec identifier, if the route has one.
    #[must_use]
    pub fn codec(&self) -> Option<&str> {
        self.codec.as_deref()
    }

    /// Compiled routing requirements attached by the config boundary.
    /// Adapters cannot populate this from request bodies.
    #[must_use]
    pub fn routing(&self) -> Option<&RoutingRequirements> {
        self.routing.as_ref()
    }

    /// Attach canonical routing requirements after request decoding.
    #[must_use]
    pub fn with_routing(mut self, routing: RoutingRequirements) -> Self {
        self.routing = Some(routing);
        self
    }

    fn with_fallback_depth(mut self, depth: usize) -> Self {
        self.fallback_depth = depth;
        self
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

/// Immutable metadata for one concrete model/target/account binding.
///
/// The policy registry owns eligibility and reservations; this index owns the
/// transport/model facts needed after a lease is selected. Keeping those facts
/// beside the composite binding prevents a later provider or route lookup from
/// silently recovering the wrong target.
#[derive(Clone)]
struct RuntimeBinding {
    binding: BindingKey,
    model: ModelId,
    provider: ProviderId,
    upstream_id: Arc<str>,
    upstream_model: Arc<str>,
    account: Option<AccountPlan>,
    pool_id: Option<Arc<str>>,
    priority: u32,
    capabilities: CapabilitySet,
    facts: CandidateFacts,
    wire_family: Option<Arc<str>>,
    endpoint_family: Option<Arc<str>>,
    profile: ModelProfile,
    request_overlay: RequestOverlay,
}

type RegistryMap = RwLock<BTreeMap<String, Arc<CredentialRegistry>>>;
type RegistryView = (
    BTreeMap<String, Arc<CredentialRegistry>>,
    BTreeMap<BindingKey, Arc<RuntimeBinding>>,
);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AccountMutationIdentity {
    account_id: String,
    provider_id: String,
    configuration_fingerprint: String,
}

impl AccountMutationIdentity {
    fn store_identity(&self) -> Result<CredentialConfigurationIdentity, PoolError> {
        CredentialConfigurationIdentity::new(
            &self.account_id,
            &self.provider_id,
            &self.configuration_fingerprint,
        )
        .map_err(|_| PoolError::InvalidCredential)
    }
}

#[derive(Clone)]
struct AccountEnablementChange {
    credential: CredentialId,
    identity: AccountMutationIdentity,
    enabled: bool,
}

#[derive(Default)]
struct AccountMutationState {
    gate: Mutex<Vec<RegisteredRegistryView>>,
    enablement: RwLock<BTreeMap<AccountMutationIdentity, bool>>,
}

struct RegisteredRegistryView {
    registries: Weak<RegistryMap>,
    accounts: BTreeSet<AccountMutationIdentity>,
}

struct LiveRegistryView {
    registries: Vec<Arc<CredentialRegistry>>,
    accounts: BTreeSet<AccountMutationIdentity>,
}

impl RuntimeBinding {
    fn profile_capabilities(&self) -> CapabilitySet {
        self.facts
            .capabilities
            .value()
            .copied()
            .unwrap_or(self.capabilities)
    }
}

/// One selected upstream target and its short-lived account lease.
pub struct PoolSelection {
    upstream_id: Arc<str>,
    upstream_model: Option<Arc<str>>,
    profile: ModelProfile,
    request_overlay: RequestOverlay,
    account: Option<AccountPlan>,
    lease: Option<SelectionLease>,
    policy: Option<PolicyPlan>,
    explanation: Option<SelectionExplanation>,
    model: ModelId,
    provider: ProviderId,
    credential: Option<CredentialId>,
    affinity_key: Option<AffinityKey>,
    binding_target: Option<Arc<RuntimeBinding>>,
    affinity_scope: Option<AffinityBindingIdentity>,
    affinity_scope_seed: Option<Arc<str>>,
    registry_key: Option<Arc<str>>,
    selection_request: Option<SelectionRequest>,
    /// Exclusions inserted only for the immediately preceding transport retry.
    /// They are removed before rebuilding the next canonical selection request.
    network_retry_exclusions: BTreeSet<BindingKey>,
}

impl PoolSelection {
    fn retry_selection_request(&self) -> Option<SelectionRequest> {
        let mut request = self.selection_request.clone()?;
        request
            .excluded_bindings
            .retain(|binding| !self.network_retry_exclusions.contains(binding));
        Some(request)
    }
}

#[derive(Clone)]
pub(crate) struct AffinityCommit {
    key: AffinityKey,
    credential: CredentialId,
    provider: ProviderId,
    upstream_model: String,
    registry_key: String,
    scope: AffinityBindingIdentity,
    ttl: Duration,
}

impl std::fmt::Debug for PoolSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolSelection")
            .field("upstream_id", &self.upstream_id)
            .field("upstream_model", &self.upstream_model)
            .field("profile", &self.profile)
            .field("request_overlay", &self.request_overlay)
            .field("provider", &self.provider)
            .field("has_account", &self.account.is_some())
            .field("has_lease", &self.lease.is_some())
            .field(
                "binding_target",
                &self.binding_target.as_ref().map(|target| &target.binding),
            )
            .field(
                "wire_family",
                &self
                    .binding_target
                    .as_ref()
                    .and_then(|target| target.wire_family.as_deref()),
            )
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

    /// Build the authoritative endpoint for the selected provider binding.
    ///
    /// The route's upstream is only an admission/selection anchor. Once a
    /// model target has committed, its provider origin, provider path, and
    /// required query belong to that selected binding. Callers append no
    /// route-derived origin after this boundary.
    pub fn upstream_uri(
        &self,
        config: &CompiledConfig,
        route: &RoutePlan,
        downstream: &Uri,
    ) -> Result<Uri, PoolError> {
        let upstream = config
            .upstreams()
            .get(self.upstream_id())
            .ok_or(PoolError::InvalidUpstreamUri)?;
        self.upstream_uri_for(upstream, route, downstream)
    }

    /// Build an endpoint from the transport chosen for this attempt.
    ///
    /// Semantic routes may select an account through an HTTP provider and then
    /// use its explicit WebSocket sibling. The binding still owns path and
    /// query semantics, while the resolved attempt upstream owns the origin.
    pub(crate) fn upstream_uri_for(
        &self,
        upstream: &UpstreamPlan,
        route: &RoutePlan,
        downstream: &Uri,
    ) -> Result<Uri, PoolError> {
        let endpoint_family = if upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
        {
            match route.target().endpoint_family() {
                Some("image_generations") => Some("image_generations"),
                _ => Some("responses"),
            }
        } else {
            self.endpoint_family_for(route)
        };
        let path = provider_endpoint_path(
            upstream,
            route.target().path(),
            downstream.path(),
            endpoint_family,
        )?;
        let mut url = upstream.url().clone();
        url.set_path(&path);
        merge_downstream_query(&mut url, downstream.query());
        apply_required_query(&mut url, upstream.query());
        url.as_str()
            .parse()
            .map_err(|_| PoolError::InvalidUpstreamUri)
    }

    /// Endpoint family supported by the selected model target. Prefer the
    /// caller's route family when that target supports it; otherwise use the
    /// target's native family and let the semantic bridge translate.
    pub(crate) fn endpoint_family_for<'a>(&'a self, route: &'a RoutePlan) -> Option<&'a str> {
        let requested = route.target().endpoint_family();
        let Some(target) = self.binding_target.as_ref() else {
            return requested;
        };
        // Substituting the target's family rewrites the request onto a
        // different upstream surface, so it is only correct when the profile
        // positively reports the requested family as unavailable. A family the
        // profile does not model leaves the route's declaration authoritative.
        if requested
            .is_some_and(|family| endpoint_family_supported(target.profile, family).unwrap_or(true))
        {
            return requested;
        }
        target.endpoint_family.as_deref().or(requested)
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
        self.profile.dialect
    }

    /// Evidence-backed facts for the selected upstream model.
    #[must_use]
    pub const fn profile(&self) -> ModelProfile {
        self.profile
    }

    /// Request body fields an operator pinned for the selected public model.
    ///
    /// These are keyed by the public model the caller asked for rather than by
    /// the committed target, so a failover to another provider still applies
    /// the operator's intent for that model.
    #[must_use]
    pub const fn request_overlay(&self) -> &RequestOverlay {
        &self.request_overlay
    }

    /// Account secret reference, if an account rather than static upstream
    /// authentication was selected.
    #[must_use]
    pub fn account_secret(&self) -> Option<&SecretRef> {
        self.account.as_ref().and_then(AccountPlan::secret)
    }

    /// Selected account authentication kind, without exposing its secret.
    #[must_use]
    pub fn account_auth_kind(&self) -> Option<AccountAuthKind> {
        self.account.as_ref().map(AccountPlan::auth_kind)
    }

    /// Exact target/account binding selected for this attempt.
    #[must_use]
    pub fn binding_key(&self) -> Option<&BindingKey> {
        self.lease.as_ref().map(SelectionLease::binding_key)
    }

    /// Stable target-binding identifier for this attempt.
    #[must_use]
    pub fn target_binding_id(&self) -> Option<&str> {
        self.binding_target
            .as_ref()
            .map(|target| target.binding.target_id().as_str())
    }

    /// Positive priority tier selected for this attempt.
    #[must_use]
    pub fn priority_tier(&self) -> Option<u32> {
        self.binding_target.as_ref().map(|target| target.priority)
    }

    /// Homogeneous account-pool identity selected for this attempt.
    #[must_use]
    pub fn account_pool_id(&self) -> Option<&str> {
        self.binding_target
            .as_ref()
            .and_then(|target| target.pool_id.as_deref())
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

    pub(crate) fn affinity_commit(&self) -> Option<AffinityCommit> {
        let key = self.affinity_key.clone()?;
        let credential = self.credential.clone()?;
        let registry_key = self.registry_key.as_deref()?.to_owned();
        let scope = self.affinity_scope.clone()?;
        let ttl = self.policy()?.selection().affinity()?.ttl();
        Some(AffinityCommit {
            key,
            credential,
            provider: self.provider.clone(),
            upstream_model: self
                .upstream_model()
                .unwrap_or(self.model().as_str())
                .to_owned(),
            registry_key,
            scope,
            ttl,
        })
    }
}

/// Whether a model profile supports an endpoint family.
///
/// `None` means the profile records no variant for this family and so has no
/// opinion about it. That is distinct from `Some(false)`, which is positive
/// evidence that the family is unavailable, and callers must not conflate the
/// two: most families a route can name, such as `responses_compact`,
/// `embeddings`, or `models`, are not modelled as variants at all.
fn endpoint_family_supported(profile: ModelProfile, family: &str) -> Option<bool> {
    let variants = profile.endpoint_variants;
    match family {
        "responses" => Some(variants.responses),
        "chat_completions" => Some(variants.chat_completions),
        "messages" => Some(variants.messages),
        "generate_content" => Some(variants.generate_content),
        "realtime" => Some(variants.realtime),
        _ => None,
    }
}

const PALANTIR_OPENAI_PROXY_PREFIX: &str = "/api/v2/llm/proxy/openai";
const PALANTIR_ANTHROPIC_PROXY_PREFIX: &str = "/api/v2/llm/proxy/anthropic";

fn provider_endpoint_path(
    upstream: &pooler_config::UpstreamPlan,
    route_path: Option<&str>,
    downstream_path: &str,
    endpoint_family: Option<&str>,
) -> Result<String, PoolError> {
    let requested_path = route_path.unwrap_or(downstream_path);
    let requested_canonical = canonical_provider_path(requested_path);
    // A route that names its upstream path states the operator's contract with
    // this provider, including a non-standard one. The endpoint family only
    // supplies the conventional path when the route leaves it unset.
    let canonical = if route_path.is_some() {
        requested_canonical
    } else {
        endpoint_family
            .and_then(normalize_endpoint_family)
            .map(endpoint_family_path)
            .unwrap_or(requested_canonical)
    };
    if upstream
        .native()
        .is_some_and(|native| native.kind().eq_ignore_ascii_case("palantir_aip"))
    {
        let family = endpoint_family
            .and_then(normalize_endpoint_family)
            .or_else(|| path_endpoint_family(canonical))
            .ok_or(PoolError::InvalidUpstreamUri)?;
        let prefix = match family {
            "messages" => PALANTIR_ANTHROPIC_PROXY_PREFIX,
            "chat_completions" | "responses" => PALANTIR_OPENAI_PROXY_PREFIX,
            _ => return Err(PoolError::InvalidUpstreamUri),
        };
        let exact_path = (family == "messages" && canonical == "/v1/messages")
            || (family == "chat_completions" && canonical == "/v1/chat/completions")
            || (family == "responses" && canonical == "/v1/responses");
        if requested_path.starts_with(prefix) && exact_path {
            return Ok(requested_path.to_owned());
        }
        return Ok(format!("{prefix}{canonical}"));
    }

    if upstream
        .known_provider()
        .is_some_and(|provider| provider.eq_ignore_ascii_case("kimi-for-coding"))
    {
        return KimiAdapter::coding_subscription()
            .map_err(|_| PoolError::InvalidUpstreamUri)?
            .openai_endpoint_path(canonical)
            .map_err(|_| PoolError::InvalidUpstreamUri);
    }

    // A Palantir route can be reused by another target only after its
    // enrollment prefix is removed. This is the important anti-anchor fence:
    // a selected generic provider never receives another provider's path. Its
    // own configured API base path is still authoritative.
    Ok(provider_api_base_path(upstream.url().path(), canonical))
}

fn provider_api_base_path(base_path: &str, canonical: &str) -> String {
    let Some(suffix) = canonical
        .strip_prefix("/v1")
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
    else {
        return canonical.to_owned();
    };
    let base = base_path.trim_end_matches('/');
    if base.is_empty() {
        return canonical.to_owned();
    }
    if suffix.is_empty() || base.ends_with(suffix) {
        return base.to_owned();
    }
    format!("{base}{suffix}")
}

fn canonical_provider_path(path: &str) -> &str {
    path.strip_prefix(PALANTIR_OPENAI_PROXY_PREFIX)
        .or_else(|| path.strip_prefix(PALANTIR_ANTHROPIC_PROXY_PREFIX))
        .unwrap_or(path)
}

fn normalize_endpoint_family(value: &str) -> Option<&'static str> {
    match value {
        "chat" | "chat_completions" | "openai_chat" => Some("chat_completions"),
        "responses" | "openai_responses" => Some("responses"),
        "messages" | "anthropic_messages" => Some("messages"),
        "images" | "image_generations" => Some("image_generations"),
        _ => None,
    }
}

fn endpoint_family_path(family: &str) -> &'static str {
    match family {
        "chat_completions" => "/v1/chat/completions",
        "responses" => "/v1/responses",
        "messages" => "/v1/messages",
        "image_generations" => "/v1/images/generations",
        _ => unreachable!("endpoint family is normalized before path selection"),
    }
}

fn path_endpoint_family(path: &str) -> Option<&'static str> {
    if path.ends_with("/chat/completions") {
        Some("chat_completions")
    } else if path.ends_with("/responses") {
        Some("responses")
    } else if path.ends_with("/messages") {
        Some("messages")
    } else {
        None
    }
}

fn merge_downstream_query(url: &mut Url, downstream: Option<&str>) {
    let base = url
        .query()
        .filter(|query| !query.is_empty())
        .map(str::to_owned);
    let merged = match (
        base.as_deref(),
        downstream.filter(|query| !query.is_empty()),
    ) {
        (Some(base), Some(downstream)) => Some(format!("{base}&{downstream}")),
        (Some(base), None) => Some(base.to_owned()),
        (None, Some(downstream)) => Some(downstream.to_owned()),
        (None, None) => None,
    };
    url.set_query(merged.as_deref());
}

fn apply_required_query(url: &mut Url, required: &[(Arc<str>, Arc<str>)]) {
    for (name, value) in required {
        if url
            .query_pairs()
            .any(|(existing, _)| existing == name.as_ref())
        {
            continue;
        }
        url.query_pairs_mut().append_pair(name, value);
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
    /// Take the request-local alternate reserved for this retry.
    pub(crate) fn take_replacement(&mut self) -> Option<PoolSelection> {
        self.replacement.take()
    }

    /// Return the stable metadata-only reason for a no-change health mutation.
    pub(crate) fn health_mutation_reason(&self) -> Option<&'static str> {
        let HealthMutation::NoChange { reason } = &self.mutation else {
            return None;
        };
        Some(match reason {
            HealthMutationReason::CredentialDisabled => "credential_disabled",
            HealthMutationReason::CredentialDisableNotPersisted => {
                "credential_disable_not_persisted"
            }
            HealthMutationReason::CredentialGenerationChanged => "credential_generation_changed",
            HealthMutationReason::CredentialUnavailable => "credential_unavailable",
            HealthMutationReason::NoCooldownRequested => "no_cooldown_requested",
            HealthMutationReason::InvalidRequestCannotCooldownCredential => {
                "invalid_request_cannot_cooldown_credential"
            }
            HealthMutationReason::MissingCooldownTarget => "missing_cooldown_target",
            HealthMutationReason::ZeroCooldown => "zero_cooldown",
        })
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
    pub credentials_used: &'a BTreeSet<CredentialId>,
    pub providers_used: &'a BTreeSet<ProviderId>,
    pub elapsed_retry_delay: Duration,
    pub elapsed_recovery_wait: Duration,
    pub started: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OAuthCredentialMutation {
    Applied,
    DisableNotPersisted,
    GenerationAdvanced,
    Unavailable,
}

/// Inputs for replacing one native OAuth credential that requires interactive reauthentication.
pub(crate) struct NativeReauthInput<'a> {
    pub config: &'a CompiledConfig,
    pub route: &'a RoutePlan,
    pub selection: &'a mut PoolSelection,
    pub replay: ReplayCheck,
    pub commitment: CommitmentState,
    pub idempotency_key_present: bool,
    pub attempt: u32,
    /// Token generation whose provider response required reauthorization.
    pub failed_generation: u64,
    /// Whether token and metadata generations share a durable CAS domain.
    pub generation_fenced: bool,
    /// Runtime-specific provider bindings that recovery candidates must support.
    pub native_runtime: Option<&'a crate::NativeRuntime>,
    /// Whether the failed authorization followed a physical provider send.
    pub outbound_attempt_consumed: bool,
    pub credentials_used: &'a BTreeSet<CredentialId>,
    pub providers_used: &'a BTreeSet<ProviderId>,
    pub elapsed_retry_delay: Duration,
    pub elapsed_recovery_wait: Duration,
    pub started: Instant,
}

struct NetworkRetryInput<'a> {
    config: &'a CompiledConfig,
    route: &'a RoutePlan,
    failed: &'a mut PoolSelection,
    registry: &'a CredentialRegistry,
    retry_policy: &'a RetryPolicy,
    classification: &'a FailureClassification,
    fallback_decision: RetryDecision,
    retry_context: RetryContext,
    credentials_used: &'a BTreeSet<CredentialId>,
    providers_used: &'a BTreeSet<ProviderId>,
    attempt: u32,
    now: Instant,
}

struct NetworkRetryOutcome {
    replacement: Option<PoolSelection>,
    decision: RetryDecision,
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
    #[error("model `{model}` is disabled by the operator")]
    ModelDisabled { model: String },
    #[error("model `{model}` is not configured")]
    UnknownModel { model: String },
    #[error("pool policy `{policy}` has no eligible account")]
    NoEligible { policy: String },
    #[error("pool state unavailable")]
    Store,
    #[error("selection state unavailable")]
    Selection,
    #[error("selected provider endpoint is invalid")]
    InvalidUpstreamUri,
}

/// A fully built pooling generation that has not entered shared account
/// topology and has not changed durable credential identity state.
pub struct PreparedPoolingCoordinator {
    coordinator: Arc<PoolingCoordinator>,
    activations: Vec<CredentialConfigurationActivation>,
    activated: AtomicBool,
}

impl PreparedPoolingCoordinator {
    /// Borrow the candidate coordinator while constructing generation proxies.
    #[must_use]
    pub fn coordinator(&self) -> Arc<PoolingCoordinator> {
        Arc::clone(&self.coordinator)
    }

    /// Commit the exact prepared credential identities and publish this
    /// candidate into the shared account-mutation topology.
    pub fn activate(&self) -> Result<(), PoolError> {
        if self.activated.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut views = self
            .coordinator
            .account_mutations
            .gate
            .lock()
            .map_err(|_| PoolError::Selection)?;
        if self.activated.load(Ordering::Acquire) {
            return Ok(());
        }
        let activated = self
            .coordinator
            .store
            .activate_credential_configurations(&self.activations)
            .map_err(|_| PoolError::Store)?;
        self.coordinator
            .apply_activated_account_states(&activated)?;
        self.coordinator.register_registry_view_locked(&mut views)?;
        self.activated.store(true, Ordering::Release);
        Ok(())
    }
}

/// Shared mutable account-pooling state for one compiled configuration.
#[derive(Clone)]
pub struct PoolingCoordinator {
    registries: Arc<RegistryMap>,
    binding_index: Arc<RwLock<BTreeMap<BindingKey, Arc<RuntimeBinding>>>>,
    registry_view_gate: Arc<RwLock<()>>,
    interaction_affinity_registries: Arc<BTreeMap<String, BTreeSet<String>>>,
    accounts: Arc<BTreeMap<String, AccountPlan>>,
    account_identities: Arc<BTreeMap<String, AccountMutationIdentity>>,
    config: Arc<CompiledConfig>,
    store: Arc<dyn Store>,
    catalog: Option<Arc<CatalogService>>,
    catalog_generation: Arc<AtomicU64>,
    disabled_models: Arc<RwLock<BTreeSet<String>>>,
    persistence: PersistenceStatus,
    telemetry: RoutingTelemetry,
    account_mutations: Arc<AccountMutationState>,
}

/// Non-secret snapshot of the selected account and compatible registries used
/// while observing a Gemini create response. It intentionally contains no
/// interaction identifier.
pub(crate) struct InteractionAffinityBinding {
    credential: CredentialId,
    provider: ProviderId,
    upstream_model: String,
    ttl: Duration,
    registries: Vec<(String, ModelId, BindingKey)>,
    scope: AffinityBindingIdentity,
    scope_seed: String,
}

impl std::fmt::Debug for PoolingCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolingCoordinator")
            .field(
                "registries",
                &self
                    .registries
                    .read()
                    .map_or(0, |registries| registries.len()),
            )
            .field("accounts", &self.accounts.len())
            .field(
                "disabled_models",
                &self
                    .disabled_models
                    .read()
                    .map_or(0, |disabled| disabled.len()),
            )
            .field("persistence", &self.persistence)
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
        Self::with_store_and_account_mutations(
            config,
            store,
            Arc::new(AccountMutationState::default()),
            true,
        )
    }

    fn with_store_and_account_mutations(
        config: &CompiledConfig,
        store: Arc<dyn Store>,
        account_mutations: Arc<AccountMutationState>,
        activate: bool,
    ) -> Result<Self, PoolError> {
        let accounts = config
            .accounts()
            .values()
            .map(|account| (account.id().to_owned(), account.clone()))
            .collect::<BTreeMap<_, _>>();
        let account_identities = accounts
            .values()
            .map(|account| {
                let upstream = config
                    .upstreams()
                    .get(account.provider())
                    .ok_or(PoolError::InvalidUpstreamUri)?;
                let configuration_fingerprint = crate::account_configuration_fingerprint(
                    upstream,
                    account.id(),
                    account.auth_kind(),
                )
                .map_err(|_| PoolError::InvalidCredential)?;
                Ok((
                    account.id().to_owned(),
                    AccountMutationIdentity {
                        account_id: account.id().to_owned(),
                        provider_id: upstream.id().to_owned(),
                        configuration_fingerprint,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PoolError>>()?;
        let mut registries = BTreeMap::new();
        let mut binding_index = BTreeMap::new();

        for model in config.models().values() {
            let registry = Arc::new(CredentialRegistry::new());
            register_model_accounts(
                &registry,
                model.id(),
                model.targets(),
                &accounts,
                config.account_pools(),
                config.upstreams(),
                &mut binding_index,
            )?;
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
                config.upstreams(),
                &mut binding_index,
            )?;
            registries.insert(key, registry);
        }

        let mut interaction_affinity_registries = BTreeMap::<String, BTreeSet<String>>::new();
        for route in config.routes() {
            let Some(policy_id) = route.target().policy() else {
                continue;
            };
            let Some(affinity) = config
                .policies()
                .get(policy_id)
                .and_then(|policy| policy.selection().affinity())
            else {
                continue;
            };
            if affinity.key() == "gemini.interaction_id" && route.target().model_source().is_none()
            {
                interaction_affinity_registries
                    .entry(policy_id.to_owned())
                    .or_default()
                    .insert(route_registry_key(route.id()));
            }
        }

        let coordinator = Self {
            registries: Arc::new(RwLock::new(registries)),
            binding_index: Arc::new(RwLock::new(binding_index)),
            registry_view_gate: Arc::new(RwLock::new(())),
            interaction_affinity_registries: Arc::new(interaction_affinity_registries),
            accounts: Arc::new(accounts),
            account_identities: Arc::new(account_identities),
            config: Arc::new(config.clone()),
            store,
            catalog: None,
            catalog_generation: Arc::new(AtomicU64::new(0)),
            disabled_models: Arc::new(RwLock::new(BTreeSet::new())),
            persistence: PersistenceStatus::new(true),
            telemetry: RoutingTelemetry::default(),
            account_mutations,
        };
        if activate {
            coordinator.register_and_restore_runtime_state()?;
        }
        Ok(coordinator)
    }

    /// Rebuild the immutable registration view for a new configuration while
    /// retaining the same mutable store. Credential health, cooldowns,
    /// session affinity, decisions, and owner-selected enablement therefore
    /// survive a successful configuration generation swap.
    pub fn reconfigure(&self, config: &CompiledConfig) -> Result<Self, PoolError> {
        let mut coordinator = Self::with_store_and_account_mutations(
            config,
            Arc::clone(&self.store),
            Arc::clone(&self.account_mutations),
            true,
        )?;
        coordinator.catalog.clone_from(&self.catalog);
        if coordinator.catalog.is_some() {
            coordinator.sync_catalog_snapshot()?;
        }
        coordinator.disabled_models = Arc::clone(&self.disabled_models);
        coordinator.persistence = self.persistence.clone();
        coordinator.telemetry = self.telemetry.clone();
        Ok(coordinator)
    }

    /// Build a reload candidate without mutating credential identities or
    /// registering unpublished account topology.
    pub fn prepare_reconfigure(
        &self,
        config: &CompiledConfig,
        retirements: &[CredentialFingerprintRetirement],
        catalog: Option<Arc<CatalogService>>,
    ) -> Result<PreparedPoolingCoordinator, PoolError> {
        let mut coordinator = Self::with_store_and_account_mutations(
            config,
            Arc::clone(&self.store),
            Arc::clone(&self.account_mutations),
            false,
        )?;
        coordinator.catalog = catalog;
        coordinator.disabled_models = Arc::clone(&self.disabled_models);
        coordinator.persistence = self.persistence.clone();
        coordinator.telemetry = self.telemetry.clone();

        if let Some(catalog) = coordinator.catalog.as_ref() {
            let snapshot = catalog.snapshot();
            let (registries, bindings) =
                coordinator.build_registry_view(Some(snapshot.as_ref()))?;
            *coordinator
                .registries
                .write()
                .map_err(|_| PoolError::Selection)? = registries;
            *coordinator
                .binding_index
                .write()
                .map_err(|_| PoolError::Selection)? = bindings;
            coordinator
                .catalog_generation
                .store(snapshot.generation(), Ordering::Release);
        }
        // These restorations are read-only with respect to durable state and
        // happen while the candidate registries remain unpublished.
        coordinator.restore_cooldowns()?;
        coordinator.restore_quota_states()?;
        coordinator.restore_affinities()?;

        let mut retirement_map = BTreeMap::new();
        for retirement in retirements {
            if retirement_map
                .insert(retirement.credential_id().to_owned(), retirement.clone())
                .is_some()
            {
                return Err(PoolError::InvalidCredential);
            }
        }
        let now = timestamp_now();
        let mut activations = Vec::with_capacity(coordinator.accounts.len());
        for account in coordinator.accounts.values() {
            let identity = coordinator.account_mutation_identity(account.id())?;
            let expected = coordinator
                .store
                .credential_state(account.id())
                .map_err(|_| PoolError::Store)?;
            let retirement = retirement_map.remove(account.id());
            let desired = CredentialState::new_with_fingerprint(
                account.id(),
                &identity.provider_id,
                &identity.configuration_fingerprint,
                account.enabled(),
                now,
            );
            activations.push(
                CredentialConfigurationActivation::new(expected, desired, retirement)
                    .map_err(|_| PoolError::InvalidCredential)?,
            );
        }
        if !retirement_map.is_empty() {
            return Err(PoolError::InvalidCredential);
        }
        Ok(PreparedPoolingCoordinator {
            coordinator: Arc::new(coordinator),
            activations,
            activated: AtomicBool::new(false),
        })
    }

    fn apply_activated_account_states(
        &self,
        activated: &[ActivatedCredentialState],
    ) -> Result<(), PoolError> {
        if activated.len() != self.accounts.len() {
            return Err(PoolError::Store);
        }
        let mut changes = Vec::with_capacity(activated.len());
        for activated in activated {
            let state = activated.state();
            let identity = self.account_mutation_identity(&state.credential_id)?;
            if state.provider_id != identity.provider_id
                || state.configuration_fingerprint != identity.configuration_fingerprint
            {
                return Err(PoolError::Store);
            }
            let credential = CredentialId::new(&state.credential_id)
                .map_err(|_| PoolError::InvalidCredential)?;
            changes.push((credential, identity, activated.effectively_enabled()));
        }
        let credential_changes = changes
            .iter()
            .map(|(credential, _, enabled)| (credential.clone(), *enabled))
            .collect::<Vec<_>>();
        let registries = self.registries.read().map_err(|_| PoolError::Selection)?;
        for registry in registries.values() {
            registry
                .set_credentials_enabled(&credential_changes)
                .map_err(|_| PoolError::Selection)?;
        }
        drop(registries);
        let mut enablement = self
            .account_mutations
            .enablement
            .write()
            .map_err(|_| PoolError::Selection)?;
        for (_, identity, enabled) in changes {
            enablement.insert(identity, enabled);
        }
        Ok(())
    }

    /// Attach the atomically refreshed catalog used by request model selection.
    #[must_use]
    pub fn with_catalog(mut self, catalog: Arc<CatalogService>) -> Self {
        self.catalog = Some(catalog);
        self.catalog_generation.store(u64::MAX, Ordering::Release);
        let _ = self.sync_catalog_snapshot();
        self
    }

    /// Replace or clear the catalog attached to this coordinator.
    #[must_use]
    pub fn with_optional_catalog(mut self, catalog: Option<Arc<CatalogService>>) -> Self {
        self.catalog = catalog;
        if self.catalog.is_some() {
            // A configuration reload creates a new catalog service whose first
            // snapshot can have the same generation number as the retired
            // service. Force one rebuild so generation equality across two
            // distinct services never leaves stale model bindings installed.
            self.catalog_generation.store(u64::MAX, Ordering::Release);
            let _ = self.sync_catalog_snapshot();
        } else {
            self.catalog_generation.store(0, Ordering::Release);
        }
        self
    }

    fn sync_catalog_snapshot(&self) -> Result<(), PoolError> {
        let Some(catalog) = self.catalog.as_ref() else {
            return Ok(());
        };
        let snapshot = catalog.snapshot();
        let generation = snapshot.generation();
        if self.catalog_generation.load(Ordering::Acquire) == generation {
            return Ok(());
        }

        let (registries, bindings) = self.build_registry_view(Some(snapshot.as_ref()))?;
        let mut views = self
            .account_mutations
            .gate
            .lock()
            .map_err(|_| PoolError::Selection)?;
        if self.catalog_generation.load(Ordering::Acquire) == generation {
            return Ok(());
        }
        self.register_registry_view_locked(&mut views)?;
        let _view = self
            .registry_view_gate
            .write()
            .map_err(|_| PoolError::Selection)?;
        *self.registries.write().map_err(|_| PoolError::Selection)? = registries;
        *self
            .binding_index
            .write()
            .map_err(|_| PoolError::Selection)? = bindings;
        self.restore_runtime_state_locked()?;
        self.catalog_generation.store(generation, Ordering::Release);
        Ok(())
    }

    fn build_registry_view(
        &self,
        catalog: Option<&CatalogSnapshot>,
    ) -> Result<RegistryView, PoolError> {
        let mut registries = BTreeMap::new();
        let mut binding_index = BTreeMap::new();
        for model in self.config.models().values() {
            let registry = Arc::new(CredentialRegistry::new());
            register_model_accounts(
                &registry,
                model.id(),
                model.targets(),
                &self.accounts,
                self.config.account_pools(),
                self.config.upstreams(),
                &mut binding_index,
            )?;
            registries.insert(model.id().to_owned(), registry);
        }
        for route in self.config.routes() {
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
                &self.accounts,
                self.config.upstreams(),
                &mut binding_index,
            )?;
            registries.insert(key, registry);
        }
        if let Some(catalog) = catalog {
            for model in catalog.models().values() {
                let key = model.id().to_string();
                let registry = registries
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(CredentialRegistry::new()))
                    .clone();
                register_catalog_model(
                    &registry,
                    model,
                    &self.accounts,
                    self.config.account_pools(),
                    self.config.upstreams(),
                    &mut binding_index,
                )?;
            }
        }
        Ok((registries, binding_index))
    }

    /// Return the mutable state store shared by this coordinator.
    #[must_use]
    pub fn store(&self) -> Arc<dyn Store> {
        Arc::clone(&self.store)
    }

    /// Whether the supplied OAuth token store shares this coordinator's
    /// credential revision domain. A caller-selected or process-local store
    /// must fail closed to unfenced ID-based disablement instead of comparing
    /// unrelated generations.
    #[must_use]
    pub(crate) fn shares_credential_generation_domain(
        &self,
        token_store: Option<&pooler_store::SqliteOAuthTokenStore>,
    ) -> bool {
        token_store.is_some_and(|token_store| {
            self.store
                .shares_credential_generation_domain(token_store.store())
        })
    }

    /// Return the process-local status for request and usage persistence.
    #[must_use]
    pub fn persistence_status(&self) -> PersistenceStatus {
        self.persistence.clone()
    }

    /// Return the bounded telemetry registry used by adaptive selection.
    #[must_use]
    pub fn routing_telemetry(&self) -> RoutingTelemetry {
        self.telemetry.clone()
    }

    /// Record one completed attempt for adaptive ranking. Only fixed numeric
    /// timing fields and the composite binding identity cross this boundary.
    pub fn record_routing_telemetry(&self, binding: BindingKey, sample: TelemetrySample) {
        self.telemetry.record(binding, sample);
    }

    /// Allocate one process-unique logical request identifier. The caller owns
    /// this identity through admission, attempts, retries, commitment, and completion.
    #[must_use]
    pub fn next_logical_request_id(&self) -> String {
        self.next_request_id()
    }

    /// Current published model-catalog generation, when a catalog is mounted.
    #[must_use]
    pub fn catalog_generation(&self) -> Option<u64> {
        self.catalog
            .as_ref()
            .map(|catalog| catalog.snapshot().generation())
    }

    /// Return all bounded metadata-only request lifecycle events.
    pub fn request_events(&self) -> Result<Vec<pooler_store::RequestEvent>, PoolError> {
        self.store.request_events().map_err(|_| PoolError::Store)
    }

    /// Return one bounded logical request timeline.
    pub fn request_events_for(
        &self,
        request_id: &str,
    ) -> Result<Vec<pooler_store::RequestEvent>, PoolError> {
        self.store
            .request_events_for(request_id)
            .map_err(|_| PoolError::Store)
    }

    /// Return bounded, metadata-only historical usage records.
    pub fn usage_records(&self) -> Result<Vec<pooler_store::UsageRecord>, PoolError> {
        self.store.usage_records().map_err(|_| PoolError::Store)
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

    /// Return deduplicated, redacted typed quota windows for management views.
    pub fn quota_states(&self) -> Result<Vec<pooler_policy::PersistedQuotaSnapshot>, PoolError> {
        self.sync_catalog_snapshot()?;
        let now = Instant::now();
        let now_unix_ms = timestamp_now();
        let mut records = BTreeMap::new();
        let registries = self.registries.read().map_err(|_| PoolError::Selection)?;
        for registry in registries.values() {
            for record in registry
                .quota_state_records(now, now_unix_ms)
                .map_err(|_| PoolError::Selection)?
            {
                let identity = serde_json::to_string(&record).map_err(|_| PoolError::Selection)?;
                records.insert(identity, record);
            }
        }
        Ok(records.into_values().collect())
    }

    /// Disable one credential after provider evidence proves it needs
    /// interactive reauthorization. The state is persisted and removed from
    /// every model/route registry in this coordinator.
    pub fn disable_credential(&self, credential: &CredentialId) {
        let _ = self.set_account_enabled(credential.as_str(), false);
    }

    /// Enable or disable one configured account in persistence and every live registry generation.
    pub fn set_account_enabled(&self, account_id: &str, enabled: bool) -> Result<(), PoolError> {
        self.sync_catalog_snapshot()?;
        if !self.accounts.contains_key(account_id) {
            return Err(PoolError::InvalidCredential);
        }
        let changes = vec![self.account_enablement_change(account_id, enabled)?];
        let account_identities = changes
            .iter()
            .map(|change| change.identity.clone())
            .collect::<BTreeSet<_>>();
        let mut views = self
            .account_mutations
            .gate
            .lock()
            .map_err(|_| PoolError::Selection)?;
        self.register_registry_view_locked(&mut views)?;
        let registry_views =
            self.live_registries_for_accounts_locked(&mut views, &account_identities)?;

        let identity = changes[0].identity.store_identity()?;
        match self
            .store
            .set_credential_enabled_if_identity(&identity, enabled, timestamp_now())
            .map_err(|_| PoolError::Store)?
        {
            ConditionalCredentialMutation::Applied(_) => {
                self.publish_account_changes_locked(&registry_views, &changes)
            }
            ConditionalCredentialMutation::Stale { .. }
            | ConditionalCredentialMutation::Missing => Err(PoolError::InvalidCredential),
        }
    }

    /// Enable or disable an OAuth account only while its persisted token
    /// generation and immutable provider identity match the caller's
    /// observation. The matching live registry state is published only after
    /// the durable mutation commits.
    pub fn set_oauth_account_enabled_if_current(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        expected_generation: u64,
        enabled: bool,
    ) -> Result<bool, PoolError> {
        self.mutate_oauth_account_enabled_if_current(
            config,
            account_id,
            expected_generation,
            enabled,
        )
        .map(|outcome| {
            outcome == OAuthCredentialMutation::Applied
                || (enabled && outcome == OAuthCredentialMutation::GenerationAdvanced)
        })
    }

    fn mutate_oauth_account_enabled_if_current(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        expected_generation: u64,
        enabled: bool,
    ) -> Result<OAuthCredentialMutation, PoolError> {
        self.sync_catalog_snapshot()?;
        let account = config
            .accounts()
            .get(account_id)
            .filter(|account| account.auth_kind() == AccountAuthKind::OAuth)
            .ok_or(PoolError::InvalidCredential)?;
        if !self.accounts.contains_key(account_id) {
            return Err(PoolError::InvalidCredential);
        }
        let upstream = config
            .upstreams()
            .get(account.provider())
            .ok_or(PoolError::InvalidUpstreamUri)?;
        let credential = CredentialId::new(account_id).map_err(|_| PoolError::InvalidCredential)?;
        let fingerprint =
            crate::account_configuration_fingerprint(upstream, account_id, AccountAuthKind::OAuth)
                .map_err(|_| PoolError::InvalidCredential)?;
        let mutation_identity = AccountMutationIdentity {
            account_id: account_id.to_owned(),
            provider_id: upstream.id().to_owned(),
            configuration_fingerprint: fingerprint.clone(),
        };
        if self.account_identities.get(account_id) != Some(&mutation_identity) {
            return Err(PoolError::InvalidCredential);
        }
        let changes = vec![AccountEnablementChange {
            credential: credential.clone(),
            identity: mutation_identity.clone(),
            enabled,
        }];
        let account_identities = BTreeSet::from([mutation_identity]);
        let mut views = self
            .account_mutations
            .gate
            .lock()
            .map_err(|_| PoolError::Selection)?;
        self.register_registry_view_locked(&mut views)?;
        let registry_views =
            self.live_registries_for_accounts_locked(&mut views, &account_identities)?;
        let outcome = self
            .store
            .set_credential_enabled_if_current(
                account_id,
                expected_generation,
                upstream.id(),
                &fingerprint,
                enabled,
                timestamp_now(),
            )
            .map_err(|_| PoolError::Store)?;
        match outcome {
            ConditionalCredentialMutation::Applied(_) => {
                self.publish_account_changes_locked(&registry_views, &changes)?;
                Ok(OAuthCredentialMutation::Applied)
            }
            ConditionalCredentialMutation::Stale {
                current,
                credential_payload_present: Some(true),
                credential_payload_generation: Some(newer_generation),
            } if (current.enabled || (enabled && current.revision == newer_generation))
                && current.provider_id == upstream.id()
                && current.configuration_fingerprint == fingerprint
                && newer_generation > expected_generation =>
            {
                if enabled {
                    let identity = changes[0].identity.store_identity()?;
                    match self
                        .store
                        .set_credential_enabled_if_newer_payload(
                            &identity,
                            current.revision,
                            expected_generation,
                            true,
                            timestamp_now(),
                        )
                        .map_err(|_| PoolError::Store)?
                    {
                        ConditionalCredentialMutation::Applied(_) => {
                            self.publish_account_changes_locked(&registry_views, &changes)?;
                        }
                        ConditionalCredentialMutation::Stale { .. }
                        | ConditionalCredentialMutation::Missing => {
                            return Ok(OAuthCredentialMutation::Unavailable);
                        }
                    }
                }
                Ok(OAuthCredentialMutation::GenerationAdvanced)
            }
            ConditionalCredentialMutation::Stale { .. }
            | ConditionalCredentialMutation::Missing => Ok(OAuthCredentialMutation::Unavailable),
        }
    }

    /// Disable a selected OAuth credential only while the persisted token
    /// generation and immutable provider identity still match the failed
    /// authorization. A concurrent login or refresh preserves the newer
    /// generation, while removal or replacement makes the failed binding
    /// unavailable for this request.
    fn disable_selected_oauth_credential_if_current(
        &self,
        config: &CompiledConfig,
        selection: &PoolSelection,
        expected_generation: u64,
    ) -> Result<OAuthCredentialMutation, PoolError> {
        let credential = selection.credential().ok_or(PoolError::InvalidCredential)?;
        if selection.account_auth_kind() != Some(AccountAuthKind::OAuth) {
            return Err(PoolError::InvalidCredential);
        }
        self.mutate_oauth_account_enabled_if_current(
            config,
            credential.as_str(),
            expected_generation,
            false,
        )
    }

    /// Atomically select one account and disable its same-provider siblings.
    pub fn switch_account(&self, account_id: &str) -> Result<(), PoolError> {
        self.sync_catalog_snapshot()?;
        let selected = self
            .accounts
            .get(account_id)
            .ok_or(PoolError::InvalidCredential)?;
        let siblings = self
            .accounts
            .values()
            .filter(|account| {
                account.provider() == selected.provider() && account.id() != selected.id()
            })
            .map(|account| account.id().to_owned())
            .collect::<Vec<_>>();
        let mut changes = Vec::with_capacity(siblings.len().saturating_add(1));
        changes.push(self.account_enablement_change(account_id, true)?);
        for sibling in &siblings {
            changes.push(self.account_enablement_change(sibling, false)?);
        }
        let account_identities = changes
            .iter()
            .map(|change| change.identity.clone())
            .collect::<BTreeSet<_>>();
        let mut views = self
            .account_mutations
            .gate
            .lock()
            .map_err(|_| PoolError::Selection)?;
        self.register_registry_view_locked(&mut views)?;
        let registry_views =
            self.live_registries_for_accounts_locked(&mut views, &account_identities)?;

        let selected_identity = changes[0].identity.store_identity()?;
        let sibling_identities = changes[1..]
            .iter()
            .map(|change| change.identity.store_identity())
            .collect::<Result<Vec<_>, _>>()?;
        match self
            .store
            .switch_credential_if_identities(
                &selected_identity,
                &sibling_identities,
                timestamp_now(),
            )
            .map_err(|_| PoolError::Store)?
        {
            Some(_) => self.publish_account_changes_locked(&registry_views, &changes),
            None => Err(PoolError::InvalidCredential),
        }
    }

    fn account_mutation_identity(
        &self,
        account_id: &str,
    ) -> Result<AccountMutationIdentity, PoolError> {
        self.account_identities
            .get(account_id)
            .cloned()
            .ok_or(PoolError::InvalidCredential)
    }

    fn account_enablement_change(
        &self,
        account_id: &str,
        enabled: bool,
    ) -> Result<AccountEnablementChange, PoolError> {
        Ok(AccountEnablementChange {
            credential: CredentialId::new(account_id).map_err(|_| PoolError::InvalidCredential)?,
            identity: self.account_mutation_identity(account_id)?,
            enabled,
        })
    }

    fn live_registries_for_accounts_locked(
        &self,
        views: &mut Vec<RegisteredRegistryView>,
        account_identities: &BTreeSet<AccountMutationIdentity>,
    ) -> Result<Vec<LiveRegistryView>, PoolError> {
        let mut live_views = Vec::new();
        views.retain(|view| view.registries.upgrade().is_some());
        for view in views.iter() {
            if view.accounts.is_disjoint(account_identities) {
                continue;
            }
            let Some(registry_map) = view.registries.upgrade() else {
                continue;
            };
            let registries = registry_map
                .read()
                .map_err(|_| PoolError::Selection)?
                .values()
                .cloned()
                .collect();
            live_views.push(LiveRegistryView {
                registries,
                accounts: view.accounts.clone(),
            });
        }
        Ok(live_views)
    }

    fn publish_account_changes_locked(
        &self,
        registry_views: &[LiveRegistryView],
        changes: &[AccountEnablementChange],
    ) -> Result<(), PoolError> {
        let mut registry_failed = false;
        for view in registry_views {
            let matching_changes = changes
                .iter()
                .filter(|change| view.accounts.contains(&change.identity))
                .map(|change| (change.credential.clone(), change.enabled))
                .collect::<Vec<_>>();
            if matching_changes.is_empty() {
                continue;
            }
            for registry in &view.registries {
                if registry.set_credentials_enabled(&matching_changes).is_err() {
                    registry_failed = true;
                }
            }
        }

        let mut enablement = self
            .account_mutations
            .enablement
            .write()
            .map_err(|_| PoolError::Selection)?;
        for change in changes {
            enablement.insert(change.identity.clone(), change.enabled);
        }
        if registry_failed {
            Err(PoolError::Selection)
        } else {
            Ok(())
        }
    }

    /// Enable or disable one public model for new selections.
    pub fn set_model_enabled(&self, model: &str, enabled: bool) -> Result<(), PoolError> {
        let model = ModelId::new(model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
        let mut disabled = self
            .disabled_models
            .write()
            .map_err(|_| PoolError::Selection)?;
        if enabled {
            disabled.remove(model.as_str());
        } else if disabled.contains(model.as_str()) || disabled.len() < MAX_DISABLED_MODELS {
            disabled.insert(model.as_str().to_owned());
        } else {
            return Err(PoolError::Selection);
        }
        Ok(())
    }

    /// Whether the operator currently permits selection of one public model.
    pub fn model_enabled(&self, model: &str) -> Result<bool, PoolError> {
        let disabled = self
            .disabled_models
            .read()
            .map_err(|_| PoolError::Selection)?;
        if disabled.contains(model) {
            return Ok(false);
        }
        Ok(!self.catalog.as_ref().is_some_and(|catalog| {
            catalog
                .snapshot()
                .overrides()
                .disabled_models()
                .iter()
                .any(|disabled| disabled.as_str() == model)
        }))
    }

    /// Return operator-disabled public model IDs in deterministic order.
    pub fn disabled_models(&self) -> Result<Vec<String>, PoolError> {
        self.disabled_models
            .read()
            .map(|disabled| disabled.iter().cloned().collect())
            .map_err(|_| PoolError::Selection)
    }

    /// Public model IDs this deployment will actually serve right now.
    ///
    /// This is the active model view, not the upstream's list. It applies the
    /// catalog's public aliases and exclusions, drops models an operator has
    /// disabled at runtime, keeps only models with a target whose capabilities
    /// satisfy `required`, and keeps only models with at least one target whose
    /// credential is enabled and not cooling down. A model nothing can serve is
    /// not advertised.
    ///
    /// Provider IDs, upstream model names, account IDs, secret references, and
    /// upstream endpoints are deliberately absent from the result.
    ///
    /// # Errors
    ///
    /// Returns [`PoolError`] when runtime enablement or health state cannot be
    /// read.
    pub fn published_models(
        &self,
        config: &CompiledConfig,
        _provider: &str,
        required: CapabilitySet,
    ) -> Result<PublishedModels, PoolError> {
        self.sync_catalog_snapshot()?;
        let snapshot = self.catalog.as_ref().map(|catalog| catalog.snapshot());
        let now = timestamp_now();
        let cooling: BTreeSet<String> = self
            .cooldowns()?
            .into_iter()
            .filter(|cooldown| cooldown.scope == "provider" && cooldown.until > now)
            .map(|cooldown| cooldown.key)
            .collect();
        let mut provider_credentials = BTreeMap::<String, bool>::new();
        let mut account_enabled = BTreeMap::<String, bool>::new();
        for state in self.credential_states()? {
            if !self.accounts.contains_key(&state.credential_id) {
                continue;
            }
            account_enabled.insert(state.credential_id.clone(), state.enabled);
            provider_credentials
                .entry(state.provider_id)
                .and_modify(|enabled| *enabled |= state.enabled)
                .or_insert(state.enabled);
        }

        // A provider is usable when it is not cooling down and at least one of
        // its credentials is still enabled. A deployment with no credential
        // state at all has nothing to contradict, so configuration stands.
        let provider_is_usable = |provider: &str| {
            !cooling.contains(provider)
                && provider_credentials.get(provider).copied().unwrap_or(true)
        };

        let binding_index = self
            .binding_index
            .read()
            .map_err(|_| PoolError::Selection)?;
        let binding_is_usable =
            |model: &str, target_id: &str, target_provider: &str, capabilities: CapabilitySet| {
                binding_index.values().any(|binding| {
                    binding.model.as_str() == model
                        && binding.binding.target_id().as_str() == target_id
                        && binding.provider.as_str() == target_provider
                        && binding.profile_capabilities().contains_all(required)
                        && binding.profile_capabilities().contains_all(capabilities)
                        && provider_is_usable(target_provider)
                        && binding
                            .account
                            .as_ref()
                            .and_then(|account| account_enabled.get(account.id()))
                            .copied()
                            .unwrap_or(true)
                })
            };

        let mut published = BTreeSet::new();
        for (id, model) in config.models() {
            if !self.model_enabled(id)? {
                continue;
            }
            if model.targets().iter().any(|target| {
                binding_is_usable(
                    id,
                    &target.binding_id().as_str(),
                    target.provider(),
                    target.capabilities(),
                )
            }) {
                published.insert(id.to_string());
            }
        }
        if let Some(snapshot) = snapshot.as_deref() {
            for (id, model) in snapshot.models() {
                let id = id.as_str();
                if !self.model_enabled(id)? {
                    continue;
                }
                if model.targets().iter().any(|target| {
                    binding_is_usable(
                        id,
                        target.binding_id(),
                        target.provider().as_str(),
                        target.capabilities(),
                    )
                }) {
                    published.insert(id.to_owned());
                }
            }
        }
        Ok(PublishedModels {
            models: published.into_iter().collect(),
            configuration_generation: config.generation(),
            catalog_generation: snapshot.as_deref().map(CatalogSnapshot::generation),
        })
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
        self.sync_catalog_snapshot()?;
        let policy = route
            .target()
            .policy()
            .and_then(|id| config.policies().get(id))
            .cloned();

        let catalog = self.catalog.as_ref().map(|catalog| catalog.snapshot());
        let contextual_model = context.model().filter(|model| {
            config.models().get(*model).is_some_and(|plan| {
                plan.targets()
                    .iter()
                    .any(|target| target.provider() == route.target().upstream())
            }) || catalog
                .as_deref()
                .and_then(|catalog| catalog.get(model))
                .is_some_and(|model| {
                    model
                        .targets()
                        .iter()
                        .any(|target| target.provider().as_str() == route.target().upstream())
                })
        });
        let route_has_model_namespace = config.models().values().any(|model| {
            model
                .targets()
                .iter()
                .any(|target| target.provider() == route.target().upstream())
        }) || catalog.as_deref().is_some_and(|catalog| {
            catalog.models().values().any(|model| {
                model
                    .targets()
                    .iter()
                    .any(|target| target.provider().as_str() == route.target().upstream())
            })
        });
        if contextual_model.is_none() && context.model_must_resolve() && route_has_model_namespace {
            if let Some(model) = context.model() {
                return Err(PoolError::UnknownModel {
                    model: model.to_owned(),
                });
            }
        }
        let requested_model = model.or_else(|| {
            if route.target().model_source().is_some() {
                context.model()
            } else {
                contextual_model
            }
        });
        let (logical_model, static_upstream, static_model) =
            resolve_with_configured_model_fallback(
                config,
                route,
                requested_model,
                policy.as_ref(),
                catalog.as_deref(),
            )?;
        if !self.model_enabled(&logical_model)? {
            return Err(PoolError::ModelDisabled {
                model: logical_model,
            });
        }
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
            let _view = self
                .registry_view_gate
                .read()
                .map_err(|_| PoolError::Selection)?;
            let enablement = self
                .account_mutations
                .enablement
                .read()
                .map_err(|_| PoolError::Selection)?;
            let binding_index = self
                .binding_index
                .read()
                .map_err(|_| PoolError::Selection)?;
            let candidates = binding_index
                .values()
                .filter(|target| {
                    target.model.as_str() == logical_model
                        && target.provider.as_str() == static_upstream
                        && static_model
                            .as_deref()
                            .is_none_or(|model| target.upstream_model.as_ref() == model)
                })
                .cloned()
                .collect::<Vec<_>>();
            let binding_target = candidates
                .iter()
                .filter(|target| {
                    target.account.as_ref().is_none_or(|account| {
                        self.account_identities
                            .get(account.id())
                            .and_then(|identity| enablement.get(identity))
                            .copied()
                            .unwrap_or(account.enabled())
                    })
                })
                .min_by_key(|target| target.priority)
                .cloned();
            if binding_target.is_none() && !candidates.is_empty() {
                return Err(PoolError::NoEligible {
                    policy: route.id().to_owned(),
                });
            }
            let profile = binding_target
                .as_ref()
                .map_or(ModelProfile::DEFAULT, |target| target.profile);
            let request_overlay = binding_target
                .as_ref()
                .map_or_else(RequestOverlay::default, |target| {
                    target.request_overlay.clone()
                });
            let account = binding_target
                .as_ref()
                .and_then(|target| target.account.clone());
            let credential = account.as_ref().map(|account| {
                CredentialId::new(account.id().to_owned())
                    .expect("compiled account IDs remain valid")
            });
            return Ok(PoolSelection {
                upstream_id: binding_target.as_ref().map_or_else(
                    || {
                        Arc::from(
                            route
                                .target()
                                .transport_upstream()
                                .unwrap_or(&static_upstream),
                        )
                    },
                    |target| Arc::clone(&target.upstream_id),
                ),
                upstream_model: static_model.map(Arc::from),
                profile,
                request_overlay,
                account,
                lease: None,
                policy: None,
                explanation: None,
                model: model_id,
                provider,
                credential,
                affinity_key: None,
                binding_target,
                affinity_scope: None,
                affinity_scope_seed: None,
                registry_key: None,
                selection_request: None,
                network_retry_exclusions: BTreeSet::new(),
            });
        };

        let _view = self
            .registry_view_gate
            .read()
            .map_err(|_| PoolError::Selection)?;
        let registry_key = if requested_model.is_some() {
            logical_model.to_owned()
        } else {
            route_registry_key(route.id())
        };
        let model_id =
            ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
        let registry = self
            .registries
            .read()
            .map_err(|_| PoolError::Selection)?
            .get(&registry_key)
            .cloned();
        let Some(registry) = registry else {
            if let Some(fallback) = next_model_fallback(&policy, requested_model, context) {
                drop(_view);
                return self.select_with_context(
                    config,
                    route,
                    Some(fallback),
                    headers,
                    &context
                        .clone()
                        .with_fallback_depth(context.fallback_depth + 1),
                    timing,
                );
            }
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
            // Eligibility must use the current instant. A request-admission
            // timestamp can predate a concurrent zero-delay quota recovery.
            .at(Instant::now());
        let mut routing = routing_requirements(&policy);
        if routing.target_order.is_empty() {
            routing.target_order = model_target_order(config, &logical_model);
        }
        request = request
            .with_routing(routing)
            .with_telemetry(self.telemetry.snapshot(), timestamp_now());
        if let Some(codec) = required_codec_for_selection(route, requested_model, context) {
            request = request
                .with_codec(codec)
                .map_err(|_| PoolError::Selection)?;
        }
        if let Some(allowed) = model_account_allow_list(config, &logical_model) {
            let ids = allowed
                .into_iter()
                .filter_map(|id| CredentialId::new(id).ok())
                .collect::<Vec<_>>();
            request = request.with_allowed_credentials(ids);
        }
        let affinity_scope_seed =
            affinity_scope_seed(config, catalog.as_deref(), route, &logical_model);
        let affinity_key = affinity_value(&policy, headers, context)
            .and_then(|value| scoped_affinity_key(&affinity_scope_seed, &value));
        if let Some(affinity) = policy.selection().affinity() {
            request = request.with_affinity_rebind(affinity.rebind());
            if let Some(value) = affinity_value(&policy, headers, context) {
                if let Some(key) = scoped_affinity_key(&affinity_scope_seed, &value) {
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
                if let Some(fallback) = next_model_fallback(&policy, requested_model, context) {
                    drop(_view);
                    return self.select_with_context(
                        config,
                        route,
                        Some(fallback),
                        headers,
                        &context
                            .clone()
                            .with_fallback_depth(context.fallback_depth + 1),
                        timing,
                    );
                }
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
        let binding_target = self
            .binding_index
            .read()
            .map_err(|_| PoolError::Selection)?
            .get(lease.binding_key())
            .cloned()
            .ok_or(PoolError::Selection)?;
        let account = binding_target
            .account
            .clone()
            .or_else(|| self.accounts.get(account_id.as_str()).cloned());
        let selected_model = Some(binding_target.upstream_model.as_ref().to_owned());
        self.record_selection(
            route,
            &logical_model,
            timing.attempt,
            config.generation(),
            &lease,
            selected_model.as_deref(),
        );
        let profile = binding_target.profile;
        Ok(PoolSelection {
            upstream_id: Arc::clone(&binding_target.upstream_id),
            upstream_model: Some(binding_target.upstream_model.clone()),
            profile,
            request_overlay: binding_target.request_overlay.clone(),
            account,
            lease: Some(lease),
            policy: Some(policy.clone()),
            explanation: Some(explanation),
            model: ModelId::new(logical_model.to_owned()).map_err(|_| PoolError::InvalidModel)?,
            provider,
            credential: Some(account_id),
            affinity_key,
            binding_target: Some(binding_target.clone()),
            affinity_scope: Some(affinity_scope_for_selection(
                route,
                &policy,
                &logical_model,
                &binding_target,
                &affinity_scope_seed,
            )),
            affinity_scope_seed: Some(Arc::from(affinity_scope_seed)),
            registry_key: Some(Arc::from(registry_key)),
            selection_request: Some(selection_request),
            network_retry_exclusions: BTreeSet::new(),
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
            binding: selection.binding_key().cloned(),
        };
        let registry = self.registry_for(selection);
        let policy = selection.policy().cloned();
        let retry_policy = policy.as_ref().map(configured_retry_policy);
        let retry_context = RetryContext::new(attempt, commitment, replay)
            .with_elapsed(started.elapsed())
            .with_used_targets(
                u32::try_from(credentials_used.len()).unwrap_or(u32::MAX),
                u32::try_from(providers_used.len()).unwrap_or(u32::MAX),
            )
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
                selection.retry_selection_request(),
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
                            self.selection_from_recovery(
                                config,
                                route,
                                selection,
                                request,
                                lease,
                                BTreeSet::new(),
                            )
                        });
                        recovered = Some((mutation, decision));
                    }
                }
            }
        }

        let (mutation, mut decision) = recovered.unwrap_or_else(|| {
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
        let network_retry_can_reconsider_target_budget = decision.is_retry()
            || matches!(
                decision,
                RetryDecision::DoNotRetry {
                    reason: RetryStopReason::ProvidersExhausted
                }
            );
        if replacement.is_none()
            && classification.classification.class == ErrorClass::Network
            && network_retry_can_reconsider_target_budget
        {
            if let (Some(registry), Some(retry_policy)) = (registry.as_ref(), retry_policy.as_ref())
            {
                if let Some(outcome) = self.network_retry_replacement(NetworkRetryInput {
                    config,
                    route,
                    failed: selection,
                    registry,
                    retry_policy,
                    classification: &classification,
                    fallback_decision: decision,
                    retry_context,
                    credentials_used,
                    providers_used,
                    attempt,
                    now,
                }) {
                    replacement = outcome.replacement;
                    decision = outcome.decision;
                }
            }
        }
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

    /// Fence a native OAuth reauthentication failure against durable state
    /// and reserve one policy-bounded retry target for this request.
    pub(crate) fn classify_native_reauth(
        &self,
        input: NativeReauthInput<'_>,
    ) -> Result<PoolFailure, PoolError> {
        let NativeReauthInput {
            config,
            route,
            selection,
            replay,
            commitment,
            idempotency_key_present,
            attempt,
            failed_generation,
            generation_fenced,
            native_runtime,
            outbound_attempt_consumed,
            credentials_used,
            providers_used,
            elapsed_retry_delay,
            elapsed_recovery_wait,
            started,
        } = input;
        let failed_credential = selection
            .credential()
            .cloned()
            .ok_or(PoolError::InvalidCredential)?;
        let credential_mutation = if generation_fenced {
            match self.disable_selected_oauth_credential_if_current(
                config,
                selection,
                failed_generation,
            ) {
                Ok(mutation) => mutation,
                Err(PoolError::Store) => OAuthCredentialMutation::DisableNotPersisted,
                Err(error) => return Err(error),
            }
        } else {
            // A token generation observed in another store cannot fence this
            // metadata mutation. Disabling by account ID could race a newer
            // login and publish that fresh credential as disabled. Keep the
            // failure request-local and reserve a different retry target.
            OAuthCredentialMutation::DisableNotPersisted
        };
        let failed_binding_unavailable =
            credential_mutation != OAuthCredentialMutation::GenerationAdvanced;

        let classification = FailureClassification::for_class(ErrorClass::ProviderAuthentication)
            .with_credential_causation(pooler_policy::CredentialCausation::Proven);
        let mutation = HealthMutation::NoChange {
            reason: match credential_mutation {
                OAuthCredentialMutation::Applied => HealthMutationReason::CredentialDisabled,
                OAuthCredentialMutation::DisableNotPersisted => {
                    HealthMutationReason::CredentialDisableNotPersisted
                }
                OAuthCredentialMutation::GenerationAdvanced => {
                    HealthMutationReason::CredentialGenerationChanged
                }
                OAuthCredentialMutation::Unavailable => HealthMutationReason::CredentialUnavailable,
            },
        };
        let _view = self
            .registry_view_gate
            .read()
            .map_err(|_| PoolError::Selection)?;
        let registry = self.registry_for(selection);
        let retry_policy = selection.policy().map(configured_retry_policy);
        let decision_policy = retry_policy.as_ref().map(|policy| {
            let mut policy = policy.clone();
            if !outbound_attempt_consumed {
                policy.max_attempts = policy.max_attempts.saturating_add(1);
            }
            policy
        });
        let retry_context = RetryContext::new(attempt, commitment, replay)
            .with_elapsed(started.elapsed())
            .with_used_targets(
                u32::try_from(credentials_used.len()).unwrap_or(u32::MAX),
                u32::try_from(providers_used.len()).unwrap_or(u32::MAX),
            )
            .with_elapsed_retry_delay(elapsed_retry_delay)
            .with_elapsed_recovery_wait(elapsed_recovery_wait)
            .with_idempotency_key(idempotency_key_present)
            .with_target_change(RetryTargetChange::DifferentCredential);
        let mut decision = decision_policy.as_ref().map_or(
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::ClassificationNotRetryable,
            },
            |policy| policy.decide(&classification, retry_context),
        );
        let mut replacement = None;
        let replacement_may_reuse_budgeted_credential = decision.is_retry()
            || matches!(
                decision,
                RetryDecision::DoNotRetry {
                    reason: RetryStopReason::CredentialsExhausted
                }
            );

        if replacement_may_reuse_budgeted_credential {
            if let (Some(registry), Some(retry_policy), Some(decision_policy), Some(mut request)) = (
                registry.as_ref(),
                retry_policy.as_ref(),
                decision_policy.as_ref(),
                selection.retry_selection_request(),
            ) {
                request.attempt = attempt.saturating_add(u32::from(outbound_attempt_consumed));
                request.now = Instant::now();
                let credential_budget_full =
                    credentials_used.len() >= retry_policy.max_credentials as usize;
                let provider_budget_full =
                    providers_used.len() >= retry_policy.max_providers as usize;
                let bindings = self
                    .binding_index
                    .read()
                    .map_err(|_| PoolError::Selection)?;
                let transient = registry
                    .registrations()
                    .map_err(|_| PoolError::Selection)?
                    .into_iter()
                    .filter(|registration| {
                        let unsupported_native = native_runtime.is_some_and(|runtime| {
                            bindings
                                .get(registration.binding())
                                .and_then(|binding| config.upstreams().get(&binding.upstream_id))
                                .is_none_or(|upstream| {
                                    upstream.native().is_some() && !runtime.supports(upstream)
                                })
                        });
                        unsupported_native
                            || (failed_binding_unavailable
                                && registration.credential() == &failed_credential)
                            || (credential_budget_full
                                && !credentials_used.contains(registration.credential()))
                            || (provider_budget_full
                                && !providers_used.contains(registration.provider()))
                    })
                    .map(|registration| registration.binding().clone())
                    .collect::<BTreeSet<_>>();
                drop(bindings);
                // Authorization failures happen before a provider send. Keep every
                // request-local failed or ineligible binding excluded for the rest
                // of this request; one-hop transport exclusions would allow two
                // unfenced credentials to cycle until the request deadline.
                request.excluded_bindings.extend(transient);
                drop(selection.take_lease());

                match registry.select(request.clone()) {
                    Ok(lease) => {
                        let candidate_credential = lease.registration().credential();
                        let candidate_provider = lease.registration().provider();
                        let credential_was_used = credentials_used.contains(candidate_credential);
                        let provider_was_used = providers_used.contains(candidate_provider);
                        let target_change = if candidate_credential == &failed_credential {
                            RetryTargetChange::SameTarget
                        } else if candidate_provider == selection.provider() {
                            RetryTargetChange::DifferentCredential
                        } else {
                            RetryTargetChange::DifferentProvider
                        };
                        let candidate_context = retry_context
                            .with_used_targets(
                                if credential_was_used {
                                    retry_context.credentials_used.saturating_sub(1)
                                } else {
                                    retry_context.credentials_used
                                },
                                if provider_was_used {
                                    retry_context.providers_used.saturating_sub(1)
                                } else {
                                    retry_context.providers_used
                                },
                            )
                            .with_target_change(target_change);
                        decision = decision_policy.decide(&classification, candidate_context);
                        if decision.is_retry() {
                            replacement = Some(self.selection_from_recovery(
                                config,
                                route,
                                selection,
                                request,
                                lease,
                                BTreeSet::new(),
                            ));
                        }
                    }
                    Err(SelectionError::NoEligible { .. }) => {
                        decision = RetryDecision::DoNotRetry {
                            reason: RetryStopReason::NoAlternateTarget,
                        };
                    }
                    Err(_) => return Err(PoolError::Selection),
                }
            } else {
                decision = RetryDecision::DoNotRetry {
                    reason: RetryStopReason::NoAlternateTarget,
                };
            }
        }

        self.record_failure(
            route,
            selection,
            attempt,
            config.generation(),
            &classification,
            decision,
        );
        Ok(PoolFailure {
            classification,
            mutation,
            decision,
            replacement,
        })
    }

    fn insert_network_retry_exclusions(
        request: &mut SelectionRequest,
        exclusions: impl IntoIterator<Item = BindingKey>,
    ) -> BTreeSet<BindingKey> {
        exclusions
            .into_iter()
            .filter(|binding| request.excluded_bindings.insert(binding.clone()))
            .collect()
    }

    fn network_retry_replacement(
        &self,
        input: NetworkRetryInput<'_>,
    ) -> Option<NetworkRetryOutcome> {
        let NetworkRetryInput {
            config,
            route,
            failed,
            registry,
            retry_policy,
            classification,
            fallback_decision,
            retry_context,
            credentials_used,
            providers_used,
            attempt,
            now,
        } = input;
        let failed_provider = failed.provider().clone();
        let mut base_request = failed.retry_selection_request()?;
        base_request.attempt = attempt.saturating_add(1);
        base_request.now = now;

        let credential_budget_full = retry_context.credentials_used >= retry_policy.max_credentials;
        let provider_budget_full = retry_context.providers_used >= retry_policy.max_providers;
        let bindings = self.binding_index.read().ok()?;
        let budget_exclusions = bindings
            .values()
            .filter(|binding| {
                (credential_budget_full && !credentials_used.contains(binding.binding.account_id()))
                    || (provider_budget_full && !providers_used.contains(&binding.provider))
            })
            .map(|binding| binding.binding.clone())
            .collect::<BTreeSet<_>>();
        let failed_provider_exclusions = bindings
            .values()
            .filter(|binding| binding.provider == failed_provider)
            .map(|binding| binding.binding.clone())
            .collect::<BTreeSet<_>>();
        let alternate_provider_exclusions = bindings
            .values()
            .filter(|binding| binding.provider != failed_provider)
            .map(|binding| binding.binding.clone())
            .collect::<BTreeSet<_>>();
        drop(bindings);
        drop(failed.take_lease()?);

        let mut alternate_request = base_request.clone();
        let alternate_exclusions = Self::insert_network_retry_exclusions(
            &mut alternate_request,
            budget_exclusions
                .iter()
                .chain(&failed_provider_exclusions)
                .cloned(),
        );
        if let Ok(lease) = registry.select(alternate_request.clone()) {
            let candidate_provider = lease.registration().provider();
            if candidate_provider != &failed_provider {
                let credential_was_used =
                    credentials_used.contains(lease.registration().credential());
                let provider_was_used = providers_used.contains(candidate_provider);
                let decision_context = retry_context
                    .with_used_targets(
                        if credential_was_used {
                            retry_context.credentials_used.saturating_sub(1)
                        } else {
                            retry_context.credentials_used
                        },
                        if provider_was_used {
                            retry_context.providers_used.saturating_sub(1)
                        } else {
                            retry_context.providers_used
                        },
                    )
                    .with_target_change(RetryTargetChange::DifferentProvider);
                let decision = retry_policy.decide(classification, decision_context);
                if decision.is_retry() {
                    return Some(NetworkRetryOutcome {
                        replacement: Some(self.selection_from_recovery(
                            config,
                            route,
                            failed,
                            alternate_request,
                            lease,
                            alternate_exclusions,
                        )),
                        decision,
                    });
                }
            }
        }

        if fallback_decision.is_retry() {
            let mut fallback_request = base_request;
            let fallback_exclusions = Self::insert_network_retry_exclusions(
                &mut fallback_request,
                budget_exclusions
                    .into_iter()
                    .chain(alternate_provider_exclusions),
            );
            if let Ok(lease) = registry.select(fallback_request.clone()) {
                if lease.registration().provider() == &failed_provider {
                    return Some(NetworkRetryOutcome {
                        replacement: Some(self.selection_from_recovery(
                            config,
                            route,
                            failed,
                            fallback_request,
                            lease,
                            fallback_exclusions,
                        )),
                        decision: fallback_decision,
                    });
                }
            }
            return Some(NetworkRetryOutcome {
                replacement: None,
                decision: RetryDecision::DoNotRetry {
                    reason: RetryStopReason::NoAlternateTarget,
                },
            });
        }
        None
    }

    fn selection_from_recovery(
        &self,
        config: &CompiledConfig,
        route: &RoutePlan,
        failed: &PoolSelection,
        request: SelectionRequest,
        lease: SelectionLease,
        network_retry_exclusions: BTreeSet<BindingKey>,
    ) -> PoolSelection {
        let registration = lease.registration().clone();
        let explanation = lease.explanation().clone();
        let provider = registration.provider().clone();
        let credential = registration.credential().clone();
        let binding_target = self
            .binding_index
            .read()
            .ok()
            .and_then(|bindings| bindings.get(lease.binding_key()).cloned());
        let upstream_model = binding_target
            .as_ref()
            .map(|target| target.upstream_model.clone())
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
        let profile = binding_target
            .as_ref()
            .map_or(ModelProfile::DEFAULT, |target| target.profile);
        let affinity_scope = failed.affinity_scope.clone().map(|mut scope| {
            if let Some(target) = binding_target.as_ref() {
                scope.target_binding_id = target.binding.target_id().as_str().to_owned();
            }
            scope
        });
        PoolSelection {
            upstream_id: binding_target.as_ref().map_or_else(
                || {
                    Arc::from(
                        route
                            .target()
                            .transport_upstream()
                            .unwrap_or(provider.as_str()),
                    )
                },
                |target| Arc::clone(&target.upstream_id),
            ),
            upstream_model,
            profile,
            request_overlay: binding_target
                .as_ref()
                .map_or_else(RequestOverlay::default, |target| {
                    target.request_overlay.clone()
                }),
            account: binding_target
                .as_ref()
                .and_then(|target| target.account.clone())
                .or_else(|| self.accounts.get(credential.as_str()).cloned()),
            lease: Some(lease),
            policy: failed.policy.clone(),
            explanation: Some(explanation),
            model: registration.model().clone(),
            provider,
            credential: Some(credential),
            affinity_key: failed.affinity_key.clone(),
            binding_target,
            affinity_scope,
            affinity_scope_seed: failed.affinity_scope_seed.clone(),
            registry_key: failed.registry_key.clone(),
            selection_request: Some(request),
            network_retry_exclusions,
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
        let Ok(registries) = self.registries.read() else {
            return;
        };
        for registry in registries.values() {
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
        let Ok(registries) = self.registries.read() else {
            return;
        };
        for registry in registries.values() {
            if Arc::ptr_eq(registry, current) {
                continue;
            }
            let Ok(registrations) = registry.registrations() else {
                continue;
            };
            for registration in registrations.into_iter().filter(|registration| {
                quota_registration_matches(
                    registration,
                    failed,
                    classification.snapshot.scope,
                    quota_project.as_ref(),
                )
            }) {
                let _ =
                    registry.set_quota_snapshot(registration.credential(), classification.snapshot);
            }
        }
    }

    /// Capture the non-secret account and registry metadata needed to bind a
    /// Gemini Interaction ID observed after response headers are committed.
    pub(crate) fn interaction_affinity_binding(
        &self,
        selection: &PoolSelection,
    ) -> Option<InteractionAffinityBinding> {
        let policy = selection.policy()?;
        let affinity = policy.selection().affinity()?;
        if affinity.key() != "gemini.interaction_id" {
            return None;
        }
        let credential = selection.credential()?.clone();
        let provider = selection.provider().clone();
        let mut registry_keys = self
            .interaction_affinity_registries
            .get(policy.id())
            .cloned()
            .unwrap_or_default();
        registry_keys.insert(selection.registry_key.as_deref()?.to_owned());
        let registries_by_key = self.registries.read().ok()?;
        let registries = registry_keys
            .into_iter()
            .filter_map(|registry_key| {
                let registry = registries_by_key.get(&registry_key)?;
                let desired_target = registry_key
                    .strip_prefix("route:")
                    .map(route_registry_key)
                    .or_else(|| selection.target_binding_id().map(str::to_owned));
                let model = registry
                    .registrations()
                    .ok()?
                    .into_iter()
                    .filter(|registration| {
                        registration.credential() == &credential
                            && registration.provider() == &provider
                            && desired_target
                                .as_deref()
                                .is_none_or(|target| registration.target_id().as_str() == target)
                    })
                    .min_by(|left, right| left.target_id().cmp(right.target_id()))?
                    .clone();
                Some((
                    registry_key,
                    model.model().clone(),
                    model.binding_key().clone(),
                ))
            })
            .collect::<Vec<_>>();
        if registries.is_empty() {
            return None;
        }
        Some(InteractionAffinityBinding {
            credential,
            provider,
            upstream_model: selection
                .upstream_model()
                .unwrap_or(selection.model().as_str())
                .to_owned(),
            ttl: affinity.ttl(),
            scope: selection.affinity_scope.clone()?,
            scope_seed: selection.affinity_scope_seed.as_deref()?.to_owned(),
            registries,
        })
    }

    /// Bind one provider-returned Gemini Interaction ID after a clean response
    /// terminal to the exact account selected for its create request. Only the
    /// scoped redacted key is installed in memory and persistence.
    pub(crate) fn bind_interaction_affinity(
        &self,
        binding: &InteractionAffinityBinding,
        interaction_id: String,
        now: Timestamp,
    ) {
        let Some(key) = scoped_affinity_key(&binding.scope_seed, &interaction_id) else {
            return;
        };
        let Some(expires_at) =
            now.checked_add(u64::try_from(binding.ttl.as_millis()).unwrap_or(u64::MAX))
        else {
            return;
        };
        let now_instant = Instant::now();
        let expires_instant = now_instant.checked_add(binding.ttl).unwrap_or(now_instant);
        let Ok(registries) = self.registries.read() else {
            return;
        };
        for (registry_key, model, target_binding) in &binding.registries {
            let Some(registry) = registries.get(registry_key) else {
                continue;
            };
            let evicted = match registry.restore_affinity_binding(
                key.clone(),
                target_binding.clone(),
                binding.provider.clone(),
                model.clone(),
                now_instant,
                expires_instant,
            ) {
                Ok(evicted) => evicted,
                Err(_) => continue,
            };
            if let Some(evicted) = evicted {
                let _ = self.store.remove_session_affinity(&affinity_storage_key(
                    registry_key,
                    target_binding.target_id().as_str(),
                    evicted.as_str(),
                ));
            }
            let scope = AffinityBindingIdentity::new(
                registry_key
                    .strip_prefix("route:")
                    .unwrap_or(binding.scope.route_id.as_str()),
                binding.scope.policy_id.clone(),
                model.as_str(),
                binding.scope.account_pool_id.clone(),
                target_binding.target_id().as_str(),
            );
            let persisted = SessionAffinity::new_scoped(
                affinity_storage_key(
                    registry_key,
                    target_binding.target_id().as_str(),
                    key.as_str(),
                ),
                binding.provider.as_str(),
                binding.credential.as_str(),
                &binding.upstream_model,
                scope,
                now,
                expires_at,
            );
            let _ = self.store.upsert_session_affinity(persisted);
        }
    }

    /// Persist a newly selected affinity binding without storing raw keys.
    pub fn persist_affinity(&self, selection: &PoolSelection, now: Timestamp) {
        let Some(commit) = selection.affinity_commit() else {
            return;
        };
        self.persist_affinity_commit(commit, now);
    }

    pub(crate) fn persist_affinity_commit(&self, commit: AffinityCommit, now: Timestamp) {
        let Some(expires_at) = now.checked_add(commit.ttl.as_millis() as u64) else {
            return;
        };
        let binding = SessionAffinity::new_scoped(
            affinity_storage_key(
                &commit.registry_key,
                &commit.scope.target_binding_id,
                commit.key.as_str(),
            ),
            commit.provider.as_str(),
            commit.credential.as_str(),
            commit.upstream_model,
            commit.scope,
            now,
            expires_at,
        );
        let _ = self.store.upsert_session_affinity(binding);
    }

    fn register_and_restore_runtime_state(&self) -> Result<(), PoolError> {
        let mut views = self
            .account_mutations
            .gate
            .lock()
            .map_err(|_| PoolError::Selection)?;
        self.register_registry_view_locked(&mut views)?;
        self.restore_runtime_state_locked()
    }

    fn register_registry_view_locked(
        &self,
        views: &mut Vec<RegisteredRegistryView>,
    ) -> Result<(), PoolError> {
        views.retain(|view| view.registries.upgrade().is_some());
        if !views
            .iter()
            .any(|view| Weak::ptr_eq(&view.registries, &Arc::downgrade(&self.registries)))
        {
            views.push(RegisteredRegistryView {
                registries: Arc::downgrade(&self.registries),
                accounts: self.account_identities.values().cloned().collect(),
            });
        }

        let live_accounts = views
            .iter()
            .flat_map(|view| view.accounts.iter().cloned())
            .collect::<BTreeSet<_>>();
        self.account_mutations
            .enablement
            .write()
            .map_err(|_| PoolError::Selection)?
            .retain(|identity, _| live_accounts.contains(identity));
        Ok(())
    }

    fn restore_runtime_state_locked(&self) -> Result<(), PoolError> {
        self.restore_account_enablement_locked()?;
        self.restore_cooldowns()?;
        self.restore_quota_states()?;
        self.restore_affinities()?;
        Ok(())
    }

    fn restore_account_enablement_locked(&self) -> Result<(), PoolError> {
        let mut changes = Vec::with_capacity(self.accounts.len());
        for account in self.accounts.values() {
            let identity = self.account_mutation_identity(account.id())?;
            let current = self
                .store
                .credential_state(account.id())
                .map_err(|_| PoolError::Store)?;
            let exact_identity = current.as_ref().is_some_and(|state| {
                state.provider_id == identity.provider_id
                    && state.configuration_fingerprint == identity.configuration_fingerprint
            });
            let safe_legacy_identity = current.as_ref().is_some_and(|state| {
                state.provider_id == identity.provider_id
                    && state.configuration_fingerprint.is_empty()
            });
            let enabled = if exact_identity || safe_legacy_identity {
                current.as_ref().is_some_and(|state| state.enabled)
            } else {
                account.enabled()
            };
            if !exact_identity {
                self.store
                    .upsert_credential_state(CredentialState::new_with_fingerprint(
                        account.id(),
                        &identity.provider_id,
                        &identity.configuration_fingerprint,
                        enabled,
                        timestamp_now(),
                    ))
                    .map_err(|_| PoolError::Store)?;
            }
            let health_disabled = self
                .store
                .credential_health(account.id())
                .map_err(|_| PoolError::Store)?
                .is_some_and(|health| health.status == CredentialHealthStatus::Disabled);
            let credential =
                CredentialId::new(account.id()).map_err(|_| PoolError::InvalidCredential)?;
            changes.push((credential, enabled && !health_disabled));
        }

        let registries = self.registries.read().map_err(|_| PoolError::Selection)?;
        for registry in registries.values() {
            registry
                .set_credentials_enabled(&changes)
                .map_err(|_| PoolError::Selection)?;
        }
        drop(registries);

        let mut enablement = self
            .account_mutations
            .enablement
            .write()
            .map_err(|_| PoolError::Selection)?;
        for (credential, enabled) in changes {
            let identity = self.account_mutation_identity(credential.as_str())?;
            enablement.insert(identity, enabled);
        }
        Ok(())
    }

    fn restore_cooldowns(&self) -> Result<(), PoolError> {
        let now_wall = timestamp_now();
        let now_instant = Instant::now();
        let registries = self.registries.read().map_err(|_| PoolError::Selection)?;
        for cooldown in self
            .store
            .cooldowns_snapshot(now_wall)
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
            for (key, registry) in registries.iter() {
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
        let registries = self.registries.read().map_err(|_| PoolError::Selection)?;
        for cooldown in self
            .store
            .cooldowns_snapshot(now_wall)
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
            for registry in registries.values() {
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
        let registries = self.registries.read().map_err(|_| PoolError::Selection)?;
        let bindings = self
            .binding_index
            .read()
            .map_err(|_| PoolError::Selection)?;
        for affinity in self
            .store
            .session_affinities_snapshot(now_wall)
            .map_err(|_| PoolError::Store)?
        {
            let Some((registry_key, target_id, redacted_key)) =
                parse_affinity_storage_key(&affinity.key)
            else {
                continue;
            };
            if affinity.route_id.is_empty()
                || affinity.policy_id.is_empty()
                || affinity.logical_model.is_empty()
                || affinity.account_pool_id.is_empty()
                || affinity.target_binding_id != target_id
            {
                continue;
            }
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
            let Some(binding) = bindings.values().find(|binding| {
                binding.binding.target_id().as_str() == target_id
                    && binding.binding.account_id() == &credential
                    && binding.provider == provider
                    && binding.model.as_str() == affinity.logical_model
                    && binding.upstream_model.as_ref() == affinity.upstream_model.as_str()
            }) else {
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
            if let Some(registry) = registries.get(registry_key) {
                registry
                    .restore_affinity_binding(
                        key,
                        binding.binding.clone(),
                        provider,
                        binding.model.clone(),
                        last_used,
                        expires,
                    )
                    .map_err(|_| PoolError::Selection)?;
            }
        }
        Ok(())
    }

    fn registry_for(&self, selection: &PoolSelection) -> Option<Arc<CredentialRegistry>> {
        let key = selection.registry_key.as_deref()?;
        self.registries.read().ok()?.get(key).cloned()
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
        if let Ok(bindings) = self.binding_index.read() {
            if let Some(binding) = bindings.get(lease.binding_key()) {
                record.target_binding_id = Some(binding.binding.target_id().as_str().to_owned());
                record.priority_tier = Some(binding.priority);
            }
        }
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
        RequestId::new().to_string()
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
    .expect("compiled retry budgets satisfy runtime policy invariants")
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

fn account_is_selectable_for_upstream(
    upstream: Option<&pooler_config::UpstreamPlan>,
    account: &AccountPlan,
) -> bool {
    upstream.is_none_or(|upstream| {
        upstream.native().is_none()
            || crate::native::account_auth_kind_compatible(upstream, account.auth_kind())
    })
}

fn register_model_accounts(
    registry: &CredentialRegistry,
    model: &str,
    targets: &[pooler_config::ModelTargetPlan],
    accounts: &BTreeMap<String, AccountPlan>,
    account_pools: &BTreeMap<Arc<str>, pooler_config::AccountPoolPlan>,
    upstreams: &BTreeMap<Arc<str>, pooler_config::UpstreamPlan>,
    binding_index: &mut BTreeMap<BindingKey, Arc<RuntimeBinding>>,
) -> Result<(), PoolError> {
    let model = ModelId::new(model.to_owned()).map_err(|_| PoolError::InvalidModel)?;
    for target in targets {
        let account_ids = target_bound_accounts(target, account_pools);
        for account_id in account_ids {
            let Some(account) = accounts.get(account_id) else {
                continue;
            };
            if account.provider() != target.provider()
                || !account_is_selectable_for_upstream(upstreams.get(account.provider()), account)
            {
                continue;
            }
            let fingerprint = upstreams
                .get(account.provider())
                .map(|upstream| {
                    crate::account_configuration_fingerprint(
                        upstream,
                        account.id(),
                        account.auth_kind(),
                    )
                    .map_err(|_| PoolError::Selection)
                })
                .transpose()?
                .unwrap_or_else(|| format!("{}:{}", account.provider(), account.id()));
            let binding = BindingKey::new(target.binding_id().as_str(), account.id(), fingerprint)
                .map_err(|_| PoolError::Selection)?;
            let binding_target = Arc::new(RuntimeBinding {
                binding: binding.clone(),
                model: model.clone(),
                provider: ProviderId::new(target.provider().to_owned())
                    .map_err(|_| PoolError::InvalidProvider)?,
                upstream_id: Arc::from(target.provider()),
                upstream_model: Arc::from(target.upstream_model()),
                account: Some(account.clone()),
                pool_id: Some(Arc::from(
                    target
                        .account_pool()
                        .or(target.account())
                        .unwrap_or(target.id().as_str()),
                )),
                priority: target.priority(),
                capabilities: target.capabilities(),
                facts: target_routing_facts(target),
                wire_family: Some(Arc::from(target.wire_family())),
                endpoint_family: static_endpoint_family(target.wire_family()).map(Arc::from),
                profile: ModelProfile::DEFAULT,
                request_overlay: RequestOverlay::default(),
            });
            let registration = CredentialRegistration::with_binding(
                binding.clone(),
                ProviderId::new(account.provider().to_owned())
                    .map_err(|_| PoolError::InvalidProvider)?,
                model.clone(),
                target.capabilities(),
            )
            .map_err(|_| PoolError::Selection)?
            .with_weight(account.weight())
            .map_err(|_| PoolError::Selection)?;
            let registration = registration
                .with_target_weight(target.weight())
                .map_err(|_| PoolError::Selection)?
                .with_priority(target.priority())
                .map_err(|_| PoolError::Selection)?
                .with_pool_id(
                    target
                        .account_pool()
                        .or(target.account())
                        .unwrap_or(target.id().as_str()),
                )
                .map_err(|_| PoolError::Selection)?
                .with_codecs(target.codecs().iter().map(AsRef::as_ref))
                .map_err(|_| PoolError::Selection)?;
            let registration = registration.with_facts(target_routing_facts(target));
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
            binding_index.insert(binding, binding_target);
        }
    }
    Ok(())
}

/// Canonical endpoint family for a wire family that serves exactly one.
///
/// The OpenAI wire deliberately has no entry: it serves several families, so
/// the endpoint is chosen from the route rather than from the target.
fn static_endpoint_family(wire_family: &str) -> Option<&'static str> {
    match wire_family {
        "anthropic" | "anthropic_messages" => Some("messages"),
        _ => None,
    }
}

fn register_route_accounts(
    registry: &CredentialRegistry,
    route_key: &str,
    upstream: &str,
    target: &pooler_config::TargetPlan,
    accounts: &BTreeMap<String, AccountPlan>,
    upstreams: &BTreeMap<Arc<str>, pooler_config::UpstreamPlan>,
    binding_index: &mut BTreeMap<BindingKey, Arc<RuntimeBinding>>,
) -> Result<(), PoolError> {
    let model = ModelId::new(route_key.to_owned()).map_err(|_| PoolError::InvalidModel)?;
    for account in accounts.values().filter(|account| {
        account.provider() == upstream
            && account_is_selectable_for_upstream(upstreams.get(account.provider()), account)
    }) {
        let fingerprint = upstreams
            .get(account.provider())
            .map(|upstream| {
                crate::account_configuration_fingerprint(
                    upstream,
                    account.id(),
                    account.auth_kind(),
                )
                .map_err(|_| PoolError::Selection)
            })
            .transpose()?
            .unwrap_or_else(|| format!("{}:{}", account.provider(), account.id()));
        let target_id = route_registry_key(route_key);
        let binding = BindingKey::new(&target_id, account.id(), fingerprint)
            .map_err(|_| PoolError::Selection)?;
        let binding_target = Arc::new(RuntimeBinding {
            binding: binding.clone(),
            model: model.clone(),
            provider: ProviderId::new(account.provider().to_owned())
                .map_err(|_| PoolError::InvalidProvider)?,
            upstream_id: Arc::from(account.provider()),
            upstream_model: Arc::from(route_key),
            account: Some(account.clone()),
            pool_id: Some(Arc::from(route_key)),
            priority: 1,
            capabilities: target.capabilities(),
            facts: CandidateFacts::operator_capabilities(target.capabilities()),
            wire_family: None,
            endpoint_family: target.endpoint_family().map(Arc::from),
            profile: ModelProfile::DEFAULT,
            request_overlay: RequestOverlay::default(),
        });
        let registration = CredentialRegistration::with_binding(
            binding.clone(),
            ProviderId::new(account.provider().to_owned())
                .map_err(|_| PoolError::InvalidProvider)?,
            model.clone(),
            target.capabilities(),
        )
        .map_err(|_| PoolError::Selection)?
        .with_weight(account.weight())
        .map_err(|_| PoolError::Selection)?;
        let registration = registration
            .with_target_weight(1)
            .map_err(|_| PoolError::Selection)?
            .with_priority(1)
            .map_err(|_| PoolError::Selection)?
            .with_pool_id(route_key)
            .map_err(|_| PoolError::Selection)?
            .with_codecs(target.codecs().iter().map(AsRef::as_ref))
            .map_err(|_| PoolError::Selection)?;
        let registration =
            registration.with_facts(CandidateFacts::operator_capabilities(target.capabilities()));
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
        binding_index.insert(binding, binding_target);
    }
    Ok(())
}

fn register_catalog_model(
    registry: &CredentialRegistry,
    model: &pooler_model_catalog::CatalogModel,
    accounts: &BTreeMap<String, AccountPlan>,
    account_pools: &BTreeMap<Arc<str>, pooler_config::AccountPoolPlan>,
    upstreams: &BTreeMap<Arc<str>, pooler_config::UpstreamPlan>,
    binding_index: &mut BTreeMap<BindingKey, Arc<RuntimeBinding>>,
) -> Result<(), PoolError> {
    for target in model.targets() {
        let account_ids = target
            .account()
            .map(|account| vec![account.to_owned()])
            .or_else(|| {
                target.account_pool().and_then(|pool| {
                    account_pools
                        .get(pool)
                        .map(|pool| pool.accounts().iter().map(ToString::to_string).collect())
                })
            })
            .unwrap_or_default();
        let Some(upstream) = upstreams.get(target.provider().as_str()) else {
            continue;
        };
        if account_ids.is_empty() {
            let binding = BindingKey::new(
                target.binding_id(),
                "catalog-static",
                target.provider().as_str(),
            )
            .map_err(|_| PoolError::Selection)?;
            binding_index.insert(
                binding.clone(),
                Arc::new(RuntimeBinding {
                    binding,
                    model: model.id().clone(),
                    provider: target.provider().clone(),
                    upstream_id: Arc::from(target.provider().as_str()),
                    upstream_model: Arc::from(target.upstream_model().as_str()),
                    account: None,
                    pool_id: None,
                    priority: target.priority(),
                    capabilities: target.capabilities(),
                    facts: CandidateFacts::operator_capabilities(target.capabilities()),
                    wire_family: catalog_wire_family(target.profile()),
                    endpoint_family: catalog_endpoint_family(target.profile()),
                    profile: target.profile(),
                    request_overlay: model.request_overlay().clone(),
                }),
            );
            continue;
        }
        for account_id in account_ids {
            let Some(account) = accounts.get(&account_id) else {
                continue;
            };
            if account.provider() != target.provider().as_str()
                || !account_is_selectable_for_upstream(Some(upstream), account)
            {
                continue;
            }
            let fingerprint = crate::account_configuration_fingerprint(
                upstream,
                account.id(),
                account.auth_kind(),
            )
            .map_err(|_| PoolError::Selection)?;
            let binding = BindingKey::new(target.binding_id(), account.id(), fingerprint)
                .map_err(|_| PoolError::Selection)?;
            let binding_target = Arc::new(RuntimeBinding {
                binding: binding.clone(),
                model: model.id().clone(),
                provider: target.provider().clone(),
                upstream_id: Arc::from(target.provider().as_str()),
                upstream_model: Arc::from(target.upstream_model().as_str()),
                account: Some(account.clone()),
                pool_id: target.account_pool().or(target.account()).map(Arc::from),
                priority: target.priority(),
                capabilities: target.capabilities(),
                facts: CandidateFacts::operator_capabilities(target.capabilities()),
                wire_family: catalog_wire_family(target.profile()),
                endpoint_family: catalog_endpoint_family(target.profile()),
                profile: target.profile(),
                request_overlay: model.request_overlay().clone(),
            });
            let registration = CredentialRegistration::with_binding(
                binding.clone(),
                target.provider().clone(),
                model.id().clone(),
                target.capabilities(),
            )
            .map_err(|_| PoolError::Selection)?
            .with_weight(account.weight())
            .map_err(|_| PoolError::Selection)?
            .with_priority(target.priority())
            .map_err(|_| PoolError::Selection)?
            .with_pool_id(
                target
                    .account_pool()
                    .or(target.account())
                    .unwrap_or(target.binding_id()),
            )
            .map_err(|_| PoolError::Selection)?;
            let registration = registration
                .with_facts(CandidateFacts::operator_capabilities(target.capabilities()));
            let registration = registration
                .with_codecs(catalog_target_codecs(target.profile()))
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
            binding_index.insert(binding, binding_target);
        }
    }
    Ok(())
}

fn catalog_wire_family(profile: ModelProfile) -> Option<Arc<str>> {
    let family = match profile.request_transform {
        pooler_core::ModelRequestTransform::AnthropicMessages => "anthropic",
        pooler_core::ModelRequestTransform::GeminiGenerateContent => "gemini",
        pooler_core::ModelRequestTransform::XaiChat => "xai",
        pooler_core::ModelRequestTransform::KimiChat => "kimi",
        pooler_core::ModelRequestTransform::OpenAiChat
        | pooler_core::ModelRequestTransform::ProtocolDefault => "openai",
    };
    Some(Arc::from(family))
}

fn catalog_target_codecs(profile: ModelProfile) -> impl Iterator<Item = &'static str> {
    let variants = profile.endpoint_variants;
    let text = variants.responses || variants.chat_completions || variants.messages;
    [
        variants.responses.then_some("decode.openai.responses"),
        variants.chat_completions.then_some("decode.openai.chat"),
        variants.messages.then_some("decode.anthropic.messages"),
        text.then_some("decode.fx.language_model"),
        variants
            .generate_content
            .then_some("decode.gemini.generate_content"),
    ]
    .into_iter()
    .flatten()
}

fn catalog_endpoint_family(profile: ModelProfile) -> Option<Arc<str>> {
    let variants = profile.endpoint_variants;
    if variants.responses {
        Some(Arc::from("responses"))
    } else if variants.chat_completions {
        Some(Arc::from("chat_completions"))
    } else if variants.messages {
        Some(Arc::from("messages"))
    } else if variants.generate_content {
        Some(Arc::from("generate_content"))
    } else if variants.realtime {
        Some(Arc::from("realtime"))
    } else {
        None
    }
}

fn target_routing_facts(target: &pooler_config::ModelTargetPlan) -> CandidateFacts {
    let mut facts = CandidateFacts::operator_capabilities(target.capabilities());
    if !target.parameters().is_empty() {
        facts = facts.with_parameters(target.parameters().iter().map(ToString::to_string));
    }
    if let Some(context_window) = target.context_window() {
        facts = facts.with_context_window(context_window);
    }
    if !target.quantization().is_empty() {
        facts = facts.with_quantization(target.quantization().iter().map(ToString::to_string));
    }
    if let Some(privacy) = target.privacy() {
        facts = facts.with_privacy(privacy);
    }
    if let Some(zdr) = target.zdr() {
        facts = facts.with_zdr(zdr);
    }
    if let Some(data_policy) = target.data_policy() {
        facts = facts.with_data_policy(data_policy);
    }
    if let Some(region) = target.region() {
        facts = facts.with_region(region);
    }
    if let Some(price) = target.price() {
        facts = facts.with_price(price);
    }
    facts
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
    if let Some(model) = model {
        if let Some(plan) = config.models().get(model) {
            let target = plan
                .targets()
                .iter()
                .filter(|target| target.provider() == route.target().upstream())
                .min_by(|left, right| {
                    left.priority()
                        .cmp(&right.priority())
                        .then_with(|| left.binding_id().cmp(right.binding_id()))
                })
                .or_else(|| {
                    plan.targets().iter().min_by(|left, right| {
                        left.priority()
                            .cmp(&right.priority())
                            .then_with(|| left.binding_id().cmp(right.binding_id()))
                    })
                })
                .ok_or(PoolError::UnknownModel {
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
            .and_then(|model| {
                model
                    .targets()
                    .iter()
                    .filter(|target| target.provider().as_str() == route.target().upstream())
                    .min_by(|left, right| {
                        left.priority()
                            .cmp(&right.priority())
                            .then_with(|| left.binding_id().cmp(right.binding_id()))
                    })
                    .or_else(|| {
                        model.targets().iter().min_by(|left, right| {
                            left.priority()
                                .cmp(&right.priority())
                                .then_with(|| left.binding_id().cmp(right.binding_id()))
                        })
                    })
            })
        {
            return Ok((
                model.to_owned(),
                target.provider().to_string(),
                Some(target.upstream_model().to_string()),
            ));
        }
        if route.target().model_source().is_some() {
            return Err(PoolError::UnknownModel {
                model: model.to_owned(),
            });
        }
    } else if route.target().model_source().is_some() {
        return Err(PoolError::InvalidModel);
    }
    Ok((
        model.unwrap_or(route.id()).to_owned(),
        route.target().upstream().to_owned(),
        None,
    ))
}

fn resolve_with_configured_model_fallback(
    config: &CompiledConfig,
    route: &RoutePlan,
    requested_model: Option<&str>,
    policy: Option<&PolicyPlan>,
    catalog: Option<&CatalogSnapshot>,
) -> Result<(String, String, Option<String>), PoolError> {
    let Some(requested_model) = requested_model else {
        return resolve_static_target(config, route, None, catalog);
    };
    match resolve_static_target(config, route, Some(requested_model), catalog) {
        Ok(value) => Ok(value),
        Err(error) => {
            let Some(policy) = policy else {
                return Err(error);
            };
            if !policy.routing().allow_fallbacks() {
                return Err(error);
            }
            for fallback in policy.routing().fallback_models() {
                if fallback.as_ref() == requested_model {
                    continue;
                }
                if let Ok(value) = resolve_static_target(config, route, Some(fallback), catalog) {
                    return Ok(value);
                }
            }
            Err(error)
        }
    }
}

fn next_model_fallback<'a>(
    policy: &'a PolicyPlan,
    requested_model: Option<&str>,
    context: &SelectionContext,
) -> Option<&'a str> {
    if !policy.routing().allow_fallbacks() {
        return None;
    }
    let index = context.fallback_depth;
    let requested_model = requested_model.unwrap_or_default();
    policy
        .routing()
        .fallback_models()
        .iter()
        .filter(|model| model.as_ref() != requested_model)
        .nth(index)
        .map(|model| model.as_ref())
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
    let (capabilities, codec_supported) = if let Some(model) = model {
        if let Some(plan) = config.models().get(model) {
            let Some(target) = plan
                .targets()
                .iter()
                .filter(|target| target.provider() == static_upstream)
                .min_by(|left, right| {
                    left.priority()
                        .cmp(&right.priority())
                        .then_with(|| left.binding_id().cmp(right.binding_id()))
                })
                .or_else(|| {
                    plan.targets().iter().min_by(|left, right| {
                        left.priority()
                            .cmp(&right.priority())
                            .then_with(|| left.binding_id().cmp(right.binding_id()))
                    })
                })
            else {
                return false;
            };
            (
                target.capabilities(),
                context.codec().is_none_or(|codec| {
                    target.codecs().iter().any(|value| value.as_ref() == codec)
                }),
            )
        } else {
            let Some(target) = catalog
                .and_then(|catalog| catalog.get(model))
                .and_then(|model| {
                    model
                        .targets()
                        .iter()
                        .filter(|target| target.provider().as_str() == static_upstream)
                        .min_by(|left, right| {
                            left.priority()
                                .cmp(&right.priority())
                                .then_with(|| left.binding_id().cmp(right.binding_id()))
                        })
                        .or_else(|| {
                            model.targets().iter().min_by(|left, right| {
                                left.priority()
                                    .cmp(&right.priority())
                                    .then_with(|| left.binding_id().cmp(right.binding_id()))
                            })
                        })
                })
            else {
                return false;
            };
            (
                target.capabilities(),
                context
                    .codec()
                    .is_none_or(|codec| profile_supports_codec(target.profile(), codec)),
            )
        }
    } else {
        (
            route.target().capabilities(),
            context.codec().is_none_or(|codec| {
                route
                    .target()
                    .codecs()
                    .iter()
                    .any(|value| value.as_ref() == codec)
            }),
        )
    };
    let required_capabilities = context
        .required_capabilities()
        .union(route.target().capabilities());
    capabilities.contains_all(required_capabilities) && codec_supported
}

fn profile_supports_codec(profile: ModelProfile, codec: &str) -> bool {
    match codec {
        "decode.gemini.generate_content" => {
            profile.request_transform == pooler_core::ModelRequestTransform::GeminiGenerateContent
                || profile.endpoint_variants.generate_content
        }
        _ => false,
    }
}

fn route_registry_key(route: &str) -> String {
    format!("route:{route}")
}

fn scoped_affinity_key(scope: &str, value: &str) -> Option<AffinityKey> {
    if value.is_empty() {
        return None;
    }
    AffinityKey::new(format!("{scope}|{value}").as_bytes()).ok()
}

fn affinity_scope_seed(
    config: &CompiledConfig,
    catalog: Option<&CatalogSnapshot>,
    route: &RoutePlan,
    logical_model: &str,
) -> String {
    let policy = route.target().policy().unwrap_or("direct");
    let interaction_scope = config
        .policies()
        .get(policy)
        .and_then(|policy| policy.selection().affinity())
        .is_some_and(|affinity| affinity.key() == "gemini.interaction_id");
    let mut bindings = BTreeSet::new();
    let configured_models = if interaction_scope {
        config.models().values().collect::<Vec<_>>()
    } else {
        config.models().get(logical_model).into_iter().collect()
    };
    for model in configured_models {
        for target in model.targets() {
            bindings.insert(format!(
                "{}:{}:{}",
                target.binding_id(),
                target.provider(),
                target
                    .account_pool()
                    .or(target.account())
                    .unwrap_or_default()
            ));
        }
    }
    let catalog_models = catalog
        .map(|catalog| {
            if interaction_scope {
                catalog.models().values().collect::<Vec<_>>()
            } else {
                catalog.get(logical_model).into_iter().collect()
            }
        })
        .unwrap_or_default();
    for model in catalog_models {
        for target in model.targets() {
            bindings.insert(format!(
                "{}:{}:{}",
                target.binding_id(),
                target.provider(),
                target
                    .account_pool()
                    .or(target.account())
                    .unwrap_or_default()
            ));
        }
    }
    if interaction_scope {
        let routes = config
            .routes()
            .iter()
            .filter(|candidate| candidate.target().policy() == Some(policy))
            .map(|candidate| candidate.id())
            .collect::<Vec<_>>()
            .join(",");
        return format!(
            "v2|interaction-routes:{routes}|policy:{policy}|bindings:{}",
            bindings.into_iter().collect::<Vec<_>>().join(",")
        );
    }
    format!(
        "v2|route:{}|policy:{}|model:{}|bindings:{}",
        route.id(),
        policy,
        logical_model,
        bindings.into_iter().collect::<Vec<_>>().join(",")
    )
}

fn affinity_scope_for_selection(
    route: &RoutePlan,
    policy: &PolicyPlan,
    logical_model: &str,
    target: &RuntimeBinding,
    _scope_seed: &str,
) -> AffinityBindingIdentity {
    AffinityBindingIdentity::new(
        route.id(),
        policy.id(),
        logical_model,
        target
            .pool_id
            .as_deref()
            .unwrap_or(target.binding.account_id().as_str()),
        target.binding.target_id().as_str(),
    )
}

fn affinity_storage_key(registry_key: &str, target_id: &str, redacted_key: &str) -> String {
    format!("v2|{registry_key}|{target_id}|{redacted_key}")
}

fn parse_affinity_storage_key(key: &str) -> Option<(&str, &str, &str)> {
    let mut parts = key.splitn(4, '|');
    if parts.next() != Some("v2") {
        return None;
    }
    Some((parts.next()?, parts.next()?, parts.next()?))
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

fn routing_requirements(policy: &PolicyPlan) -> RoutingRequirements {
    let routing = policy.routing();
    RoutingRequirements {
        provider_order: routing.order().iter().map(ToString::to_string).collect(),
        provider_allow: routing.allow().iter().map(ToString::to_string).collect(),
        provider_deny: routing.deny().iter().map(ToString::to_string).collect(),
        target_order: routing
            .target_order()
            .iter()
            .map(ToString::to_string)
            .collect(),
        target_allow: routing
            .target_allow()
            .iter()
            .map(ToString::to_string)
            .collect(),
        target_deny: routing
            .target_deny()
            .iter()
            .map(ToString::to_string)
            .collect(),
        allow_fallbacks: routing.allow_fallbacks(),
        required_parameters: routing
            .required_parameters()
            .iter()
            .map(ToString::to_string)
            .collect(),
        required_capabilities: routing.required_capabilities(),
        minimum_context: routing.minimum_context(),
        quantization: routing
            .quantization()
            .iter()
            .map(ToString::to_string)
            .collect(),
        privacy: routing.privacy().map(str::to_owned),
        require_zdr: routing.require_zdr(),
        data_policy: routing.data_policy().map(str::to_owned),
        region: routing.region().map(str::to_owned),
        max_price: routing.max_price(),
        prefer_price: routing.preference().price(),
        prefer_latency: routing.preference().latency(),
        prefer_throughput: routing.preference().throughput(),
        max_latency_ms: routing.preference().max_latency_ms(),
        min_throughput: routing.preference().min_throughput(),
        min_samples: routing.preference().min_samples(),
        stale_after_ms: routing.preference().stale_after_ms(),
    }
}

fn model_target_order(config: &CompiledConfig, model: &str) -> Vec<String> {
    config
        .models()
        .get(model)
        .map(|model| {
            model
                .targets()
                .iter()
                .map(|target| target.id().as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn model_account_allow_list(config: &CompiledConfig, model: &str) -> Option<Vec<String>> {
    let targets = config.models().get(model)?.targets();
    let mut accounts = Vec::new();
    let mut seen = BTreeSet::new();
    for target in targets {
        for account in target_bound_accounts(target, config.account_pools()) {
            if seen.insert(account) {
                accounts.push(account.to_owned());
            }
        }
    }
    Some(accounts)
}

fn target_bound_accounts<'a>(
    target: &'a pooler_config::ModelTargetPlan,
    account_pools: &'a BTreeMap<Arc<str>, pooler_config::AccountPoolPlan>,
) -> Vec<&'a str> {
    if let Some(account) = target.account() {
        return vec![account];
    }
    target
        .account_pool()
        .and_then(|pool| account_pools.get(pool))
        .map_or_else(Vec::new, |pool| {
            pool.accounts().iter().map(AsRef::as_ref).collect()
        })
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
        | "openai.previous_response_id"
        | "gemini.interaction_id" => context
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
        CooldownScope::CredentialModel { credential, model } => (
            "credential_model",
            encode_compound_cooldown_key(credential.as_str(), model.as_str()),
        ),
        CooldownScope::Binding(binding) => (
            "binding",
            serde_json::to_string(binding).expect("binding identity serializes"),
        ),
        CooldownScope::BindingModel { binding, model } => (
            "binding_model",
            encode_compound_cooldown_key(
                &serde_json::to_string(binding).expect("binding identity serializes"),
                model.as_str(),
            ),
        ),
        CooldownScope::Model(model) => ("model", model.to_string()),
        CooldownScope::Provider(provider) => ("provider", provider.to_string()),
        CooldownScope::ProviderModel { provider, model } => (
            "provider_model",
            encode_compound_cooldown_key(provider.as_str(), model.as_str()),
        ),
        CooldownScope::Route(route) => ("route", route.to_string()),
    }
}

fn encode_compound_cooldown_key(left: &str, right: &str) -> String {
    format!("v2:{}:{}:{}{}", left.len(), right.len(), left, right)
}

fn decode_compound_cooldown_key(key: &str) -> Option<(String, String)> {
    let value = key.strip_prefix("v2:")?;
    let (left_length, value) = value.split_once(':')?;
    let (right_length, value) = value.split_once(':')?;
    let left_length = left_length.parse::<usize>().ok()?;
    let right_length = right_length.parse::<usize>().ok()?;
    let bytes = value.as_bytes();
    let total = left_length.checked_add(right_length)?;
    if bytes.len() != total {
        return None;
    }
    let left = String::from_utf8(bytes[..left_length].to_vec()).ok()?;
    let right = String::from_utf8(bytes[left_length..].to_vec()).ok()?;
    Some((left, right))
}

fn parse_compound_cooldown_key(key: &str) -> Option<(String, String)> {
    decode_compound_cooldown_key(key).or_else(|| {
        // Legacy keys were only unambiguous when neither component contained
        // a colon. Keep accepting that safe subset for restart compatibility.
        (key.matches(':').count() == 1).then(|| {
            key.split_once(':')
                .map(|(left, right)| (left.to_owned(), right.to_owned()))
        })?
    })
}

fn parse_cooldown_scope(scope: &str, key: &str) -> Option<(CooldownScope, Option<String>)> {
    let parse_id = |value: &str| ModelId::new(value.to_owned()).ok();
    match scope {
        "credential" => Some((
            CooldownScope::Credential(CredentialId::new(key.to_owned()).ok()?),
            None,
        )),
        "credential_model" => {
            let (credential, model) = parse_compound_cooldown_key(key)?;
            Some((
                CooldownScope::CredentialModel {
                    credential: CredentialId::new(credential).ok()?,
                    model: parse_id(&model)?,
                },
                None,
            ))
        }
        "binding" => Some((
            CooldownScope::Binding(serde_json::from_str(key).ok()?),
            None,
        )),
        "binding_model" => {
            let (binding, model) = parse_compound_cooldown_key(key)?;
            Some((
                CooldownScope::BindingModel {
                    binding: serde_json::from_str(&binding).ok()?,
                    model: parse_id(&model)?,
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
            let (provider, model) = parse_compound_cooldown_key(key)?;
            Some((
                CooldownScope::ProviderModel {
                    provider: ProviderId::new(provider).ok()?,
                    model: parse_id(&model)?,
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

/// Apply one configured account secret using the upstream provider's complete
/// authentication placement.
pub fn apply_configured_account_auth(
    headers: &mut HeaderMap,
    secret: Option<&SecretRef>,
    configured_auth: Option<&pooler_config::AuthPlan>,
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
        SecretRef::Managed(_) => return Err(PoolError::Store),
    };
    let value = reference.resolve().map_err(|_| PoolError::Store)?;
    if value.expose_secret().chars().any(char::is_whitespace) {
        return Err(PoolError::Store);
    }
    let placement = if let Some(auth) = configured_auth {
        AuthPlacement::from_configured_parts(auth.kind(), auth.header(), auth.value_prefix())
    } else {
        AuthPlacement::from_configured_parts("bearer_secret", None, None)
    }
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
    use pooler_model_catalog::{
        CatalogSourceConfig, DiscoveredModel, DiscoveryFuture, DiscoveryResponse, ModelDiscovery,
        RefreshConfig, RegisteredSource,
    };
    use pooler_store::{CredentialPayload, MasterKey, SqliteStore};
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[derive(Debug)]
    struct FixedCatalogModel(&'static str);

    impl ModelDiscovery for FixedCatalogModel {
        fn discover(&self) -> DiscoveryFuture<'_> {
            let model = DiscoveredModel::new(
                ModelId::new(self.0).expect("test model ID"),
                CapabilitySet::from(Capability::Text),
            );
            Box::pin(std::future::ready(Ok(DiscoveryResponse::new(vec![model]))))
        }
    }

    async fn one_model_catalog(
        source_id: &str,
        provider: &str,
        account: &str,
        model: &'static str,
    ) -> Arc<CatalogService> {
        let source = CatalogSourceConfig {
            id: source_id.to_owned(),
            provider: provider.to_owned(),
            account: Some(account.to_owned()),
            ..CatalogSourceConfig::default()
        }
        .compile()
        .expect("catalog source");
        let service = Arc::new(
            CatalogService::new(
                vec![RegisteredSource::new(
                    source,
                    Arc::new(FixedCatalogModel(model)),
                )],
                RefreshConfig::default().compile().expect("refresh limits"),
            )
            .expect("catalog service"),
        );
        service.select_all(source_id).expect("select all models");
        service.refresh(1).await.expect("catalog refresh");
        service
    }

    #[tokio::test]
    async fn replacing_catalog_service_rebuilds_same_generation_bindings() {
        let config = compile_yaml(
            "catalog-replacement.yaml",
            r#"
version: 2
upstreams:
  first: {url: https://first.example/v1}
  second: {url: https://second.example/v1}
accounts:
  first-account: {provider: first, secret: env:FIRST_KEY}
  second-account: {provider: second, secret: env:SECOND_KEY}
"#,
        )
        .expect("catalog replacement config");
        let first = one_model_catalog("first.models", "first", "first-account", "old-model").await;
        let second =
            one_model_catalog("second.models", "second", "second-account", "new-model").await;
        assert_eq!(
            first.snapshot().generation(),
            second.snapshot().generation()
        );

        let coordinator = PoolingCoordinator::new(&config)
            .expect("coordinator")
            .with_catalog(first);
        let reconfigured = coordinator
            .reconfigure(&config)
            .expect("reconfigured coordinator")
            .with_optional_catalog(Some(second));
        let registries = reconfigured.registries.read().expect("registries");

        assert!(!registries.contains_key("old-model"));
        assert!(registries.contains_key("new-model"));
    }

    #[test]
    fn provider_routes_keep_their_configured_api_base_path() {
        let config = compile_yaml(
            "provider-endpoints.yaml",
            r#"
version: 2
upstreams:
  fireworks: {known_provider: fireworks-ai}
  openrouter: {known_provider: openrouter}
  zai: {known_provider: zai}
"#,
        )
        .expect("provider config");

        assert_eq!(
            provider_endpoint_path(
                &config.upstreams()["fireworks"],
                None,
                "/v1/chat/completions",
                Some("chat_completions")
            )
            .expect("Fireworks chat endpoint"),
            "/inference/v1/chat/completions"
        );
        assert_eq!(
            provider_endpoint_path(&config.upstreams()["openrouter"], None, "/v1/models", None)
                .expect("OpenRouter models endpoint"),
            "/api/v1/models"
        );
        assert_eq!(
            provider_endpoint_path(
                &config.upstreams()["zai"],
                None,
                "/v1/chat/completions",
                Some("chat_completions")
            )
            .expect("Z.AI chat endpoint"),
            "/api/paas/v4/chat/completions"
        );
        assert_eq!(
            provider_endpoint_path(&config.upstreams()["fireworks"], None, "/v1/models", None)
                .expect("Fireworks models endpoint"),
            "/inference/v1/models"
        );
    }

    #[test]
    fn account_secret_preserves_custom_header_placement() {
        let mut secret = NamedTempFile::new().expect("temporary account secret");
        secret
            .write_all(b"account-secret")
            .expect("account secret contents");
        let secret_ref = SecretRef::File(Arc::from(secret.path().to_string_lossy().into_owned()));
        let config = compile_yaml(
            "custom-account-auth.yaml",
            r#"
version: 2
upstreams:
  custom:
    url: https://provider.example
    auth:
      kind: header
      header: api-key
      value_prefix: 'Token '
      secret: env:UPSTREAM_UNUSED
"#,
        )
        .expect("custom auth config");
        let mut headers = HeaderMap::new();

        assert!(apply_configured_account_auth(
            &mut headers,
            Some(&secret_ref),
            config.upstreams()["custom"].auth(),
        )
        .expect("account auth applies"));
        assert_eq!(
            headers.get("api-key"),
            Some(&HeaderValue::from_static("Token account-secret"))
        );
        assert!(!headers.contains_key(http::header::AUTHORIZATION));
    }

    #[test]
    fn persistence_status_tracks_redacted_write_loss_and_recovery() {
        let status = PersistenceStatus::new(true);
        let initial = status.json();
        assert_eq!(initial["enabled"], true);
        assert_eq!(initial["complete"], true);

        status.record_failure(
            PersistenceStream::RequestEvents,
            &StoreError::Sqlite("/private/operator/path".to_owned()),
        );
        let failed = status.json();
        assert_eq!(failed["complete"], false);
        assert_eq!(failed["request_events"]["complete"], false);
        assert_eq!(failed["request_events"]["lost_writes"], 1);
        assert_eq!(failed["request_events"]["last_failure_class"], "database");
        assert!(!failed.to_string().contains("/private/operator/path"));

        status.record_success(PersistenceStream::RequestEvents, 1_700_000_000_000);
        let recovered = status.json();
        assert_eq!(recovered["request_events"]["complete"], false);
        assert_eq!(recovered["request_events"]["successful_writes"], 1);
        assert_eq!(
            recovered["request_events"]["last_success_at_ms"],
            1_700_000_000_000_u64
        );
    }

    fn pooled_config(affinity: bool) -> CompiledConfig {
        let affinity = if affinity {
            "\n      affinity: {key: header:x-session, ttl: 10m, rebind: true}"
        } else {
            ""
        };
        compile_yaml(
            "pooling-test.yaml",
            &format!(
                "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://127.0.0.1:1}}}}\naccounts:\n  first: {{provider: local, secret: env:POOLER_FIRST}}\n  second: {{provider: local, secret: env:POOLER_SECOND}}\naccount_pools:\n  pool: {{provider: local, strategy: ordered_fallback, accounts: [first, second]}}\npolicies:\n  pooled:\n    selection:\n      strategy: ordered_fallback{affinity}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}}\nroutes:\n  - id: pooled\n    listen: local\n    target: {{provider: local, policy: pooled}}\n",
            ),
        )
        .expect("pooling test config")
    }

    fn account_mutation_config() -> CompiledConfig {
        compile_yaml(
            "account-mutation.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  provider-a: {url: http://127.0.0.1:1}
  provider-b: {url: http://127.0.0.1:2}
accounts:
  alpha: {provider: provider-a, secret: env:POOLER_ALPHA}
  beta: {provider: provider-a, secret: env:POOLER_BETA}
  gamma: {provider: provider-b, secret: env:POOLER_GAMMA}
account_pools:
  provider-a-accounts: {provider: provider-a, strategy: ordered_fallback, accounts: [alpha, beta]}
policies:
  provider-a-policy:
    selection: {strategy: ordered_fallback}
models:
  - id: public
    targets:
      - {id: public-target, provider: provider-a, account_pool: provider-a-accounts, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
routes:
  - id: pooled
    listen: local
    match: {path: /pooled}
    target: {provider: provider-a, policy: provider-a-policy}
  - id: static
    listen: local
    match: {path: /static}
    ingress: {mode: patch}
    target: {provider: provider-a, model_from: request.model}
"#,
        )
        .expect("account mutation config")
    }

    fn native_reauth_budget_config(
        maximum_credentials: u32,
        maximum_upstreams: u32,
    ) -> CompiledConfig {
        compile_yaml(
            "native-reauth-budget.yaml",
            &format!(
                r#"
version: 2
listeners: {{local: {{bind: 127.0.0.1:0}}}}
upstreams:
  first:
    url: http://127.0.0.1:1
    native: {{kind: codex}}
    oauth: {{authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: first-client, scopes: [openid]}}
  second:
    url: http://127.0.0.1:2
    native: {{kind: codex}}
    oauth: {{authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: second-client, scopes: [openid]}}
accounts:
  first: {{provider: first, auth_kind: oauth, max_concurrency: 1}}
  second: {{provider: second, auth_kind: oauth}}
models:
  - id: public
    targets:
      - {{id: first-target, provider: first, account: first, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}}
      - {{id: second-target, provider: second, account: second, priority: 2, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}}
policies:
  pooled:
    selection: {{strategy: ordered_fallback}}
    retry: {{maximum_attempts: 2, maximum_credentials: {maximum_credentials}, maximum_upstreams: {maximum_upstreams}, statuses: [503], before_commit_only: true, base_delay: 25ms, maximum_delay: 25ms, maximum_total_delay: 25ms}}
routes:
  - id: pooled
    listen: local
    ingress: {{mode: patch}}
    target: {{provider: first, model_from: request.model, policy: pooled}}
    response: {{mode: opaque}}
"#
            ),
        )
        .expect("native reauthentication budget config")
    }

    fn fingerprinted_native_reauth_coordinator(config: &CompiledConfig) -> PoolingCoordinator {
        let coordinator = PoolingCoordinator::new(config).expect("coordinator");
        for account_id in ["first", "second"] {
            let upstream = &config.upstreams()[account_id];
            let fingerprint = crate::account_configuration_fingerprint(
                upstream,
                account_id,
                AccountAuthKind::OAuth,
            )
            .expect("OAuth account fingerprint");
            coordinator
                .store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    account_id,
                    account_id,
                    fingerprint,
                    true,
                    timestamp_now(),
                ))
                .expect("fingerprinted OAuth account state");
        }
        coordinator
    }

    fn classify_native_reauth_budget_case(
        maximum_credentials: u32,
        maximum_upstreams: u32,
    ) -> (PoolingCoordinator, PoolFailure) {
        let config = native_reauth_budget_config(maximum_credentials, maximum_upstreams);
        let coordinator = fingerprinted_native_reauth_coordinator(&config);
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let failed_generation = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential")
            .revision;
        let (credentials_used, providers_used) = used_target_sets(&selection);
        let failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("reauthentication classification");
        (coordinator, failure)
    }

    #[test]
    fn native_reauth_replacement_honors_distinct_credential_and_provider_budgets() {
        for (credentials, providers) in [(1, 2), (2, 1)] {
            let (coordinator, failure) = classify_native_reauth_budget_case(credentials, providers);
            assert!(!failure.decision.is_retry());
            assert!(failure.replacement.is_none());
            let states = coordinator
                .credential_states()
                .expect("credential states remain readable");
            assert!(states
                .iter()
                .any(|state| state.credential_id == "first" && !state.enabled));
            assert!(states
                .iter()
                .any(|state| state.credential_id == "second" && state.enabled));
        }

        let (_coordinator, mut failure) = classify_native_reauth_budget_case(2, 2);
        assert!(failure.decision.is_retry());
        let replacement = failure
            .take_replacement()
            .expect("both budgets admit the alternate target");
        assert_eq!(
            replacement.credential().map(CredentialId::as_str),
            Some("second")
        );
        assert_eq!(replacement.provider().as_str(), "second");
    }

    #[test]
    fn native_selection_and_recovery_skip_non_oauth_candidates() {
        let config = compile_yaml(
            "native-reauth-auth-kind.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  provider:
    url: http://127.0.0.1:1
    native: {kind: kimi}
    oauth: {authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: client, scopes: [openid]}
accounts:
  first: {provider: provider, auth_kind: oauth}
  middle: {provider: provider, auth_kind: api_key, secret: env:MIDDLE_KEY}
  last: {provider: provider, auth_kind: oauth}
models:
  - id: public
    targets:
      - {id: first-target, provider: provider, account: first, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
      - {id: middle-target, provider: provider, account: middle, priority: 2, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
      - {id: last-target, provider: provider, account: last, priority: 3, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
    retry: {maximum_attempts: 3, maximum_credentials: 3, maximum_upstreams: 1, statuses: [429, 503], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}
routes:
  - id: pooled
    listen: local
    ingress: {mode: patch}
    target: {provider: provider, model_from: request.model, policy: pooled}
    response: {mode: opaque}
"#,
        )
        .expect("mixed authentication-kind config");
        let route = config.route("pooled").expect("route");

        let initial_coordinator = PoolingCoordinator::new(&config).expect("initial coordinator");
        initial_coordinator
            .set_account_enabled("first", false)
            .expect("disable first account");
        let initial = initial_coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("compatible initial selection");
        assert_eq!(
            initial.credential().map(CredentialId::as_str),
            Some("last"),
            "initial selection must skip the incompatible API-key account",
        );

        let quota_coordinator = PoolingCoordinator::new(&config).expect("quota coordinator");
        let mut quota_selection = quota_coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first quota selection");
        let (quota_credentials, quota_providers) = used_target_sets(&quota_selection);
        let mut quota_failure = quota_coordinator.classify_failure(FailureInput {
            config: &config,
            route,
            selection: &mut quota_selection,
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
            credentials_used: &quota_credentials,
            providers_used: &quota_providers,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        });
        assert_eq!(
            quota_failure
                .take_replacement()
                .expect("compatible quota replacement")
                .credential()
                .map(CredentialId::as_str),
            Some("last"),
            "quota recovery must skip the incompatible API-key account",
        );

        let coordinator = PoolingCoordinator::new(&config).expect("reauth coordinator");
        let upstream = &config.upstreams()["provider"];
        for account_id in ["first", "last"] {
            let fingerprint = crate::account_configuration_fingerprint(
                upstream,
                account_id,
                AccountAuthKind::OAuth,
            )
            .expect("OAuth account fingerprint");
            coordinator
                .store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    account_id,
                    "provider",
                    fingerprint,
                    true,
                    timestamp_now(),
                ))
                .expect("fingerprinted OAuth account state");
        }
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        assert_eq!(
            selection.credential().map(CredentialId::as_str),
            Some("first")
        );
        let failed_generation = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential")
            .revision;
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("reauthentication classification");

        let replacement = failure.take_replacement().expect("OAuth replacement");
        assert_eq!(
            replacement.credential().cloned(),
            Some(CredentialId::new("last").expect("credential"))
        );
        assert!(
            !coordinator
                .binding_index
                .read()
                .expect("binding index")
                .values()
                .any(|binding| binding.binding.account_id().as_str() == "middle"),
            "authentication-incompatible targets must never enter a selectable registry",
        );
    }

    #[test]
    fn native_reauth_preserves_compatible_cross_provider_api_key_fallback() {
        let config = compile_yaml(
            "native-reauth-api-key-fallback.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  native:
    url: http://127.0.0.1:1
    native: {kind: codex}
    oauth: {authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: client, scopes: [openid]}
  api: {url: http://127.0.0.1:2}
accounts:
  native: {provider: native, auth_kind: oauth}
  api: {provider: api, auth_kind: api_key, secret: env:API_KEY}
models:
  - id: public
    targets:
      - {id: native-target, provider: native, account: native, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
      - {id: api-target, provider: api, account: api, priority: 2, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
    retry: {maximum_attempts: 2, maximum_credentials: 2, maximum_upstreams: 2, statuses: [503], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}
routes:
  - id: pooled
    listen: local
    ingress: {mode: patch}
    target: {provider: native, model_from: request.model, policy: pooled}
    response: {mode: opaque}
"#,
        )
        .expect("cross-provider authentication config");
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let upstream = &config.upstreams()["native"];
        let fingerprint =
            crate::account_configuration_fingerprint(upstream, "native", AccountAuthKind::OAuth)
                .expect("OAuth account fingerprint");
        let native = coordinator
            .store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "native",
                "native",
                fingerprint,
                true,
                timestamp_now(),
            ))
            .expect("fingerprinted OAuth account state");
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("native selection");
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation: native.revision,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("reauthentication classification");

        let replacement = failure.take_replacement().expect("API-key fallback");
        assert_eq!(
            replacement.credential().map(CredentialId::as_str),
            Some("api")
        );
        assert_eq!(
            replacement.account_auth_kind(),
            Some(AccountAuthKind::ApiKey)
        );
    }

    #[test]
    fn native_reauth_store_failure_keeps_disable_local_and_fails_over() {
        let config = native_reauth_budget_config(2, 2);
        let directory = tempdir().expect("temporary SQLite directory");
        #[cfg(unix)]
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private SQLite directory");
        let path = directory.path().join("reauth-store-failure.db");
        let store = Arc::new(
            SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"native reauth store failure key").expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let initial = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential");
        let expected_fingerprint = crate::account_configuration_fingerprint(
            &config.upstreams()["first"],
            "first",
            AccountAuthKind::OAuth,
        )
        .expect("configured fingerprint");
        let first = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "first",
                "first",
                &expected_fingerprint,
                initial.enabled,
                timestamp_now(),
            ))
            .expect("adopt configured fingerprint");
        store
            .upsert_credential_payload_for_fingerprint(
                "first",
                &first.configuration_fingerprint,
                &CredentialPayload::new(b"failed refresh token").expect("payload"),
                timestamp_now(),
            )
            .expect("failed payload generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint(
                "first",
                &first.configuration_fingerprint,
            )
            .expect("failed generation");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        assert_eq!(first.configuration_fingerprint, expected_fingerprint);
        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "first",
                    failed_generation,
                    "first",
                    &expected_fingerprint,
                    true,
                    timestamp_now(),
                )
                .expect("matching precondition probe"),
            ConditionalCredentialMutation::Applied(_)
        ));
        let connection = rusqlite::Connection::open(&path).expect("failure injection connection");
        connection
            .execute_batch(
                "CREATE TRIGGER reject_credential_disable                  BEFORE UPDATE OF enabled ON credentials                  WHEN NEW.enabled = 0                  BEGIN SELECT RAISE(FAIL, 'injected disable failure'); END;",
            )
            .expect("install disable failure trigger");
        drop(connection);
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("store failure remains request-local");

        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialDisableNotPersisted,
            }
        );
        assert_eq!(
            failure.health_mutation_reason(),
            Some("credential_disable_not_persisted")
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("second").expect("credential"))
        );
        assert!(failure.decision.is_retry());
        assert!(
            coordinator
                .store
                .credential_state("first")
                .expect("credential state")
                .expect("first credential")
                .enabled
        );
    }

    #[test]
    fn native_reauth_recovery_skips_runtime_unsupported_candidate() {
        #[derive(Debug)]
        struct NeedsReauthRefresher;

        impl pooler_auth::OAuthRefresher for NeedsReauthRefresher {
            fn refresh<'a>(
                &'a self,
                _refresh_token: &'a pooler_auth::SecretValue,
                _cancellation: tokio_util::sync::CancellationToken,
            ) -> pooler_auth::OAuthFuture<'a, pooler_auth::OAuthTokens> {
                Box::pin(async { Err(pooler_auth::OAuthError::NeedsReauth) })
            }
        }

        let config = compile_yaml(
            "native-runtime-support-recovery.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  first:
    url: http://127.0.0.1:1
    native: {kind: codex}
    oauth: {authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: first-client, scopes: [openid]}
  unsupported:
    url: http://127.0.0.1:2
    native: {kind: codex}
    oauth: {authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: unsupported-client, scopes: [openid]}
  api: {url: http://127.0.0.1:3}
accounts:
  first: {provider: first, auth_kind: oauth}
  unsupported: {provider: unsupported, auth_kind: oauth}
  api: {provider: api, auth_kind: api_key, secret: env:API_KEY}
models:
  - id: public
    targets:
      - {id: first-target, provider: first, account: first, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
      - {id: unsupported-target, provider: unsupported, account: unsupported, priority: 2, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
      - {id: api-target, provider: api, account: api, priority: 3, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
    retry: {maximum_attempts: 3, maximum_credentials: 3, maximum_upstreams: 3, statuses: [503], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}
routes:
  - id: pooled
    listen: local
    ingress: {mode: patch}
    target: {provider: first, model_from: request.model, policy: pooled}
    response: {mode: opaque}
"#,
        )
        .expect("native support recovery config");
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        for account_id in ["first", "unsupported"] {
            let upstream = &config.upstreams()[account_id];
            let fingerprint = crate::account_configuration_fingerprint(
                upstream,
                account_id,
                AccountAuthKind::OAuth,
            )
            .expect("OAuth account fingerprint");
            coordinator
                .store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    account_id,
                    account_id,
                    fingerprint,
                    true,
                    timestamp_now(),
                ))
                .expect("fingerprinted OAuth state");
        }
        let runtime = crate::NativeRuntime::with_codex_provider(
            Arc::new(pooler_auth::MemoryOAuthTokenStore::new()),
            "first",
            Arc::new(NeedsReauthRefresher),
        );
        assert!(runtime.supports(&config.upstreams()["first"]));
        assert!(!runtime.supports(&config.upstreams()["unsupported"]));
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let failed_generation = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential")
            .revision;
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: Some(&runtime),
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("reauthentication classification");

        let replacement = failure
            .take_replacement()
            .expect("supported API-key fallback");
        assert_eq!(replacement.provider().as_str(), "api");
        assert_eq!(
            replacement.credential().map(CredentialId::as_str),
            Some("api")
        );
        assert_eq!(
            replacement.account_auth_kind(),
            Some(AccountAuthKind::ApiKey)
        );
    }

    #[test]
    fn successful_oauth_login_reenables_exact_generation_and_live_registry() {
        let config = native_reauth_budget_config(2, 2);
        let coordinator = fingerprinted_native_reauth_coordinator(&config);
        coordinator
            .set_account_enabled("first", false)
            .expect("disable account");
        let disabled = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("disabled credential");
        let login = coordinator
            .store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "first",
                "first",
                disabled.configuration_fingerprint,
                false,
                timestamp_now(),
            ))
            .expect("persisted login generation");

        assert!(coordinator
            .set_oauth_account_enabled_if_current(&config, "first", login.revision, true,)
            .expect("enable exact login generation"));
        let enabled = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("enabled credential");
        assert!(enabled.enabled);
        assert_eq!(enabled.revision, login.revision.saturating_add(1));

        let selection = coordinator
            .select(
                &config,
                config.route("pooled").expect("route"),
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("re-enabled account is selectable");
        assert_eq!(
            selection.credential().map(CredentialId::as_str),
            Some("first")
        );
        assert!(!coordinator
            .set_oauth_account_enabled_if_current(&config, "first", login.revision, false,)
            .expect("stale login cannot mutate newer state"));
    }

    #[test]
    fn successful_oauth_login_rebases_enablement_after_concurrent_refresh() {
        let config = native_reauth_budget_config(2, 2);
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"OAuth login enable rebase regression key")
                    .expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        coordinator
            .set_account_enabled("first", false)
            .expect("disable account before login");
        let fingerprint = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential")
            .configuration_fingerprint;
        let expected_generation = store
            .credential_payload_compare_generation_for_fingerprint("first", &fingerprint)
            .expect("initial compare generation");
        let login = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "first",
                expected_generation,
                &fingerprint,
                &CredentialPayload::new(b"login token").expect("login payload"),
                timestamp_now(),
            )
            .expect("persist login");
        let refresh = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "first",
                login.revision,
                &fingerprint,
                &CredentialPayload::new(b"refreshed token").expect("refresh payload"),
                timestamp_now(),
            )
            .expect("concurrent refresh");
        assert!(refresh.revision > login.revision);
        assert!(
            !store
                .credential_state("first")
                .expect("disabled state")
                .expect("first credential")
                .enabled
        );

        assert!(coordinator
            .set_oauth_account_enabled_if_current(&config, "first", login.revision, true)
            .expect("rebase login enablement"));
        assert!(
            store
                .credential_state("first")
                .expect("enabled state")
                .expect("first credential")
                .enabled
        );
        let selected = coordinator
            .select(
                &config,
                config.route("pooled").expect("route"),
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("rebased account is selectable");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("first")
        );
    }

    #[test]
    fn stale_native_reauth_retries_newer_login_generation_on_same_credential() {
        let config = native_reauth_budget_config(1, 1);
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"native reauth newer login generation key")
                    .expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let fingerprint = crate::account_configuration_fingerprint(
            config.upstreams().get("first").expect("first upstream"),
            "first",
            AccountAuthKind::OAuth,
        )
        .expect("OAuth account fingerprint");
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "first",
                "first",
                &fingerprint,
                true,
                timestamp_now(),
            ))
            .expect("fingerprinted login metadata");
        store
            .upsert_credential_payload_for_fingerprint(
                "first",
                &fingerprint,
                &CredentialPayload::new(b"failed refresh token").expect("payload"),
                timestamp_now(),
            )
            .expect("failed login generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint("first", &fingerprint)
            .expect("failed payload generation");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let login = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "first",
                failed_generation,
                &fingerprint,
                &CredentialPayload::new(b"new login refresh token").expect("payload"),
                timestamp_now(),
            )
            .expect("concurrent login generation");
        assert!(login.revision > failed_generation);
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("stale reauthentication classification");

        let preserved = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential");
        assert!(preserved.enabled);
        assert_eq!(preserved.revision, login.revision);
        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialGenerationChanged,
            }
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("first").expect("credential"))
        );
        assert_eq!(failure.decision.delay(), Duration::from_millis(25));
        assert!(failure.decision.is_retry());
    }

    #[test]
    fn unfenced_native_reauth_never_disables_a_potentially_newer_login() {
        let config = native_reauth_budget_config(2, 2);
        let coordinator = fingerprinted_native_reauth_coordinator(&config);
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let failed_generation = 1;
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: false,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("unfenced reauthentication classification");

        assert!(
            coordinator
                .store
                .credential_state("first")
                .expect("credential state")
                .expect("first credential")
                .enabled
        );
        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialDisableNotPersisted,
            }
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("second").expect("credential"))
        );
        assert!(failure.decision.is_retry());
    }

    #[test]
    fn unfenced_pre_send_reauth_does_not_cycle_between_failed_credentials() {
        let config = native_reauth_budget_config(2, 2);
        let coordinator = fingerprinted_native_reauth_coordinator(&config);
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let (mut credentials_used, mut providers_used) = used_target_sets(&selection);

        let mut first_failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation: 1,
                generation_fenced: false,
                native_runtime: None,
                outbound_attempt_consumed: false,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("first request-local reauthentication classification");
        assert!(first_failure.decision.is_retry());
        selection = first_failure
            .take_replacement()
            .expect("second credential is selected once");
        credentials_used.insert(selection.credential().expect("credential").clone());
        providers_used.insert(selection.provider().clone());
        assert_eq!(
            selection.credential().map(CredentialId::as_str),
            Some("second")
        );

        let second_failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation: 1,
                generation_fenced: false,
                native_runtime: None,
                outbound_attempt_consumed: false,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("second request-local reauthentication classification");

        assert!(!second_failure.decision.is_retry());
        assert!(second_failure.replacement.is_none());
        assert_eq!(
            second_failure.decision,
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::NoAlternateTarget,
            }
        );
        assert!(coordinator
            .credential_states()
            .expect("credential states remain readable")
            .into_iter()
            .all(|state| state.enabled));
    }

    #[test]
    fn metadata_only_disable_and_reenable_does_not_masquerade_as_a_new_login() {
        let config = native_reauth_budget_config(2, 2);
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"native reauth metadata toggle key").expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let fingerprint = crate::account_configuration_fingerprint(
            config.upstreams().get("first").expect("first upstream"),
            "first",
            AccountAuthKind::OAuth,
        )
        .expect("OAuth account fingerprint");
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "first",
                "first",
                &fingerprint,
                true,
                timestamp_now(),
            ))
            .expect("fingerprinted login metadata");
        store
            .upsert_credential_payload_for_fingerprint(
                "first",
                &fingerprint,
                &CredentialPayload::new(b"invalid refresh token").expect("payload"),
                timestamp_now(),
            )
            .expect("failed payload generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint("first", &fingerprint)
            .expect("failed payload generation");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        coordinator
            .store
            .set_credential_enabled("first", false, timestamp_now())
            .expect("metadata-only disable");
        coordinator
            .store
            .set_credential_enabled("first", true, timestamp_now())
            .expect("metadata-only re-enable");
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("first", &fingerprint,)
                .expect("unchanged payload generation"),
            failed_generation
        );
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("metadata toggle classification");

        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialDisabled,
            }
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("second").expect("credential"))
        );
        assert!(
            !coordinator
                .store
                .credential_state("first")
                .expect("credential state")
                .expect("first credential")
                .enabled
        );
        assert!(failure.decision.is_retry());
    }

    #[test]
    fn externally_disabled_newer_generation_is_not_retried_as_a_fresh_login() {
        let config = native_reauth_budget_config(2, 2);
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"disabled newer login generation key").expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let route = config.route("pooled").expect("route");
        let first = store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "first",
                &first.configuration_fingerprint,
                &CredentialPayload::new(b"failed login token").expect("payload"),
                timestamp_now(),
            )
            .expect("failed login generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint(
                "first",
                &first.configuration_fingerprint,
            )
            .expect("failed payload generation");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let newer = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "first",
                failed_generation,
                &first.configuration_fingerprint,
                &CredentialPayload::new(b"new login token").expect("payload"),
                timestamp_now(),
            )
            .expect("newer login generation");
        assert!(newer.revision > failed_generation);
        store
            .set_credential_enabled("first", false, timestamp_now())
            .expect("external disable after login");
        assert!(
            !store
                .credential_state("first")
                .expect("disabled credential state")
                .expect("first credential")
                .enabled
        );
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("disabled newer credential classification");

        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialUnavailable,
            }
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("second").expect("credential"))
        );
        assert!(failure.decision.is_retry());
        assert!(
            !store
                .credential_state("first")
                .expect("final credential state")
                .expect("first credential")
                .enabled
        );
    }

    #[test]
    fn revoked_native_payload_fails_over_during_metadata_tombstone_window() {
        let config = native_reauth_budget_config(2, 2);
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"native reauth tombstone test key").expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let first = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "first",
                &first.configuration_fingerprint,
                &CredentialPayload::new(b"refresh token").expect("payload"),
                timestamp_now(),
            )
            .expect("credential payload");
        let failed_generation = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential")
            .revision;
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        assert!(store
            .remove_credential_payload("first")
            .expect("revoke credential payload"));
        let tombstone = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("tombstoned credential");
        assert!(tombstone.revision > failed_generation);
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("tombstoned credential classification");

        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialUnavailable,
            }
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("second").expect("credential"))
        );
        assert!(failure.decision.is_retry());
    }

    #[test]
    fn stale_native_reauth_cannot_disable_a_recreated_login_at_the_same_account_id() {
        let config = native_reauth_budget_config(1, 1);
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"native reauth credential incarnation key")
                    .expect("master key"),
            )
            .expect("encrypted store"),
        );
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let initial = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential");
        let account = config.accounts().get("first").expect("account");
        let upstream = config
            .upstreams()
            .get(account.provider())
            .expect("upstream");
        let fingerprint =
            crate::account_configuration_fingerprint(upstream, "first", AccountAuthKind::OAuth)
                .expect("fingerprint");
        let first = coordinator
            .store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "first",
                upstream.id(),
                &fingerprint,
                true,
                timestamp_now(),
            ))
            .expect("fingerprinted old login metadata");
        assert!(first.revision > initial.revision);
        let old = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "first",
                first.revision,
                &fingerprint,
                &CredentialPayload::new(b"old refresh token").expect("old payload"),
                timestamp_now(),
            )
            .expect("old login generation");
        let failed_generation = old.revision;
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("old login selection");

        assert!(store
            .remove_credential_payload("first")
            .expect("remove old payload"));
        assert!(coordinator
            .store
            .remove_credential_state("first")
            .expect("remove old metadata"));
        let recreated = coordinator
            .store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "first",
                upstream.id(),
                &fingerprint,
                true,
                timestamp_now(),
            ))
            .expect("recreated account metadata");
        let fresh = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "first",
                recreated.revision,
                &fingerprint,
                &CredentialPayload::new(b"fresh refresh token").expect("fresh payload"),
                timestamp_now(),
            )
            .expect("fresh login generation");
        assert!(fresh.revision > failed_generation);
        let durable = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("fresh credential");
        assert!(store
            .credential_payload_exists("first")
            .expect("payload presence"));
        assert!(durable.enabled);
        assert_eq!(durable.provider_id, upstream.id());
        assert_eq!(durable.configuration_fingerprint, fingerprint);
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("stale reauthentication classification");

        let preserved = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("recreated credential");
        assert!(preserved.enabled);
        assert_eq!(preserved.revision, fresh.revision);
        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialGenerationChanged,
            }
        );
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("first").expect("credential"))
        );
        assert!(failure.decision.is_retry());
    }

    #[test]
    fn removed_native_credential_fails_over_instead_of_reselecting_stale_binding() {
        let config = native_reauth_budget_config(2, 2);
        let coordinator = fingerprinted_native_reauth_coordinator(&config);
        let route = config.route("pooled").expect("route");
        let mut selection = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("first selection");
        let failed_generation = coordinator
            .store
            .credential_state("first")
            .expect("credential state")
            .expect("first credential")
            .revision;
        assert!(coordinator
            .store
            .remove_credential_state("first")
            .expect("remove failed credential"));
        let (credentials_used, providers_used) = used_target_sets(&selection);

        let mut failure = coordinator
            .classify_native_reauth(NativeReauthInput {
                config: &config,
                route,
                selection: &mut selection,
                replay: ReplayCheck::safe(),
                commitment: CommitmentState::Uncommitted,
                idempotency_key_present: true,
                attempt: 1,
                failed_generation,
                generation_fenced: true,
                native_runtime: None,
                outbound_attempt_consumed: true,
                credentials_used: &credentials_used,
                providers_used: &providers_used,
                elapsed_retry_delay: Duration::ZERO,
                elapsed_recovery_wait: Duration::ZERO,
                started: Instant::now(),
            })
            .expect("removed credential classification");

        assert_eq!(
            failure.mutation,
            HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialUnavailable,
            }
        );
        assert_eq!(failure.decision.delay(), Duration::ZERO);
        assert_eq!(
            failure
                .take_replacement()
                .and_then(|replacement| replacement.credential().cloned()),
            Some(CredentialId::new("second").expect("credential"))
        );
        assert!(failure.decision.is_retry());
    }

    fn request_headers(session: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(session) = session {
            headers.insert("x-session", HeaderValue::from_str(session).expect("header"));
        }
        headers
    }

    #[test]
    fn published_models_use_any_eligible_target_without_stale_accounts() {
        let config = compile_yaml(
            "published-model-scope.yaml",
            r#"
version: 2
upstreams:
  first: {url: http://127.0.0.1:1}
  second: {url: http://127.0.0.1:2}
accounts:
  first-selected: {provider: first, secret: env:FIRST_SELECTED}
  first-disabled: {provider: first, secret: env:FIRST_DISABLED}
  second-selected: {provider: second, secret: env:SECOND_SELECTED}
models:
  - id: first-model
    targets:
      - {id: first-target, provider: first, account: first-selected, priority: 1, upstream_model: first-private, capabilities: [text], codecs: [], wire_family: openai}
  - id: second-model
    targets:
      - {id: second-target, provider: second, account: second-selected, priority: 1, upstream_model: second-private, capabilities: [text], codecs: [], wire_family: openai}
"#,
        )
        .expect("published model config");
        let store = Arc::new(MemoryStore::new());
        store
            .upsert_credential_state(CredentialState::new(
                "removed-account",
                "first",
                true,
                timestamp_now(),
            ))
            .expect("stale credential state");
        let coordinator = PoolingCoordinator::with_store(&config, store).expect("coordinator");
        coordinator
            .set_account_enabled("first-disabled", false)
            .expect("disable sibling");

        let published = coordinator
            .published_models(&config, "first", CapabilitySet::new())
            .expect("published models");

        assert_eq!(
            published.models(),
            &["first-model".to_owned(), "second-model".to_owned()]
        );

        coordinator
            .set_account_enabled("first-selected", false)
            .expect("disable selected account");
        let published = coordinator
            .published_models(&config, "first", CapabilitySet::new())
            .expect("published models without an eligible current account");
        assert_eq!(published.models(), &["second-model".to_owned()]);
    }

    #[test]
    fn provider_wide_switch_updates_live_and_durable_state_only_for_siblings() {
        let config = account_mutation_config();
        let store = Arc::new(MemoryStore::new());
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        coordinator.switch_account("beta").expect("switch account");

        let states = store
            .credential_states()
            .expect("credential states")
            .into_iter()
            .map(|state| (state.credential_id, state.enabled))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(states.get("alpha"), Some(&false));
        assert_eq!(states.get("beta"), Some(&true));
        assert_eq!(states.get("gamma"), Some(&true));

        let selected = coordinator
            .select(
                &config,
                config.route("pooled").expect("pooled route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("selected sibling");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("beta")
        );
    }

    #[test]
    fn failed_durable_switch_does_not_publish_live_sibling_changes() {
        let config = account_mutation_config();
        let store = Arc::new(MemoryStore::new());
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        assert!(store
            .remove_credential_state("alpha")
            .expect("remove durable sibling"));

        assert!(matches!(
            coordinator.switch_account("beta"),
            Err(PoolError::InvalidCredential)
        ));
        let selected = coordinator
            .select(
                &config,
                config.route("pooled").expect("pooled route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("live state remains selectable");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("alpha")
        );
        assert!(
            store
                .credential_state("beta")
                .expect("beta state")
                .expect("beta exists")
                .enabled
        );
    }

    #[test]
    fn policy_free_models_reject_disabled_accounts_and_recover_after_switch() {
        let config = account_mutation_config();
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let route = config.route("static").expect("static route");
        coordinator
            .set_account_enabled("alpha", false)
            .expect("disable alpha");
        coordinator
            .set_account_enabled("beta", false)
            .expect("disable beta");
        assert!(matches!(
            coordinator.select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                0,
                Instant::now(),
            ),
            Err(PoolError::NoEligible { .. })
        ));

        coordinator.switch_account("beta").expect("switch beta");
        let selected = coordinator
            .select(
                &config,
                route,
                Some("public"),
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("enabled static selection");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("beta")
        );
    }

    #[test]
    fn policy_free_models_honor_initially_disabled_accounts() {
        let config = compile_yaml(
            "initial-policy-free-enablement.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {provider: {url: http://127.0.0.1:1}}
accounts:
  alpha: {provider: provider, secret: env:POOLER_ALPHA, enabled: false}
  beta: {provider: provider, secret: env:POOLER_BETA}
account_pools:
  accounts: {provider: provider, strategy: ordered_fallback, accounts: [alpha, beta]}
models:
  - id: public
    targets:
      - {id: public-target, provider: provider, account_pool: accounts, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
routes:
  - id: static
    listen: local
    ingress: {mode: patch}
    target: {provider: provider, model_from: request.model}
"#,
        )
        .expect("initial policy-free enablement config");
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        let selected = coordinator
            .select(
                &config,
                config.route("static").expect("static route"),
                Some("public"),
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("enabled policy-free sibling");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("beta")
        );
    }

    #[test]
    fn account_mutations_propagate_between_live_runtime_generations() {
        let config = account_mutation_config();
        let retired = PoolingCoordinator::new(&config).expect("retired coordinator");
        let current = retired.reconfigure(&config).expect("current coordinator");
        let route = config.route("pooled").expect("pooled route");

        retired.disable_credential(&CredentialId::new("alpha").expect("credential"));
        let selected = current
            .select(&config, route, None, &HeaderMap::new(), 0, Instant::now())
            .expect("current generation observes retired disable");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("beta")
        );

        current
            .switch_account("alpha")
            .expect("switch from current");
        let selected = retired
            .select(&config, route, None, &HeaderMap::new(), 1, Instant::now())
            .expect("retired generation observes current switch");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("alpha")
        );
    }

    #[test]
    fn account_mutations_do_not_cross_reused_ids_with_changed_identity() {
        let retired_config = compile_yaml(
            "retired-account-identity.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  provider: {url: http://127.0.0.1:1}
accounts:
  shared: {provider: provider, secret: env:POOLER_SHARED, enabled: true}
account_pools:
  accounts: {provider: provider, strategy: ordered_fallback, accounts: [shared]}
policies:
  pooled: {selection: {strategy: ordered_fallback}}
models:
  - id: public
    targets:
      - {id: public-target, provider: provider, account_pool: accounts, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
routes:
  - id: pooled
    listen: local
    match: {path: /pooled}
    target: {provider: provider, policy: pooled}
  - id: static
    listen: local
    match: {path: /static}
    ingress: {mode: patch}
    target: {provider: provider, model_from: request.model}
"#,
        )
        .expect("retired account config");
        let current_config = compile_yaml(
            "current-account-identity.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  provider:
    url: http://127.0.0.1:2
    native: {kind: codex}
    oauth: {authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: current-client, scopes: [openid]}
accounts:
  shared: {provider: provider, auth_kind: oauth, enabled: false}
account_pools:
  accounts: {provider: provider, strategy: ordered_fallback, accounts: [shared]}
policies:
  pooled: {selection: {strategy: ordered_fallback}}
models:
  - id: public
    targets:
      - {id: public-target, provider: provider, account_pool: accounts, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
routes:
  - id: pooled
    listen: local
    match: {path: /pooled}
    target: {provider: provider, policy: pooled}
  - id: static
    listen: local
    match: {path: /static}
    ingress: {mode: patch}
    target: {provider: provider, model_from: request.model}
"#,
        )
        .expect("current account config");
        let store = Arc::new(MemoryStore::new());
        let retired = PoolingCoordinator::with_store(&retired_config, store.clone())
            .expect("retired coordinator");
        let current = retired
            .reconfigure(&current_config)
            .expect("current coordinator");
        assert_ne!(
            retired.account_identities.get("shared"),
            current.account_identities.get("shared")
        );

        let account = current_config
            .accounts()
            .get("shared")
            .expect("current account");
        let upstream = current_config
            .upstreams()
            .get(account.provider())
            .expect("current upstream");
        let fingerprint =
            crate::account_configuration_fingerprint(upstream, account.id(), account.auth_kind())
                .expect("current account fingerprint");
        let restored = store
            .credential_state(account.id())
            .expect("restored current state")
            .expect("current state exists");
        assert_eq!(restored.provider_id, upstream.id());
        assert_eq!(restored.configuration_fingerprint, fingerprint);
        assert!(
            !restored.enabled,
            "replacement must not inherit old enablement"
        );
        let adopted = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                account.id(),
                upstream.id(),
                &fingerprint,
                false,
                timestamp_now(),
            ))
            .expect("adopt current account identity");
        assert!(current
            .set_oauth_account_enabled_if_current(
                &current_config,
                account.id(),
                adopted.revision,
                true,
            )
            .expect("enable current login"));

        let enabled_state = store
            .credential_state(account.id())
            .expect("enabled current state")
            .expect("current state exists");
        assert!(matches!(
            retired.set_account_enabled(account.id(), false),
            Err(PoolError::InvalidCredential)
        ));
        assert_eq!(
            store
                .credential_state(account.id())
                .expect("state after stale disable")
                .expect("current state exists"),
            enabled_state
        );

        current
            .set_account_enabled(account.id(), false)
            .expect("disable current identity");
        let disabled_state = store
            .credential_state(account.id())
            .expect("disabled current state")
            .expect("current state exists");
        assert!(!disabled_state.enabled);
        assert!(matches!(
            retired.switch_account(account.id()),
            Err(PoolError::InvalidCredential)
        ));
        assert_eq!(
            store
                .credential_state(account.id())
                .expect("state after stale switch")
                .expect("current state exists"),
            disabled_state
        );
        current
            .set_account_enabled(account.id(), true)
            .expect("reenable current identity");

        let selected = current
            .select(
                &current_config,
                current_config.route("pooled").expect("current route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("current generation selects its login");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("shared")
        );

        let retired_selection = retired
            .select(
                &retired_config,
                retired_config.route("pooled").expect("retired route"),
                None,
                &HeaderMap::new(),
                1,
                Instant::now(),
            )
            .expect("retired identity retains its own enablement");
        assert_eq!(
            retired_selection.credential().map(CredentialId::as_str),
            Some("shared")
        );

        let reloaded = current
            .reconfigure(&current_config)
            .expect("reload current identity");
        let reloaded_selection = reloaded
            .select(
                &current_config,
                current_config.route("pooled").expect("reloaded route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("reload preserves current durable enablement");
        assert_eq!(
            reloaded_selection.credential().map(CredentialId::as_str),
            Some("shared")
        );
    }

    #[test]
    fn account_mutations_do_not_cross_reused_oauth_ids_with_changed_scopes() {
        let retired_yaml = r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  provider:
    url: http://127.0.0.1:1
    native: {kind: codex}
    oauth: {authorization_endpoint: https://oauth.example/authorize, token_endpoint: https://oauth.example/token, client_id: shared-client, scopes: [openid]}
accounts:
  shared: {provider: provider, auth_kind: oauth, enabled: false}
account_pools:
  accounts: {provider: provider, strategy: ordered_fallback, accounts: [shared]}
policies:
  pooled: {selection: {strategy: ordered_fallback}}
models:
  - id: public
    targets:
      - {id: public-target, provider: provider, account_pool: accounts, priority: 1, upstream_model: private, capabilities: [text], codecs: [openai], wire_family: openai}
routes:
  - id: pooled
    listen: local
    match: {path: /pooled}
    target: {provider: provider, policy: pooled}
"#;
        let current_yaml = retired_yaml.replace("scopes: [openid]", "scopes: [profile]");
        let retired_config =
            compile_yaml("retired-oauth-scopes.yaml", retired_yaml).expect("retired config");
        let current_config =
            compile_yaml("current-oauth-scopes.yaml", &current_yaml).expect("current config");
        let store = Arc::new(MemoryStore::new());
        let retired = PoolingCoordinator::with_store(&retired_config, store.clone())
            .expect("retired coordinator");
        let current = retired
            .reconfigure(&current_config)
            .expect("current coordinator");
        assert_ne!(
            retired.account_identities.get("shared"),
            current.account_identities.get("shared")
        );

        let account = current_config
            .accounts()
            .get("shared")
            .expect("current account");
        let upstream = current_config
            .upstreams()
            .get(account.provider())
            .expect("current upstream");
        let fingerprint =
            crate::account_configuration_fingerprint(upstream, account.id(), account.auth_kind())
                .expect("current account fingerprint");
        let adopted = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                account.id(),
                upstream.id(),
                &fingerprint,
                false,
                timestamp_now(),
            ))
            .expect("adopt current OAuth identity");
        assert!(current
            .set_oauth_account_enabled_if_current(
                &current_config,
                account.id(),
                adopted.revision,
                true,
            )
            .expect("enable current OAuth login"));

        let current_state = store
            .credential_state(account.id())
            .expect("current OAuth state")
            .expect("current OAuth state exists");
        assert!(matches!(
            retired.set_account_enabled(account.id(), false),
            Err(PoolError::InvalidCredential)
        ));
        assert_eq!(
            store
                .credential_state(account.id())
                .expect("state after stale scope mutation")
                .expect("current OAuth state exists"),
            current_state
        );

        let selected = current
            .select(
                &current_config,
                current_config.route("pooled").expect("current route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("current generation selects its OAuth login");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("shared")
        );
        assert!(matches!(
            retired.select(
                &retired_config,
                retired_config.route("pooled").expect("retired route"),
                None,
                &HeaderMap::new(),
                1,
                Instant::now(),
            ),
            Err(PoolError::NoEligible { .. })
        ));
    }

    #[test]
    fn concurrent_switches_leave_store_and_all_generations_consistent() {
        let config = Arc::new(account_mutation_config());
        let store = Arc::new(MemoryStore::new());
        let first = Arc::new(
            PoolingCoordinator::with_store(&config, store.clone()).expect("first coordinator"),
        );
        let second = Arc::new(first.reconfigure(&config).expect("second coordinator"));
        let barrier = Arc::new(Barrier::new(3));
        let alpha = {
            let coordinator = Arc::clone(&first);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                coordinator.switch_account("alpha")
            })
        };
        let beta = {
            let coordinator = Arc::clone(&second);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                coordinator.switch_account("beta")
            })
        };
        barrier.wait();
        alpha.join().expect("alpha thread").expect("alpha switch");
        beta.join().expect("beta thread").expect("beta switch");

        let states = store
            .credential_states()
            .expect("credential states")
            .into_iter()
            .filter(|state| state.provider_id == "provider-a")
            .collect::<Vec<_>>();
        assert_eq!(states.iter().filter(|state| state.enabled).count(), 1);
        let expected = states
            .iter()
            .find(|state| state.enabled)
            .expect("one selected account")
            .credential_id
            .as_str();
        for coordinator in [&first, &second] {
            let selected = coordinator
                .select(
                    &config,
                    config.route("pooled").expect("pooled route"),
                    None,
                    &HeaderMap::new(),
                    0,
                    Instant::now(),
                )
                .expect("consistent selection");
            assert_eq!(
                selected.credential().map(CredentialId::as_str),
                Some(expected)
            );
        }
    }

    #[test]
    fn selections_never_observe_a_partial_provider_switch() {
        let config = Arc::new(account_mutation_config());
        let coordinator = Arc::new(PoolingCoordinator::new(&config).expect("coordinator"));
        coordinator.switch_account("alpha").expect("initial switch");
        let barrier = Arc::new(Barrier::new(3));
        let switching = {
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for index in 0..1_000 {
                    coordinator
                        .switch_account(if index % 2 == 0 { "beta" } else { "alpha" })
                        .expect("switch account");
                }
            })
        };
        let selecting = {
            let config = Arc::clone(&config);
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for attempt in 0..1_000 {
                    let selected = coordinator
                        .select(
                            &config,
                            config.route("pooled").expect("pooled route"),
                            None,
                            &HeaderMap::new(),
                            attempt,
                            Instant::now(),
                        )
                        .expect("one sibling remains eligible");
                    assert!(matches!(
                        selected.credential().map(CredentialId::as_str),
                        Some("alpha" | "beta")
                    ));
                }
            })
        };
        barrier.wait();
        switching.join().expect("switching thread");
        selecting.join().expect("selecting thread");
    }

    #[test]
    fn retired_registry_views_are_pruned_after_the_generation_drops() {
        let config = account_mutation_config();
        let retired = PoolingCoordinator::new(&config).expect("retired coordinator");
        let current = retired.reconfigure(&config).expect("current coordinator");
        assert_eq!(
            current
                .account_mutations
                .gate
                .lock()
                .expect("account gate")
                .len(),
            2
        );
        drop(retired);

        current
            .set_account_enabled("alpha", false)
            .expect("trigger pruning");
        assert_eq!(
            current
                .account_mutations
                .gate
                .lock()
                .expect("account gate")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn catalog_rebuild_racing_account_switch_restores_the_durable_winner() {
        let config = Arc::new(account_mutation_config());
        let catalog =
            one_model_catalog("provider-a.models", "provider-a", "alpha", "dynamic-model").await;
        let coordinator = Arc::new(
            PoolingCoordinator::new(&config)
                .expect("coordinator")
                .with_catalog(Arc::clone(&catalog)),
        );
        catalog
            .select_none("provider-a.models")
            .expect("hide catalog models");
        catalog.refresh(2).await.expect("refresh catalog");
        let barrier = Arc::new(Barrier::new(3));
        let rebuilding = {
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                coordinator.sync_catalog_snapshot()
            })
        };
        let switching = {
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                coordinator.switch_account("beta")
            })
        };
        barrier.wait();
        rebuilding
            .join()
            .expect("catalog thread")
            .expect("catalog rebuild");
        switching
            .join()
            .expect("switch thread")
            .expect("account switch");

        let selected = coordinator
            .select(
                &config,
                config.route("pooled").expect("pooled route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("durable winner remains selected");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("beta")
        );
    }

    #[test]
    fn sqlite_account_switch_restores_selected_account_after_restart() {
        let config = account_mutation_config();
        let directory = tempdir().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private temporary directory");
        }
        let path = directory.path().join("accounts.sqlite");
        {
            let store = Arc::new(SqliteStore::open(&path).expect("open store"));
            let coordinator = PoolingCoordinator::with_store(&config, store).expect("coordinator");
            coordinator.switch_account("beta").expect("switch beta");
        }

        let store = Arc::new(SqliteStore::open(&path).expect("reopen store"));
        let coordinator = PoolingCoordinator::with_store(&config, store).expect("restart");
        let selected = coordinator
            .select(
                &config,
                config.route("pooled").expect("pooled route"),
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            )
            .expect("restored selection");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("beta")
        );
    }

    fn project_quota_config() -> CompiledConfig {
        compile_yaml(
            "project-quota-test.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  first: {provider: local, secret: env:POOLER_FIRST, quota_project: shared-billing}
  second: {provider: local, secret: env:POOLER_SECOND, quota_project: shared-billing}
  third: {provider: local, secret: env:POOLER_THIRD, quota_project: alternate-billing}
account_pools:
  pool: {provider: local, strategy: ordered_fallback, accounts: [first, second, third]}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
    retry: {maximum_attempts: 3, maximum_credentials: 3, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}
routes:
  - id: pooled
    listen: local
    target: {provider: local, policy: pooled}
"#,
        )
        .expect("project quota config")
    }

    fn used_target_sets(
        selection: &PoolSelection,
    ) -> (BTreeSet<CredentialId>, BTreeSet<ProviderId>) {
        let credentials = selection.credential().cloned().into_iter().collect();
        let providers = [selection.provider().clone()].into_iter().collect();
        (credentials, providers)
    }

    #[test]
    fn network_retry_tracks_only_new_request_local_exclusions() {
        let existing = BindingKey::new(
            "existing-target",
            "existing-account",
            "existing-fingerprint",
        )
        .expect("existing binding");
        let inserted =
            BindingKey::new("new-target", "new-account", "new-fingerprint").expect("new binding");
        let mut request =
            SelectionRequest::new(ModelId::new("public-model").expect("public model"));
        request.excluded_bindings.insert(existing.clone());

        let transient = PoolingCoordinator::insert_network_retry_exclusions(
            &mut request,
            [existing.clone(), inserted.clone()],
        );

        assert_eq!(transient, BTreeSet::from([inserted.clone()]));
        assert!(request.excluded_bindings.contains(&existing));
        assert!(request.excluded_bindings.contains(&inserted));
    }

    fn classify_quota_failure(
        coordinator: &PoolingCoordinator,
        config: &CompiledConfig,
        selection: &mut PoolSelection,
        commitment: CommitmentState,
        replay: ReplayCheck,
    ) -> PoolFailure {
        let (credentials_used, providers_used) = used_target_sets(selection);
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
            credentials_used: &credentials_used,
            providers_used: &providers_used,
            elapsed_retry_delay: Duration::ZERO,
            elapsed_recovery_wait: Duration::ZERO,
            started: Instant::now(),
        })
    }

    #[test]
    fn logical_request_ids_are_unique_across_coordinators() {
        let config = pooled_config(false);
        let first = PoolingCoordinator::new(&config).expect("first coordinator");
        let second = PoolingCoordinator::new(&config).expect("second coordinator");
        let first_id = first.next_logical_request_id();
        let second_id = second.next_logical_request_id();
        assert_ne!(first_id, second_id);
        assert!(RequestId::parse(&first_id).is_ok());
        assert!(RequestId::parse(&second_id).is_ok());
    }

    #[test]
    fn compound_cooldown_keys_round_trip_colons_without_legacy_ambiguity() {
        let credential = CredentialId::new("a:b").expect("credential");
        let model = ModelId::new("model:c").expect("model");
        let (scope, key) = cooldown_key(&CooldownScope::CredentialModel {
            credential: credential.clone(),
            model: model.clone(),
        });
        assert_eq!(scope, "credential_model");
        assert!(key.starts_with("v2:"));
        let (parsed, registry_key) = parse_cooldown_scope(scope, &key).expect("parse key");
        assert_eq!(registry_key, None);
        assert_eq!(parsed, CooldownScope::CredentialModel { credential, model });

        assert!(parse_cooldown_scope("credential_model", "a:b:model").is_none());
        let (legacy, _) =
            parse_cooldown_scope("credential_model", "a:model").expect("safe legacy key");
        assert_eq!(
            legacy,
            CooldownScope::CredentialModel {
                credential: CredentialId::new("a").expect("credential"),
                model: ModelId::new("model").expect("model"),
            }
        );
    }

    #[test]
    fn compound_cooldown_persists_restarts_and_deletes_the_exact_credential() {
        let directory = tempdir().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(directory.path())
                .expect("temporary directory metadata")
                .permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(directory.path(), permissions)
                .expect("owner-private temporary directory");
        }
        let path = directory.path().join("cooldowns.sqlite");
        let store = SqliteStore::open(&path).expect("store");
        store
            .upsert_credential_state(CredentialState::new("a", "provider", true, 1))
            .expect("short credential");
        store
            .upsert_credential_state(CredentialState::new("a:b", "provider", true, 1))
            .expect("long credential");
        let credential = CredentialId::new("a:b").expect("credential");
        let model = ModelId::new("model:c").expect("model");
        let (_, key) = cooldown_key(&CooldownScope::CredentialModel { credential, model });
        store
            .upsert_cooldown(CooldownState::new("credential_model", key.clone(), 100, 1))
            .expect("cooldown");
        drop(store);

        let reopened = SqliteStore::open(&path).expect("restart");
        assert!(matches!(
            parse_cooldown_scope("credential_model", &key),
            Some((CooldownScope::CredentialModel { ref credential, .. }, None))
                if credential.as_str() == "a:b"
        ));
        reopened
            .remove_credential_state("a")
            .expect("remove short credential");
        assert!(reopened
            .cooldown("credential_model", &key, 2)
            .expect("long cooldown")
            .is_some());
        reopened
            .remove_credential_state("a:b")
            .expect("remove long credential");
        assert!(reopened
            .cooldown("credential_model", &key, 2)
            .expect("removed cooldown")
            .is_none());
    }

    #[test]
    fn selection_filters_model_capabilities_and_codecs_before_scoring() {
        let config = pooler_config::compile_yaml(
            "selection-requirements.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:1}}
upstreams:
  capable: {url: http://127.0.0.1:1}
  incomplete: {url: http://127.0.0.1:2}
accounts:
  capable: {provider: capable, secret: env:POOLER_CAPABLE}
  incomplete: {provider: incomplete, secret: env:POOLER_INCOMPLETE}
account_pools:
  capable-pool: {provider: capable, strategy: ordered_fallback, accounts: [capable]}
  incomplete-pool: {provider: incomplete, strategy: ordered_fallback, accounts: [incomplete]}
models:
  - id: public-model
    targets:
      - {id: capable-target, provider: capable, account_pool: capable-pool, priority: 1, upstream_model: capable-model, capabilities: [text, streaming], codecs: [decode.factory.language_model], wire_family: openai}
      - {id: incomplete-target, provider: incomplete, account_pool: incomplete-pool, priority: 2, upstream_model: incomplete-model, capabilities: [streaming], codecs: [decode.other], wire_family: openai}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
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
    fn semantic_model_uses_known_alias_and_passes_unknown_provider_model_through() {
        let config = pooler_config::compile_yaml(
            "optional-semantic-model.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:1}}
upstreams:
  local: {url: http://127.0.0.1:1}
  other: {url: http://127.0.0.1:2}
models:
  - id: public-model
    targets:
      - {id: public-local-target, provider: local, account: local-account, priority: 1, upstream_model: private-model, capabilities: [text], codecs: [decode.gemini.generate_content], wire_family: gemini}
  - id: foreign-only
    targets:
      - {id: foreign-target, provider: other, account: other-account, priority: 1, upstream_model: foreign-model, capabilities: [text], codecs: [], wire_family: openai}
accounts:
  local-account: {provider: local, secret: env:POOLER_LOCAL}
  other-account: {provider: other, secret: env:POOLER_OTHER}
routes:
  - id: semantic
    listen: local
    ingress: {mode: semantic, decoder: decode.gemini.generate_content}
    target: {provider: local}
    response: {mode: opaque}
"#,
        )
        .expect("semantic model config");
        let route = config.route("semantic").expect("route");
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");

        let mut known = SelectionContext::default();
        known.with_model("public-model");
        known.require(Capability::Text);
        known.with_codec("decode.gemini.generate_content");
        let selected = coordinator
            .select_with_context(
                &config,
                route,
                None,
                &HeaderMap::new(),
                &known,
                SelectionTiming::new(1, Instant::now()),
            )
            .expect("known alias selected");
        assert_eq!(selected.upstream_model(), Some("private-model"));

        let mut unknown = SelectionContext::default();
        unknown.with_model("provider-model-not-in-catalog");
        unknown.require(Capability::Text);
        unknown.with_codec("decode.gemini.generate_content");
        let selected = coordinator
            .select_with_context(
                &config,
                route,
                None,
                &HeaderMap::new(),
                &unknown,
                SelectionTiming::new(1, Instant::now()),
            )
            .expect("unknown provider model passes through");
        assert_eq!(selected.provider().as_str(), "local");
        assert_eq!(selected.upstream_model(), None);

        let mut foreign = SelectionContext::default();
        foreign.with_model("foreign-only");
        foreign.require(Capability::Text);
        let selected = coordinator
            .select_with_context(
                &config,
                route,
                None,
                &HeaderMap::new(),
                &foreign,
                SelectionTiming::new(1, Instant::now()),
            )
            .expect("foreign-only alias is not inferred across providers");
        assert_eq!(selected.provider().as_str(), "local");
        assert_eq!(selected.upstream_model(), None);
    }

    #[test]
    fn gemini_interaction_id_is_a_policy_affinity_source() {
        let config = pooler_config::compile_yaml(
            "gemini-affinity.yaml",
            r#"
version: 2
policies:
  interactions:
    selection:
      strategy: round_robin
      affinity: {key: gemini.interaction_id, ttl: 30m}
"#,
        )
        .expect("Gemini affinity config");
        let policy = &config.policies()["interactions"];
        let mut context = SelectionContext::default();
        context.with_affinity_value("gemini.interaction_id", "int_123");

        assert_eq!(
            affinity_value(policy, &HeaderMap::new(), &context),
            Some("int_123".to_owned())
        );
    }

    #[test]
    fn returned_gemini_interaction_id_binds_exact_account_across_operations() {
        let config = pooler_config::compile_yaml(
            "gemini-returned-affinity.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  first: {provider: local, secret: env:POOLER_FIRST}
  second: {provider: local, secret: env:POOLER_SECOND}
models:
  - id: public-gemini
    targets:
      - {id: public-gemini-target, provider: local, account_pool: interaction-pool, priority: 1, upstream_model: private-gemini, capabilities: [text], codecs: [decode.gemini.generate_content], wire_family: gemini}
account_pools:
  interaction-pool: {provider: local, strategy: round_robin, accounts: [first, second]}
policies:
  interactions:
    selection:
      strategy: round_robin
      affinity: {key: gemini.interaction_id, ttl: 30m}
routes:
  - id: create
    listen: local
    match: {method: POST, path: /v1beta/interactions}
    ingress: {mode: semantic, decoder: decode.gemini.generate_content}
    target: {provider: local, model_from: request.model, policy: interactions}
    response: {mode: opaque}
  - id: resource
    listen: local
    match: {methods: [GET, DELETE], path_template: '/v1beta/interactions/{interaction}'}
    ingress: {mode: semantic, decoder: decode.gemini.generate_content}
    target: {provider: local, policy: interactions}
    response: {mode: opaque}
  - id: cancel
    listen: local
    match: {method: POST, path_template: '/v1beta/interactions/{interaction}/cancel'}
    ingress: {mode: semantic, decoder: decode.gemini.generate_content}
    target: {provider: local, policy: interactions}
    response: {mode: opaque}
"#,
        )
        .expect("Gemini interaction affinity config");
        let store = Arc::new(MemoryStore::new());
        let coordinator =
            PoolingCoordinator::with_store(&config, store.clone()).expect("coordinator");
        let resource = config.route("resource").expect("resource route");

        // Advance the resource route's independent round-robin cursor so an
        // affinity miss would choose the other account.
        drop(
            coordinator
                .select_with_context(
                    &config,
                    resource,
                    None,
                    &HeaderMap::new(),
                    &SelectionContext::default(),
                    SelectionTiming::new(1, Instant::now()),
                )
                .expect("unbound resource selection"),
        );

        let mut create_context = SelectionContext::default();
        create_context.with_model("public-gemini");
        create_context.require(Capability::Text);
        let create = coordinator
            .select_with_context(
                &config,
                config.route("create").expect("create route"),
                None,
                &HeaderMap::new(),
                &create_context,
                SelectionTiming::new(1, Instant::now()),
            )
            .expect("create selection");
        assert_eq!(create.credential().map(CredentialId::as_str), Some("first"));
        let binding = coordinator
            .interaction_affinity_binding(&create)
            .expect("configured interaction binding");
        let now = timestamp_now();
        coordinator.bind_interaction_affinity(&binding, "int_returned_123".to_owned(), now);
        drop(create);

        let persisted = store.session_affinities(now).expect("persisted affinities");
        assert!(persisted.len() >= 3);
        assert!(persisted
            .iter()
            .all(|entry| !entry.key.contains("int_returned_123")));
        assert!(persisted.iter().all(|entry| {
            entry.expires_at == now + Duration::from_secs(30 * 60).as_millis() as u64
        }));

        let mut follow_up = SelectionContext::default();
        follow_up.with_affinity_value("gemini.interaction_id", "int_returned_123");
        for route_id in ["resource", "cancel"] {
            let selected = coordinator
                .select_with_context(
                    &config,
                    config.route(route_id).expect("follow-up route"),
                    None,
                    &HeaderMap::new(),
                    &follow_up,
                    SelectionTiming::new(2, Instant::now()),
                )
                .expect("bound follow-up selection");
            assert_eq!(
                selected.credential().map(CredentialId::as_str),
                Some("first")
            );
        }

        let restarted = coordinator.reconfigure(&config).expect("reconfigure");
        let selected = restarted
            .select_with_context(
                &config,
                resource,
                None,
                &HeaderMap::new(),
                &follow_up,
                SelectionTiming::new(3, Instant::now()),
            )
            .expect("persisted follow-up selection");
        assert_eq!(
            selected.credential().map(CredentialId::as_str),
            Some("first")
        );
    }

    #[test]
    fn static_target_contract_rejects_missing_capability_or_codec() {
        let config = pooler_config::compile_yaml(
            "static-selection-contract.yaml",
            r#"
version: 2
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
        let (credentials_used, providers_used) = used_target_sets(&selection);
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
            credentials_used: &credentials_used,
            providers_used: &providers_used,
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
        let (credentials_used, providers_used) = used_target_sets(&first);
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
            credentials_used: &credentials_used,
            providers_used: &providers_used,
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
        let (credentials_used, providers_used) = used_target_sets(&first);
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
            credentials_used: &credentials_used,
            providers_used: &providers_used,
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
        let (credentials_used, providers_used) = used_target_sets(&first);
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
            credentials_used: &credentials_used,
            providers_used: &providers_used,
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
        let (credentials_used, providers_used) = used_target_sets(&failed);
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
            credentials_used: &credentials_used,
            providers_used: &providers_used,
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
        let registry = coordinator.registry_for(&failed).expect("route registry");
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
    fn selection_uses_current_time_for_concurrent_quota_recovery() {
        let config = pooled_config(false);
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        coordinator
            .set_account_enabled("second", false)
            .expect("disable fallback");
        let registry = coordinator
            .registries
            .read()
            .expect("registry map")
            .get(&route_registry_key("pooled"))
            .cloned()
            .expect("route registry");
        let credential = CredentialId::new("first").expect("credential");
        let reset_at = Instant::now();
        registry
            .set_quota(&credential, Some(0), Some(reset_at))
            .expect("set elapsed quota");

        let selection = coordinator
            .select_with_context(
                &config,
                &config.routes()[0],
                None,
                &HeaderMap::new(),
                &SelectionContext::default(),
                SelectionTiming::new(0, reset_at - Duration::from_secs(1)),
            )
            .expect("elapsed quota must recover despite stale request start");
        assert_eq!(
            selection.credential().map(CredentialId::as_str),
            Some("first")
        );
    }

    #[test]
    fn operator_model_enablement_survives_runtime_reconfiguration() {
        let config = pooled_config(false);
        let coordinator = PoolingCoordinator::new(&config).expect("coordinator");
        coordinator
            .set_model_enabled("public/model", false)
            .expect("disable model");
        coordinator
            .set_model_enabled("pooled", false)
            .expect("disable route model");
        assert!(matches!(
            coordinator.select(
                &config,
                &config.routes()[0],
                None,
                &HeaderMap::new(),
                0,
                Instant::now(),
            ),
            Err(PoolError::ModelDisabled { model }) if model == "pooled"
        ));
        coordinator
            .set_model_enabled("pooled", true)
            .expect("enable route model");
        assert!(!coordinator
            .model_enabled("public/model")
            .expect("model state"));
        let reconfigured = coordinator.reconfigure(&config).expect("reconfigure");
        assert_eq!(
            reconfigured.disabled_models().expect("disabled models"),
            vec!["public/model".to_owned()]
        );
        reconfigured
            .set_model_enabled("public/model", true)
            .expect("enable model");
        assert!(coordinator
            .model_enabled("public/model")
            .expect("shared model state"));
    }

    #[test]
    fn no_eligible_selection_is_persisted_as_a_decision() {
        let config = pooler_config::compile_yaml(
            "no-eligible.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  first: {provider: local, secret: env:POOLER_FIRST, enabled: false}
account_pools: {pool: {provider: local, strategy: ordered_fallback, accounts: [first]}}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
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

/// The active public model view for one route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedModels {
    models: Vec<String>,
    configuration_generation: u64,
    catalog_generation: Option<u64>,
}

impl PublishedModels {
    /// Public model IDs in deterministic order.
    #[must_use]
    pub fn models(&self) -> &[String] {
        &self.models
    }

    /// Configuration generation this view was built from.
    #[must_use]
    pub const fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// Catalog generation this view was built from, when discovery is enabled.
    #[must_use]
    pub const fn catalog_generation(&self) -> Option<u64> {
        self.catalog_generation
    }
}
