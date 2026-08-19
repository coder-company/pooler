//! Retry, health, and target-selection policy.
//!
//! A classifier produces a [`FailureClassification`]. It does not mutate
//! health. The request executor decides whether an attempt can be replayed,
//! then applies the classification to [`HealthRegistry`] when appropriate.
//! Keeping those operations separate is important: a malformed request must
//! not cool a credential merely because it happened to use that credential.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub use pooler_core::{
    ConfigGeneration, CredentialId, ErrorClass, ErrorClassification, ErrorScope, ModelId,
    ProviderId, ReplaySafety, Retryability, RouteId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

/// The bounded information a classifier may inspect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedFailure {
    pub source: FailureSource,
    pub status: Option<u16>,
    pub provider_code: Option<String>,
    pub message: Option<String>,
    pub retry_after: Option<Duration>,
}

impl ObservedFailure {
    /// Construct an observation from a source and optional status.
    #[must_use]
    pub fn new(source: FailureSource, status: Option<u16>) -> Self {
        Self {
            source,
            status,
            ..Self::default()
        }
    }

    /// Attach an already-redacted provider code.
    #[must_use]
    pub fn with_provider_code(mut self, code: impl Into<String>) -> Self {
        self.provider_code = Some(code.into());
        self
    }

    /// Attach an already-bounded message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Attach a provider recovery hint.
    #[must_use]
    pub fn with_retry_after(mut self, delay: Duration) -> Self {
        self.retry_after = Some(delay);
        self
    }
}

/// Where a failure was observed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FailureSource {
    Downstream,
    #[default]
    Upstream,
    Transport,
    Internal,
}

/// A normalized response safe to expose to a downstream client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicResponse {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl PublicResponse {
    /// Construct a normalized response.
    #[must_use]
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Redacted evidence retained in a decision record.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedEvidence {
    pub status: Option<u16>,
    pub provider_code: Option<String>,
    pub summary: Option<String>,
}

/// Whether a request-local error was proven to be caused by a credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum CredentialCausation {
    #[default]
    Unknown,
    Proven,
}

/// An abstract health scope used by a failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CooldownScopeKind {
    Credential,
    CredentialModel,
    Model,
    Provider,
    ProviderModel,
    Route,
}

/// A classification plus its public response and optional health action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureClassification {
    pub classification: ErrorClassification,
    pub response: PublicResponse,
    pub evidence: RedactedEvidence,
    pub cooldown: Option<CooldownSpec>,
    pub credential_causation: CredentialCausation,
}

impl FailureClassification {
    /// Construct a classification without changing health.
    #[must_use]
    pub fn new(
        classification: ErrorClassification,
        response: PublicResponse,
        evidence: RedactedEvidence,
    ) -> Self {
        Self {
            classification,
            response,
            evidence,
            cooldown: None,
            credential_causation: CredentialCausation::Unknown,
        }
    }

    /// Construct the conservative defaults for a normalized error class.
    #[must_use]
    pub fn for_class(class: ErrorClass) -> Self {
        let (scope, retryability, replay_safety, response) = match class {
            ErrorClass::DownstreamAuthentication => (
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
                PublicResponse::new(
                    401,
                    "downstream_authentication",
                    "downstream authentication failed",
                ),
            ),
            ErrorClass::InvalidRequest => (
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
                PublicResponse::new(400, "invalid_request", "the downstream request is invalid"),
            ),
            ErrorClass::UnsupportedConversion => (
                ErrorScope::Route,
                Retryability::Never,
                ReplaySafety::NotReplayable,
                PublicResponse::new(
                    422,
                    "unsupported_conversion",
                    "the requested conversion is unsupported",
                ),
            ),
            ErrorClass::ProviderAuthentication => (
                ErrorScope::Credential,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(
                    401,
                    "provider_authentication",
                    "provider authentication failed",
                ),
            ),
            ErrorClass::CredentialQuotaExhausted => (
                ErrorScope::Credential,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(
                    429,
                    "credential_quota_exhausted",
                    "credential quota is exhausted",
                ),
            ),
            ErrorClass::ModelQuotaExhausted => (
                ErrorScope::Model,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(429, "model_quota_exhausted", "model quota is exhausted"),
            ),
            ErrorClass::ProviderRateLimited => (
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(
                    429,
                    "provider_rate_limited",
                    "provider rate limited the request",
                ),
            ),
            ErrorClass::ProviderUnavailable => (
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(503, "provider_unavailable", "provider is unavailable"),
            ),
            ErrorClass::Network | ErrorClass::Timeout => (
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(503, "upstream_unavailable", "the upstream operation failed"),
            ),
            ErrorClass::InvalidUpstreamResponse => (
                ErrorScope::Provider,
                Retryability::Never,
                ReplaySafety::NotReplayable,
                PublicResponse::new(
                    502,
                    "invalid_upstream_response",
                    "upstream response was invalid",
                ),
            ),
            ErrorClass::IncompleteStream => (
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
                PublicResponse::new(
                    502,
                    "incomplete_upstream_stream",
                    "upstream stream ended unexpectedly",
                ),
            ),
            ErrorClass::InternalInvariant => (
                ErrorScope::Internal,
                Retryability::Never,
                ReplaySafety::NotReplayable,
                PublicResponse::new(500, "internal_invariant", "an internal invariant failed"),
            ),
            ErrorClass::DownstreamDisconnected => (
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
                PublicResponse::new(
                    499,
                    "downstream_disconnected",
                    "downstream client disconnected",
                ),
            ),
        };

        Self::new(
            ErrorClassification::new(class, scope, retryability, replay_safety),
            response,
            RedactedEvidence::default(),
        )
    }

    /// Attach an optional provider recovery delay.
    #[must_use]
    pub fn with_recovery_after(mut self, delay: Duration) -> Self {
        self.classification = self.classification.with_recovery_after(delay);
        self
    }

    /// Request a scoped cooldown.
    #[must_use]
    pub fn with_cooldown(mut self, cooldown: CooldownSpec) -> Self {
        self.cooldown = Some(cooldown);
        self
    }

    /// Mark credential causation as proven by provider-specific evidence.
    #[must_use]
    pub fn with_credential_causation(mut self, causation: CredentialCausation) -> Self {
        self.credential_causation = causation;
        self
    }

    /// Whether this classification describes a request-local invalidity.
    #[must_use]
    pub fn is_request_invalid(&self) -> bool {
        matches!(
            self.classification.class,
            ErrorClass::InvalidRequest | ErrorClass::UnsupportedConversion
        )
    }
}

/// Classifiers inspect failures and return data. They receive no health state,
/// so classification cannot accidentally mutate cooldowns.
pub trait FailureClassifier: Send + Sync {
    /// Classify one bounded observation.
    fn classify(&self, failure: &ObservedFailure) -> FailureClassification;
}

/// Conservative HTTP/status classifier for adapters that have no provider
/// reason-code rules of their own.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpFailureClassifier;

impl FailureClassifier for HttpFailureClassifier {
    fn classify(&self, failure: &ObservedFailure) -> FailureClassification {
        let class = match failure.source {
            FailureSource::Downstream => match failure.status {
                Some(401 | 403) => ErrorClass::DownstreamAuthentication,
                _ => ErrorClass::InvalidRequest,
            },
            FailureSource::Transport => ErrorClass::Network,
            FailureSource::Internal => ErrorClass::InternalInvariant,
            FailureSource::Upstream => match failure.status {
                Some(401 | 403) => ErrorClass::ProviderAuthentication,
                Some(429) => ErrorClass::ProviderRateLimited,
                Some(408 | 500..=599) => ErrorClass::ProviderUnavailable,
                Some(400..=499) => ErrorClass::InvalidRequest,
                _ => ErrorClass::InvalidUpstreamResponse,
            },
        };
        let mut result = FailureClassification::for_class(class);
        result.evidence = RedactedEvidence {
            status: failure.status,
            provider_code: failure.provider_code.clone(),
            summary: failure.message.clone(),
        };
        if let Some(delay) = failure.retry_after {
            result = result.with_recovery_after(delay);
        }
        result
    }
}

// -----------------------------------------------------------------------------
// Retry
// -----------------------------------------------------------------------------

/// Downstream output state. Both visible headers and committed body output
/// prohibit retry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommitmentState {
    #[default]
    Uncommitted,
    HeadersSent,
    Committed,
}

impl CommitmentState {
    /// Returns true once any downstream output is visible.
    #[must_use]
    pub const fn is_committed(self) -> bool {
        !matches!(self, Self::Uncommitted)
    }
}

/// Monotonic state held by a streaming executor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Commitment(CommitmentState);

impl Commitment {
    /// Start before downstream output.
    #[must_use]
    pub const fn new() -> Self {
        Self(CommitmentState::Uncommitted)
    }

    /// Read the state.
    #[must_use]
    pub const fn state(self) -> CommitmentState {
        self.0
    }

    /// Mark headers visible.
    pub fn mark_headers_sent(&mut self) {
        if matches!(self.0, CommitmentState::Uncommitted) {
            self.0 = CommitmentState::HeadersSent;
        }
    }

    /// Mark downstream output committed.
    pub fn mark_committed(&mut self) {
        self.0 = CommitmentState::Committed;
    }
}

/// Request properties needed for replay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayCheck {
    pub body_replayable: bool,
    pub operation_replayable: bool,
    pub no_nonrepeatable_side_effect: bool,
    pub session_allows_replay: bool,
}

impl ReplayCheck {
    /// A replay-safe value for an idempotent retained request.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            body_replayable: true,
            operation_replayable: true,
            no_nonrepeatable_side_effect: true,
            session_allows_replay: true,
        }
    }

    /// Whether all request-level replay checks pass.
    #[must_use]
    pub const fn is_safe(self) -> bool {
        self.body_replayable
            && self.operation_replayable
            && self.no_nonrepeatable_side_effect
            && self.session_allows_replay
    }
}

/// Inputs to a retry decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryContext {
    pub attempt: u32,
    pub commitment: CommitmentState,
    pub replay: ReplayCheck,
    pub elapsed_retry_delay: Duration,
}

impl RetryContext {
    /// Construct context for a failed one-based attempt.
    #[must_use]
    pub const fn new(attempt: u32, commitment: CommitmentState, replay: ReplayCheck) -> Self {
        Self {
            attempt,
            commitment,
            replay,
            elapsed_retry_delay: Duration::ZERO,
        }
    }

    /// Include delay already spent on earlier retries.
    #[must_use]
    pub const fn with_elapsed_retry_delay(mut self, delay: Duration) -> Self {
        self.elapsed_retry_delay = delay;
        self
    }
}

/// Why policy refused a retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryStopReason {
    DownstreamCommitted,
    NotReplaySafe,
    ClassificationNotRetryable,
    AttemptsExhausted,
    RetryBudgetExhausted,
}

/// Why policy allowed a retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryReason {
    ReplaySafeBeforeCommit,
}

/// The retry decision and its auditable reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    Retry {
        delay: Duration,
        reason: RetryReason,
    },
    DoNotRetry {
        reason: RetryStopReason,
    },
}

impl RetryDecision {
    /// Whether another attempt is permitted.
    #[must_use]
    pub const fn is_retry(self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    /// The wait before a retry, or zero when stopped.
    #[must_use]
    pub const fn delay(self) -> Duration {
        match self {
            Self::Retry { delay, .. } => delay,
            Self::DoNotRetry { .. } => Duration::ZERO,
        }
    }
}

/// Bounded retry policy. The attempt limit includes the initial attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub max_total_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            max_total_delay: Duration::from_secs(60),
        }
    }
}

impl RetryPolicy {
    /// Construct and validate retry bounds.
    pub fn new(
        max_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
        max_total_delay: Duration,
    ) -> Result<Self, PolicyError> {
        if max_attempts == 0 || base_delay > max_delay {
            return Err(PolicyError::InvalidRetryBudget);
        }
        Ok(Self {
            max_attempts,
            base_delay,
            max_delay,
            max_total_delay,
        })
    }

    /// Decide whether this failed attempt can be replayed.
    #[must_use]
    pub fn decide(&self, failure: &FailureClassification, context: RetryContext) -> RetryDecision {
        if context.commitment.is_committed() {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::DownstreamCommitted,
            };
        }
        if failure.classification.retryability != Retryability::BeforeCommit
            || failure.classification.replay_safety == ReplaySafety::NotReplayable
        {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::ClassificationNotRetryable,
            };
        }
        if !context.replay.is_safe() {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::NotReplaySafe,
            };
        }
        if context.attempt == 0 || context.attempt >= self.max_attempts {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::AttemptsExhausted,
            };
        }
        let delay = self.delay_for(failure, context.attempt);
        if context.elapsed_retry_delay.saturating_add(delay) > self.max_total_delay {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::RetryBudgetExhausted,
            };
        }
        RetryDecision::Retry {
            delay,
            reason: RetryReason::ReplaySafeBeforeCommit,
        }
    }

    /// Convenience boolean form of [`Self::decide`].
    #[must_use]
    pub fn should_retry(&self, failure: &FailureClassification, context: RetryContext) -> bool {
        self.decide(failure, context).is_retry()
    }

    fn delay_for(&self, failure: &FailureClassification, attempt: u32) -> Duration {
        let multiplier = 1_u32 << attempt.saturating_sub(1).min(31);
        let exponential = self.base_delay.saturating_mul(multiplier);
        exponential
            .max(
                failure
                    .classification
                    .recovery_after
                    .unwrap_or(Duration::ZERO),
            )
            .min(self.max_delay)
    }
}

// -----------------------------------------------------------------------------
// Health and cooldowns
// -----------------------------------------------------------------------------

/// A concrete typed cooldown key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CooldownScope {
    Credential(CredentialId),
    CredentialModel {
        credential: CredentialId,
        model: ModelId,
    },
    Model(ModelId),
    Provider(ProviderId),
    ProviderModel {
        provider: ProviderId,
        model: ModelId,
    },
    Route(RouteId),
}

impl CooldownScope {
    /// Return the abstract kind.
    #[must_use]
    pub const fn kind(&self) -> CooldownScopeKind {
        match self {
            Self::Credential(_) => CooldownScopeKind::Credential,
            Self::CredentialModel { .. } => CooldownScopeKind::CredentialModel,
            Self::Model(_) => CooldownScopeKind::Model,
            Self::Provider(_) => CooldownScopeKind::Provider,
            Self::ProviderModel { .. } => CooldownScopeKind::ProviderModel,
            Self::Route(_) => CooldownScopeKind::Route,
        }
    }

    /// Return the credential ID for credential-scoped keys.
    #[must_use]
    pub fn credential(&self) -> Option<&CredentialId> {
        match self {
            Self::Credential(id) | Self::CredentialModel { credential: id, .. } => Some(id),
            _ => None,
        }
    }
}

/// A cooldown request carried by a classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CooldownSpec {
    pub scope: CooldownScopeKind,
    pub duration: Duration,
}

impl CooldownSpec {
    /// Cool a a credential.
    #[must_use]
    pub const fn credential(duration: Duration) -> Self {
        Self {
            scope: CooldownScopeKind::Credential,
            duration,
        }
    }

    /// Cool a credential/model pair.
    #[must_use]
    pub const fn credential_model(duration: Duration) -> Self {
        Self {
            scope: CooldownScopeKind::CredentialModel,
            duration,
        }
    }

    /// Cool a model.
    #[must_use]
    pub const fn model(duration: Duration) -> Self {
        Self {
            scope: CooldownScopeKind::Model,
            duration,
        }
    }

    /// Cool a provider.
    #[must_use]
    pub const fn provider(duration: Duration) -> Self {
        Self {
            scope: CooldownScopeKind::Provider,
            duration,
        }
    }

    /// Cool a provider/model pair.
    #[must_use]
    pub const fn provider_model(duration: Duration) -> Self {
        Self {
            scope: CooldownScopeKind::ProviderModel,
            duration,
        }
    }

    /// Cool one route.
    #[must_use]
    pub const fn route(duration: Duration) -> Self {
        Self {
            scope: CooldownScopeKind::Route,
            duration,
        }
    }
}

/// IDs needed to resolve a classification's abstract cooldown scope.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthSubject {
    pub credential: Option<CredentialId>,
    pub model: Option<ModelId>,
    pub provider: Option<ProviderId>,
    pub route: Option<RouteId>,
}

impl HealthSubject {
    /// Create a fully identified target.
    #[must_use]
    pub fn new(
        provider: ProviderId,
        model: ModelId,
        credential: CredentialId,
        route: RouteId,
    ) -> Self {
        Self {
            credential: Some(credential),
            model: Some(model),
            provider: Some(provider),
            route: Some(route),
        }
    }

    /// Resolve a concrete typed key, if all required IDs are present.
    #[must_use]
    pub fn resolve(&self, kind: CooldownScopeKind) -> Option<CooldownScope> {
        match kind {
            CooldownScopeKind::Credential => self.credential.clone().map(CooldownScope::Credential),
            CooldownScopeKind::CredentialModel => self
                .credential
                .clone()
                .zip(self.model.clone())
                .map(|(credential, model)| CooldownScope::CredentialModel { credential, model }),
            CooldownScopeKind::Model => self.model.clone().map(CooldownScope::Model),
            CooldownScopeKind::Provider => self.provider.clone().map(CooldownScope::Provider),
            CooldownScopeKind::ProviderModel => self
                .provider
                .clone()
                .zip(self.model.clone())
                .map(|(provider, model)| CooldownScope::ProviderModel { provider, model }),
            CooldownScopeKind::Route => self.route.clone().map(CooldownScope::Route),
        }
    }
}

/// Coarse health exposed to target selection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CredentialStatus {
    #[default]
    Healthy,
    CoolingDown,
    Disabled,
}

/// Why applying a failure changed nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthMutationReason {
    NoCooldownRequested,
    InvalidRequestCannotCooldownCredential,
    MissingCooldownTarget,
    ZeroCooldown,
    CredentialDisabled,
}

/// Result of applying one classification to health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthMutation {
    NoChange {
        reason: HealthMutationReason,
    },
    CooldownApplied {
        scope: CooldownScope,
        until: Instant,
    },
}

impl HealthMutation {
    /// Whether policy wrote a cooldown.
    #[must_use]
    pub const fn applied(&self) -> bool {
        matches!(self, Self::CooldownApplied { .. })
    }
}

/// Health for one credential. Narrow model scopes do not mark the whole
/// credential as cooling down.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialHealth {
    pub status: CredentialStatus,
    pub cooldown_until: Option<Instant>,
}

impl Default for CredentialHealth {
    fn default() -> Self {
        Self {
            status: CredentialStatus::Healthy,
            cooldown_until: None,
        }
    }
}

/// Mutable cooldown state, separate from immutable route plans.
#[derive(Clone, Debug, Default)]
pub struct HealthRegistry {
    cooldowns: HashMap<CooldownScope, Instant>,
    credentials: HashMap<CredentialId, CredentialHealth>,
}

impl HealthRegistry {
    /// Create empty health state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a classification. Classifiers never call this method.
    pub fn apply_failure(
        &mut self,
        failure: &FailureClassification,
        subject: &HealthSubject,
        now: Instant,
    ) -> HealthMutation {
        let Some(spec) = failure.cooldown.as_ref() else {
            return HealthMutation::NoChange {
                reason: HealthMutationReason::NoCooldownRequested,
            };
        };
        if failure.is_request_invalid()
            && failure.credential_causation != CredentialCausation::Proven
            && matches!(
                spec.scope,
                CooldownScopeKind::Credential | CooldownScopeKind::CredentialModel
            )
        {
            return HealthMutation::NoChange {
                reason: HealthMutationReason::InvalidRequestCannotCooldownCredential,
            };
        }
        if spec.duration.is_zero() {
            return HealthMutation::NoChange {
                reason: HealthMutationReason::ZeroCooldown,
            };
        }
        let Some(scope) = subject.resolve(spec.scope) else {
            return HealthMutation::NoChange {
                reason: HealthMutationReason::MissingCooldownTarget,
            };
        };
        if scope.credential().is_some_and(|id| {
            self.credentials
                .get(id)
                .is_some_and(|health| health.status == CredentialStatus::Disabled)
        }) {
            return HealthMutation::NoChange {
                reason: HealthMutationReason::CredentialDisabled,
            };
        }
        let until = now
            .checked_add(spec.duration)
            .unwrap_or(now + Duration::from_secs(60 * 60 * 24));
        let until = self
            .cooldowns
            .get(&scope)
            .copied()
            .map_or(until, |old| old.max(until));
        self.cooldowns.insert(scope.clone(), until);
        if let CooldownScope::Credential(id) = &scope {
            let health = self.credentials.entry(id.clone()).or_default();
            health.status = CredentialStatus::CoolingDown;
            health.cooldown_until = Some(until);
        }
        HealthMutation::CooldownApplied { scope, until }
    }

    /// Return an exact scope's active expiry.
    #[must_use]
    pub fn cooldown_until(&self, scope: &CooldownScope, now: Instant) -> Option<Instant> {
        self.cooldowns
            .get(scope)
            .copied()
            .filter(|until| *until > now)
    }

    /// Return whether an exact scope is active.
    #[must_use]
    pub fn is_cooling_down(&self, scope: &CooldownScope, now: Instant) -> bool {
        self.cooldown_until(scope, now).is_some()
    }

    /// Return whether any scope applicable to a target is active.
    #[must_use]
    pub fn target_is_cooling_down(&self, subject: &HealthSubject, now: Instant) -> bool {
        [
            CooldownScopeKind::Credential,
            CooldownScopeKind::CredentialModel,
            CooldownScopeKind::Model,
            CooldownScopeKind::Provider,
            CooldownScopeKind::ProviderModel,
            CooldownScopeKind::Route,
        ]
        .into_iter()
        .filter_map(|kind| subject.resolve(kind))
        .any(|scope| self.is_cooling_down(&scope, now))
    }

    /// Return credential health without creating a new entry.
    #[must_use]
    pub fn credential_health(&self, id: &CredentialId) -> Option<&CredentialHealth> {
        self.credentials.get(id)
    }

    /// Disable a credential until an outer control plane re-enables it.
    pub fn disable_credential(&mut self, id: CredentialId) {
        self.credentials.insert(
            id,
            CredentialHealth {
                status: CredentialStatus::Disabled,
                cooldown_until: None,
            },
        );
    }

    /// Remove expired entries and restore expired credential status.
    pub fn clear_expired(&mut self, now: Instant) -> usize {
        let expired: Vec<_> = self
            .cooldowns
            .iter()
            .filter(|(_, until)| **until <= now)
            .map(|(scope, _)| scope.clone())
            .collect();
        for scope in &expired {
            self.cooldowns.remove(scope);
            if let CooldownScope::Credential(id) = scope {
                if let Some(health) = self.credentials.get_mut(id) {
                    if health.status == CredentialStatus::CoolingDown {
                        health.status = CredentialStatus::Healthy;
                        health.cooldown_until = None;
                    }
                }
            }
        }
        expired.len()
    }
}

// -----------------------------------------------------------------------------
// Selection explanation
// -----------------------------------------------------------------------------

/// Pseudonym used instead of a credential ID in records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialPseudonym(String);

impl CredentialPseudonym {
    /// Construct a pseudonym from a redacted label.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return the pseudonym.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for CredentialPseudonym {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// A target safe to include in a decision record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelectionTarget {
    pub provider: ProviderId,
    pub model: ModelId,
    pub credential_pseudonym: CredentialPseudonym,
}

impl SelectionTarget {
    /// Construct a redacted target.
    #[must_use]
    pub fn new(provider: ProviderId, model: ModelId, credential: CredentialPseudonym) -> Self {
        Self {
            provider,
            model,
            credential_pseudonym: credential,
        }
    }
}

/// Why a candidate was filtered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FilterReason {
    ModelMismatch,
    MissingCapability(String),
    CodecUnavailable(String),
    CredentialUnavailable,
    CredentialCooldown,
    ModelCooldown,
    ProviderCooldown,
    ConcurrencyLimit,
    RoutePolicy,
    SessionAffinity,
    LossPolicy,
    QuotaExhausted,
    Disabled,
}

/// Candidate score and filter reasons.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CandidateExplanation {
    pub target: SelectionTarget,
    pub score: Option<f64>,
    pub filter_reasons: Vec<FilterReason>,
}

impl CandidateExplanation {
    /// Create an eligible candidate.
    #[must_use]
    pub fn eligible(target: SelectionTarget, score: f64) -> Self {
        Self {
            target,
            score: Some(score),
            filter_reasons: Vec::new(),
        }
    }

    /// Create a filtered candidate.
    #[must_use]
    pub fn filtered(target: SelectionTarget, reason: FilterReason) -> Self {
        Self {
            target,
            score: None,
            filter_reasons: vec![reason],
        }
    }

    /// Whether no filter rejected this candidate.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.filter_reasons.is_empty()
    }
}

/// Affinity lookup and rebinding result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AffinityDecision {
    NotRequested,
    NoMatch {
        key_pseudonym: String,
    },
    Matched {
        key_pseudonym: String,
        target: SelectionTarget,
    },
    Rebound {
        key_pseudonym: String,
        previous_provider: ProviderId,
        target: SelectionTarget,
    },
}

/// Requested and resolved model IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelAliasResolution {
    pub requested: ModelId,
    pub resolved: ModelId,
    pub alias_used: bool,
}

impl ModelAliasResolution {
    /// Record an exact model.
    #[must_use]
    pub fn exact(model: ModelId) -> Self {
        Self {
            requested: model.clone(),
            resolved: model,
            alias_used: false,
        }
    }

    /// Record an alias expansion.
    #[must_use]
    pub fn alias(requested: ModelId, resolved: ModelId) -> Self {
        Self {
            requested,
            resolved,
            alias_used: true,
        }
    }
}

/// Explain one target-selection attempt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelectionExplanation {
    pub candidates: Vec<CandidateExplanation>,
    pub affinity: AffinityDecision,
    pub selected: Option<SelectionTarget>,
    pub selected_score: Option<f64>,
    pub model_alias_resolution: ModelAliasResolution,
    pub attempt: u32,
    pub configuration_generation: ConfigGeneration,
}

impl SelectionExplanation {
    /// Start a decision record.
    #[must_use]
    pub fn new(model: ModelAliasResolution, attempt: u32, generation: ConfigGeneration) -> Self {
        Self {
            candidates: Vec::new(),
            affinity: AffinityDecision::NotRequested,
            selected: None,
            selected_score: None,
            model_alias_resolution: model,
            attempt,
            configuration_generation: generation,
        }
    }

    /// Add a candidate evaluation.
    pub fn push_candidate(&mut self, candidate: CandidateExplanation) {
        self.candidates.push(candidate);
    }

    /// Set the affinity result.
    pub fn set_affinity(&mut self, affinity: AffinityDecision) {
        self.affinity = affinity;
    }

    /// Set the selected target.
    pub fn set_selected(&mut self, target: SelectionTarget, score: Option<f64>) {
        self.selected = Some(target);
        self.selected_score = score;
    }

    /// Return the selected provider, if any.
    #[must_use]
    pub fn selected_provider(&self) -> Option<&ProviderId> {
        self.selected.as_ref().map(|target| &target.provider)
    }

    /// Return the selected credential pseudonym, if any.
    #[must_use]
    pub fn selected_credential_pseudonym(&self) -> Option<&CredentialPseudonym> {
        self.selected
            .as_ref()
            .map(|target| &target.credential_pseudonym)
    }
}

/// Errors constructing policy settings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    #[error("invalid retry budget")]
    InvalidRetryBudget,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(value: &str) -> CredentialId {
        CredentialId::new(value).expect("valid credential ID")
    }

    fn model(value: &str) -> ModelId {
        ModelId::new(value).expect("valid model ID")
    }

    fn provider(value: &str) -> ProviderId {
        ProviderId::new(value).expect("valid provider ID")
    }

    fn route(value: &str) -> RouteId {
        RouteId::new(value).expect("valid route ID")
    }

    fn subject() -> HealthSubject {
        HealthSubject::new(
            provider("provider-a"),
            model("model-a"),
            credential("credential-a"),
            route("route-a"),
        )
    }

    #[test]
    fn invalid_requests_are_non_retryable_and_have_no_cooldown() {
        let failure = FailureClassification::for_class(ErrorClass::InvalidRequest);
        assert_eq!(failure.classification.scope, ErrorScope::Downstream);
        assert!(!failure.classification.can_retry_before_commit());
        assert!(failure.cooldown.is_none());
    }

    #[test]
    fn classifier_returns_data_without_mutating_health() {
        let classifier = HttpFailureClassifier;
        let failure = classifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(429))
                .with_provider_code("rate_limit")
                .with_retry_after(Duration::from_secs(2)),
        );
        assert_eq!(
            failure.classification.class,
            ErrorClass::ProviderRateLimited
        );
        assert_eq!(
            failure.classification.recovery_after,
            Some(Duration::from_secs(2))
        );
        assert!(HealthRegistry::new()
            .credential_health(&credential("credential-a"))
            .is_none());
    }

    #[test]
    fn retry_stops_after_commit_even_for_replayable_failures() {
        let policy = RetryPolicy::default();
        let failure = FailureClassification::for_class(ErrorClass::ProviderUnavailable);
        for commitment in [CommitmentState::HeadersSent, CommitmentState::Committed] {
            assert!(!policy
                .decide(
                    &failure,
                    RetryContext::new(1, commitment, ReplayCheck::safe())
                )
                .is_retry());
        }
        let decision = policy.decide(
            &failure,
            RetryContext::new(1, CommitmentState::Committed, ReplayCheck::safe()),
        );
        assert_eq!(
            decision,
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::DownstreamCommitted
            }
        );
    }

    #[test]
    fn retry_requires_replay_safety_before_commit() {
        let failure = FailureClassification::for_class(ErrorClass::Network);
        let context = RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::default());
        assert_eq!(
            RetryPolicy::default().decide(&failure, context),
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::NotReplaySafe,
            }
        );
    }

    #[test]
    fn invalid_request_cannot_cool_a_credential() {
        let now = Instant::now();
        let failure = FailureClassification::for_class(ErrorClass::InvalidRequest)
            .with_cooldown(CooldownSpec::credential(Duration::from_secs(30)));
        let mut health = HealthRegistry::new();
        assert_eq!(
            health.apply_failure(&failure, &subject(), now),
            HealthMutation::NoChange {
                reason: HealthMutationReason::InvalidRequestCannotCooldownCredential
            },
        );
        assert!(health
            .credential_health(&credential("credential-a"))
            .is_none());
    }

    #[test]
    fn proven_credential_causation_allows_the_exception() {
        let now = Instant::now();
        let failure = FailureClassification::for_class(ErrorClass::InvalidRequest)
            .with_credential_causation(CredentialCausation::Proven)
            .with_cooldown(CooldownSpec::credential(Duration::from_secs(30)));
        let mut health = HealthRegistry::new();
        assert!(health.apply_failure(&failure, &subject(), now).applied());
    }

    #[test]
    fn cooldown_scopes_are_typed_and_narrow() {
        let now = Instant::now();
        let failure = FailureClassification::for_class(ErrorClass::ProviderRateLimited)
            .with_cooldown(CooldownSpec::provider_model(Duration::from_secs(30)));
        let mut health = HealthRegistry::new();
        assert!(health.apply_failure(&failure, &subject(), now).applied());
        let provider = provider("provider-a");
        let model = model("model-a");
        assert!(health.is_cooling_down(&CooldownScope::ProviderModel { provider, model }, now));
        assert!(health
            .credential_health(&credential("credential-a"))
            .is_none());
    }

    #[test]
    fn selection_record_contains_filters_affinity_alias_and_generation() {
        let provider_id = provider("provider-a");
        let model_id = model("model-a");
        let selected = SelectionTarget::new(
            provider_id.clone(),
            model_id.clone(),
            CredentialPseudonym::from("cred-1"),
        );
        let filtered = SelectionTarget::new(
            provider("provider-b"),
            model_id.clone(),
            CredentialPseudonym::from("cred-2"),
        );
        let mut explanation = SelectionExplanation::new(
            ModelAliasResolution::alias(model("public"), model_id),
            2,
            ConfigGeneration::new(9),
        );
        explanation.push_candidate(CandidateExplanation::eligible(selected.clone(), 0.9));
        explanation.push_candidate(CandidateExplanation::filtered(
            filtered,
            FilterReason::ProviderCooldown,
        ));
        explanation.set_affinity(AffinityDecision::NoMatch {
            key_pseudonym: "session-1".to_owned(),
        });
        explanation.set_selected(selected, Some(0.9));
        assert_eq!(explanation.selected_provider(), Some(&provider_id));
        assert_eq!(explanation.candidates.len(), 2);
        assert!(explanation.model_alias_resolution.alias_used);
    }
}
