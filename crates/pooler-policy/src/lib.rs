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
    ProviderId, ReplaySafety, Retryability, RouteId, TargetId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod quota;
mod selection;

pub(crate) use quota::QuotaPersistenceIdentity;

pub use quota::{
    PersistedQuotaSnapshot, ProviderNeutralQuotaClassifier, QuotaClassification, QuotaClassifier,
    QuotaError, QuotaFailureClassifier, QuotaObservation, QuotaProjectKey, QuotaScope, QuotaSignal,
    QuotaSnapshot, QuotaState, QuotaSubject, QuotaUnit, QUOTA_STATE_SCHEMA_VERSION,
};

pub use selection::{
    AffinityKey, BindingKey, CandidateFacts, CredentialRegistration, CredentialRegistry,
    QuotaRecovery, RoutingFact, RoutingRequirements, RoutingTelemetry, SelectionError,
    SelectionLease, SelectionRequest, SelectionReservation, SelectionStrategy, TelemetrySample,
};

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

/// Classifies common provider HTTP failures and bounded provider reason codes.
///
/// The classifier only returns data.  It never mutates a credential or model,
/// so callers can safely classify a malformed request before selecting a
/// target or applying health changes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProviderFailureClassifier;

impl FailureClassifier for ProviderFailureClassifier {
    fn classify(&self, failure: &ObservedFailure) -> FailureClassification {
        classify_provider_failure(failure)
    }
}

/// OpenAI-compatible provider reason-code classifier.
///
/// OpenAI-compatible gateways commonly use the same status and reason-code
/// vocabulary.  Keeping this as a named classifier makes the route contract
/// explicit while sharing the conservative rules with other HTTP providers.
pub type OpenAiCompatibleFailureClassifier = ProviderFailureClassifier;

/// Short compatibility name for OpenAI-style classifiers.
pub type OpenAiFailureClassifier = ProviderFailureClassifier;

/// Anthropic-compatible provider reason-code classifier.
pub type AnthropicCompatibleFailureClassifier = ProviderFailureClassifier;

/// Short compatibility name for Anthropic-style classifiers.
pub type AnthropicFailureClassifier = ProviderFailureClassifier;

/// HTTP/status classifier using the shared conservative provider rules.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpFailureClassifier;

impl FailureClassifier for HttpFailureClassifier {
    fn classify(&self, failure: &ObservedFailure) -> FailureClassification {
        classify_provider_failure(failure)
    }
}

const DEFAULT_PROVIDER_AUTH_RECOVERY: Duration = Duration::from_secs(30);
const DEFAULT_QUOTA_RECOVERY: Duration = Duration::from_secs(60);
const DEFAULT_RATE_LIMIT_RECOVERY: Duration = Duration::from_secs(1);
const DEFAULT_PROVIDER_UNAVAILABLE_RECOVERY: Duration = Duration::from_secs(1);

fn classify_provider_failure(failure: &ObservedFailure) -> FailureClassification {
    let class = match failure.source {
        FailureSource::Downstream => match failure.status {
            Some(401 | 403) => ErrorClass::DownstreamAuthentication,
            _ => ErrorClass::InvalidRequest,
        },
        FailureSource::Transport => ErrorClass::Network,
        FailureSource::Internal => ErrorClass::InternalInvariant,
        FailureSource::Upstream => classify_upstream_class(failure),
    };

    let mut result = FailureClassification::for_class(class);
    result.evidence = RedactedEvidence {
        status: failure.status,
        provider_code: failure.provider_code.clone(),
        summary: failure.message.clone(),
    };

    let recovery = failure
        .retry_after
        .unwrap_or_else(|| default_recovery_for(class));
    if recovery > Duration::ZERO && allows_recovery_hint(class) {
        result = result.with_recovery_after(recovery);
        if let Some(scope) = cooldown_scope_for(class) {
            result = result.with_cooldown(CooldownSpec {
                scope,
                duration: recovery,
            });
        }
    }
    result
}

fn classify_upstream_class(failure: &ObservedFailure) -> ErrorClass {
    let hint = provider_hint(failure);
    if has_any(
        &hint,
        &[
            "invalid_request",
            "invalid_argument",
            "bad_request",
            "malformed",
            "validation_error",
        ],
    ) {
        return ErrorClass::InvalidRequest;
    }
    if has_any(
        &hint,
        &[
            "insufficient_quota",
            "quota_exceeded",
            "billing_hard_limit",
            "resource_exhausted",
            "quota",
            "daily_limit",
            "monthly_limit",
            "credit_exhausted",
        ],
    ) {
        return if has_any(&hint, &["model_quota", "model_limit", "model_capacity"]) {
            ErrorClass::ModelQuotaExhausted
        } else {
            ErrorClass::CredentialQuotaExhausted
        };
    }
    if has_any(
        &hint,
        &[
            "invalid_api_key",
            "invalid_auth",
            "authentication",
            "unauthorized",
        ],
    ) || (matches!(failure.status, Some(401 | 403))
        && !has_any(&hint, &["invalid_request", "invalid_argument"]))
    {
        return ErrorClass::ProviderAuthentication;
    }
    if matches!(failure.status, Some(429))
        || has_any(
            &hint,
            &[
                "rate_limit",
                "too_many_requests",
                "throttl",
                "overload",
                "temporarily_unavailable",
            ],
        )
    {
        return ErrorClass::ProviderRateLimited;
    }
    match failure.status {
        Some(408 | 500..=599) => ErrorClass::ProviderUnavailable,
        Some(400..=499) => ErrorClass::InvalidRequest,
        _ => ErrorClass::InvalidUpstreamResponse,
    }
}

fn provider_hint(failure: &ObservedFailure) -> String {
    let mut hint = String::new();
    if let Some(code) = &failure.provider_code {
        hint.push_str(&code.to_ascii_lowercase());
    }
    if let Some(message) = &failure.message {
        if !hint.is_empty() {
            hint.push(' ');
        }
        hint.push_str(&message.to_ascii_lowercase());
    }
    hint
}

fn has_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn default_recovery_for(class: ErrorClass) -> Duration {
    match class {
        ErrorClass::ProviderAuthentication => DEFAULT_PROVIDER_AUTH_RECOVERY,
        ErrorClass::CredentialQuotaExhausted | ErrorClass::ModelQuotaExhausted => {
            DEFAULT_QUOTA_RECOVERY
        }
        ErrorClass::ProviderRateLimited => DEFAULT_RATE_LIMIT_RECOVERY,
        ErrorClass::ProviderUnavailable => DEFAULT_PROVIDER_UNAVAILABLE_RECOVERY,
        _ => Duration::ZERO,
    }
}

fn allows_recovery_hint(class: ErrorClass) -> bool {
    matches!(
        class,
        ErrorClass::ProviderAuthentication
            | ErrorClass::CredentialQuotaExhausted
            | ErrorClass::ModelQuotaExhausted
            | ErrorClass::ProviderRateLimited
            | ErrorClass::ProviderUnavailable
    )
}

fn cooldown_scope_for(class: ErrorClass) -> Option<CooldownScopeKind> {
    match class {
        ErrorClass::ProviderAuthentication | ErrorClass::CredentialQuotaExhausted => {
            Some(CooldownScopeKind::Credential)
        }
        ErrorClass::ModelQuotaExhausted => Some(CooldownScopeKind::Model),
        ErrorClass::ProviderRateLimited | ErrorClass::ProviderUnavailable => {
            Some(CooldownScopeKind::Provider)
        }
        _ => None,
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

    /// Build the replay proof for an HTTP operation whose body is retained.
    ///
    /// HTTP methods with idempotent semantics may be replayed directly. A
    /// non-idempotent method, such as POST, requires an explicit
    /// `Idempotency-Key` header before the operation is considered repeatable.
    #[must_use]
    pub fn for_http_method(method: &str, idempotency_key_present: bool) -> Self {
        let idempotent = matches!(
            method,
            "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE" | "TRACE"
        );
        Self {
            body_replayable: true,
            operation_replayable: idempotent || idempotency_key_present,
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

/// Whether the next retry waits for the failed target or rotates away from it.
///
/// A recovery hint belongs to the failed scope. It must delay a same-target
/// retry, but it must not stall an immediately available credential/provider
/// outside that scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetryTargetChange {
    /// Retry the same credential and provider after their recovery window.
    #[default]
    SameTarget,
    /// Rotate to another credential that is outside a credential-scoped limit.
    DifferentCredential,
    /// Rotate to another provider that is outside a provider-scoped limit.
    DifferentProvider,
}

/// Inputs to a retry decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryContext {
    pub attempt: u32,
    pub commitment: CommitmentState,
    pub replay: ReplayCheck,
    pub elapsed_retry_delay: Duration,
    /// Total request time observed before making another attempt.
    pub elapsed: Duration,
    /// Number of credentials already tried by this request.
    pub credentials_used: u32,
    /// Number of providers already tried by this request.
    pub providers_used: u32,
    /// Time spent waiting on provider-advertised recovery windows.
    pub elapsed_recovery_wait: Duration,
    /// Whether the request carries the idempotency key required by the
    /// provider before replaying a non-idempotent operation.
    pub idempotency_key_present: bool,
    /// Planned target change for the next attempt.
    pub target_change: RetryTargetChange,
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
            elapsed: Duration::ZERO,
            credentials_used: 1,
            providers_used: 1,
            elapsed_recovery_wait: Duration::ZERO,
            idempotency_key_present: false,
            target_change: RetryTargetChange::SameTarget,
        }
    }

    /// Include delay already spent on earlier retries.
    #[must_use]
    pub const fn with_elapsed_retry_delay(mut self, delay: Duration) -> Self {
        self.elapsed_retry_delay = delay;
        self
    }

    /// Include total request time already consumed by this attempt.
    #[must_use]
    pub const fn with_elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    /// Include the number of credentials and providers already attempted.
    #[must_use]
    pub const fn with_used_targets(mut self, credentials: u32, providers: u32) -> Self {
        self.credentials_used = credentials;
        self.providers_used = providers;
        self
    }

    /// Include time already spent waiting for provider recovery.
    #[must_use]
    pub const fn with_elapsed_recovery_wait(mut self, delay: Duration) -> Self {
        self.elapsed_recovery_wait = delay;
        self
    }

    /// Mark whether a request-scoped idempotency key is available for replay.
    #[must_use]
    pub const fn with_idempotency_key(mut self, present: bool) -> Self {
        self.idempotency_key_present = present;
        self
    }

    /// Describe how the next attempt moves outside the failed quota scope.
    #[must_use]
    pub const fn with_target_change(mut self, target_change: RetryTargetChange) -> Self {
        self.target_change = target_change;
        self
    }
}

/// Why policy refused a retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryStopReason {
    DownstreamCommitted,
    NotReplaySafe,
    ClassificationNotRetryable,
    RequiresIdempotencyKey,
    AttemptsExhausted,
    CredentialsExhausted,
    ProvidersExhausted,
    RecoveryWaitExhausted,
    RetryBudgetExhausted,
    /// Retry was otherwise allowed but every alternate target was filtered.
    NoAlternateTarget,
}

/// Why policy allowed a retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryReason {
    ReplaySafeBeforeCommit,
    /// A credential-scoped recovery window was bypassed by account rotation.
    AlternateCredential,
    /// A provider-scoped recovery window was bypassed by provider rotation.
    AlternateProvider,
}

/// The retry decision and its auditable reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    Retry {
        /// Wall-clock wait before the next attempt. Ordinary backoff and a
        /// provider recovery window overlap, so this is the larger component.
        delay: Duration,
        /// Ordinary exponential-backoff charge applied to `max_total_delay`.
        retry_delay: Duration,
        /// Provider recovery-window charge applied to `max_recovery_wait`.
        recovery_wait: Duration,
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

    /// The wall-clock wait before a retry, or zero when stopped.
    #[must_use]
    pub const fn delay(self) -> Duration {
        match self {
            Self::Retry { delay, .. } => delay,
            Self::DoNotRetry { .. } => Duration::ZERO,
        }
    }

    /// The ordinary retry-delay budget charge, or zero when stopped.
    #[must_use]
    pub const fn retry_delay(self) -> Duration {
        match self {
            Self::Retry { retry_delay, .. } => retry_delay,
            Self::DoNotRetry { .. } => Duration::ZERO,
        }
    }

    /// The provider recovery-wait budget charge, or zero when stopped.
    #[must_use]
    pub const fn recovery_wait(self) -> Duration {
        match self {
            Self::Retry { recovery_wait, .. } => recovery_wait,
            Self::DoNotRetry { .. } => Duration::ZERO,
        }
    }
}

/// Bounded retry policy. The attempt limit includes the initial attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    /// Maximum distinct credential attempts for one request.
    pub max_credentials: u32,
    /// Maximum distinct provider attempts for one request.
    pub max_providers: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub max_total_delay: Duration,
    /// Optional wall-clock bound for the complete request retry window.
    pub max_elapsed: Option<Duration>,
    /// Maximum time spent honoring provider recovery hints.
    pub max_recovery_wait: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            max_credentials: 2,
            max_providers: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            max_total_delay: Duration::from_secs(60),
            max_elapsed: Some(Duration::from_secs(60)),
            max_recovery_wait: Duration::from_secs(60),
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
            max_credentials: max_attempts,
            max_providers: max_attempts,
            base_delay,
            max_delay,
            max_total_delay,
            max_recovery_wait: max_total_delay,
            max_elapsed: Some(max_total_delay),
        })
    }

    /// Construct a policy with explicit attempt, target, and wait bounds.
    pub fn with_bounds(
        max_attempts: u32,
        max_credentials: u32,
        max_providers: u32,
        base_delay: Duration,
        max_delay: Duration,
        max_total_delay: Duration,
        max_recovery_wait: Duration,
    ) -> Result<Self, PolicyError> {
        if max_attempts == 0 || max_credentials == 0 || max_providers == 0 || base_delay > max_delay
        {
            return Err(PolicyError::InvalidRetryBudget);
        }
        Ok(Self {
            max_attempts,
            max_credentials,
            max_providers,
            base_delay,
            max_delay,
            max_total_delay,
            max_recovery_wait,
            max_elapsed: Some(max_total_delay),
        })
    }

    /// Set an optional wall-clock retry bound.
    #[must_use]
    pub const fn with_max_elapsed(mut self, max_elapsed: Option<Duration>) -> Self {
        self.max_elapsed = max_elapsed;
        self
    }

    /// Decide whether this failed attempt can be replayed.
    #[must_use]
    pub fn decide(&self, failure: &FailureClassification, context: RetryContext) -> RetryDecision {
        if context.commitment.is_committed() {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::DownstreamCommitted,
            };
        }
        if self
            .max_elapsed
            .is_some_and(|limit| context.elapsed > limit)
        {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::RetryBudgetExhausted,
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
        if failure.classification.replay_safety == ReplaySafety::RequiresIdempotencyKey
            && !context.idempotency_key_present
        {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::RequiresIdempotencyKey,
            };
        }
        if context.attempt == 0 || context.attempt >= self.max_attempts {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::AttemptsExhausted,
            };
        }
        if matches!(failure.classification.scope, ErrorScope::Credential)
            && context.credentials_used >= self.max_credentials
        {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::CredentialsExhausted,
            };
        }
        if matches!(failure.classification.scope, ErrorScope::Provider)
            && context.providers_used >= self.max_providers
        {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::ProvidersExhausted,
            };
        }
        let avoids_failed_scope = context.target_change.avoids(failure.classification.scope);
        let (retry_delay, recovery_wait) =
            self.delay_components(failure, context.attempt, avoids_failed_scope);
        let delay = retry_delay.max(recovery_wait);
        if self
            .max_elapsed
            .is_some_and(|limit| context.elapsed.saturating_add(delay) > limit)
        {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::RetryBudgetExhausted,
            };
        }
        if context.elapsed_recovery_wait.saturating_add(recovery_wait) > self.max_recovery_wait {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::RecoveryWaitExhausted,
            };
        }
        if context.elapsed_retry_delay.saturating_add(retry_delay) > self.max_total_delay {
            return RetryDecision::DoNotRetry {
                reason: RetryStopReason::RetryBudgetExhausted,
            };
        }
        RetryDecision::Retry {
            delay,
            retry_delay,
            recovery_wait,
            reason: match context.target_change {
                RetryTargetChange::SameTarget => RetryReason::ReplaySafeBeforeCommit,
                RetryTargetChange::DifferentCredential => RetryReason::AlternateCredential,
                RetryTargetChange::DifferentProvider => RetryReason::AlternateProvider,
            },
        }
    }

    /// Convenience boolean form of [`Self::decide`].
    #[must_use]
    pub fn should_retry(&self, failure: &FailureClassification, context: RetryContext) -> bool {
        self.decide(failure, context).is_retry()
    }

    fn delay_components(
        &self,
        failure: &FailureClassification,
        attempt: u32,
        avoids_failed_scope: bool,
    ) -> (Duration, Duration) {
        if avoids_failed_scope {
            return (Duration::ZERO, Duration::ZERO);
        }
        let multiplier = 1_u32 << attempt.saturating_sub(1).min(31);
        let retry_delay = self
            .base_delay
            .saturating_mul(multiplier)
            .min(self.max_delay);
        let recovery_wait = failure
            .classification
            .recovery_after
            .unwrap_or(Duration::ZERO);
        (retry_delay, recovery_wait)
    }
}

impl RetryTargetChange {
    const fn avoids(self, scope: ErrorScope) -> bool {
        matches!(
            (self, scope),
            (
                Self::DifferentCredential | Self::DifferentProvider,
                ErrorScope::Credential
            ) | (Self::DifferentProvider, ErrorScope::Provider)
        )
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
    /// One concrete target/account binding. This is emitted for a
    /// credential-scoped failure when the request supplied a composite
    /// binding identity, so identical account IDs cannot cool one another.
    Binding(BindingKey),
    /// One concrete target/account binding and model pair.
    BindingModel {
        binding: BindingKey,
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
            Self::Binding(_) => CooldownScopeKind::Credential,
            Self::BindingModel { .. } => CooldownScopeKind::CredentialModel,
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
            Self::Binding(binding) | Self::BindingModel { binding, .. } => {
                Some(binding.account_id())
            }
            _ => None,
        }
    }

    /// Return the composite binding identity for binding-scoped keys.
    #[must_use]
    pub fn binding(&self) -> Option<&BindingKey> {
        match self {
            Self::Binding(binding) | Self::BindingModel { binding, .. } => Some(binding),
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
    /// Concrete target/account identity used to isolate credential health.
    #[doc(hidden)]
    pub binding: Option<BindingKey>,
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
            binding: None,
        }
    }

    /// Attach a concrete target/account binding to this health subject.
    #[must_use]
    pub fn with_binding(mut self, binding: BindingKey) -> Self {
        self.credential = Some(binding.account_id().clone());
        self.binding = Some(binding);
        self
    }

    /// Alias that makes the composite identity explicit at call sites.
    #[must_use]
    pub fn with_binding_key(self, binding: BindingKey) -> Self {
        self.with_binding(binding)
    }

    /// Resolve a concrete typed key, if all required IDs are present.
    #[must_use]
    pub fn resolve(&self, kind: CooldownScopeKind) -> Option<CooldownScope> {
        match kind {
            CooldownScopeKind::Credential => self.binding.clone().map_or_else(
                || self.credential.clone().map(CooldownScope::Credential),
                |binding| Some(CooldownScope::Binding(binding)),
            ),
            CooldownScopeKind::CredentialModel => self.binding.clone().map_or_else(
                || {
                    self.credential
                        .clone()
                        .zip(self.model.clone())
                        .map(|(credential, model)| CooldownScope::CredentialModel {
                            credential,
                            model,
                        })
                },
                |binding| {
                    self.model
                        .clone()
                        .map(|model| CooldownScope::BindingModel { binding, model })
                },
            ),
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
    CredentialDisableNotPersisted,
    CredentialGenerationChanged,
    CredentialUnavailable,
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
    bindings: HashMap<BindingKey, CredentialHealth>,
}

impl HealthRegistry {
    /// Create empty health state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rehydrate one persisted cooldown without reconstructing a synthetic
    /// failure classification.
    pub fn restore_cooldown(&mut self, scope: CooldownScope, until: Instant) {
        self.cooldowns
            .entry(scope.clone())
            .and_modify(|old| *old = (*old).max(until))
            .or_insert(until);
        match scope {
            CooldownScope::Credential(id) => {
                set_cooling_down(self.credentials.entry(id).or_default(), until);
            }
            CooldownScope::Binding(binding) | CooldownScope::BindingModel { binding, .. } => {
                set_cooling_down(self.bindings.entry(binding).or_default(), until);
            }
            _ => {}
        }
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
        let disabled = match &scope {
            CooldownScope::Binding(binding) | CooldownScope::BindingModel { binding, .. } => self
                .bindings
                .get(binding)
                .is_some_and(|health| health.status == CredentialStatus::Disabled),
            _ => scope.credential().is_some_and(|id| {
                self.credentials
                    .get(id)
                    .is_some_and(|health| health.status == CredentialStatus::Disabled)
            }),
        };
        if disabled {
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
        match &scope {
            CooldownScope::Credential(id) => {
                set_cooling_down(self.credentials.entry(id.clone()).or_default(), until);
            }
            CooldownScope::Binding(binding) | CooldownScope::BindingModel { binding, .. } => {
                set_cooling_down(self.bindings.entry(binding.clone()).or_default(), until);
            }
            _ => {}
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
        self.target_cooldown_scopes(subject, now)
            .into_iter()
            .next()
            .is_some()
    }

    /// Return every active cooldown scope that applies to a target.
    #[must_use]
    pub fn target_cooldown_scopes(
        &self,
        subject: &HealthSubject,
        now: Instant,
    ) -> Vec<CooldownScopeKind> {
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
        .filter(|scope| self.is_cooling_down(scope, now))
        .map(|scope| scope.kind())
        .collect()
    }

    /// Return the earliest active recovery deadline that applies to a target.
    ///
    /// The caller can use this value to wait or to record why a target was
    /// skipped.  Expired entries are ignored and are left for the next
    /// mutable cleanup pass.
    #[must_use]
    pub fn target_recovery_until(&self, subject: &HealthSubject, now: Instant) -> Option<Instant> {
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
        .filter_map(|scope| self.cooldown_until(&scope, now))
        .min()
    }

    /// Return the remaining recovery delay for a target, if any cooldown is
    /// active.
    #[must_use]
    pub fn target_recovery_after(&self, subject: &HealthSubject, now: Instant) -> Option<Duration> {
        self.target_recovery_until(subject, now)
            .map(|until| until.saturating_duration_since(now))
    }

    /// Return credential health without creating a new entry.
    #[must_use]
    pub fn credential_health(&self, id: &CredentialId) -> Option<&CredentialHealth> {
        self.credentials.get(id)
    }

    /// Return health for one concrete target/account binding.
    #[must_use]
    pub fn binding_health(&self, binding: &BindingKey) -> Option<&CredentialHealth> {
        self.bindings.get(binding)
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

    /// Disable one concrete target/account binding without affecting a sibling
    /// binding that happens to reuse the same account ID.
    pub fn disable_binding(&mut self, binding: BindingKey) {
        self.bindings.insert(
            binding,
            CredentialHealth {
                status: CredentialStatus::Disabled,
                cooldown_until: None,
            },
        );
    }

    /// Re-enable a credential after an operator or control plane clears its
    /// disabled state. Active scoped cooldowns remain authoritative until
    /// they expire.
    pub fn enable_credential(&mut self, id: CredentialId) {
        let health = self.credentials.entry(id).or_default();
        if health.status == CredentialStatus::Disabled {
            health.status = CredentialStatus::Healthy;
            health.cooldown_until = None;
        }
    }

    /// Re-enable one concrete target/account binding.
    pub fn enable_binding(&mut self, binding: &BindingKey) {
        let health = self.bindings.entry(binding.clone()).or_default();
        if health.status == CredentialStatus::Disabled {
            health.status = CredentialStatus::Healthy;
            health.cooldown_until = None;
        }
    }

    /// Remove all binding-scoped health state when a compiled binding is
    /// unregistered. Shared provider/model cooldowns remain intact.
    pub fn remove_binding(&mut self, binding: &BindingKey) {
        self.bindings.remove(binding);
        self.cooldowns.retain(|scope, _| {
            !matches!(
                scope,
                CooldownScope::Binding(candidate)
                    | CooldownScope::BindingModel {
                        binding: candidate,
                        ..
                    } if candidate == binding
            )
        });
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
            match scope {
                CooldownScope::Credential(id) => clear_cooling_down(self.credentials.get_mut(id)),
                CooldownScope::Binding(binding) | CooldownScope::BindingModel { binding, .. } => {
                    clear_cooling_down(self.bindings.get_mut(binding));
                }
                _ => {}
            }
        }
        expired.len()
    }
}

fn set_cooling_down(health: &mut CredentialHealth, until: Instant) {
    if health.status != CredentialStatus::Disabled {
        health.status = CredentialStatus::CoolingDown;
        health.cooldown_until = Some(until);
    }
}

fn clear_cooling_down(health: Option<&mut CredentialHealth>) {
    if let Some(health) = health {
        if health.status == CredentialStatus::CoolingDown {
            health.status = CredentialStatus::Healthy;
            health.cooldown_until = None;
        }
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
    /// Stable target ID, when selection came from a structured target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<TargetId>,
    /// Redacted composite target/account identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_pseudonym: Option<String>,
    /// Priority tier used by the selector; lower values win.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Optional homogeneous account-pool ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<String>,
}

impl SelectionTarget {
    /// Construct a redacted target.
    #[must_use]
    pub fn new(provider: ProviderId, model: ModelId, credential: CredentialPseudonym) -> Self {
        Self {
            provider,
            model,
            credential_pseudonym: credential,
            target_id: None,
            binding_pseudonym: None,
            priority: None,
            pool_id: None,
        }
    }

    /// Construct a target explanation from a concrete registration.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn structured(
        provider: ProviderId,
        model: ModelId,
        credential: CredentialPseudonym,
        target_id: TargetId,
        binding_pseudonym: String,
        priority: u32,
        pool_id: Option<String>,
    ) -> Self {
        Self {
            provider,
            model,
            credential_pseudonym: credential,
            target_id: Some(target_id),
            binding_pseudonym: Some(binding_pseudonym),
            priority: Some(priority),
            pool_id,
        }
    }
}

/// Why a candidate was filtered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FilterReason {
    ModelMismatch,
    MissingCapability(String),
    CodecUnavailable(String),
    ProviderNotAllowed,
    ProviderDenied,
    TargetNotAllowed,
    TargetDenied,
    FallbackDisabled,
    MissingParameter(String),
    UnknownParameters,
    MissingContext,
    UnknownContext,
    MissingQuantization(String),
    UnknownQuantization,
    PrivacyMismatch,
    UnknownPrivacy,
    ZdrRequired,
    UnknownZdr,
    DataPolicyMismatch,
    UnknownDataPolicy,
    RegionMismatch,
    UnknownRegion,
    PriceExceeded,
    UnknownPrice,
    StaleTelemetry,
    UnknownTelemetry,
    CredentialUnavailable,
    CredentialCooldown,
    CredentialModelCooldown,
    ModelCooldown,
    ProviderCooldown,
    ProviderModelCooldown,
    RouteCooldown,
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
    /// The bound target was unavailable and policy forbade rebinding.
    Unavailable {
        key_pseudonym: String,
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
    /// Priority tier that won the decision, when target metadata was
    /// structured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_priority: Option<u32>,
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
            selected_priority: None,
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
        self.selected_priority = target.priority;
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
    fn malformed_provider_request_does_not_cool_a_credential() {
        let classifier = ProviderFailureClassifier;
        let failure = classifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(400))
                .with_provider_code("invalid_request")
                .with_message("request body is malformed"),
        );
        assert_eq!(failure.classification.class, ErrorClass::InvalidRequest);
        assert!(failure.cooldown.is_none());
        let mut health = HealthRegistry::new();
        assert_eq!(
            health.apply_failure(&failure, &subject(), Instant::now()),
            HealthMutation::NoChange {
                reason: HealthMutationReason::NoCooldownRequested,
            }
        );
    }

    #[test]
    fn retry_after_is_preserved_for_rate_limit_recovery() {
        let failure = ProviderFailureClassifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(429))
                .with_provider_code("rate_limit_exceeded")
                .with_retry_after(Duration::from_secs(7)),
        );
        assert_eq!(
            failure.classification.class,
            ErrorClass::ProviderRateLimited
        );
        assert_eq!(
            failure.classification.recovery_after,
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            failure.cooldown,
            Some(CooldownSpec::provider(Duration::from_secs(7)))
        );
    }

    #[test]
    fn quota_failure_cools_one_credential_and_allows_failover() {
        let failure = ProviderFailureClassifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(429))
                .with_provider_code("insufficient_quota")
                .with_retry_after(Duration::from_secs(45)),
        );
        assert_eq!(
            failure.classification.class,
            ErrorClass::CredentialQuotaExhausted
        );
        assert_eq!(failure.classification.scope, ErrorScope::Credential);
        let now = Instant::now();
        let mut health = HealthRegistry::new();
        let mutation = health.apply_failure(&failure, &subject(), now);
        assert!(mutation.applied());
        assert!(health.target_is_cooling_down(&subject(), now));
        assert_eq!(
            health.target_recovery_after(&subject(), now),
            Some(Duration::from_secs(45))
        );

        let retry = RetryPolicy::default().decide(
            &failure,
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe())
                .with_used_targets(1, 1),
        );
        assert!(retry.is_retry());
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
    fn replay_proof_requires_idempotent_method_or_key() {
        let failure = ProviderFailureClassifier
            .classify(&ObservedFailure::new(FailureSource::Upstream, Some(503)));
        let policy = RetryPolicy::default();
        let post_without_key = RetryContext::new(
            1,
            CommitmentState::Uncommitted,
            ReplayCheck::for_http_method("POST", false),
        );
        assert_eq!(
            policy.decide(&failure, post_without_key),
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::NotReplaySafe
            }
        );
        let post_with_key = RetryContext::new(
            1,
            CommitmentState::Uncommitted,
            ReplayCheck::for_http_method("POST", true),
        );
        assert!(policy.decide(&failure, post_with_key).is_retry());
        let get = RetryContext::new(
            1,
            CommitmentState::Uncommitted,
            ReplayCheck::for_http_method("GET", false),
        );
        assert!(policy.decide(&failure, get).is_retry());
    }

    #[test]
    fn retry_requires_an_idempotency_key_when_classification_requires_one() {
        let classification = ErrorClassification::new(
            ErrorClass::ProviderUnavailable,
            ErrorScope::Provider,
            Retryability::BeforeCommit,
            ReplaySafety::RequiresIdempotencyKey,
        );
        let failure = FailureClassification::new(
            classification,
            PublicResponse::new(503, "provider_unavailable", "provider unavailable"),
            RedactedEvidence::default(),
        );
        let context = RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe());
        assert_eq!(
            RetryPolicy::default().decide(&failure, context),
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::RequiresIdempotencyKey,
            }
        );
        assert!(RetryPolicy::default()
            .decide(&failure, context.with_idempotency_key(true))
            .is_retry());
    }

    #[test]
    fn retry_budget_limits_credentials_and_recovery_wait() {
        let independent = RetryPolicy::with_bounds(
            2,
            2,
            2,
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .expect("recovery horizon is independent from retry delay budget");
        assert_eq!(independent.max_total_delay, Duration::from_secs(1));
        assert_eq!(independent.max_recovery_wait, Duration::from_secs(30));

        let failure = ProviderFailureClassifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(429))
                .with_provider_code("insufficient_quota")
                .with_retry_after(Duration::from_secs(10)),
        );
        let policy = RetryPolicy::with_bounds(
            3,
            1,
            3,
            Duration::from_millis(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .expect("valid retry bounds");
        assert_eq!(
            policy.decide(
                &failure,
                RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe())
                    .with_used_targets(1, 1),
            ),
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::CredentialsExhausted,
            }
        );

        let policy = RetryPolicy::with_bounds(
            3,
            3,
            3,
            Duration::from_millis(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .expect("valid retry bounds");
        assert_eq!(
            policy.decide(
                &failure,
                RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe())
                    .with_used_targets(1, 1),
            ),
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::RecoveryWaitExhausted,
            }
        );

        let policy = RetryPolicy::default().with_max_elapsed(Some(Duration::from_secs(2)));
        assert_eq!(
            policy.decide(
                &failure,
                RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe())
                    .with_elapsed(Duration::from_secs(3)),
            ),
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::RetryBudgetExhausted,
            }
        );
    }

    #[test]
    fn provider_recovery_wait_is_not_capped_by_ordinary_maximum_delay() {
        let policy = RetryPolicy::with_bounds(
            3,
            3,
            3,
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .expect("valid independent retry bounds")
        .with_max_elapsed(None);
        let failure = ProviderFailureClassifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(503))
                .with_retry_after(Duration::from_secs(10)),
        );

        assert_eq!(
            policy.decide(
                &failure,
                RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe()),
            ),
            RetryDecision::Retry {
                delay: Duration::from_secs(10),
                retry_delay: Duration::from_millis(100),
                recovery_wait: Duration::from_secs(10),
                reason: RetryReason::ReplaySafeBeforeCommit,
            }
        );
    }

    #[test]
    fn recovery_wait_does_not_consume_ordinary_retry_delay_budget() {
        let policy = RetryPolicy::with_bounds(
            3,
            3,
            3,
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .expect("valid independent retry bounds")
        .with_max_elapsed(None);
        let failure = ProviderFailureClassifier.classify(
            &ObservedFailure::new(FailureSource::Upstream, Some(503))
                .with_retry_after(Duration::from_millis(600)),
        );
        let first = policy.decide(
            &failure,
            RetryContext::new(1, CommitmentState::Uncommitted, ReplayCheck::safe()),
        );
        assert_eq!(
            first,
            RetryDecision::Retry {
                delay: Duration::from_millis(600),
                retry_delay: Duration::from_millis(100),
                recovery_wait: Duration::from_millis(600),
                reason: RetryReason::ReplaySafeBeforeCommit,
            }
        );

        assert_eq!(
            policy.decide(
                &failure,
                RetryContext::new(2, CommitmentState::Uncommitted, ReplayCheck::safe())
                    .with_elapsed_retry_delay(first.retry_delay())
                    .with_elapsed_recovery_wait(first.recovery_wait())
                    .with_elapsed(first.delay()),
            ),
            RetryDecision::Retry {
                delay: Duration::from_millis(600),
                retry_delay: Duration::from_millis(200),
                recovery_wait: Duration::from_millis(600),
                reason: RetryReason::ReplaySafeBeforeCommit,
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
