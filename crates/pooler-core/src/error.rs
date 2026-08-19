//! Shared, redaction-friendly error and failure classification contracts.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::limits::LimitResource;

/// Broad failure classes used by classifiers and retry policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    DownstreamAuthentication,
    InvalidRequest,
    UnsupportedConversion,
    ProviderAuthentication,
    CredentialQuotaExhausted,
    ModelQuotaExhausted,
    ProviderRateLimited,
    ProviderUnavailable,
    Network,
    Timeout,
    InvalidUpstreamResponse,
    IncompleteStream,
    InternalInvariant,
    DownstreamDisconnected,
}

/// The state owner to which health or cooldown decisions may apply.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorScope {
    Downstream,
    Credential,
    Model,
    Provider,
    Route,
    Internal,
}

/// Retry boundary for one classified failure.
///
/// There is deliberately no variant that permits retry after downstream output
/// is committed. Retry policy must check the stream state separately.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retryability {
    /// Never retry this failure.
    #[default]
    Never,
    /// Retry only before downstream commitment and only if replay is safe.
    BeforeCommit,
}

/// Whether the request can be reproduced for another upstream attempt.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySafety {
    /// The body or operation cannot be replayed safely.
    #[default]
    NotReplayable,
    /// The request is retained and the operation is safe to repeat.
    Replayable,
    /// A configured idempotency key is required before repeating the operation.
    RequiresIdempotencyKey,
}

/// A classifier result. Classifiers describe failures; policy decides whether to
/// mutate health, wait, or attempt another target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErrorClassification {
    pub class: ErrorClass,
    pub scope: ErrorScope,
    pub retryability: Retryability,
    pub replay_safety: ReplaySafety,
    #[serde(with = "optional_duration_millis")]
    pub recovery_after: Option<Duration>,
}

impl ErrorClassification {
    /// Construct a classification without a recovery hint.
    #[must_use]
    pub const fn new(
        class: ErrorClass,
        scope: ErrorScope,
        retryability: Retryability,
        replay_safety: ReplaySafety,
    ) -> Self {
        Self {
            class,
            scope,
            retryability,
            replay_safety,
            recovery_after: None,
        }
    }

    /// Attach a provider-advertised recovery delay.
    #[must_use]
    pub const fn with_recovery_after(mut self, recovery_after: Duration) -> Self {
        self.recovery_after = Some(recovery_after);
        self
    }

    /// Whether the classification is eligible for a pre-commit replay.
    #[must_use]
    pub const fn can_retry_before_commit(self) -> bool {
        matches!(self.retryability, Retryability::BeforeCommit)
            && !matches!(self.replay_safety, ReplaySafety::NotReplayable)
    }
}

/// Errors returned by shared core contracts.
///
/// Messages supplied to constructors are expected to be already redacted. The
/// core error type has no credential or authorization-material fields and never
/// captures an upstream body implicitly.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PoolerError {
    #[error("invalid configuration: {message}")]
    InvalidConfiguration { message: String },
    #[error("invalid request: {message}")]
    InvalidRequest { message: String },
    #[error("unsupported conversion: {message}")]
    UnsupportedConversion { message: String },
    #[error("downstream authentication failed")]
    DownstreamAuthentication,
    #[error("provider authentication failed")]
    ProviderAuthentication,
    #[error("provider failure ({classification:?}): {message}")]
    Provider {
        classification: ErrorClassification,
        message: String,
    },
    #[error("network failure: {message}")]
    Network { message: String },
    #[error("timeout during {stage}")]
    Timeout { stage: String },
    #[error("invalid upstream response: {message}")]
    InvalidUpstreamResponse { message: String },
    #[error("incomplete upstream stream: {message}")]
    IncompleteStream { message: String },
    #[error("downstream disconnected")]
    DownstreamDisconnected,
    #[error("request cancelled")]
    Cancelled,
    #[error("{resource} limit exceeded: observed {observed}, limit {limit}")]
    LimitExceeded {
        resource: LimitResource,
        limit: u64,
        observed: u64,
    },
    #[error("internal invariant failed: {message}")]
    InternalInvariant { message: String },
}

/// The result type shared by Pooler libraries.
pub type PoolerResult<T> = Result<T, PoolerError>;

impl PoolerError {
    /// Construct an invalid-request error with caller-provided redacted context.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            message: message.into(),
        }
    }

    /// Construct an unsupported-conversion error.
    pub fn unsupported_conversion(message: impl Into<String>) -> Self {
        Self::UnsupportedConversion {
            message: message.into(),
        }
    }

    /// Construct a provider failure classification.
    pub fn provider(classification: ErrorClassification, message: impl Into<String>) -> Self {
        Self::Provider {
            classification,
            message: message.into(),
        }
    }

    /// Construct a network failure.
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
        }
    }

    /// Construct a timeout at a named stage.
    pub fn timeout(stage: impl Into<String>) -> Self {
        Self::Timeout {
            stage: stage.into(),
        }
    }

    /// Construct an internal invariant failure.
    pub fn invariant(message: impl Into<String>) -> Self {
        Self::InternalInvariant {
            message: message.into(),
        }
    }

    /// Classify this error for retry and health policy.
    #[must_use]
    pub fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidConfiguration { .. } => ErrorClassification::new(
                ErrorClass::InternalInvariant,
                ErrorScope::Internal,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::InvalidRequest { .. } => ErrorClassification::new(
                ErrorClass::InvalidRequest,
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::UnsupportedConversion { .. } => ErrorClassification::new(
                ErrorClass::UnsupportedConversion,
                ErrorScope::Route,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::DownstreamAuthentication => ErrorClassification::new(
                ErrorClass::DownstreamAuthentication,
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::ProviderAuthentication => ErrorClassification::new(
                ErrorClass::ProviderAuthentication,
                ErrorScope::Credential,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::Provider { classification, .. } => classification.clone(),
            Self::Network { .. } => ErrorClassification::new(
                ErrorClass::Network,
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
            ),
            Self::Timeout { .. } => ErrorClassification::new(
                ErrorClass::Timeout,
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
            ),
            Self::InvalidUpstreamResponse { .. } => ErrorClassification::new(
                ErrorClass::InvalidUpstreamResponse,
                ErrorScope::Provider,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::IncompleteStream { .. } => ErrorClassification::new(
                ErrorClass::IncompleteStream,
                ErrorScope::Provider,
                Retryability::BeforeCommit,
                ReplaySafety::Replayable,
            ),
            Self::DownstreamDisconnected => ErrorClassification::new(
                ErrorClass::DownstreamDisconnected,
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::Cancelled => ErrorClassification::new(
                ErrorClass::DownstreamDisconnected,
                ErrorScope::Downstream,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::LimitExceeded { .. } => ErrorClassification::new(
                ErrorClass::InvalidRequest,
                ErrorScope::Route,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
            Self::InternalInvariant { .. } => ErrorClassification::new(
                ErrorClass::InternalInvariant,
                ErrorScope::Internal,
                Retryability::Never,
                ReplaySafety::NotReplayable,
            ),
        }
    }

    /// Return only the broad class, without cloning a recovery hint.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        self.classification().class
    }

    /// Whether policy may consider a replay before downstream commitment.
    #[must_use]
    pub fn can_retry_before_commit(&self) -> bool {
        self.classification().can_retry_before_commit()
    }
}

mod optional_duration_millis {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .map(|duration| duration.as_millis() as u64)
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = Option::<u64>::deserialize(deserializer)?;
        Ok(millis.map(Duration::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn invalid_requests_never_retry_or_cool_credentials() {
        let error = PoolerError::invalid_request("missing model");
        assert_eq!(error.class(), ErrorClass::InvalidRequest);
        assert!(!error.can_retry_before_commit());
        assert_eq!(error.classification().scope, ErrorScope::Downstream);
    }

    #[test]
    fn network_failures_are_replayable_only_before_commit() {
        let error = PoolerError::network("connection refused");
        let classification = error.classification();
        assert_eq!(classification.retryability, Retryability::BeforeCommit);
        assert_eq!(classification.replay_safety, ReplaySafety::Replayable);
        assert!(error.can_retry_before_commit());
    }

    #[test]
    fn classifiers_can_carry_recovery_without_mutating_health() {
        let classification = ErrorClassification::new(
            ErrorClass::ProviderRateLimited,
            ErrorScope::Provider,
            Retryability::BeforeCommit,
            ReplaySafety::Replayable,
        )
        .with_recovery_after(Duration::from_secs(30));
        let error = PoolerError::provider(classification.clone(), "rate limited");
        assert_eq!(error.classification(), classification);
        let json = serde_json::to_value(error.classification()).expect("serialize class");
        assert_eq!(json["recovery_after"], 30_000);
    }
}
