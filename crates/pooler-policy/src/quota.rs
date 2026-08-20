//! Provider-neutral quota observations and persistence records.
//!
//! Provider adapters are responsible for parsing their wire formats.  They
//! hand policy a bounded [`QuotaObservation`], which is classified without
//! retaining a response body or provider credential.  Runtime selection stores
//! monotonic [`QuotaSnapshot`] values; persistence uses Unix-millisecond DTOs
//! so an `Instant` never crosses a process boundary.

use std::fmt::{self, Write as _};
use std::time::{Duration, Instant};

use pooler_core::{
    CredentialId, ErrorClass, ErrorScope, ModelId, ProviderId, ReplaySafety, Retryability,
};
use ring::digest::{digest, SHA256};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    CooldownSpec, CredentialCausation, FailureClassification, PublicResponse, RedactedEvidence,
};

/// Current persistence representation for quota state.
pub const QUOTA_STATE_SCHEMA_VERSION: u8 = 2;

const DEFAULT_EXHAUSTION_RECOVERY: Duration = Duration::from_secs(60);
const DEFAULT_RATE_LIMIT_RECOVERY: Duration = Duration::from_secs(1);

/// The selection scope affected by a quota window.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaScope {
    /// One credential across its registered models.
    Credential,
    /// One credential/model pair.
    CredentialModel,
    /// Every credential associated with one upstream project.
    Project,
    /// One upstream project/model pair.
    ProjectModel,
    /// Every credential associated with one provider.
    Provider,
    /// One provider/model pair.
    ProviderModel,
}

/// Provider-neutral unit used by a quota window.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum QuotaUnit {
    /// Request count.
    #[default]
    Requests,
    /// Combined token count.
    Tokens,
    /// Input token count.
    InputTokens,
    /// Output token count.
    OutputTokens,
    /// Monetary or provider-defined credits.
    Credits,
    /// Provider-defined compute units.
    Compute,
}

/// Normalized state of one quota window.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaState {
    /// The provider did not supply enough data to establish availability.
    Unknown,
    /// The window currently permits selection.
    Available,
    /// The window prevents selection until its reset, if one is known.
    Exhausted,
}

/// A stable, redacted upstream project key.
///
/// Raw project, organization, tenant, and billing identifiers are hashed before
/// they enter policy state.  Accounts configured with the same raw value share
/// the same key and therefore the same project-scoped quota windows.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuotaProjectKey(String);

impl QuotaProjectKey {
    /// Hash one non-empty upstream project identifier.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, QuotaError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(QuotaError::EmptyProjectKey);
        }
        Ok(Self(digest_label("project", value)))
    }

    /// Restore a previously redacted key without hashing it again.
    pub fn from_redacted(value: impl Into<String>) -> Result<Self, QuotaError> {
        let mut value = value.into();
        if valid_digest_label("project", &value) {
            value.make_ascii_lowercase();
            Ok(Self(value))
        } else {
            Err(QuotaError::InvalidProjectKey)
        }
    }

    /// Return the bounded redacted value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for QuotaProjectKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for QuotaProjectKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_redacted(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Concrete owner of a quota window.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuotaSubject {
    /// One credential across models.
    Credential { credential: CredentialId },
    /// One credential/model pair.
    CredentialModel {
        credential: CredentialId,
        model: ModelId,
    },
    /// Every credential in one redacted upstream project.
    Project {
        provider: ProviderId,
        project: QuotaProjectKey,
    },
    /// One redacted upstream project/model pair.
    ProjectModel {
        provider: ProviderId,
        project: QuotaProjectKey,
        model: ModelId,
    },
    /// Every credential for one provider.
    Provider { provider: ProviderId },
    /// One provider/model pair.
    ProviderModel {
        provider: ProviderId,
        model: ModelId,
    },
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub(crate) struct QuotaCredentialKey(String);

impl QuotaCredentialKey {
    fn new(credential: &CredentialId) -> Self {
        Self(digest_label(
            "quota-credential",
            credential.as_str().as_bytes(),
        ))
    }

    pub(crate) fn matches(&self, credential: &CredentialId) -> bool {
        self == &Self::new(credential)
    }
}

impl fmt::Debug for QuotaCredentialKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuotaCredentialKey([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for QuotaCredentialKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = String::deserialize(deserializer)?;
        if !valid_digest_label("quota-credential", &value) {
            return Err(de::Error::custom("invalid quota credential key"));
        }
        value.make_ascii_lowercase();
        Ok(Self(value))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum QuotaPersistenceIdentity {
    Credential {
        credential: QuotaCredentialKey,
    },
    CredentialModel {
        credential: QuotaCredentialKey,
        model: ModelId,
    },
    Project {
        provider: ProviderId,
        project: QuotaProjectKey,
    },
    ProjectModel {
        provider: ProviderId,
        project: QuotaProjectKey,
        model: ModelId,
    },
    Provider {
        provider: ProviderId,
    },
    ProviderModel {
        provider: ProviderId,
        model: ModelId,
    },
}

impl QuotaPersistenceIdentity {
    const fn scope(&self) -> QuotaScope {
        match self {
            Self::Credential { .. } => QuotaScope::Credential,
            Self::CredentialModel { .. } => QuotaScope::CredentialModel,
            Self::Project { .. } => QuotaScope::Project,
            Self::ProjectModel { .. } => QuotaScope::ProjectModel,
            Self::Provider { .. } => QuotaScope::Provider,
            Self::ProviderModel { .. } => QuotaScope::ProviderModel,
        }
    }

    fn from_subject(subject: &QuotaSubject) -> Self {
        match subject {
            QuotaSubject::Credential { credential } => Self::Credential {
                credential: QuotaCredentialKey::new(credential),
            },
            QuotaSubject::CredentialModel { credential, model } => Self::CredentialModel {
                credential: QuotaCredentialKey::new(credential),
                model: model.clone(),
            },
            QuotaSubject::Project { provider, project } => Self::Project {
                provider: provider.clone(),
                project: project.clone(),
            },
            QuotaSubject::ProjectModel {
                provider,
                project,
                model,
            } => Self::ProjectModel {
                provider: provider.clone(),
                project: project.clone(),
                model: model.clone(),
            },
            QuotaSubject::Provider { provider } => Self::Provider {
                provider: provider.clone(),
            },
            QuotaSubject::ProviderModel { provider, model } => Self::ProviderModel {
                provider: provider.clone(),
                model: model.clone(),
            },
        }
    }
}

impl fmt::Debug for QuotaPersistenceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaPersistenceIdentity")
            .field("scope", &self.scope())
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

/// Monotonic runtime view of one quota window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaSnapshot {
    pub scope: QuotaScope,
    pub unit: QuotaUnit,
    pub state: QuotaState,
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at: Option<Instant>,
    pub observed_at: Instant,
}

impl QuotaSnapshot {
    /// Construct a provider-neutral snapshot.
    #[must_use]
    pub const fn new(
        scope: QuotaScope,
        unit: QuotaUnit,
        state: QuotaState,
        observed_at: Instant,
    ) -> Self {
        Self {
            scope,
            unit,
            state,
            limit: None,
            remaining: None,
            reset_at: None,
            observed_at,
        }
    }

    /// Construct an unrestricted compatibility snapshot.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(
            QuotaScope::Credential,
            QuotaUnit::Requests,
            QuotaState::Available,
            Instant::now(),
        )
    }

    /// Attach provider-advertised limit and remaining values.
    #[must_use]
    pub const fn with_window(mut self, limit: Option<u64>, remaining: Option<u64>) -> Self {
        self.limit = limit;
        self.remaining = remaining;
        self
    }

    /// Attach a monotonic reset deadline.
    #[must_use]
    pub const fn with_reset_at(mut self, reset_at: Option<Instant>) -> Self {
        self.reset_at = reset_at;
        self
    }

    /// Whether this window prevents a new selection at `now`.
    #[must_use]
    pub fn exhausted(self, now: Instant) -> bool {
        if self.reset_at.is_some_and(|reset_at| reset_at <= now) {
            return false;
        }
        self.state == QuotaState::Exhausted || self.remaining == Some(0)
    }

    /// Remaining time before the window resets.
    #[must_use]
    pub fn recovery_after(self, now: Instant) -> Option<Duration> {
        self.reset_at
            .filter(|reset_at| *reset_at > now)
            .map(|reset_at| reset_at.saturating_duration_since(now))
    }

    pub(crate) fn expired_at(self, now: Instant) -> bool {
        self.reset_at.is_some_and(|reset_at| reset_at <= now)
    }
}

/// A serializable quota record suitable for an existing generic state store.
///
/// The record contains no raw project identifier, provider body, or secret.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedQuotaSnapshot {
    pub schema_version: u8,
    identity: QuotaPersistenceIdentity,
    pub unit: QuotaUnit,
    pub state: QuotaState,
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at_unix_ms: Option<u64>,
    pub observed_at_unix_ms: u64,
}

impl PersistedQuotaSnapshot {
    /// Convert one runtime window using a paired monotonic/wall-clock anchor.
    #[must_use]
    pub(crate) fn from_runtime(
        subject: QuotaSubject,
        snapshot: QuotaSnapshot,
        now: Instant,
        now_unix_ms: u64,
    ) -> Self {
        let observed_age = now.saturating_duration_since(snapshot.observed_at);
        let observed_at_unix_ms = now_unix_ms.saturating_sub(duration_millis(observed_age));
        let reset_at_unix_ms = snapshot.reset_at.map(|reset_at| {
            now_unix_ms.saturating_add(duration_millis(reset_at.saturating_duration_since(now)))
        });
        Self {
            schema_version: QUOTA_STATE_SCHEMA_VERSION,
            identity: QuotaPersistenceIdentity::from_subject(&subject),
            unit: snapshot.unit,
            state: snapshot.state,
            limit: snapshot.limit,
            remaining: snapshot.remaining,
            reset_at_unix_ms,
            observed_at_unix_ms,
        }
    }

    /// Restore an unexpired runtime window from a wall-clock record.
    pub fn to_runtime(
        &self,
        now: Instant,
        now_unix_ms: u64,
    ) -> Result<Option<QuotaSnapshot>, QuotaError> {
        if self.schema_version != QUOTA_STATE_SCHEMA_VERSION {
            return Err(QuotaError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self
            .reset_at_unix_ms
            .is_some_and(|reset_at| reset_at <= now_unix_ms)
        {
            return Ok(None);
        }
        let observed_age =
            Duration::from_millis(now_unix_ms.saturating_sub(self.observed_at_unix_ms));
        let observed_at = now.checked_sub(observed_age).unwrap_or(now);
        let reset_at = self
            .reset_at_unix_ms
            .map(|reset_at| {
                now.checked_add(Duration::from_millis(reset_at.saturating_sub(now_unix_ms)))
                    .ok_or(QuotaError::DeadlineOutOfRange)
            })
            .transpose()?;
        Ok(Some(
            QuotaSnapshot::new(self.identity.scope(), self.unit, self.state, observed_at)
                .with_window(self.limit, self.remaining)
                .with_reset_at(reset_at),
        ))
    }

    /// Quota scope carried by the opaque persistence identity.
    #[must_use]
    pub const fn scope(&self) -> QuotaScope {
        self.identity.scope()
    }

    /// Absolute wall-clock reset used by persistence cleanup.
    #[must_use]
    pub const fn reset_at_unix_ms(&self) -> Option<u64> {
        self.reset_at_unix_ms
    }

    /// Wall-clock observation time used for monotonic restore ordering.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    pub(crate) const fn identity(&self) -> &QuotaPersistenceIdentity {
        &self.identity
    }
}

impl fmt::Debug for PersistedQuotaSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedQuotaSnapshot")
            .field("schema_version", &self.schema_version)
            .field("identity", &self.identity)
            .field("unit", &self.unit)
            .field("state", &self.state)
            .field("limit", &self.limit)
            .field("remaining", &self.remaining)
            .field("reset_at_unix_ms", &self.reset_at_unix_ms)
            .field("observed_at_unix_ms", &self.observed_at_unix_ms)
            .finish()
    }
}

/// Structured signal emitted by a provider adapter or quota poller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaSignal {
    /// An informational quota snapshot.
    Snapshot,
    /// A hard account, project, model, or provider allowance was exhausted.
    Exhausted,
    /// A bounded rate window rejected the request.
    RateLimited,
    /// A previous exhaustion was explicitly cleared.
    Recovered,
}

/// Bounded provider-neutral quota evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaObservation {
    pub signal: QuotaSignal,
    pub scope: QuotaScope,
    pub unit: QuotaUnit,
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub retry_after: Option<Duration>,
    pub reset_after: Option<Duration>,
    pub provider_code: Option<String>,
}

impl QuotaObservation {
    /// Construct one typed observation.
    #[must_use]
    pub const fn new(signal: QuotaSignal, scope: QuotaScope, unit: QuotaUnit) -> Self {
        Self {
            signal,
            scope,
            unit,
            limit: None,
            remaining: None,
            retry_after: None,
            reset_after: None,
            provider_code: None,
        }
    }

    /// Attach provider-advertised limit and remaining values.
    #[must_use]
    pub const fn with_window(mut self, limit: Option<u64>, remaining: Option<u64>) -> Self {
        self.limit = limit;
        self.remaining = remaining;
        self
    }

    /// Attach a delay before retrying the same target.
    #[must_use]
    pub const fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Attach the quota window's relative reset deadline.
    #[must_use]
    pub const fn with_reset_after(mut self, reset_after: Duration) -> Self {
        self.reset_after = Some(reset_after);
        self
    }

    /// Attach an already-redacted, bounded provider code.
    #[must_use]
    pub fn with_provider_code(mut self, provider_code: impl Into<String>) -> Self {
        self.provider_code = bounded_provider_code(provider_code.into());
        self
    }
}

/// Typed quota snapshot and optional request-failure classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaClassification {
    pub signal: QuotaSignal,
    pub snapshot: QuotaSnapshot,
    pub failure: Option<FailureClassification>,
}

impl QuotaClassification {
    /// Whether this observation should rotate away from the affected subject.
    #[must_use]
    pub fn exhausted(&self, now: Instant) -> bool {
        self.snapshot.exhausted(now)
    }

    /// Failure classification for rejected requests, when present.
    #[must_use]
    pub const fn failure(&self) -> Option<&FailureClassification> {
        self.failure.as_ref()
    }
}

/// Classifies already-parsed quota evidence.  It receives no mutable registry.
pub trait QuotaClassifier: Send + Sync {
    /// Normalize one observation at a caller-supplied monotonic instant.
    fn classify(&self, observation: &QuotaObservation, now: Instant) -> QuotaClassification;
}

/// Conservative provider-neutral quota classifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderNeutralQuotaClassifier {
    default_exhaustion_recovery: Duration,
    default_rate_limit_recovery: Duration,
}

impl Default for ProviderNeutralQuotaClassifier {
    fn default() -> Self {
        Self {
            default_exhaustion_recovery: DEFAULT_EXHAUSTION_RECOVERY,
            default_rate_limit_recovery: DEFAULT_RATE_LIMIT_RECOVERY,
        }
    }
}

impl ProviderNeutralQuotaClassifier {
    /// Construct with explicit fallbacks for providers that omit reset data.
    #[must_use]
    pub const fn new(
        default_exhaustion_recovery: Duration,
        default_rate_limit_recovery: Duration,
    ) -> Self {
        Self {
            default_exhaustion_recovery,
            default_rate_limit_recovery,
        }
    }
}

impl QuotaClassifier for ProviderNeutralQuotaClassifier {
    fn classify(&self, observation: &QuotaObservation, now: Instant) -> QuotaClassification {
        let signal =
            if observation.signal == QuotaSignal::Recovered && observation.remaining == Some(0) {
                QuotaSignal::Exhausted
            } else {
                observation.signal
            };
        let exhausted = matches!(signal, QuotaSignal::Exhausted | QuotaSignal::RateLimited)
            || (signal == QuotaSignal::Snapshot && observation.remaining == Some(0));
        let state = if signal == QuotaSignal::Recovered {
            QuotaState::Available
        } else if exhausted {
            QuotaState::Exhausted
        } else if observation.remaining.is_some() {
            QuotaState::Available
        } else {
            QuotaState::Unknown
        };
        let fallback = match signal {
            QuotaSignal::Exhausted => self.default_exhaustion_recovery,
            QuotaSignal::RateLimited => self.default_rate_limit_recovery,
            QuotaSignal::Snapshot | QuotaSignal::Recovered => Duration::ZERO,
        };
        let recovery = [observation.reset_after, observation.retry_after]
            .into_iter()
            .flatten()
            .max()
            .or((exhausted && !fallback.is_zero()).then_some(fallback));
        let reset_at = recovery.and_then(|delay| now.checked_add(delay));
        let snapshot = QuotaSnapshot::new(observation.scope, observation.unit, state, now)
            .with_window(observation.limit, observation.remaining)
            .with_reset_at(reset_at);
        let failure = exhausted.then(|| quota_failure(observation, recovery));
        QuotaClassification {
            signal,
            snapshot,
            failure,
        }
    }
}

/// Compatibility name for the shared typed quota classifier.
pub type QuotaFailureClassifier = ProviderNeutralQuotaClassifier;

/// Errors validating redacted quota state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QuotaError {
    /// A raw project identifier was empty.
    #[error("quota project key must not be empty")]
    EmptyProjectKey,
    /// A persisted project key was not a valid redacted digest.
    #[error("quota project key is invalid")]
    InvalidProjectKey,
    /// A persisted quota record used a newer representation.
    #[error("quota state schema version {0} is unsupported")]
    UnsupportedSchemaVersion(u8),
    /// A persisted reset deadline cannot be represented by the monotonic clock.
    #[error("quota reset deadline is outside the supported clock range")]
    DeadlineOutOfRange,
}

fn quota_failure(
    observation: &QuotaObservation,
    recovery: Option<Duration>,
) -> FailureClassification {
    let (class, error_scope, cooldown, causation, public_code, public_message) =
        match observation.scope {
            QuotaScope::Credential => (
                ErrorClass::CredentialQuotaExhausted,
                ErrorScope::Credential,
                recovery.map(CooldownSpec::credential),
                CredentialCausation::Proven,
                "credential_quota_exhausted",
                "credential quota is exhausted",
            ),
            QuotaScope::CredentialModel => (
                ErrorClass::ModelQuotaExhausted,
                ErrorScope::Credential,
                recovery.map(CooldownSpec::credential_model),
                CredentialCausation::Proven,
                "credential_model_quota_exhausted",
                "credential quota for the requested model is exhausted",
            ),
            QuotaScope::Project | QuotaScope::ProjectModel => (
                ErrorClass::CredentialQuotaExhausted,
                ErrorScope::Credential,
                None,
                CredentialCausation::Proven,
                "project_quota_exhausted",
                "upstream project quota is exhausted",
            ),
            QuotaScope::Provider => (
                ErrorClass::ProviderRateLimited,
                ErrorScope::Provider,
                recovery.map(CooldownSpec::provider),
                CredentialCausation::Unknown,
                "provider_rate_limited",
                "provider rate limited the request",
            ),
            QuotaScope::ProviderModel => (
                ErrorClass::ProviderRateLimited,
                ErrorScope::Provider,
                recovery.map(CooldownSpec::provider_model),
                CredentialCausation::Unknown,
                "provider_model_rate_limited",
                "provider rate limited the requested model",
            ),
        };
    let mut failure = FailureClassification::new(
        pooler_core::ErrorClassification::new(
            class,
            error_scope,
            Retryability::BeforeCommit,
            ReplaySafety::Replayable,
        ),
        PublicResponse::new(429, public_code, public_message),
        RedactedEvidence {
            status: Some(429),
            provider_code: observation.provider_code.clone(),
            summary: Some(public_code.to_owned()),
        },
    )
    .with_credential_causation(causation);
    if let Some(recovery) = recovery.filter(|delay| !delay.is_zero()) {
        failure = failure.with_recovery_after(recovery);
    }
    if let Some(cooldown) = cooldown.filter(|value| !value.duration.is_zero()) {
        failure = failure.with_cooldown(cooldown);
    }
    failure
}

fn bounded_provider_code(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-')))
    .then(|| value.to_ascii_lowercase())
}

fn duration_millis(duration: Duration) -> u64 {
    let whole = duration.as_secs().saturating_mul(1_000);
    let fractional = u64::from(duration.subsec_nanos()).div_ceil(1_000_000);
    whole.saturating_add(fractional)
}

fn digest_label(prefix: &str, value: &[u8]) -> String {
    let digest = digest(&SHA256, value);
    let mut label = String::with_capacity(prefix.len() + 1 + 32);
    label.push_str(prefix);
    label.push('-');
    for byte in digest.as_ref().iter().take(16) {
        write!(&mut label, "{byte:02x}").expect("writing to a String cannot fail");
    }
    label
}

fn valid_digest_label(prefix: &str, value: &str) -> bool {
    value.len() == prefix.len() + 1 + 32
        && value.starts_with(prefix)
        && value.as_bytes().get(prefix.len()) == Some(&b'-')
        && value[prefix.len() + 1..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_keys_are_redacted_and_round_trip() {
        let key = QuotaProjectKey::new("tenant-production").expect("project key");
        assert!(key.as_str().starts_with("project-"));
        assert!(!key.as_str().contains("tenant-production"));
        assert_eq!(
            QuotaProjectKey::from_redacted(key.as_str()).expect("restore key"),
            key
        );
    }

    #[test]
    fn typed_project_exhaustion_does_not_fabricate_a_credential_cooldown() {
        let now = Instant::now();
        let classification = ProviderNeutralQuotaClassifier::default().classify(
            &QuotaObservation::new(
                QuotaSignal::Exhausted,
                QuotaScope::Project,
                QuotaUnit::Credits,
            )
            .with_window(Some(1_000), Some(0))
            .with_reset_after(Duration::from_secs(300))
            .with_provider_code("billing_limit"),
            now,
        );
        assert!(classification.snapshot.exhausted(now));
        let failure = classification.failure().expect("failure");
        assert_eq!(
            failure.classification.class,
            ErrorClass::CredentialQuotaExhausted
        );
        assert_eq!(failure.classification.scope, ErrorScope::Credential);
        assert!(failure.cooldown.is_none());
        assert_eq!(
            failure.classification.recovery_after,
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn persistence_uses_wall_clock_deadlines_and_drops_expired_windows() {
        let now = Instant::now();
        let subject = QuotaSubject::Provider {
            provider: ProviderId::new("provider-a").expect("provider"),
        };
        let snapshot = QuotaSnapshot::new(
            QuotaScope::Provider,
            QuotaUnit::Requests,
            QuotaState::Exhausted,
            now,
        )
        .with_window(Some(100), Some(0))
        .with_reset_at(Some(now + Duration::from_secs(10)));
        let persisted = PersistedQuotaSnapshot::from_runtime(subject, snapshot, now, 1_000_000);
        let restored = persisted
            .to_runtime(now + Duration::from_secs(2), 1_002_000)
            .expect("restore")
            .expect("active");
        assert_eq!(
            restored.recovery_after(now + Duration::from_secs(2)),
            Some(Duration::from_secs(8))
        );
        assert!(persisted
            .to_runtime(now + Duration::from_secs(10), 1_010_000)
            .expect("expired record")
            .is_none());
    }

    #[test]
    fn retry_and_reset_hints_use_the_stricter_deadline() {
        let now = Instant::now();
        let classified = ProviderNeutralQuotaClassifier::default().classify(
            &QuotaObservation::new(
                QuotaSignal::RateLimited,
                QuotaScope::Provider,
                QuotaUnit::Requests,
            )
            .with_reset_after(Duration::from_secs(10))
            .with_retry_after(Duration::from_secs(20)),
            now,
        );
        assert_eq!(
            classified.snapshot.recovery_after(now),
            Some(Duration::from_secs(20))
        );
        assert_eq!(
            classified
                .failure()
                .expect("failure")
                .classification
                .recovery_after,
            Some(Duration::from_secs(20))
        );
    }

    #[test]
    fn persistence_rounds_active_sub_millisecond_windows_up() {
        let now = Instant::now();
        let snapshot = QuotaSnapshot::new(
            QuotaScope::Credential,
            QuotaUnit::Requests,
            QuotaState::Exhausted,
            now,
        )
        .with_reset_at(Some(now + Duration::from_nanos(1)));
        let record = PersistedQuotaSnapshot::from_runtime(
            QuotaSubject::Credential {
                credential: CredentialId::new("credential").expect("credential"),
            },
            snapshot,
            now,
            10,
        );
        assert_eq!(record.reset_at_unix_ms, Some(11));
    }
}
