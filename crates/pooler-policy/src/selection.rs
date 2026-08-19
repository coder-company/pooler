//! Deterministic credential registration and target selection.
//!
//! The registry owns only credential metadata and request accounting.  It
//! never stores authorization material.  Selection is deliberately performed
//! while holding one short write lock: a selection advances its strategy state
//! and reserves one in-flight slot as one operation, so concurrent callers
//! cannot make the same decision from stale counters.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use pooler_core::CapabilitySet;
use ring::digest::{digest, SHA256};

use crate::{
    AffinityDecision, CandidateExplanation, ConfigGeneration, CredentialHealth, CredentialId,
    CredentialPseudonym, CredentialStatus, FailureClassification, HealthRegistry, HealthSubject,
    ModelAliasResolution, ModelId, ProviderId, SelectionExplanation, SelectionTarget,
};

const DEFAULT_AFFINITY_TTL: Duration = Duration::from_secs(30 * 60);

/// A stable, redacted key used for session affinity.
///
/// The original key is never retained.  The digest is intentionally
/// deterministic so a decision record can be correlated across process
/// restarts without exposing a header, conversation ID, or prompt content.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AffinityKey(String);

impl AffinityKey {
    /// Hash one caller-provided affinity value into a bounded key.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, SelectionError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(SelectionError::EmptyAffinityKey);
        }
        Ok(Self(digest_label("session", value)))
    }

    /// Rehydrate a previously redacted key without hashing it again.
    pub fn from_redacted(value: impl Into<String>) -> Result<Self, SelectionError> {
        let value = value.into();
        let valid = value.len() == 40
            && value.starts_with("session-")
            && value[8..]
                .chars()
                .all(|character| character.is_ascii_hexdigit());
        if valid {
            Ok(Self(value))
        } else {
            Err(SelectionError::EmptyAffinityKey)
        }
    }

    /// Return the redacted value used in an explanation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Metadata for one provider credential and model target.
///
/// A registration contains no access token, refresh token, cookie, or secret
/// handle.  The credential identifier is retained only in the registry and is
/// replaced with a pseudonym in [`SelectionExplanation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRegistration {
    credential: CredentialId,
    provider: ProviderId,
    model: ModelId,
    capabilities: CapabilitySet,
    codecs: BTreeSet<String>,
    weight: u32,
    max_in_flight: Option<u32>,
}

impl CredentialRegistration {
    /// Construct a registration with a positive default weight.
    #[must_use]
    pub fn new(
        credential: CredentialId,
        provider: ProviderId,
        model: ModelId,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            credential,
            provider,
            model,
            capabilities,
            codecs: BTreeSet::new(),
            weight: 1,
            max_in_flight: None,
        }
    }

    /// Credential metadata with a string-friendly constructor.
    pub fn from_strings(
        credential: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        capabilities: CapabilitySet,
    ) -> Result<Self, SelectionError> {
        Ok(Self::new(
            CredentialId::new(credential.into()).map_err(SelectionError::InvalidIdentifier)?,
            ProviderId::new(provider.into()).map_err(SelectionError::InvalidIdentifier)?,
            ModelId::new(model.into()).map_err(SelectionError::InvalidIdentifier)?,
            capabilities,
        ))
    }

    /// Credential identifier, available only to the selection executor.
    #[must_use]
    pub fn credential(&self) -> &CredentialId {
        &self.credential
    }

    /// Provider identifier.
    #[must_use]
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Upstream model identifier.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.model
    }

    /// Advertised capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// Codec identifiers supported by this credential target.
    #[must_use]
    pub fn codecs(&self) -> &BTreeSet<String> {
        &self.codecs
    }

    /// Static selection weight.
    #[must_use]
    pub const fn weight(&self) -> u32 {
        self.weight
    }

    /// Optional maximum number of simultaneous requests.
    #[must_use]
    pub const fn max_in_flight(&self) -> Option<u32> {
        self.max_in_flight
    }

    /// Set a positive smooth-weight and health-weighted selection weight.
    pub fn with_weight(mut self, weight: u32) -> Result<Self, SelectionError> {
        if weight == 0 {
            return Err(SelectionError::ZeroWeight);
        }
        self.weight = weight;
        Ok(self)
    }

    /// Set a concurrency ceiling; zero is rejected as unusable.
    pub fn with_max_in_flight(mut self, max: u32) -> Result<Self, SelectionError> {
        if max == 0 {
            return Err(SelectionError::ZeroConcurrencyLimit);
        }
        self.max_in_flight = Some(max);
        Ok(self)
    }

    /// Add a codec identifier to the target.
    pub fn with_codec(mut self, codec: impl Into<String>) -> Result<Self, SelectionError> {
        let codec = codec.into();
        if codec.trim().is_empty() {
            return Err(SelectionError::EmptyCodec);
        }
        self.codecs.insert(codec);
        Ok(self)
    }

    /// Add several codec identifiers to the target.
    pub fn with_codecs<I, S>(mut self, codecs: I) -> Result<Self, SelectionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for codec in codecs {
            self = self.with_codec(codec)?;
        }
        Ok(self)
    }

    fn selection_target(&self) -> SelectionTarget {
        SelectionTarget::new(
            self.provider.clone(),
            self.model.clone(),
            CredentialPseudonym::new(pseudonym(self.credential.as_str())),
        )
    }
}

/// A bounded view of quota state used by diagnostics and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaSnapshot {
    pub remaining: Option<u64>,
    pub reset_at: Option<Instant>,
}

impl QuotaSnapshot {
    /// Unlimited quota.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            remaining: None,
            reset_at: None,
        }
    }

    /// Whether this state prevents a new request at `now`.
    #[must_use]
    pub fn exhausted(self, now: Instant) -> bool {
        matches!(self.remaining, Some(0)) && self.reset_at.map_or(true, |reset_at| reset_at > now)
    }
}

/// Strategy used after eligibility filters have run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SelectionStrategy {
    /// Select candidates in stable registration order, advancing a cursor.
    RoundRobin,
    /// Apply smooth weighted round-robin state per public model.
    SmoothWeightedRoundRobin,
    /// Select the first eligible registration.
    FillFirst,
    /// Select the candidate with the fewest in-flight requests.
    LeastInFlight,
    /// Select the highest static weight adjusted by in-flight load.
    #[default]
    HealthWeighted,
    /// Select the first eligible registration and preserve fallback order.
    OrderedFallback,
}

/// Request-local selection inputs.
#[derive(Clone, Debug)]
pub struct SelectionRequest {
    pub model: ModelId,
    /// Optional account allow-list supplied by a named or inline pool.
    /// `None` keeps the historical behavior of considering every registered
    /// account for the requested model.
    pub allowed_credentials: Option<BTreeSet<CredentialId>>,
    pub required_capabilities: CapabilitySet,
    pub codec: Option<String>,
    pub strategy: SelectionStrategy,
    pub affinity_key: Option<AffinityKey>,
    pub affinity_ttl: Duration,
    pub affinity_rebind: bool,
    pub route: Option<crate::RouteId>,
    pub attempt: u32,
    pub configuration_generation: ConfigGeneration,
    pub now: Instant,
}

impl SelectionRequest {
    /// Begin a request for one public model.
    #[must_use]
    pub fn new(model: ModelId) -> Self {
        Self {
            model,
            allowed_credentials: None,
            required_capabilities: CapabilitySet::new(),
            codec: None,
            strategy: SelectionStrategy::default(),
            affinity_key: None,
            affinity_ttl: DEFAULT_AFFINITY_TTL,
            affinity_rebind: true,
            route: None,
            attempt: 1,
            configuration_generation: ConfigGeneration::INITIAL,
            now: Instant::now(),
        }
    }

    /// Restrict selection to one explicit account pool.
    #[must_use]
    pub fn with_allowed_credentials(
        mut self,
        credentials: impl IntoIterator<Item = CredentialId>,
    ) -> Self {
        self.allowed_credentials = Some(credentials.into_iter().collect());
        self
    }

    /// Set required capabilities.
    #[must_use]
    pub const fn with_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.required_capabilities = capabilities;
        self
    }

    /// Require one codec identifier.
    pub fn with_codec(mut self, codec: impl Into<String>) -> Result<Self, SelectionError> {
        let codec = codec.into();
        if codec.trim().is_empty() {
            return Err(SelectionError::EmptyCodec);
        }
        self.codec = Some(codec);
        Ok(self)
    }

    /// Select with one strategy.
    #[must_use]
    pub const fn with_strategy(mut self, strategy: SelectionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Derive and attach a session affinity key.
    pub fn with_affinity_key(
        mut self,
        key: impl AsRef<[u8]>,
        ttl: Duration,
    ) -> Result<Self, SelectionError> {
        if ttl.is_zero() {
            return Err(SelectionError::ZeroAffinityTtl);
        }
        self.affinity_key = Some(AffinityKey::new(key)?);
        self.affinity_ttl = ttl;
        Ok(self)
    }

    /// Attach a pre-hashed affinity key.
    pub fn with_hashed_affinity_key(
        mut self,
        key: AffinityKey,
        ttl: Duration,
    ) -> Result<Self, SelectionError> {
        if ttl.is_zero() {
            return Err(SelectionError::ZeroAffinityTtl);
        }
        self.affinity_key = Some(key);
        self.affinity_ttl = ttl;
        Ok(self)
    }

    /// Allow or reject rebinding when the affinity target is unavailable.
    #[must_use]
    pub const fn with_affinity_rebind(mut self, rebind: bool) -> Self {
        self.affinity_rebind = rebind;
        self
    }

    /// Set route context used by health cooldown scopes.
    #[must_use]
    pub fn with_route(mut self, route: crate::RouteId) -> Self {
        self.route = Some(route);
        self
    }

    /// Set attempt number in the explainable decision record.
    #[must_use]
    pub const fn with_attempt(mut self, attempt: u32) -> Self {
        self.attempt = attempt;
        self
    }

    /// Set configuration generation in the explainable decision record.
    #[must_use]
    pub const fn with_generation(mut self, generation: ConfigGeneration) -> Self {
        self.configuration_generation = generation;
        self
    }

    /// Set the clock used for health, quota, and affinity expiry.
    #[must_use]
    pub const fn at(mut self, now: Instant) -> Self {
        self.now = now;
        self
    }
}

/// Failure returned when no target can satisfy a selection request.
#[derive(Debug, PartialEq)]
pub enum SelectionError {
    EmptyAffinityKey,
    EmptyCodec,
    ZeroAffinityTtl,
    ZeroWeight,
    ZeroConcurrencyLimit,
    ModelAliasCycle,
    InvalidIdentifier(pooler_core::IdentifierError),
    LockPoisoned,
    NoEligible {
        model: ModelId,
        explanation: Box<SelectionExplanation>,
    },
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAffinityKey => formatter.write_str("affinity key must not be empty"),
            Self::EmptyCodec => formatter.write_str("codec identifier must not be empty"),
            Self::ZeroAffinityTtl => formatter.write_str("affinity TTL must be greater than zero"),
            Self::ZeroWeight => formatter.write_str("selection weight must be greater than zero"),
            Self::ZeroConcurrencyLimit => {
                formatter.write_str("concurrency limit must be greater than zero")
            }
            Self::ModelAliasCycle => formatter.write_str("model aliases must not contain a cycle"),
            Self::InvalidIdentifier(error) => {
                write!(formatter, "invalid credential identifier: {error}")
            }
            Self::LockPoisoned => formatter.write_str("credential registry lock poisoned"),
            Self::NoEligible { model, .. } => {
                write!(
                    formatter,
                    "no eligible credential target for model `{model}`"
                )
            }
        }
    }
}

impl std::error::Error for SelectionError {}

/// A reservation that keeps one selected credential's in-flight slot held.
///
/// The reservation is separate from the metadata and explanation so a runtime
/// can move the latter into an attempt record without accidentally releasing
/// the slot before the upstream operation finishes.
#[derive(Debug)]
pub struct SelectionReservation {
    credential: CredentialId,
    inner: Arc<RegistryInner>,
}

impl Drop for SelectionReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.write() {
            if let Some(entry) = state.entries.get_mut(&self.credential) {
                entry.in_flight = entry.in_flight.saturating_sub(1);
            }
        }
    }
}

/// A successful target selection that owns one in-flight reservation.
#[derive(Debug)]
pub struct SelectionLease {
    registration: CredentialRegistration,
    explanation: SelectionExplanation,
    reservation: Option<SelectionReservation>,
}

impl SelectionLease {
    /// Return the selected metadata.
    #[must_use]
    pub const fn registration(&self) -> &CredentialRegistration {
        &self.registration
    }

    /// Return the full redacted explanation.
    #[must_use]
    pub const fn explanation(&self) -> &SelectionExplanation {
        &self.explanation
    }

    /// Return the selected credential ID for the credential-bearing executor.
    #[must_use]
    pub fn credential_id(&self) -> &CredentialId {
        &self
            .reservation
            .as_ref()
            .expect("selection lease reservation is present")
            .credential
    }

    /// Consume the lease and split its metadata from its reservation.
    ///
    /// The returned [`SelectionReservation`] must be held until the upstream
    /// operation finishes. Dropping it releases the in-flight slot.
    #[must_use]
    pub fn into_parts(
        mut self,
    ) -> (
        CredentialRegistration,
        SelectionExplanation,
        SelectionReservation,
    ) {
        let reservation = self
            .reservation
            .take()
            .expect("selection lease reservation is present");
        (
            self.registration.clone(),
            self.explanation.clone(),
            reservation,
        )
    }
}

#[derive(Clone, Debug)]
struct AffinityBinding {
    credential: CredentialId,
    provider: ProviderId,
    model: ModelId,
    last_used_at: Instant,
    expires_at: Instant,
}

impl AffinityBinding {
    fn expired_at(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

#[derive(Clone, Debug)]
struct RegistryEntry {
    registration: CredentialRegistration,
    enabled: bool,
    in_flight: u32,
    quota: QuotaSnapshot,
    order: u64,
}

#[derive(Debug, Default)]
struct RegistryState {
    entries: BTreeMap<CredentialId, RegistryEntry>,
    aliases: BTreeMap<ModelId, ModelId>,
    next_order: u64,
    round_robin: BTreeMap<ModelId, usize>,
    smooth_current: BTreeMap<ModelId, BTreeMap<CredentialId, i64>>,
    affinity: BTreeMap<AffinityKey, AffinityBinding>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    state: RwLock<RegistryState>,
    health: RwLock<HealthRegistry>,
}

/// Thread-safe credential registry and deterministic selection engine.
#[derive(Clone, Debug, Default)]
pub struct CredentialRegistry {
    inner: Arc<RegistryInner>,
}

impl CredentialRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace metadata. Replacement preserves registration order
    /// so a reload cannot unexpectedly reorder ordered fallback.
    pub fn register(&self, registration: CredentialRegistration) -> Result<(), SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        let id = registration.credential.clone();
        let order = if let Some(entry) = state.entries.get(&id) {
            entry.order
        } else {
            let order = state.next_order;
            state.next_order = state.next_order.saturating_add(1);
            order
        };
        let enabled = state.entries.get(&id).is_none_or(|entry| entry.enabled);
        let in_flight = state.entries.get(&id).map_or(0, |entry| entry.in_flight);
        let quota = state
            .entries
            .get(&id)
            .map_or(QuotaSnapshot::unlimited(), |entry| entry.quota);
        state.entries.insert(
            id,
            RegistryEntry {
                registration,
                enabled,
                in_flight,
                quota,
                order,
            },
        );
        Ok(())
    }

    /// Remove one registration. Existing leases retain their metadata and
    /// release their reservation without resurrecting the removed entry.
    pub fn unregister(&self, credential: &CredentialId) -> Result<bool, SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        Ok(state.entries.remove(credential).is_some())
    }

    /// List registrations in stable declaration order.
    pub fn registrations(&self) -> Result<Vec<CredentialRegistration>, SelectionError> {
        let state = self.inner.state.read().map_err(lock_error)?;
        Ok(sorted_entries(&state)
            .into_iter()
            .map(|entry| entry.registration.clone())
            .collect())
    }

    /// Register a public model alias. Alias chains are allowed, but cycles are
    /// rejected before they can affect a request.
    pub fn register_model_alias(
        &self,
        alias: ModelId,
        resolved: ModelId,
    ) -> Result<(), SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        let previous = state.aliases.insert(alias.clone(), resolved);
        if resolve_alias(&state.aliases, &alias).is_none() {
            if let Some(previous) = previous {
                state.aliases.insert(alias, previous);
            } else {
                state.aliases.remove(&alias);
            }
            return Err(SelectionError::ModelAliasCycle);
        }
        Ok(())
    }

    /// Resolve one public model ID using the current alias table.
    pub fn resolve_model(&self, model: &ModelId) -> Result<ModelId, SelectionError> {
        let state = self.inner.state.read().map_err(lock_error)?;
        Ok(resolve_alias(&state.aliases, model).unwrap_or_else(|| model.clone()))
    }

    /// Enable or disable a credential without deleting its metadata.
    pub fn set_enabled(
        &self,
        credential: &CredentialId,
        enabled: bool,
    ) -> Result<bool, SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        let Some(entry) = state.entries.get_mut(credential) else {
            return Ok(false);
        };
        entry.enabled = enabled;
        Ok(true)
    }

    /// Mark a credential disabled in both registry and health state.
    pub fn disable(&self, credential: CredentialId) -> Result<bool, SelectionError> {
        let changed = self.set_enabled(&credential, false)?;
        let mut health = self.inner.health.write().map_err(lock_error)?;
        health.disable_credential(credential);
        Ok(changed)
    }

    /// Enable a credential and clear its explicit disabled health state.
    pub fn enable(&self, credential: &CredentialId) -> Result<bool, SelectionError> {
        let changed = self.set_enabled(credential, true)?;
        let mut health = self.inner.health.write().map_err(lock_error)?;
        health.enable_credential(credential.clone());
        Ok(changed)
    }

    /// Set the remaining quota and optional recovery instant.
    pub fn set_quota(
        &self,
        credential: &CredentialId,
        remaining: Option<u64>,
        reset_at: Option<Instant>,
    ) -> Result<bool, SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        let Some(entry) = state.entries.get_mut(credential) else {
            return Ok(false);
        };
        entry.quota = QuotaSnapshot {
            remaining,
            reset_at,
        };
        Ok(true)
    }

    /// Record a quota failure and make a target ineligible until recovery.
    pub fn mark_quota_exhausted(
        &self,
        credential: &CredentialId,
        reset_at: Option<Instant>,
    ) -> Result<bool, SelectionError> {
        self.set_quota(credential, Some(0), reset_at)
    }

    /// Read current quota state.
    pub fn quota(
        &self,
        credential: &CredentialId,
    ) -> Result<Option<QuotaSnapshot>, SelectionError> {
        let state = self.inner.state.read().map_err(lock_error)?;
        Ok(state.entries.get(credential).map(|entry| entry.quota))
    }

    /// Number of requests currently reserved for one credential.
    pub fn in_flight(&self, credential: &CredentialId) -> Result<Option<u32>, SelectionError> {
        let state = self.inner.state.read().map_err(lock_error)?;
        Ok(state.entries.get(credential).map(|entry| entry.in_flight))
    }

    /// Apply a classified failure to the registry-owned health state.
    pub fn apply_failure(
        &self,
        failure: &FailureClassification,
        subject: &HealthSubject,
        now: Instant,
    ) -> Result<crate::HealthMutation, SelectionError> {
        let mut health = self.inner.health.write().map_err(lock_error)?;
        Ok(health.apply_failure(failure, subject, now))
    }

    /// Restore a persisted cooldown into this registry's health snapshot.
    pub fn restore_cooldown(
        &self,
        scope: crate::CooldownScope,
        until: Instant,
    ) -> Result<(), SelectionError> {
        let mut health = self.inner.health.write().map_err(lock_error)?;
        health.restore_cooldown(scope, until);
        Ok(())
    }

    /// Restore a persisted affinity binding for a registered target.
    pub fn restore_affinity(
        &self,
        key: AffinityKey,
        credential: CredentialId,
        provider: ProviderId,
        model: ModelId,
        last_used_at: Instant,
        expires_at: Instant,
    ) -> Result<(), SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        if !state.entries.contains_key(&credential) {
            return Ok(());
        }
        state.affinity.insert(
            key,
            AffinityBinding {
                credential,
                provider,
                model,
                last_used_at,
                expires_at,
            },
        );
        Ok(())
    }

    /// Take a cheap clone of one credential's health state.
    pub fn health(
        &self,
        credential: &CredentialId,
    ) -> Result<Option<CredentialHealth>, SelectionError> {
        let health = self.inner.health.read().map_err(lock_error)?;
        Ok(health.credential_health(credential).cloned())
    }

    /// Select one target using the registry's health state.
    pub fn select(&self, request: SelectionRequest) -> Result<SelectionLease, SelectionError> {
        let health = self.inner.health.read().map_err(lock_error)?.clone();
        self.select_with_health(request, &health)
    }

    /// Select one target using a caller-provided health snapshot.
    ///
    /// This method is useful for deterministic tests and for runtimes that
    /// share health state across several registries. The registry still owns
    /// in-flight, quota, strategy, and affinity mutation.
    pub fn select_with_health(
        &self,
        request: SelectionRequest,
        health: &HealthRegistry,
    ) -> Result<SelectionLease, SelectionError> {
        if request.affinity_ttl.is_zero() {
            return Err(SelectionError::ZeroAffinityTtl);
        }
        let mut state = self.inner.state.write().map_err(lock_error)?;
        purge_expired_affinity(&mut state, request.now);
        recover_quotas(&mut state, request.now);

        let requested_model = request.model.clone();
        let resolved_model = resolve_alias(&state.aliases, &requested_model)
            .unwrap_or_else(|| requested_model.clone());
        let resolved_request = SelectionRequest {
            model: resolved_model.clone(),
            ..request.clone()
        };
        let evaluations = evaluate_candidates(&state, health, &resolved_request);
        let model = requested_model.clone();
        let model_resolution = if resolved_model == requested_model {
            ModelAliasResolution::exact(requested_model)
        } else {
            ModelAliasResolution::alias(requested_model, resolved_model)
        };
        let mut explanation = SelectionExplanation::new(
            model_resolution,
            request.attempt,
            request.configuration_generation,
        );
        for evaluation in &evaluations {
            let target = evaluation.entry.registration.selection_target();
            if evaluation.reasons.is_empty() {
                explanation.push_candidate(CandidateExplanation::eligible(
                    target,
                    evaluation.score(request.strategy),
                ));
            } else {
                explanation.push_candidate(CandidateExplanation {
                    target,
                    score: None,
                    filter_reasons: evaluation.reasons.clone(),
                });
            }
        }

        let eligible: Vec<_> = evaluations
            .iter()
            .enumerate()
            .filter(|(_, evaluation)| evaluation.reasons.is_empty())
            .map(|(index, _)| index)
            .collect();
        if eligible.is_empty() {
            return Err(SelectionError::NoEligible {
                model,
                explanation: Box::new(explanation),
            });
        }

        let mut selected_index = None;
        let mut rebound_provider = None;
        if let Some(key) = request.affinity_key.as_ref() {
            let binding = state.affinity.get(key).cloned();
            if let Some(binding) = binding {
                let matching = eligible.iter().copied().find(|index| {
                    let entry = &evaluations[*index].entry;
                    entry.registration.credential == binding.credential
                        && entry.registration.provider == binding.provider
                        && entry.registration.model == binding.model
                });
                if let Some(index) = matching {
                    if let Some(binding) = state.affinity.get_mut(key) {
                        binding.last_used_at = request.now;
                        binding.expires_at = request
                            .now
                            .checked_add(request.affinity_ttl)
                            .unwrap_or(request.now);
                    }
                    selected_index = Some(index);
                    explanation.set_affinity(AffinityDecision::Matched {
                        key_pseudonym: key.as_str().to_owned(),
                        target: evaluations[index].entry.registration.selection_target(),
                    });
                } else {
                    if !request.affinity_rebind {
                        explanation.set_affinity(AffinityDecision::Unavailable {
                            key_pseudonym: key.as_str().to_owned(),
                            target: SelectionTarget::new(
                                binding.provider,
                                binding.model,
                                CredentialPseudonym::new(pseudonym(binding.credential.as_str())),
                            ),
                        });
                        return Err(SelectionError::NoEligible {
                            model,
                            explanation: Box::new(explanation),
                        });
                    }
                    rebound_provider = Some(binding.provider.clone());
                }
            } else {
                explanation.set_affinity(AffinityDecision::NoMatch {
                    key_pseudonym: key.as_str().to_owned(),
                });
            }
        }
        let index = if let Some(index) = selected_index {
            index
        } else {
            choose_index(&mut state, &evaluations, &eligible, &resolved_request)
        };
        let selected = &evaluations[index];
        let credential = selected.entry.registration.credential.clone();
        if let Some(entry) = state.entries.get_mut(&credential) {
            entry.in_flight = entry.in_flight.saturating_add(1);
        }
        let registration = selected.entry.registration.clone();
        let target = registration.selection_target();
        explanation.set_selected(target, Some(selected.score(request.strategy)));

        if let Some(key) = request.affinity_key {
            if let Some(previous_provider) = rebound_provider {
                explanation.set_affinity(AffinityDecision::Rebound {
                    key_pseudonym: key.as_str().to_owned(),
                    previous_provider,
                    target: registration.selection_target(),
                });
            }
            let expires_at = request
                .now
                .checked_add(request.affinity_ttl)
                .unwrap_or(request.now);
            state.affinity.insert(
                key,
                AffinityBinding {
                    credential: registration.credential.clone(),
                    provider: registration.provider.clone(),
                    model: registration.model.clone(),
                    last_used_at: request.now,
                    expires_at,
                },
            );
        }

        Ok(SelectionLease {
            registration,
            explanation,
            reservation: Some(SelectionReservation {
                credential,
                inner: Arc::clone(&self.inner),
            }),
        })
    }

    /// Number of active affinity bindings after expiry cleanup.
    pub fn affinity_len(&self, now: Instant) -> Result<usize, SelectionError> {
        let mut state = self.inner.state.write().map_err(lock_error)?;
        purge_expired_affinity(&mut state, now);
        Ok(state.affinity.len())
    }
}

#[derive(Clone, Debug)]
struct CandidateEvaluation {
    entry: RegistryEntry,
    reasons: Vec<crate::FilterReason>,
}

impl CandidateEvaluation {
    fn score(&self, strategy: SelectionStrategy) -> f64 {
        match strategy {
            SelectionStrategy::HealthWeighted => {
                self.entry.registration.weight as f64
                    / f64::from(self.entry.in_flight.saturating_add(1))
            }
            SelectionStrategy::SmoothWeightedRoundRobin => self.entry.registration.weight as f64,
            SelectionStrategy::LeastInFlight => {
                1.0 / f64::from(self.entry.in_flight.saturating_add(1))
            }
            SelectionStrategy::RoundRobin
            | SelectionStrategy::FillFirst
            | SelectionStrategy::OrderedFallback => 0.0,
        }
    }
}

fn evaluate_candidates(
    state: &RegistryState,
    health: &HealthRegistry,
    request: &SelectionRequest,
) -> Vec<CandidateEvaluation> {
    let mut entries = sorted_entries(state);
    entries.sort_by_key(|entry| entry.order);
    entries
        .into_iter()
        .map(|entry| {
            let mut reasons = Vec::new();
            let registration = &entry.registration;
            if request
                .allowed_credentials
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&registration.credential))
            {
                reasons.push(crate::FilterReason::RoutePolicy);
            }
            if registration.model != request.model {
                reasons.push(crate::FilterReason::ModelMismatch);
            }
            for capability in request
                .required_capabilities
                .difference(registration.capabilities)
                .iter()
            {
                reasons.push(crate::FilterReason::MissingCapability(
                    capability.as_str().to_owned(),
                ));
            }
            if let Some(codec) = request.codec.as_deref() {
                if !registration.codecs.contains(codec) {
                    reasons.push(crate::FilterReason::CodecUnavailable(codec.to_owned()));
                }
            }
            if !entry.enabled {
                reasons.push(crate::FilterReason::CredentialUnavailable);
            }
            let subject = HealthSubject {
                credential: Some(registration.credential.clone()),
                model: Some(registration.model.clone()),
                provider: Some(registration.provider.clone()),
                route: request.route.clone(),
            };
            if health
                .credential_health(&registration.credential)
                .is_some_and(|state| state.status == CredentialStatus::Disabled)
            {
                reasons.push(crate::FilterReason::Disabled);
            } else {
                reasons.extend(
                    health
                        .target_cooldown_scopes(&subject, request.now)
                        .into_iter()
                        .map(cooldown_filter_reason),
                );
            }
            if entry
                .registration
                .max_in_flight()
                .is_some_and(|limit| entry.in_flight >= limit)
            {
                reasons.push(crate::FilterReason::ConcurrencyLimit);
            }
            if entry.quota.exhausted(request.now) {
                reasons.push(crate::FilterReason::QuotaExhausted);
            }
            CandidateEvaluation {
                entry: entry.clone(),
                reasons,
            }
        })
        .collect()
}

fn cooldown_filter_reason(kind: crate::CooldownScopeKind) -> crate::FilterReason {
    match kind {
        crate::CooldownScopeKind::Credential => crate::FilterReason::CredentialCooldown,
        crate::CooldownScopeKind::CredentialModel => crate::FilterReason::CredentialModelCooldown,
        crate::CooldownScopeKind::Model => crate::FilterReason::ModelCooldown,
        crate::CooldownScopeKind::Provider => crate::FilterReason::ProviderCooldown,
        crate::CooldownScopeKind::ProviderModel => crate::FilterReason::ProviderModelCooldown,
        crate::CooldownScopeKind::Route => crate::FilterReason::RouteCooldown,
    }
}

fn choose_index(
    state: &mut RegistryState,
    evaluations: &[CandidateEvaluation],
    eligible: &[usize],
    request: &SelectionRequest,
) -> usize {
    match request.strategy {
        SelectionStrategy::RoundRobin => {
            let cursor = state.round_robin.entry(request.model.clone()).or_default();
            let index = eligible[*cursor % eligible.len()];
            *cursor = cursor.saturating_add(1);
            index
        }
        SelectionStrategy::SmoothWeightedRoundRobin => {
            let current = state
                .smooth_current
                .entry(request.model.clone())
                .or_default();
            let mut total = 0_i64;
            for index in eligible {
                let entry = &evaluations[*index].entry;
                let weight = i64::from(entry.registration.weight);
                total = total.saturating_add(weight);
                let value = current
                    .entry(entry.registration.credential.clone())
                    .or_default();
                *value = value.saturating_add(weight);
            }
            let selected = eligible
                .iter()
                .copied()
                .max_by(|left, right| {
                    let left_entry = &evaluations[*left].entry;
                    let right_entry = &evaluations[*right].entry;
                    current
                        .get(&left_entry.registration.credential)
                        .cmp(&current.get(&right_entry.registration.credential))
                        .then_with(|| right_entry.order.cmp(&left_entry.order))
                })
                .expect("eligible candidates are non-empty");
            let credential = evaluations[selected].entry.registration.credential.clone();
            if let Some(value) = current.get_mut(&credential) {
                *value = value.saturating_sub(total);
            }
            selected
        }
        SelectionStrategy::FillFirst | SelectionStrategy::OrderedFallback => eligible[0],
        SelectionStrategy::LeastInFlight => eligible
            .iter()
            .copied()
            .min_by(|left, right| {
                let left_entry = &evaluations[*left].entry;
                let right_entry = &evaluations[*right].entry;
                left_entry
                    .in_flight
                    .cmp(&right_entry.in_flight)
                    .then_with(|| left_entry.order.cmp(&right_entry.order))
                    .then_with(|| {
                        left_entry
                            .registration
                            .credential
                            .cmp(&right_entry.registration.credential)
                    })
            })
            .expect("eligible candidates are non-empty"),
        SelectionStrategy::HealthWeighted => eligible
            .iter()
            .copied()
            .max_by(|left, right| {
                let left_entry = &evaluations[*left].entry;
                let right_entry = &evaluations[*right].entry;
                let left_score = u64::from(left_entry.registration.weight)
                    .saturating_mul(u64::from(right_entry.in_flight.saturating_add(1)));
                let right_score = u64::from(right_entry.registration.weight)
                    .saturating_mul(u64::from(left_entry.in_flight.saturating_add(1)));
                left_score
                    .cmp(&right_score)
                    .then_with(|| right_entry.order.cmp(&left_entry.order))
                    .then_with(|| {
                        right_entry
                            .registration
                            .credential
                            .cmp(&left_entry.registration.credential)
                    })
            })
            .expect("eligible candidates are non-empty"),
    }
}

fn sorted_entries(state: &RegistryState) -> Vec<&RegistryEntry> {
    let mut entries: Vec<_> = state.entries.values().collect();
    entries.sort_by(|left, right| {
        left.order.cmp(&right.order).then_with(|| {
            left.registration
                .credential
                .cmp(&right.registration.credential)
        })
    });
    entries
}

fn resolve_alias(aliases: &BTreeMap<ModelId, ModelId>, model: &ModelId) -> Option<ModelId> {
    let mut current = model.clone();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return None;
        }
        let Some(next) = aliases.get(&current) else {
            return Some(current);
        };
        current = next.clone();
    }
}

fn purge_expired_affinity(state: &mut RegistryState, now: Instant) {
    state.affinity.retain(|_, binding| !binding.expired_at(now));
}

fn recover_quotas(state: &mut RegistryState, now: Instant) {
    for entry in state.entries.values_mut() {
        if entry.quota.reset_at.is_some_and(|reset_at| reset_at <= now) {
            entry.quota = QuotaSnapshot::unlimited();
        }
    }
}

fn pseudonym(value: &str) -> String {
    digest_label("cred", value.as_bytes())
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

fn lock_error<T>(_: PoisonError<T>) -> SelectionError {
    SelectionError::LockPoisoned
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use pooler_core::Capability;

    use super::*;
    use crate::FailureClassifier;

    fn ids(credential: &str, provider: &str, model: &str) -> CredentialRegistration {
        CredentialRegistration::from_strings(
            credential,
            provider,
            model,
            CapabilitySet::from_iter([Capability::Text, Capability::Tools]),
        )
        .expect("valid registration")
    }

    fn request(model: &str, now: Instant) -> SelectionRequest {
        SelectionRequest::new(ModelId::new(model).expect("model"))
            .with_capabilities(CapabilitySet::from(Capability::Text))
            .with_strategy(SelectionStrategy::RoundRobin)
            .at(now)
    }

    #[test]
    fn affinity_and_credential_labels_use_bounded_digest_values() {
        let key = AffinityKey::new("conversation-1").expect("non-empty key");
        let other = AffinityKey::new("conversation-2").expect("non-empty key");
        assert_eq!(key.as_str().len(), "session-".len() + 32);
        assert!(key.as_str().starts_with("session-"));
        assert_ne!(key, other);
        assert!(!key.as_str().contains("conversation-1"));

        let registration = ids("credential-a", "provider-a", "model");
        let target = registration.selection_target();
        assert_eq!(
            target.credential_pseudonym.as_str().len(),
            "cred-".len() + 32
        );
        assert!(!target
            .credential_pseudonym
            .as_str()
            .contains("credential-a"));
    }

    #[test]
    fn round_robin_is_stable_and_reserves_until_drop() {
        let registry = CredentialRegistry::new();
        registry
            .register(ids("a", "provider-a", "model"))
            .expect("register");
        registry
            .register(ids("b", "provider-b", "model"))
            .expect("register");
        let now = Instant::now();
        let first = registry.select(request("model", now)).expect("select");
        assert_eq!(first.registration().credential().as_str(), "a");
        assert_eq!(
            registry.in_flight(&CredentialId::new("a").unwrap()),
            Ok(Some(1))
        );
        drop(first);
        let second = registry.select(request("model", now)).expect("select");
        assert_eq!(second.registration().credential().as_str(), "b");
    }

    #[test]
    fn splitting_a_lease_keeps_the_reservation_until_the_guard_is_dropped() {
        let registry = CredentialRegistry::new();
        registry
            .register(ids("a", "provider-a", "model"))
            .expect("register");
        let lease = registry
            .select(request("model", Instant::now()))
            .expect("select");
        let (registration, _explanation, reservation) = lease.into_parts();
        assert_eq!(registration.credential().as_str(), "a");
        assert_eq!(
            registry.in_flight(&CredentialId::new("a").unwrap()),
            Ok(Some(1))
        );
        drop(reservation);
        assert_eq!(
            registry.in_flight(&CredentialId::new("a").unwrap()),
            Ok(Some(0))
        );
    }

    #[test]
    fn filters_capability_codec_health_quota_and_concurrency() {
        let registry = CredentialRegistry::new();
        let registration = ids("a", "provider-a", "model")
            .with_codec("chat")
            .expect("codec")
            .with_max_in_flight(1)
            .expect("limit");
        registry.register(registration).expect("register");
        let now = Instant::now();
        let lease = registry
            .select(
                request("model", now)
                    .with_codec("chat")
                    .expect("codec request"),
            )
            .expect("first selection");
        let error = registry
            .select(
                request("model", now)
                    .with_codec("chat")
                    .expect("codec request"),
            )
            .expect_err("limit filters active lease");
        assert!(matches!(error, SelectionError::NoEligible { .. }));
        drop(lease);
        registry
            .mark_quota_exhausted(
                &CredentialId::new("a").unwrap(),
                Some(now + Duration::from_secs(60)),
            )
            .expect("quota");
        let error = registry
            .select(
                request("model", now)
                    .with_codec("chat")
                    .expect("codec request"),
            )
            .expect_err("quota filters target");
        let SelectionError::NoEligible { explanation, .. } = error else {
            panic!("unexpected error");
        };
        assert!(explanation.candidates[0]
            .filter_reasons
            .contains(&crate::FilterReason::QuotaExhausted));
    }

    #[test]
    fn selection_explains_provider_scope_cooldown() {
        let registry = CredentialRegistry::new();
        registry
            .register(ids("a", "provider-a", "model"))
            .expect("register");
        registry
            .register(ids("b", "provider-a", "model"))
            .expect("register");
        let provider = ProviderId::new("provider-a").expect("provider");
        let model = ModelId::new("model").expect("model");
        let subject = HealthSubject {
            credential: Some(CredentialId::new("a").expect("credential")),
            model: Some(model),
            provider: Some(provider),
            route: None,
        };
        let failure = crate::ProviderFailureClassifier.classify(
            &crate::ObservedFailure::new(crate::FailureSource::Upstream, Some(429))
                .with_provider_code("rate_limit")
                .with_retry_after(Duration::from_secs(30)),
        );
        registry
            .apply_failure(&failure, &subject, Instant::now())
            .expect("apply cooldown");
        let error = registry
            .select(request("model", Instant::now()))
            .expect_err("provider cooldown filters both accounts");
        let SelectionError::NoEligible { explanation, .. } = error else {
            panic!("unexpected selection error");
        };
        assert!(explanation.candidates.iter().all(|candidate| candidate
            .filter_reasons
            .contains(&crate::FilterReason::ProviderCooldown)));
    }

    #[test]
    fn affinity_matches_and_rebinds_after_cooldown() {
        let registry = CredentialRegistry::new();
        registry
            .register(ids("a", "provider-a", "model"))
            .expect("register");
        registry
            .register(ids("b", "provider-b", "model"))
            .expect("register");
        let now = Instant::now();
        let first = registry
            .select(
                request("model", now)
                    .with_affinity_key("conversation-1", Duration::from_secs(60))
                    .expect("affinity"),
            )
            .expect("first");
        assert!(matches!(
            first.explanation().affinity,
            AffinityDecision::NoMatch { .. }
        ));
        let chosen = first.registration().credential().clone();
        drop(first);
        let second = registry
            .select(
                request("model", now + Duration::from_secs(1))
                    .with_affinity_key("conversation-1", Duration::from_secs(60))
                    .expect("affinity"),
            )
            .expect("second");
        assert_eq!(second.registration().credential(), &chosen);
        assert!(matches!(
            second.explanation().affinity,
            AffinityDecision::Matched { .. }
        ));
        registry
            .disable(chosen.clone())
            .expect("disable selected credential");
        drop(second);
        let rebound = registry
            .select(
                request("model", now + Duration::from_secs(2))
                    .with_affinity_key("conversation-1", Duration::from_secs(60))
                    .expect("affinity"),
            )
            .expect("rebind");
        assert_ne!(rebound.registration().credential(), &chosen);
        assert!(matches!(
            rebound.explanation().affinity,
            AffinityDecision::Rebound { .. }
        ));
    }

    #[test]
    fn affinity_rebind_false_rejects_when_bound_target_is_unavailable() {
        let registry = CredentialRegistry::new();
        registry
            .register(ids("a", "provider-a", "model"))
            .expect("register");
        registry
            .register(ids("b", "provider-b", "model"))
            .expect("register");
        let now = Instant::now();
        let first = registry
            .select(
                request("model", now)
                    .with_affinity_key("conversation-1", Duration::from_secs(60))
                    .expect("affinity"),
            )
            .expect("first");
        let chosen = first.registration().credential().clone();
        drop(first);
        registry.disable(chosen).expect("disable bound credential");
        let error = registry
            .select(
                request("model", now + Duration::from_secs(1))
                    .with_affinity_key("conversation-1", Duration::from_secs(60))
                    .expect("affinity")
                    .with_affinity_rebind(false),
            )
            .expect_err("rebind must be rejected");
        let SelectionError::NoEligible { explanation, .. } = error else {
            panic!("unexpected selection error");
        };
        assert!(matches!(
            explanation.affinity,
            AffinityDecision::Unavailable { .. }
        ));
    }

    #[test]
    fn weighted_and_least_in_flight_strategies_are_deterministic() {
        let registry = CredentialRegistry::new();
        registry
            .register(
                ids("light", "provider-a", "model")
                    .with_weight(1)
                    .expect("weight"),
            )
            .expect("register");
        registry
            .register(
                ids("heavy", "provider-b", "model")
                    .with_weight(2)
                    .expect("weight"),
            )
            .expect("register");
        let now = Instant::now();
        let mut selected = Vec::new();
        for _ in 0..6 {
            let lease = registry
                .select(
                    request("model", now)
                        .with_strategy(SelectionStrategy::SmoothWeightedRoundRobin),
                )
                .expect("select");
            selected.push(lease.registration().credential().to_string());
            drop(lease);
        }
        assert_eq!(
            selected,
            ["heavy", "light", "heavy", "heavy", "light", "heavy"]
        );
    }

    #[test]
    fn model_aliases_are_resolved_and_cycles_are_rejected() {
        let registry = CredentialRegistry::new();
        registry
            .register(ids("a", "provider-a", "resolved"))
            .expect("register");
        registry
            .register_model_alias(
                ModelId::new("public").expect("alias"),
                ModelId::new("resolved").expect("target"),
            )
            .expect("alias");
        let lease = registry
            .select(request("public", Instant::now()))
            .expect("aliased selection");
        assert_eq!(lease.registration().model().as_str(), "resolved");
        assert!(lease.explanation().model_alias_resolution.alias_used);
        assert_eq!(
            registry.resolve_model(&ModelId::new("public").unwrap()),
            Ok(ModelId::new("resolved").unwrap())
        );
        assert_eq!(
            registry.register_model_alias(
                ModelId::new("resolved").unwrap(),
                ModelId::new("public").unwrap(),
            ),
            Err(SelectionError::ModelAliasCycle)
        );
    }

    #[test]
    fn concurrent_selection_and_registration_do_not_corrupt_state() {
        let registry = Arc::new(CredentialRegistry::new());
        registry
            .register(ids("a", "provider-a", "model"))
            .expect("register");
        let mut threads = Vec::new();
        for worker in 0..8 {
            let registry = Arc::clone(&registry);
            threads.push(thread::spawn(move || {
                let id = format!("worker-{worker}");
                registry
                    .register(ids(&id, "provider", "model"))
                    .expect("register");
                let _ = registry.select(request("model", Instant::now()));
            }));
        }
        for thread in threads {
            thread.join().expect("thread succeeds");
        }
        assert_eq!(registry.registrations().expect("list").len(), 9);
    }
}
