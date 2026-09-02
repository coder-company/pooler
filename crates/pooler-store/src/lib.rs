//! Bounded storage contracts for Pooler's mutable state.
//!
//! The crate contains both a deterministic in-memory store and a transactional
//! SQLite store. Callers provide timestamps rather than making the store read a
//! process clock; expiry and retention are therefore deterministic and easy to
//! test. Secret values are deliberately absent from every type in this crate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{PoisonError, RwLock};

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod encrypted;
mod oauth;
mod sqlite;
mod usage;
pub use encrypted::{CredentialPayload, MasterKey, SecretPayload};
pub use oauth::{CredentialProfileMetadata, SqliteOAuthTokenStore};
pub use sqlite::SqliteStore;
pub use usage::{CostProvenance, UsageRecord};

/// Milliseconds since the Unix epoch, supplied by the caller.
pub type Timestamp = u64;

/// Maximum timeline phases retained for one logical request.
pub const MAX_REQUEST_EVENTS_PER_REQUEST: usize = 64;

/// Maximum number of retained entries in each in-memory collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub max_credentials: usize,
    pub max_affinities: usize,
    pub max_decisions: usize,
    pub max_request_events: usize,
    pub request_history_ttl_ms: u64,
    pub max_usage_records: usize,
    pub usage_history_ttl_ms: u64,
    pub max_managed_secrets: usize,
    pub max_management_sessions: usize,
    pub max_drafts: usize,
    pub max_audit_records: usize,
    pub max_reload_records: usize,
    pub max_oauth_flows: usize,
    pub control_history_ttl_ms: u64,
}

impl RetentionPolicy {
    /// Build a policy.  Zero is rejected because it is almost always an
    /// accidental request for unbounded or unusable state.
    pub const fn new(
        max_credentials: usize,
        max_affinities: usize,
        max_decisions: usize,
    ) -> Result<Self, StoreError> {
        if max_credentials == 0 || max_affinities == 0 || max_decisions == 0 {
            return Err(StoreError::InvalidRetention);
        }
        Ok(Self {
            max_credentials,
            max_affinities,
            max_decisions,
            max_request_events: 4_096,
            request_history_ttl_ms: 7 * 24 * 60 * 60 * 1_000,
            max_usage_records: 16_384,
            usage_history_ttl_ms: 90 * 24 * 60 * 60 * 1_000,
            max_managed_secrets: 1_024,
            max_management_sessions: 1_024,
            max_drafts: 1_024,
            max_audit_records: 16_384,
            max_reload_records: 4_096,
            max_oauth_flows: 1_024,
            control_history_ttl_ms: 30 * 24 * 60 * 60 * 1_000,
        })
    }

    /// Override bounded request-history retention.
    pub const fn with_request_history(
        mut self,
        max_request_events: usize,
        request_history_ttl_ms: u64,
    ) -> Result<Self, StoreError> {
        if max_request_events == 0 || request_history_ttl_ms == 0 {
            return Err(StoreError::InvalidRetention);
        }
        self.max_request_events = max_request_events;
        self.request_history_ttl_ms = request_history_ttl_ms;
        Ok(self)
    }

    /// Override bounded historical-usage retention.
    pub const fn with_usage_history(
        mut self,
        max_usage_records: usize,
        usage_history_ttl_ms: u64,
    ) -> Result<Self, StoreError> {
        if max_usage_records == 0 || usage_history_ttl_ms == 0 {
            return Err(StoreError::InvalidRetention);
        }
        self.max_usage_records = max_usage_records;
        self.usage_history_ttl_ms = usage_history_ttl_ms;
        Ok(self)
    }

    /// Override bounded durable control-plane retention.
    #[allow(clippy::too_many_arguments)]
    pub const fn with_control_plane_history(
        mut self,
        max_managed_secrets: usize,
        max_management_sessions: usize,
        max_drafts: usize,
        max_audit_records: usize,
        max_reload_records: usize,
        max_oauth_flows: usize,
        control_history_ttl_ms: u64,
    ) -> Result<Self, StoreError> {
        if max_managed_secrets == 0
            || max_management_sessions == 0
            || max_drafts == 0
            || max_audit_records == 0
            || max_reload_records == 0
            || max_oauth_flows == 0
            || control_history_ttl_ms == 0
        {
            return Err(StoreError::InvalidRetention);
        }
        self.max_managed_secrets = max_managed_secrets;
        self.max_management_sessions = max_management_sessions;
        self.max_drafts = max_drafts;
        self.max_audit_records = max_audit_records;
        self.max_reload_records = max_reload_records;
        self.max_oauth_flows = max_oauth_flows;
        self.control_history_ttl_ms = control_history_ttl_ms;
        Ok(self)
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_credentials: 1_024,
            max_affinities: 4_096,
            max_decisions: 4_096,
            max_request_events: 4_096,
            request_history_ttl_ms: 7 * 24 * 60 * 60 * 1_000,
            max_usage_records: 16_384,
            usage_history_ttl_ms: 90 * 24 * 60 * 60 * 1_000,
            max_managed_secrets: 1_024,
            max_management_sessions: 1_024,
            max_drafts: 1_024,
            max_audit_records: 16_384,
            max_reload_records: 4_096,
            max_oauth_flows: 1_024,
            control_history_ttl_ms: 30 * 24 * 60 * 60 * 1_000,
        }
    }
}

/// Non-secret immutable inputs used to derive a credential configuration
/// fingerprint. Values are configuration identity only; bearer and client
/// secret values must never be supplied here.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialFingerprintInput {
    pub account_id: String,
    pub provider_instance_id: String,
    pub provider_origin: String,
    pub auth_kind: String,
    pub provider_profile: String,
    pub oauth_client_id: Option<String>,
    pub oauth_grant_type: Option<String>,
    pub oauth_scopes: Vec<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub identity_endpoint: Option<String>,
    pub callback_endpoint: Option<String>,
    pub oauth_client_secret_reference: Option<String>,
    /// Additional non-secret provider behavior that affects OAuth identity.
    ///
    /// Entries are canonicalized by key and value. An empty collection retains
    /// the exact version-2 fingerprint used before provider-profile behavior
    /// was represented explicitly.
    pub oauth_additional_identity: Vec<(String, String)>,
    pub auth_placement: String,
}

impl CredentialFingerprintInput {
    fn validate_legacy_fields(&self) -> StoreResult<()> {
        for (field, value) in [
            ("account_id", self.account_id.as_str()),
            ("provider_instance_id", self.provider_instance_id.as_str()),
            ("provider_origin", self.provider_origin.as_str()),
            ("auth_kind", self.auth_kind.as_str()),
            ("provider_profile", self.provider_profile.as_str()),
            ("auth_placement", self.auth_placement.as_str()),
        ] {
            non_empty(field, value)?;
            if value.len() > 512 {
                return Err(StoreError::Serialization(
                    "credential fingerprint field exceeds metadata bounds".to_owned(),
                ));
            }
        }
        for value in [
            self.oauth_client_id.as_deref(),
            self.oauth_grant_type.as_deref(),
            self.authorization_endpoint.as_deref(),
            self.token_endpoint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.is_empty() || value.len() > 1_024 {
                return Err(StoreError::Serialization(
                    "credential fingerprint field exceeds metadata bounds".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn legacy_fingerprint_unchecked(&self) -> String {
        let mut canonical = String::from("pooler-credential-fingerprint:v1\n");
        for value in [
            Some(self.account_id.as_str()),
            Some(self.provider_instance_id.as_str()),
            Some(self.provider_origin.as_str()),
            Some(self.auth_kind.as_str()),
            Some(self.provider_profile.as_str()),
            self.oauth_client_id.as_deref(),
            self.oauth_grant_type.as_deref(),
            self.authorization_endpoint.as_deref(),
            self.token_endpoint.as_deref(),
            Some(self.auth_placement.as_str()),
        ] {
            let value = value.unwrap_or("");
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('|');
        }
        hex_digest(canonical.as_bytes())
    }

    /// Return the version-1 fingerprint used before OAuth scope and endpoint
    /// identity was added. This exists only for fail-closed store upgrades;
    /// new OAuth payloads must use [`Self::fingerprint`].
    pub fn legacy_fingerprint(&self) -> StoreResult<String> {
        self.validate_legacy_fields()?;
        Ok(self.legacy_fingerprint_unchecked())
    }

    /// Return a stable SHA-256 hex fingerprint over canonical, length-prefixed
    /// identity fields. Secret values are not accepted by this type.
    pub fn fingerprint(&self) -> StoreResult<String> {
        self.validate_legacy_fields()?;
        for value in [
            self.revocation_endpoint.as_deref(),
            self.identity_endpoint.as_deref(),
            self.callback_endpoint.as_deref(),
            self.oauth_client_secret_reference.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.is_empty() || value.len() > 1_024 {
                return Err(StoreError::Serialization(
                    "credential fingerprint field exceeds metadata bounds".to_owned(),
                ));
            }
        }
        if self.oauth_scopes.len() > 256
            || self
                .oauth_scopes
                .iter()
                .any(|scope| scope.is_empty() || scope.len() > 1_024)
        {
            return Err(StoreError::Serialization(
                "credential fingerprint OAuth scopes exceed metadata bounds".to_owned(),
            ));
        }
        if self.oauth_additional_identity.len() > 256
            || self.oauth_additional_identity.iter().any(|(key, value)| {
                key.is_empty() || key.len() > 256 || value.is_empty() || value.len() > 1_024
            })
        {
            return Err(StoreError::Serialization(
                "credential fingerprint OAuth provider behavior exceeds metadata bounds".to_owned(),
            ));
        }

        // API-key identities keep the exact version-1 digest. OAuth-only
        // fields do not affect an API-key binding, and changing its digest
        // would force an unnecessary credential migration.
        if !self.auth_kind.eq_ignore_ascii_case("oauth") {
            return Ok(self.legacy_fingerprint_unchecked());
        }

        let mut oauth_scopes = self
            .oauth_scopes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        oauth_scopes.sort_unstable();
        oauth_scopes.dedup();

        let has_additional_identity = !self.oauth_additional_identity.is_empty();
        let mut canonical = if has_additional_identity {
            String::from("pooler-credential-fingerprint:v3\n")
        } else {
            String::from("pooler-credential-fingerprint:v2\n")
        };
        for value in [
            Some(self.account_id.as_str()),
            Some(self.provider_instance_id.as_str()),
            Some(self.provider_origin.as_str()),
            Some(self.auth_kind.as_str()),
            Some(self.provider_profile.as_str()),
            self.oauth_client_id.as_deref(),
            self.oauth_grant_type.as_deref(),
            self.authorization_endpoint.as_deref(),
            self.token_endpoint.as_deref(),
            self.revocation_endpoint.as_deref(),
            self.identity_endpoint.as_deref(),
            self.callback_endpoint.as_deref(),
            self.oauth_client_secret_reference.as_deref(),
            Some(self.auth_placement.as_str()),
        ] {
            let value = value.unwrap_or("");
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('|');
        }
        canonical.push_str(&oauth_scopes.len().to_string());
        canonical.push(':');
        for scope in oauth_scopes {
            canonical.push_str(&scope.len().to_string());
            canonical.push(':');
            canonical.push_str(scope);
            canonical.push('|');
        }
        if has_additional_identity {
            let mut additional_identity = self
                .oauth_additional_identity
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            additional_identity.sort_unstable();
            additional_identity.dedup();
            canonical.push_str(&additional_identity.len().to_string());
            canonical.push(':');
            for (key, value) in additional_identity {
                canonical.push_str(&key.len().to_string());
                canonical.push(':');
                canonical.push_str(key);
                canonical.push('|');
                canonical.push_str(&value.len().to_string());
                canonical.push(':');
                canonical.push_str(value);
                canonical.push('|');
            }
        }
        Ok(hex_digest(canonical.as_bytes()))
    }
}

/// Compute a stable non-secret credential configuration fingerprint.
pub fn credential_configuration_fingerprint(
    input: &CredentialFingerprintInput,
) -> StoreResult<String> {
    input.fingerprint()
}

pub(crate) fn hex_digest(value: &[u8]) -> String {
    digest(&SHA256, value)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn validate_fingerprint(value: &str) -> StoreResult<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidCredentialFingerprint);
    }
    Ok(())
}

/// Mutable state for one credential.  This is metadata only; it never carries a
/// bearer token, refresh token, or other authorization material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialState {
    pub credential_id: String,
    pub provider_id: String,
    /// Immutable, non-secret account/provider/auth configuration identity.
    /// Empty is retained only for version-1 rows awaiting explicit adoption.
    #[serde(default)]
    pub configuration_fingerprint: String,
    pub enabled: bool,
    pub updated_at: Timestamp,
    /// Store-assigned revision, starting at one.
    pub revision: u64,
}

/// Immutable, non-secret identity used to fence credential metadata mutations.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialConfigurationIdentity {
    credential_id: String,
    provider_id: String,
    configuration_fingerprint: String,
}

impl CredentialConfigurationIdentity {
    pub fn new(
        credential_id: impl Into<String>,
        provider_id: impl Into<String>,
        configuration_fingerprint: impl Into<String>,
    ) -> StoreResult<Self> {
        let identity = Self {
            credential_id: credential_id.into(),
            provider_id: provider_id.into(),
            configuration_fingerprint: configuration_fingerprint.into(),
        };
        non_empty("credential_id", &identity.credential_id)?;
        non_empty("provider_id", &identity.provider_id)?;
        validate_fingerprint(&identity.configuration_fingerprint)?;
        Ok(identity)
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn configuration_fingerprint(&self) -> &str {
        &self.configuration_fingerprint
    }

    fn matches(&self, state: &CredentialState) -> bool {
        self.credential_id == state.credential_id
            && self.provider_id == state.provider_id
            && self.configuration_fingerprint == state.configuration_fingerprint
    }
}

/// One fail-closed credential fingerprint retirement in an atomic migration batch.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialFingerprintRetirement {
    credential_id: String,
    provider_id: String,
    expected_fingerprint: String,
    replacement_fingerprint: String,
}

impl CredentialFingerprintRetirement {
    pub fn new(
        credential_id: impl Into<String>,
        provider_id: impl Into<String>,
        expected_fingerprint: impl Into<String>,
        replacement_fingerprint: impl Into<String>,
    ) -> StoreResult<Self> {
        let retirement = Self {
            credential_id: credential_id.into(),
            provider_id: provider_id.into(),
            expected_fingerprint: expected_fingerprint.into(),
            replacement_fingerprint: replacement_fingerprint.into(),
        };
        non_empty("credential_id", &retirement.credential_id)?;
        non_empty("provider_id", &retirement.provider_id)?;
        validate_fingerprint(&retirement.expected_fingerprint)?;
        validate_fingerprint(&retirement.replacement_fingerprint)?;
        if retirement.replacement_fingerprint.is_empty()
            || retirement.expected_fingerprint == retirement.replacement_fingerprint
        {
            return Err(StoreError::InvalidCredentialFingerprint);
        }
        Ok(retirement)
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn expected_fingerprint(&self) -> &str {
        &self.expected_fingerprint
    }

    #[must_use]
    pub fn replacement_fingerprint(&self) -> &str {
        &self.replacement_fingerprint
    }
}

/// One prepared credential configuration transition for runtime publication.
///
/// `expected` is the exact metadata row observed while building the candidate.
/// The store commits every transition in one transaction or rejects the full
/// batch if any row changed. `desired` carries the compiled provider identity
/// and configured enablement used for a new or replaced identity. A retirement
/// removes an authenticated historical OAuth payload instead of blessing it
/// under the replacement fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialConfigurationActivation {
    expected: Option<CredentialState>,
    desired: CredentialState,
    retirement: Option<CredentialFingerprintRetirement>,
}

impl CredentialConfigurationActivation {
    pub fn new(
        expected: Option<CredentialState>,
        desired: CredentialState,
        retirement: Option<CredentialFingerprintRetirement>,
    ) -> StoreResult<Self> {
        non_empty("credential_id", &desired.credential_id)?;
        non_empty("provider_id", &desired.provider_id)?;
        validate_fingerprint(&desired.configuration_fingerprint)?;
        if desired.configuration_fingerprint.is_empty() {
            return Err(StoreError::InvalidCredentialFingerprint);
        }
        if expected
            .as_ref()
            .is_some_and(|state| state.credential_id != desired.credential_id)
        {
            return Err(StoreError::CredentialFingerprintConflict);
        }
        if retirement.as_ref().is_some_and(|retirement| {
            retirement.credential_id() != desired.credential_id
                || retirement.provider_id() != desired.provider_id
                || retirement.replacement_fingerprint() != desired.configuration_fingerprint
        }) {
            return Err(StoreError::CredentialFingerprintConflict);
        }
        Ok(Self {
            expected,
            desired,
            retirement,
        })
    }

    #[must_use]
    pub fn expected(&self) -> Option<&CredentialState> {
        self.expected.as_ref()
    }

    #[must_use]
    pub fn desired(&self) -> &CredentialState {
        &self.desired
    }

    #[must_use]
    pub fn retirement(&self) -> Option<&CredentialFingerprintRetirement> {
        self.retirement.as_ref()
    }
}

/// Metadata and effective enablement produced by one atomic runtime activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedCredentialState {
    state: CredentialState,
    health_disabled: bool,
}

impl ActivatedCredentialState {
    #[must_use]
    pub const fn new(state: CredentialState, health_disabled: bool) -> Self {
        Self {
            state,
            health_disabled,
        }
    }

    #[must_use]
    pub const fn state(&self) -> &CredentialState {
        &self.state
    }

    #[must_use]
    pub const fn health_disabled(&self) -> bool {
        self.health_disabled
    }

    #[must_use]
    pub const fn effectively_enabled(&self) -> bool {
        self.state.enabled && !self.health_disabled
    }
}

/// Atomic result of a generation- and identity-fenced credential mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConditionalCredentialMutation {
    /// The fence matched and the requested state is current.
    Applied(CredentialState),
    /// A credential exists, but its generation or immutable identity changed.
    Stale {
        current: CredentialState,
        /// Whether the same transaction observed a durable credential payload.
        /// Non-SQLite stores may not have a payload domain and return `None`.
        credential_payload_present: Option<bool>,
        /// Token-payload generation observed by the same transaction.
        /// Metadata-only revisions do not advance this value.
        credential_payload_generation: Option<u64>,
    },
    /// The credential was removed before the mutation acquired its lock.
    Missing,
}

impl ConditionalCredentialMutation {
    /// Return the applied state, if the generation and identity fence matched.
    #[must_use]
    pub fn into_applied(self) -> Option<CredentialState> {
        match self {
            Self::Applied(state) => Some(state),
            Self::Stale { .. } | Self::Missing => None,
        }
    }
}

impl CredentialState {
    pub fn new(
        credential_id: impl Into<String>,
        provider_id: impl Into<String>,
        enabled: bool,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            provider_id: provider_id.into(),
            configuration_fingerprint: String::new(),
            enabled,
            updated_at,
            revision: 0,
        }
    }

    /// Construct metadata with an immutable configuration fingerprint.
    pub fn new_with_fingerprint(
        credential_id: impl Into<String>,
        provider_id: impl Into<String>,
        configuration_fingerprint: impl Into<String>,
        enabled: bool,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            provider_id: provider_id.into(),
            configuration_fingerprint: configuration_fingerprint.into(),
            enabled,
            updated_at,
            revision: 0,
        }
    }
}

/// Stable identity that scopes an affinity to one compiled target binding.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AffinityBindingIdentity {
    pub route_id: String,
    pub policy_id: String,
    pub logical_model: String,
    pub account_pool_id: String,
    pub target_binding_id: String,
}

impl AffinityBindingIdentity {
    pub fn new(
        route_id: impl Into<String>,
        policy_id: impl Into<String>,
        logical_model: impl Into<String>,
        account_pool_id: impl Into<String>,
        target_binding_id: impl Into<String>,
    ) -> Self {
        Self {
            route_id: route_id.into(),
            policy_id: policy_id.into(),
            logical_model: logical_model.into(),
            account_pool_id: account_pool_id.into(),
            target_binding_id: target_binding_id.into(),
        }
    }

    fn validate(&self) -> StoreResult<()> {
        for (field, value) in [
            ("route_id", self.route_id.as_str()),
            ("policy_id", self.policy_id.as_str()),
            ("logical_model", self.logical_model.as_str()),
            ("account_pool_id", self.account_pool_id.as_str()),
            ("target_binding_id", self.target_binding_id.as_str()),
        ] {
            non_empty(field, value)?;
            if value.len() > 256 {
                return Err(StoreError::Serialization(
                    "affinity binding identity exceeds metadata bounds".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// A binding from an opaque session key to one upstream selection.
///
/// The key is generated by policy.  Prompt content and messages are not stored.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionAffinity {
    pub key: String,
    pub provider_id: String,
    pub credential_id: String,
    pub upstream_model: String,
    /// Full scope prevents a conversation key from leaking across routes,
    /// policies, logical models, pools, or compiled target bindings.
    #[serde(default)]
    pub route_id: String,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub logical_model: String,
    #[serde(default)]
    pub account_pool_id: String,
    #[serde(default)]
    pub target_binding_id: String,
    pub created_at: Timestamp,
    pub last_used_at: Timestamp,
    /// Expiry is exclusive: `now >= expires_at` means expired.
    pub expires_at: Timestamp,
}

impl SessionAffinity {
    pub fn new(
        key: impl Into<String>,
        provider_id: impl Into<String>,
        credential_id: impl Into<String>,
        upstream_model: impl Into<String>,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            key: key.into(),
            provider_id: provider_id.into(),
            credential_id: credential_id.into(),
            upstream_model: upstream_model.into(),
            route_id: String::new(),
            policy_id: String::new(),
            logical_model: String::new(),
            account_pool_id: String::new(),
            target_binding_id: String::new(),
            created_at,
            last_used_at: created_at,
            expires_at,
        }
    }

    #[must_use]
    pub const fn expired_at(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// Construct an affinity with an explicit composite target-binding scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new_scoped(
        key: impl Into<String>,
        provider_id: impl Into<String>,
        credential_id: impl Into<String>,
        upstream_model: impl Into<String>,
        scope: AffinityBindingIdentity,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            key: key.into(),
            provider_id: provider_id.into(),
            credential_id: credential_id.into(),
            upstream_model: upstream_model.into(),
            route_id: scope.route_id,
            policy_id: scope.policy_id,
            logical_model: scope.logical_model,
            account_pool_id: scope.account_pool_id,
            target_binding_id: scope.target_binding_id,
            created_at,
            last_used_at: created_at,
            expires_at,
        }
    }

    #[must_use]
    pub fn binding_identity(&self) -> AffinityBindingIdentity {
        AffinityBindingIdentity::new(
            self.route_id.clone(),
            self.policy_id.clone(),
            self.logical_model.clone(),
            self.account_pool_id.clone(),
            self.target_binding_id.clone(),
        )
    }
}

/// One candidate captured in a redacted selection explanation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionCandidate {
    pub provider_id: String,
    pub credential_id: Option<String>,
    pub score: i64,
    pub eligible: bool,
    pub reason: Option<String>,
}

/// A redacted selection record.  Request bodies and authorization values are not
/// represented; credential fields should contain pseudonyms when possible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Store-assigned monotonic id; zero means not yet persisted.
    pub id: u64,
    pub request_id: String,
    pub route_id: String,
    pub model: String,
    pub candidates: Vec<DecisionCandidate>,
    pub selected_provider: Option<String>,
    pub selected_credential: Option<String>,
    pub upstream_model: Option<String>,
    #[serde(default)]
    pub target_binding_id: Option<String>,
    #[serde(default)]
    pub priority_tier: Option<u32>,
    pub attempt: u32,
    pub configuration_generation: u64,
    pub reason: Option<String>,
    pub recorded_at: Timestamp,
}

impl DecisionRecord {
    pub fn new(
        request_id: impl Into<String>,
        route_id: impl Into<String>,
        model: impl Into<String>,
        recorded_at: Timestamp,
    ) -> Self {
        Self {
            id: 0,
            request_id: request_id.into(),
            route_id: route_id.into(),
            model: model.into(),
            candidates: Vec::new(),
            selected_provider: None,
            selected_credential: None,
            upstream_model: None,
            target_binding_id: None,
            priority_tier: None,
            attempt: 1,
            configuration_generation: 0,
            reason: None,
            recorded_at,
        }
    }

    /// Convert a policy explanation into the persistence shape with the
    /// request context that policy intentionally does not own.
    #[must_use]
    pub fn from_selection(
        selection: &pooler_policy::SelectionExplanation,
        request_id: impl Into<String>,
        route_id: impl Into<String>,
        recorded_at: Timestamp,
    ) -> Self {
        let requested_model = selection.model_alias_resolution.requested.to_string();
        let mut record = Self::new(request_id, route_id, requested_model, recorded_at);
        record.attempt = selection.attempt;
        record.configuration_generation = selection.configuration_generation.value();
        record.candidates = selection
            .candidates
            .iter()
            .map(|candidate| DecisionCandidate {
                provider_id: candidate.target.provider.to_string(),
                credential_id: Some(candidate.target.credential_pseudonym.as_str().to_owned()),
                score: candidate.score.map_or(0, score_as_integer),
                eligible: candidate.is_eligible(),
                reason: decision_reason(&candidate.filter_reasons),
            })
            .collect();
        if let Some(selected) = &selection.selected {
            record.selected_provider = Some(selected.provider.to_string());
            record.selected_credential = Some(selected.credential_pseudonym.as_str().to_owned());
            record.upstream_model = Some(selected.model.to_string());
            record.target_binding_id = selected.target_id.as_ref().map(ToString::to_string);
            record.priority_tier = selected.priority;
        }
        record.reason = selection_reason(selection);
        record
    }
}

/// One bounded phase in a logical request timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestEventKind {
    Admission,
    Selection,
    Attempt,
    Retry,
    Commitment,
    Completion,
}

/// Metadata-only request lifecycle event. Raw bodies, headers, credentials,
/// secret references, prompts, and responses have no representation here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestEvent {
    /// Store-assigned monotonic id; zero means not yet persisted.
    pub id: u64,
    pub request_id: String,
    pub event_index: u32,
    pub kind: RequestEventKind,
    pub recorded_at: Timestamp,
    pub listener: String,
    pub route_id: String,
    pub public_model: Option<String>,
    pub upstream_model: Option<String>,
    #[serde(default)]
    pub target_binding_id: Option<String>,
    #[serde(default)]
    pub priority_tier: Option<u32>,
    pub provider: Option<String>,
    pub account_pseudonym: Option<String>,
    pub attempt: Option<u32>,
    pub eligible: Option<bool>,
    pub retry_reason: Option<String>,
    pub commitment: Option<String>,
    pub ttft_ms: Option<u64>,
    pub latency_ms: Option<u64>,
    pub status: Option<u16>,
    pub error_class: Option<String>,
    pub quota_effect: Option<String>,
    pub cooldown_effect: Option<String>,
    pub semantic_losses: Vec<String>,
    pub configuration_generation: u64,
    pub catalog_generation: Option<u64>,
    pub request_body_sha256: Option<String>,
    pub response_body_sha256: Option<String>,
}

impl RequestEvent {
    pub fn new(
        request_id: impl Into<String>,
        event_index: u32,
        kind: RequestEventKind,
        listener: impl Into<String>,
        route_id: impl Into<String>,
        recorded_at: Timestamp,
    ) -> Self {
        Self {
            id: 0,
            request_id: request_id.into(),
            event_index,
            kind,
            recorded_at,
            listener: listener.into(),
            route_id: route_id.into(),
            public_model: None,
            upstream_model: None,
            target_binding_id: None,
            priority_tier: None,
            provider: None,
            account_pseudonym: None,
            attempt: None,
            eligible: None,
            retry_reason: None,
            commitment: None,
            ttft_ms: None,
            latency_ms: None,
            status: None,
            error_class: None,
            quota_effect: None,
            cooldown_effect: None,
            semantic_losses: Vec::new(),
            configuration_generation: 0,
            catalog_generation: None,
            request_body_sha256: None,
            response_body_sha256: None,
        }
    }
}

/// Metadata for one encrypted managed secret. The secret bytes are available
/// only through the explicit store payload methods and never through this
/// record or its debug representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManagedSecretRecord {
    pub secret_id: String,
    pub owner_id: String,
    pub kind: String,
    pub revision: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

impl ManagedSecretRecord {
    #[must_use]
    pub fn new(
        secret_id: impl Into<String>,
        owner_id: impl Into<String>,
        kind: impl Into<String>,
        created_at: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Self {
        Self {
            secret_id: secret_id.into(),
            owner_id: owner_id.into(),
            kind: kind.into(),
            revision: 0,
            created_at,
            updated_at: created_at,
            expires_at,
        }
    }
}

/// A same-origin management session. Only a keyed cookie digest is persisted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManagementSessionRecord {
    pub session_id: String,
    pub actor_id: String,
    pub revision: u64,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

impl ManagementSessionRecord {
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            actor_id: actor_id.into(),
            revision: 0,
            created_at,
            expires_at,
            revoked_at: None,
        }
    }
}

impl ManagementSessionRecord {
    #[must_use]
    pub fn active_at(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }
}

/// An owner-scoped, encrypted, non-secret configuration draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DraftRecord {
    pub draft_id: u64,
    pub owner_id: String,
    pub kind: String,
    pub etag: String,
    pub base_generation: u64,
    pub revision: u64,
    pub payload: Vec<u8>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub expires_at: Timestamp,
}

impl DraftRecord {
    #[must_use]
    pub fn new(
        owner_id: impl Into<String>,
        kind: impl Into<String>,
        base_generation: u64,
        payload: Vec<u8>,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            draft_id: 0,
            owner_id: owner_id.into(),
            kind: kind.into(),
            etag: String::new(),
            base_generation,
            revision: 0,
            payload,
            created_at,
            updated_at: created_at,
            expires_at,
        }
    }
}

impl DraftRecord {
    #[must_use]
    pub fn active_at(&self, now: Timestamp) -> bool {
        now < self.expires_at
    }
}

/// Bounded, metadata-only management audit entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: u64,
    pub owner_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub generation: u64,
    pub error_code: Option<String>,
    pub recorded_at: Timestamp,
}

impl AuditRecord {
    #[must_use]
    pub fn new(
        owner_id: Option<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        outcome: impl Into<String>,
        generation: u64,
        recorded_at: Timestamp,
    ) -> Self {
        Self {
            id: 0,
            owner_id,
            action: action.into(),
            resource: resource.into(),
            outcome: outcome.into(),
            generation,
            error_code: None,
            recorded_at,
        }
    }
}

/// Durable native reload status and its generation correlation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReloadRecord {
    pub id: u64,
    pub owner_id: Option<String>,
    pub kind: String,
    pub generation: u64,
    pub completed_generation: Option<u64>,
    pub status: String,
    pub etag: Option<String>,
    pub error_code: Option<String>,
    pub started_at: Timestamp,
    pub completed_at: Option<Timestamp>,
    pub revision: u64,
}

impl ReloadRecord {
    #[must_use]
    pub fn new(
        owner_id: Option<String>,
        generation: u64,
        status: impl Into<String>,
        started_at: Timestamp,
    ) -> Self {
        Self {
            id: 0,
            owner_id,
            kind: "configuration".to_owned(),
            generation,
            completed_generation: None,
            status: status.into(),
            etag: None,
            error_code: None,
            started_at,
            completed_at: None,
            revision: 0,
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = kind.into();
        self
    }
}

/// Lifecycle state for one persisted OAuth flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthFlowStatus {
    Pending,
    Completed,
    Failed,
    Cancelled,
}

impl OAuthFlowStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ()> {
        match value {
            "pending" => Ok(Self::Pending),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(()),
        }
    }

    #[must_use]
    pub const fn active(self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// Owner-scoped OAuth correlation metadata. Raw state and PKCE verifier bytes
/// are intentionally absent; the store accepts them only at write/consume
/// boundaries and keeps their encrypted or keyed forms.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OAuthFlowRecord {
    pub flow_id: String,
    pub owner_id: String,
    pub provider_id: String,
    pub account_id: String,
    pub flow_kind: String,
    pub status: OAuthFlowStatus,
    pub revision: u64,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub state_consumed_at: Option<Timestamp>,
    pub completed_at: Option<Timestamp>,
    pub error_code: Option<String>,
}

impl OAuthFlowRecord {
    #[must_use]
    pub fn new(
        flow_id: impl Into<String>,
        owner_id: impl Into<String>,
        provider_id: impl Into<String>,
        account_id: impl Into<String>,
        flow_kind: impl Into<String>,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            flow_id: flow_id.into(),
            owner_id: owner_id.into(),
            provider_id: provider_id.into(),
            account_id: account_id.into(),
            flow_kind: flow_kind.into(),
            status: OAuthFlowStatus::Pending,
            revision: 0,
            created_at,
            expires_at,
            state_consumed_at: None,
            completed_at: None,
            error_code: None,
        }
    }
}

impl OAuthFlowRecord {
    #[must_use]
    pub fn active_at(&self, now: Timestamp) -> bool {
        self.status.active() && now < self.expires_at
    }
}

fn score_as_integer(score: f64) -> i64 {
    if score.is_finite() {
        score.round() as i64
    } else {
        0
    }
}

fn decision_reason(reasons: &[pooler_policy::FilterReason]) -> Option<String> {
    (!reasons.is_empty()).then(|| {
        reasons
            .iter()
            .map(filter_reason)
            .collect::<Vec<_>>()
            .join(",")
    })
}

fn filter_reason(reason: &pooler_policy::FilterReason) -> String {
    match reason {
        pooler_policy::FilterReason::ModelMismatch => "model_mismatch".to_owned(),
        pooler_policy::FilterReason::ProviderNotAllowed => "provider_not_allowed".to_owned(),
        pooler_policy::FilterReason::ProviderDenied => "provider_denied".to_owned(),
        pooler_policy::FilterReason::TargetNotAllowed => "target_not_allowed".to_owned(),
        pooler_policy::FilterReason::TargetDenied => "target_denied".to_owned(),
        pooler_policy::FilterReason::FallbackDisabled => "fallback_disabled".to_owned(),
        pooler_policy::FilterReason::MissingCapability(value) => {
            format!("missing_capability:{value}")
        }
        pooler_policy::FilterReason::CodecUnavailable(value) => {
            format!("codec_unavailable:{value}")
        }
        pooler_policy::FilterReason::MissingParameter(value) => {
            format!("missing_parameter:{value}")
        }
        pooler_policy::FilterReason::UnknownParameters => "unknown_parameters".to_owned(),
        pooler_policy::FilterReason::MissingContext => "missing_context".to_owned(),
        pooler_policy::FilterReason::UnknownContext => "unknown_context".to_owned(),
        pooler_policy::FilterReason::MissingQuantization(value) => {
            format!("missing_quantization:{value}")
        }
        pooler_policy::FilterReason::UnknownQuantization => "unknown_quantization".to_owned(),
        pooler_policy::FilterReason::PrivacyMismatch => "privacy_mismatch".to_owned(),
        pooler_policy::FilterReason::UnknownPrivacy => "unknown_privacy".to_owned(),
        pooler_policy::FilterReason::ZdrRequired => "zdr_required".to_owned(),
        pooler_policy::FilterReason::UnknownZdr => "unknown_zdr".to_owned(),
        pooler_policy::FilterReason::DataPolicyMismatch => "data_policy_mismatch".to_owned(),
        pooler_policy::FilterReason::UnknownDataPolicy => "unknown_data_policy".to_owned(),
        pooler_policy::FilterReason::RegionMismatch => "region_mismatch".to_owned(),
        pooler_policy::FilterReason::UnknownRegion => "unknown_region".to_owned(),
        pooler_policy::FilterReason::PriceExceeded => "price_exceeded".to_owned(),
        pooler_policy::FilterReason::UnknownPrice => "unknown_price".to_owned(),
        pooler_policy::FilterReason::StaleTelemetry => "stale_telemetry".to_owned(),
        pooler_policy::FilterReason::UnknownTelemetry => "unknown_telemetry".to_owned(),
        pooler_policy::FilterReason::CredentialUnavailable => "credential_unavailable".to_owned(),
        pooler_policy::FilterReason::CredentialCooldown => "credential_cooldown".to_owned(),
        pooler_policy::FilterReason::CredentialModelCooldown => {
            "credential_model_cooldown".to_owned()
        }
        pooler_policy::FilterReason::ModelCooldown => "model_cooldown".to_owned(),
        pooler_policy::FilterReason::ProviderCooldown => "provider_cooldown".to_owned(),
        pooler_policy::FilterReason::ProviderModelCooldown => "provider_model_cooldown".to_owned(),
        pooler_policy::FilterReason::RouteCooldown => "route_cooldown".to_owned(),
        pooler_policy::FilterReason::ConcurrencyLimit => "concurrency_limit".to_owned(),
        pooler_policy::FilterReason::RoutePolicy => "route_policy".to_owned(),
        pooler_policy::FilterReason::SessionAffinity => "session_affinity".to_owned(),
        pooler_policy::FilterReason::LossPolicy => "loss_policy".to_owned(),
        pooler_policy::FilterReason::QuotaExhausted => "quota_exhausted".to_owned(),
        pooler_policy::FilterReason::Disabled => "disabled".to_owned(),
    }
}

fn selection_reason(selection: &pooler_policy::SelectionExplanation) -> Option<String> {
    match &selection.affinity {
        pooler_policy::AffinityDecision::NotRequested => None,
        pooler_policy::AffinityDecision::NoMatch { .. } => Some("affinity_no_match".to_owned()),
        pooler_policy::AffinityDecision::Matched { .. } => Some("affinity_matched".to_owned()),
        pooler_policy::AffinityDecision::Rebound { .. } => Some("affinity_rebound".to_owned()),
        pooler_policy::AffinityDecision::Unavailable { .. } => {
            Some("affinity_unavailable".to_owned())
        }
    }
}

/// Coarse persisted health for one credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CredentialHealthStatus {
    Healthy,
    CoolingDown,
    Disabled,
}

impl CredentialHealthStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::CoolingDown => "cooling_down",
            Self::Disabled => "disabled",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ()> {
        match value {
            "healthy" => Ok(Self::Healthy),
            "cooling_down" => Ok(Self::CoolingDown),
            "disabled" => Ok(Self::Disabled),
            _ => Err(()),
        }
    }
}

/// Persisted health metadata. This contains no authorization material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialHealthState {
    pub credential_id: String,
    pub status: CredentialHealthStatus,
    pub failure_count: u64,
    pub cooldown_until: Option<Timestamp>,
    pub updated_at: Timestamp,
}

impl CredentialHealthState {
    pub fn new(
        credential_id: impl Into<String>,
        status: CredentialHealthStatus,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            status,
            failure_count: 0,
            cooldown_until: None,
            updated_at,
        }
    }
}

/// A persisted cooldown keyed by a policy-defined scope and opaque key.
/// Typical scopes are `credential`, `provider`, `model`, and `route`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CooldownState {
    pub scope: String,
    pub key: String,
    pub until: Timestamp,
    pub reason: Option<String>,
    pub updated_at: Timestamp,
}

impl CooldownState {
    pub fn new(
        scope: impl Into<String>,
        key: impl Into<String>,
        until: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            scope: scope.into(),
            key: key.into(),
            until,
            reason: None,
            updated_at,
        }
    }
}

/// Counts returned by [`MemoryStore::len`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StoreLengths {
    pub credentials: usize,
    pub affinities: usize,
    pub decisions: usize,
    pub request_events: usize,
    pub usage_records: usize,
}

impl StoreLengths {
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.credentials == 0
            && self.affinities == 0
            && self.decisions == 0
            && self.request_events == 0
            && self.usage_records == 0
    }
}

/// Number of entries removed by [`Store::prune`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PruneReport {
    pub expired_affinities: usize,
    pub evicted_credentials: usize,
    pub evicted_affinities: usize,
    pub evicted_decisions: usize,
    pub evicted_request_events: usize,
    pub evicted_usage_records: usize,
}

impl PruneReport {
    #[must_use]
    pub const fn total(self) -> usize {
        self.expired_affinities
            + self.evicted_credentials
            + self.evicted_affinities
            + self.evicted_decisions
            + self.evicted_request_events
            + self.evicted_usage_records
    }
}

/// Errors returned by storage operations.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("retention limits must all be greater than zero")]
    InvalidRetention,
    #[error("credential `{0}` was not found")]
    CredentialNotFound(String),
    #[error("decision identifier exhausted")]
    DecisionIdExhausted,
    #[error("request event identifier exhausted")]
    RequestEventIdExhausted,
    #[error("usage record identifier exhausted")]
    UsageRecordIdExhausted,
    #[error("database path is invalid: {0}")]
    InvalidPath(String),
    #[error("database path is not private: {0}")]
    UnsafePath(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("SQLite error: {0}")]
    Sqlite(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("master key reference is not allowed for persisted credentials")]
    MasterKeyReferenceRejected,
    #[error("master key could not be resolved")]
    MasterKeyUnavailable,
    #[error("master key must not be empty")]
    EmptyMasterKey,
    #[error("credential payload must not be empty")]
    EmptyCredentialPayload,
    #[error("credential payload persistence requires an encryption key")]
    EncryptionRequired,
    #[error("credential envelope is invalid")]
    InvalidCredentialEnvelope,
    #[error("credential envelope version {0} is unsupported")]
    UnsupportedCredentialEnvelopeVersion(u8),
    #[error("credential envelope algorithm is unsupported")]
    UnsupportedCredentialEnvelopeAlgorithm,
    #[error("credential envelope was created with a different master key")]
    WrongMasterKey,
    #[error("credential envelope authentication failed")]
    CredentialEnvelopeAuthenticationFailed,
    #[error("credential payload encryption failed")]
    EncryptionFailed,
    #[error("credential revision changed during update")]
    CredentialRevisionConflict,
    #[error("credential configuration fingerprint changed")]
    CredentialFingerprintConflict,
    #[error("credential fingerprint is invalid")]
    InvalidCredentialFingerprint,
    #[error("affinity binding identity is invalid")]
    InvalidAffinityBinding,
    #[error("management owner does not match the record owner")]
    OwnerMismatch,
    #[error("management record has expired")]
    RecordExpired,
    #[error("management record revision changed during update")]
    ManagementRevisionConflict,
    #[error("management record capacity is exhausted")]
    ManagementCapacity,
    #[error("management session already exists")]
    ManagementSessionAlreadyExists,
    #[error("OAuth flow already exists for this provider account")]
    OAuthFlowAlreadyExists,
    #[error("OAuth flow was not found")]
    OAuthFlowNotFound,
    #[error("OAuth flow state is invalid or already consumed")]
    OAuthStateConflict,
    #[error("managed secret was not found")]
    ManagedSecretNotFound,
    #[error("managed secret revision changed during update")]
    ManagedSecretRevisionConflict,
    #[error("managed secret payload is required to be encrypted")]
    ManagedSecretEncryptionRequired,
    #[error("database schema version {0} is newer than this Pooler binary")]
    UnsupportedSchemaVersion(i64),
    #[error("migration {version} failed: {message}")]
    Migration { version: i64, message: String },
    #[error("store lock poisoned")]
    LockPoisoned,
}

pub type StoreResult<T> = Result<T, StoreError>;

/// Storage seam for mutable credential, affinity, and decision state.
pub trait Store: Send + Sync {
    fn retention(&self) -> RetentionPolicy;

    /// Whether this metadata store and an OAuth token store use the same
    /// credential revision domain. Implementations that cannot prove shared
    /// transactional identity must return `false`.
    fn shares_credential_generation_domain(&self, _store: &SqliteStore) -> bool {
        false
    }

    fn upsert_credential_state(&self, state: CredentialState) -> StoreResult<CredentialState>;
    /// Atomically reconcile every candidate account identity at the runtime
    /// publication boundary. Any changed expectation aborts the whole batch.
    fn activate_credential_configurations(
        &self,
        activations: &[CredentialConfigurationActivation],
    ) -> StoreResult<Vec<ActivatedCredentialState>>;

    fn credential_state(&self, credential_id: &str) -> StoreResult<Option<CredentialState>>;
    fn credential_states(&self) -> StoreResult<Vec<CredentialState>>;
    fn set_credential_enabled(
        &self,
        credential_id: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState>;
    /// Enable or disable a credential only while its immutable configuration
    /// identity matches. Payload-generation changes do not invalidate this
    /// owner-directed metadata mutation.
    fn set_credential_enabled_if_identity(
        &self,
        identity: &CredentialConfigurationIdentity,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation>;

    fn set_credential_enabled_if_current(
        &self,
        credential_id: &str,
        expected_revision: u64,
        expected_provider_id: &str,
        expected_configuration_fingerprint: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation>;

    /// Enable or disable a credential only when its immutable identity and
    /// metadata revision still match and an encrypted payload generation newer
    /// than the caller's failed generation remains present at the mutation
    /// transaction. The metadata revision fences owner-directed changes between
    /// a stale-generation probe and this mutation.
    fn set_credential_enabled_if_newer_payload(
        &self,
        identity: &CredentialConfigurationIdentity,
        expected_metadata_revision: u64,
        previous_generation: u64,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation>;

    fn switch_credential(
        &self,
        selected: &str,
        siblings: &[String],
        updated_at: Timestamp,
    ) -> StoreResult<Vec<CredentialState>>;
    /// Atomically switch credentials only if every selected configuration
    /// identity still matches. `None` means one identity was stale or missing.
    fn switch_credential_if_identities(
        &self,
        selected: &CredentialConfigurationIdentity,
        siblings: &[CredentialConfigurationIdentity],
        updated_at: Timestamp,
    ) -> StoreResult<Option<Vec<CredentialState>>>;
    fn remove_credential_state(&self, credential_id: &str) -> StoreResult<bool>;

    fn upsert_credential_health(
        &self,
        state: CredentialHealthState,
    ) -> StoreResult<CredentialHealthState>;
    fn credential_health(&self, credential_id: &str) -> StoreResult<Option<CredentialHealthState>>;
    fn credential_health_states(&self) -> StoreResult<Vec<CredentialHealthState>>;

    fn upsert_cooldown(&self, state: CooldownState) -> StoreResult<CooldownState>;
    fn cooldown(
        &self,
        scope: &str,
        key: &str,
        now: Timestamp,
    ) -> StoreResult<Option<CooldownState>>;
    fn cooldowns(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>>;
    /// Read unexpired cooldowns without pruning durable state.
    fn cooldowns_snapshot(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>>;
    fn remove_cooldown(&self, scope: &str, key: &str) -> StoreResult<bool>;

    fn upsert_session_affinity(&self, affinity: SessionAffinity) -> StoreResult<SessionAffinity>;
    fn session_affinity(&self, key: &str, now: Timestamp) -> StoreResult<Option<SessionAffinity>>;
    fn session_affinities(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>>;
    /// Read unexpired affinities without pruning or updating last-used state.
    fn session_affinities_snapshot(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>>;
    fn remove_session_affinity(&self, key: &str) -> StoreResult<bool>;

    fn append_decision(&self, record: DecisionRecord) -> StoreResult<DecisionRecord>;
    fn decisions(&self) -> StoreResult<Vec<DecisionRecord>>;
    fn recent_decisions(&self, limit: usize) -> StoreResult<Vec<DecisionRecord>>;

    fn append_request_event(&self, event: RequestEvent) -> StoreResult<RequestEvent>;
    fn request_events(&self) -> StoreResult<Vec<RequestEvent>>;
    fn request_events_for(&self, request_id: &str) -> StoreResult<Vec<RequestEvent>>;

    fn append_usage_record(&self, record: UsageRecord) -> StoreResult<UsageRecord>;
    fn usage_records(&self) -> StoreResult<Vec<UsageRecord>>;
    fn prune(&self, now: Timestamp) -> StoreResult<PruneReport>;
}

#[derive(Debug, Default)]
struct Inner {
    credentials: BTreeMap<String, CredentialState>,
    credential_revision: u64,
    health: BTreeMap<String, CredentialHealthState>,
    cooldowns: BTreeMap<(String, String), CooldownState>,
    affinities: BTreeMap<String, SessionAffinity>,
    decisions: VecDeque<DecisionRecord>,
    request_events: VecDeque<RequestEvent>,
    usage_records: VecDeque<UsageRecord>,
    next_decision_id: u64,
    next_request_event_id: u64,
    next_usage_record_id: u64,
}

/// A deterministic, concurrency-safe in-memory [`Store`].
pub struct MemoryStore {
    retention: RetentionPolicy,
    inner: RwLock<Inner>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_retention(RetentionPolicy::default())
    }

    #[must_use]
    pub fn with_retention(retention: RetentionPolicy) -> Self {
        Self {
            retention,
            inner: RwLock::new(Inner::default()),
        }
    }

    pub fn len(&self) -> StoreResult<StoreLengths> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(StoreLengths {
            credentials: inner.credentials.len(),
            affinities: inner.affinities.len(),
            decisions: inner.decisions.len(),
            request_events: inner.request_events.len(),
            usage_records: inner.usage_records.len(),
        })
    }

    pub fn is_empty(&self) -> StoreResult<bool> {
        Ok(self.len()?.is_empty())
    }

    fn next_credential_revision(inner: &mut Inner, _credential_id: &str) -> StoreResult<u64> {
        inner.credential_revision = inner
            .credential_revision
            .checked_add(1)
            .ok_or(StoreError::CredentialRevisionConflict)?;
        Ok(inner.credential_revision)
    }

    fn validate_credential(state: &CredentialState) -> StoreResult<()> {
        non_empty("credential_id", &state.credential_id)?;
        non_empty("provider_id", &state.provider_id)?;
        validate_fingerprint(&state.configuration_fingerprint)
    }

    fn validate_affinity(affinity: &SessionAffinity) -> StoreResult<()> {
        non_empty("key", &affinity.key)?;
        non_empty("provider_id", &affinity.provider_id)?;
        non_empty("credential_id", &affinity.credential_id)?;
        non_empty("upstream_model", &affinity.upstream_model)
    }

    fn validate_decision(record: &DecisionRecord) -> StoreResult<()> {
        non_empty("request_id", &record.request_id)?;
        non_empty("route_id", &record.route_id)?;
        non_empty("model", &record.model)
    }

    pub(crate) fn validate_request_event(event: &RequestEvent) -> StoreResult<()> {
        non_empty("request_id", &event.request_id)?;
        non_empty("listener", &event.listener)?;
        non_empty("route_id", &event.route_id)?;
        if event.request_id.len() > 128
            || event.listener.len() > 128
            || event.route_id.len() > 128
            || event.semantic_losses.len() > 16
        {
            return Err(StoreError::Serialization(
                "request event exceeds metadata bounds".to_owned(),
            ));
        }
        for hash in [
            event.request_body_sha256.as_deref(),
            event.response_body_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if hash.len() != 64 || !hash.bytes().all(|value| value.is_ascii_hexdigit()) {
                return Err(StoreError::Serialization(
                    "request body hash must be a SHA-256 hex digest".to_owned(),
                ));
            }
        }
        for value in [
            event.public_model.as_deref(),
            event.upstream_model.as_deref(),
            event.provider.as_deref(),
            event.account_pseudonym.as_deref(),
            event.retry_reason.as_deref(),
            event.commitment.as_deref(),
            event.error_class.as_deref(),
            event.quota_effect.as_deref(),
            event.cooldown_effect.as_deref(),
            event.request_body_sha256.as_deref(),
            event.response_body_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        .chain(event.semantic_losses.iter().map(String::as_str))
        {
            if value.len() > 256 {
                return Err(StoreError::Serialization(
                    "request event field exceeds metadata bounds".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn evict_credentials(inner: &mut Inner, limit: usize) -> usize {
        let mut count = 0;
        while inner.credentials.len() > limit {
            let key = inner
                .credentials
                .values()
                .min_by(|left, right| {
                    (left.updated_at, &left.credential_id)
                        .cmp(&(right.updated_at, &right.credential_id))
                })
                .map(|state| state.credential_id.clone());
            if let Some(key) = key {
                inner.credentials.remove(&key);
                Self::purge_credential_dependents(inner, &key);
                count += 1;
            }
        }
        count
    }

    fn purge_credential_dependents(inner: &mut Inner, credential_id: &str) {
        inner.health.remove(credential_id);
        inner
            .affinities
            .retain(|_, affinity| affinity.credential_id != credential_id);
        inner.cooldowns.retain(|(scope, key), _| {
            !((scope == "credential" && key == credential_id)
                || (scope == "credential_model"
                    && Self::cooldown_belongs_to_credential(scope, key, credential_id)))
        });
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
        Some((
            String::from_utf8(bytes[..left_length].to_vec()).ok()?,
            String::from_utf8(bytes[left_length..].to_vec()).ok()?,
        ))
    }

    fn cooldown_credential_id(scope: &str, key: &str) -> Option<String> {
        match scope {
            "credential" => Some(key.to_owned()),
            "credential_model" => Self::decode_compound_cooldown_key(key)
                .map(|(credential_id, _)| credential_id)
                .or_else(|| {
                    (key.matches(':').count() == 1)
                        .then(|| {
                            key.split_once(':')
                                .map(|(credential_id, _)| credential_id.to_owned())
                        })
                        .flatten()
                }),
            _ => None,
        }
    }

    fn cooldown_belongs_to_credential(scope: &str, key: &str, credential_id: &str) -> bool {
        Self::cooldown_credential_id(scope, key).as_deref() == Some(credential_id)
    }

    fn require_cooldown_credential(inner: &Inner, scope: &str, key: &str) -> StoreResult<()> {
        let credential_id = Self::cooldown_credential_id(scope, key);
        if let Some(credential_id) = credential_id {
            if !inner.credentials.contains_key(&credential_id) {
                return Err(StoreError::CredentialNotFound(credential_id));
            }
        } else if matches!(scope, "credential" | "credential_model") {
            return Err(StoreError::CredentialNotFound(key.to_owned()));
        }
        Ok(())
    }

    fn purge_expired(inner: &mut Inner, now: Timestamp) -> usize {
        let keys: Vec<_> = inner
            .affinities
            .iter()
            .filter(|(_, affinity)| affinity.expired_at(now))
            .map(|(key, _)| key.clone())
            .collect();
        let count = keys.len();
        for key in keys {
            inner.affinities.remove(&key);
        }
        count
    }

    fn evict_affinities(inner: &mut Inner, limit: usize) -> usize {
        let mut count = 0;
        while inner.affinities.len() > limit {
            let key = inner
                .affinities
                .values()
                .min_by(|left, right| {
                    (left.last_used_at, left.created_at, &left.key).cmp(&(
                        right.last_used_at,
                        right.created_at,
                        &right.key,
                    ))
                })
                .map(|affinity| affinity.key.clone());
            if let Some(key) = key {
                inner.affinities.remove(&key);
                count += 1;
            }
        }
        count
    }

    fn evict_decisions(inner: &mut Inner, limit: usize) -> usize {
        let mut count = 0;
        while inner.decisions.len() > limit {
            if inner.decisions.pop_front().is_some() {
                count += 1;
            }
        }
        count
    }

    fn evict_request_events(inner: &mut Inner, limit: usize, cutoff: Timestamp) -> usize {
        let before = inner.request_events.len();
        inner
            .request_events
            .retain(|event| event.recorded_at >= cutoff);
        while inner.request_events.len() > limit {
            inner.request_events.pop_front();
        }
        before.saturating_sub(inner.request_events.len())
    }

    fn purge_expired_cooldowns(inner: &mut Inner, now: Timestamp) {
        inner.cooldowns.retain(|_, cooldown| cooldown.until > now);
    }

    fn reconcile_credential_health(
        inner: &mut Inner,
        credential_id: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) {
        if enabled {
            if let Some(health) = inner.health.get_mut(credential_id) {
                if health.status == CredentialHealthStatus::Disabled {
                    health.status = CredentialHealthStatus::Healthy;
                    health.cooldown_until = None;
                    health.updated_at = updated_at;
                }
            }
        } else {
            inner.health.insert(
                credential_id.to_owned(),
                CredentialHealthState {
                    credential_id: credential_id.to_owned(),
                    status: CredentialHealthStatus::Disabled,
                    failure_count: 0,
                    cooldown_until: None,
                    updated_at,
                },
            );
        }
    }

    fn evict_cooldowns(inner: &mut Inner) {
        while inner.cooldowns.len() > 4_096 {
            let key = inner
                .cooldowns
                .iter()
                .min_by(|(_, left), (_, right)| {
                    (left.updated_at, &left.scope, &left.key).cmp(&(
                        right.updated_at,
                        &right.scope,
                        &right.key,
                    ))
                })
                .map(|(key, _)| key.clone());
            if let Some(key) = key {
                inner.cooldowns.remove(&key);
            } else {
                break;
            }
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for MemoryStore {
    fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    fn upsert_credential_state(&self, mut state: CredentialState) -> StoreResult<CredentialState> {
        Self::validate_credential(&state)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        let identity_changed = if let Some(previous) = inner.credentials.get(&state.credential_id) {
            if state.configuration_fingerprint.is_empty() {
                state.configuration_fingerprint = previous.configuration_fingerprint.clone();
            }
            previous.provider_id != state.provider_id
                || previous.configuration_fingerprint != state.configuration_fingerprint
        } else {
            false
        };
        if identity_changed {
            Self::purge_credential_dependents(&mut inner, &state.credential_id);
        }
        state.revision = Self::next_credential_revision(&mut inner, &state.credential_id)?;
        inner
            .credentials
            .insert(state.credential_id.clone(), state.clone());
        if !state.enabled {
            inner.health.insert(
                state.credential_id.clone(),
                CredentialHealthState {
                    credential_id: state.credential_id.clone(),
                    status: CredentialHealthStatus::Disabled,
                    failure_count: 0,
                    cooldown_until: None,
                    updated_at: state.updated_at,
                },
            );
        }
        Self::evict_credentials(&mut inner, self.retention.max_credentials);
        Ok(state)
    }

    fn activate_credential_configurations(
        &self,
        activations: &[CredentialConfigurationActivation],
    ) -> StoreResult<Vec<ActivatedCredentialState>> {
        let mut credential_ids = BTreeSet::new();
        for activation in activations {
            Self::validate_credential(activation.desired())?;
            if activation.retirement().is_some()
                || !credential_ids.insert(activation.desired().credential_id.as_str())
            {
                return Err(StoreError::CredentialFingerprintConflict);
            }
        }

        let mut inner = self.inner.write().map_err(lock_error)?;
        for activation in activations {
            if inner.credentials.get(&activation.desired().credential_id) != activation.expected() {
                return Err(StoreError::CredentialRevisionConflict);
            }
        }

        let writes = activations
            .iter()
            .filter(|activation| {
                let desired = activation.desired();
                inner
                    .credentials
                    .get(&desired.credential_id)
                    .is_none_or(|current| {
                        current.provider_id != desired.provider_id
                            || current.configuration_fingerprint
                                != desired.configuration_fingerprint
                    })
            })
            .count();
        inner
            .credential_revision
            .checked_add(u64::try_from(writes).unwrap_or(u64::MAX))
            .ok_or(StoreError::CredentialRevisionConflict)?;

        let mut activated = Vec::with_capacity(activations.len());
        for activation in activations {
            let desired = activation.desired();
            let current = inner.credentials.get(&desired.credential_id).cloned();
            let exact_identity = current.as_ref().is_some_and(|state| {
                state.provider_id == desired.provider_id
                    && state.configuration_fingerprint == desired.configuration_fingerprint
            });
            let state = if exact_identity {
                current.expect("exact identity requires a current credential")
            } else {
                let safe_legacy_identity = current.as_ref().is_some_and(|state| {
                    state.provider_id == desired.provider_id
                        && state.configuration_fingerprint.is_empty()
                });
                if current.is_some() {
                    Self::purge_credential_dependents(&mut inner, &desired.credential_id);
                }
                let revision = Self::next_credential_revision(&mut inner, &desired.credential_id)?;
                let state = CredentialState {
                    enabled: if safe_legacy_identity {
                        current.as_ref().is_some_and(|state| state.enabled)
                    } else {
                        desired.enabled
                    },
                    revision,
                    ..desired.clone()
                };
                inner
                    .credentials
                    .insert(state.credential_id.clone(), state.clone());
                if !state.enabled {
                    inner.health.insert(
                        state.credential_id.clone(),
                        CredentialHealthState {
                            credential_id: state.credential_id.clone(),
                            status: CredentialHealthStatus::Disabled,
                            failure_count: 0,
                            cooldown_until: None,
                            updated_at: state.updated_at,
                        },
                    );
                }
                state
            };
            let health_disabled = inner
                .health
                .get(&state.credential_id)
                .is_some_and(|health| health.status == CredentialHealthStatus::Disabled);
            activated.push(ActivatedCredentialState::new(state, health_disabled));
        }
        Self::evict_credentials(&mut inner, self.retention.max_credentials);
        Ok(activated)
    }

    fn credential_state(&self, credential_id: &str) -> StoreResult<Option<CredentialState>> {
        non_empty("credential_id", credential_id)?;
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.credentials.get(credential_id).cloned())
    }

    fn credential_states(&self) -> StoreResult<Vec<CredentialState>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.credentials.values().cloned().collect())
    }

    fn set_credential_enabled(
        &self,
        credential_id: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        non_empty("credential_id", credential_id)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        if !inner.credentials.contains_key(credential_id) {
            return Err(StoreError::CredentialNotFound(credential_id.to_owned()));
        }
        let revision = Self::next_credential_revision(&mut inner, credential_id)?;
        let state = {
            let state = inner
                .credentials
                .get_mut(credential_id)
                .expect("credential existence checked while write lock is held");
            state.enabled = enabled;
            state.updated_at = updated_at;
            state.revision = revision;
            state.clone()
        };
        if !enabled {
            inner.health.insert(
                credential_id.to_owned(),
                CredentialHealthState {
                    credential_id: credential_id.to_owned(),
                    status: CredentialHealthStatus::Disabled,
                    failure_count: 0,
                    cooldown_until: None,
                    updated_at,
                },
            );
        } else if let Some(health) = inner.health.get_mut(credential_id) {
            if health.status == CredentialHealthStatus::Disabled {
                health.status = CredentialHealthStatus::Healthy;
                health.cooldown_until = None;
                health.updated_at = updated_at;
            }
        }
        Ok(state)
    }

    fn set_credential_enabled_if_identity(
        &self,
        identity: &CredentialConfigurationIdentity,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation> {
        let credential_id = identity.credential_id();
        let mut inner = self.inner.write().map_err(lock_error)?;
        let Some(current) = inner.credentials.get(credential_id).cloned() else {
            return Ok(ConditionalCredentialMutation::Missing);
        };
        if !identity.matches(&current) {
            return Ok(ConditionalCredentialMutation::Stale {
                current,
                credential_payload_present: None,
                credential_payload_generation: None,
            });
        }
        Self::reconcile_credential_health(&mut inner, credential_id, enabled, updated_at);
        if current.enabled == enabled {
            return Ok(ConditionalCredentialMutation::Applied(current));
        }
        let revision = Self::next_credential_revision(&mut inner, credential_id)?;
        let state = {
            let state = inner
                .credentials
                .get_mut(credential_id)
                .expect("credential identity checked while write lock is held");
            state.enabled = enabled;
            state.updated_at = updated_at;
            state.revision = revision;
            state.clone()
        };
        Ok(ConditionalCredentialMutation::Applied(state))
    }

    fn set_credential_enabled_if_current(
        &self,
        credential_id: &str,
        expected_revision: u64,
        expected_provider_id: &str,
        expected_configuration_fingerprint: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation> {
        non_empty("credential_id", credential_id)?;
        non_empty("expected_provider_id", expected_provider_id)?;
        validate_fingerprint(expected_configuration_fingerprint)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        let Some(current) = inner.credentials.get(credential_id).cloned() else {
            return Ok(ConditionalCredentialMutation::Missing);
        };
        if current.revision != expected_revision
            || current.provider_id != expected_provider_id
            || current.configuration_fingerprint != expected_configuration_fingerprint
        {
            return Ok(ConditionalCredentialMutation::Stale {
                current,
                credential_payload_present: None,
                credential_payload_generation: None,
            });
        }
        Self::reconcile_credential_health(&mut inner, credential_id, enabled, updated_at);
        if current.enabled == enabled {
            return Ok(ConditionalCredentialMutation::Applied(current));
        }
        let revision = Self::next_credential_revision(&mut inner, credential_id)?;
        let state = {
            let state = inner
                .credentials
                .get_mut(credential_id)
                .expect("credential existence checked while write lock is held");
            state.enabled = enabled;
            state.updated_at = updated_at;
            state.revision = revision;
            state.clone()
        };
        Ok(ConditionalCredentialMutation::Applied(state))
    }

    fn set_credential_enabled_if_newer_payload(
        &self,
        identity: &CredentialConfigurationIdentity,
        _expected_metadata_revision: u64,
        _previous_generation: u64,
        _enabled: bool,
        _updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation> {
        let inner = self.inner.read().map_err(lock_error)?;
        let Some(current) = inner.credentials.get(identity.credential_id()).cloned() else {
            return Ok(ConditionalCredentialMutation::Missing);
        };
        Ok(ConditionalCredentialMutation::Stale {
            current,
            credential_payload_present: Some(false),
            credential_payload_generation: None,
        })
    }

    fn switch_credential(
        &self,
        selected: &str,
        siblings: &[String],
        updated_at: Timestamp,
    ) -> StoreResult<Vec<CredentialState>> {
        non_empty("selected", selected)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        if !inner.credentials.contains_key(selected) {
            return Err(StoreError::CredentialNotFound(selected.to_owned()));
        }
        for sibling in siblings {
            non_empty("sibling", sibling)?;
            if !inner.credentials.contains_key(sibling) {
                return Err(StoreError::CredentialNotFound(sibling.clone()));
            }
        }
        let mut states = Vec::with_capacity(siblings.len().saturating_add(1));
        for (credential_id, enabled) in std::iter::once((selected, true)).chain(
            siblings
                .iter()
                .filter(|sibling| sibling.as_str() != selected)
                .map(|sibling| (sibling.as_str(), false)),
        ) {
            let changed = inner
                .credentials
                .get(credential_id)
                .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?
                .enabled
                != enabled;
            let revision = changed
                .then(|| Self::next_credential_revision(&mut inner, credential_id))
                .transpose()?;
            let state = inner
                .credentials
                .get_mut(credential_id)
                .expect("credential existence checked while write lock is held");
            if let Some(revision) = revision {
                state.enabled = enabled;
                state.updated_at = updated_at;
                state.revision = revision;
            }
            states.push(state.clone());
            if enabled {
                if let Some(health) = inner.health.get_mut(credential_id) {
                    if health.status == CredentialHealthStatus::Disabled {
                        health.status = CredentialHealthStatus::Healthy;
                        health.cooldown_until = None;
                        health.updated_at = updated_at;
                    }
                }
            } else {
                inner.health.insert(
                    credential_id.to_owned(),
                    CredentialHealthState {
                        credential_id: credential_id.to_owned(),
                        status: CredentialHealthStatus::Disabled,
                        failure_count: 0,
                        cooldown_until: None,
                        updated_at,
                    },
                );
            }
        }
        Ok(states)
    }

    fn switch_credential_if_identities(
        &self,
        selected: &CredentialConfigurationIdentity,
        siblings: &[CredentialConfigurationIdentity],
        updated_at: Timestamp,
    ) -> StoreResult<Option<Vec<CredentialState>>> {
        let mut inner = self.inner.write().map_err(lock_error)?;
        for identity in std::iter::once(selected).chain(siblings) {
            let Some(current) = inner.credentials.get(identity.credential_id()) else {
                return Ok(None);
            };
            if !identity.matches(current) {
                return Ok(None);
            }
        }

        let mut states = Vec::with_capacity(siblings.len().saturating_add(1));
        for (identity, enabled) in std::iter::once((selected, true)).chain(
            siblings
                .iter()
                .filter(|sibling| sibling.credential_id() != selected.credential_id())
                .map(|sibling| (sibling, false)),
        ) {
            let credential_id = identity.credential_id();
            let changed = inner
                .credentials
                .get(credential_id)
                .expect("credential identities checked while write lock is held")
                .enabled
                != enabled;
            let revision = changed
                .then(|| Self::next_credential_revision(&mut inner, credential_id))
                .transpose()?;
            let state = inner
                .credentials
                .get_mut(credential_id)
                .expect("credential identities checked while write lock is held");
            if let Some(revision) = revision {
                state.enabled = enabled;
                state.updated_at = updated_at;
                state.revision = revision;
            }
            states.push(state.clone());
            if enabled {
                if let Some(health) = inner.health.get_mut(credential_id) {
                    if health.status == CredentialHealthStatus::Disabled {
                        health.status = CredentialHealthStatus::Healthy;
                        health.cooldown_until = None;
                        health.updated_at = updated_at;
                    }
                }
            } else {
                inner.health.insert(
                    credential_id.to_owned(),
                    CredentialHealthState {
                        credential_id: credential_id.to_owned(),
                        status: CredentialHealthStatus::Disabled,
                        failure_count: 0,
                        cooldown_until: None,
                        updated_at,
                    },
                );
            }
        }
        Ok(Some(states))
    }

    fn remove_credential_state(&self, credential_id: &str) -> StoreResult<bool> {
        non_empty("credential_id", credential_id)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        let removed = inner.credentials.remove(credential_id).is_some();
        Self::purge_credential_dependents(&mut inner, credential_id);
        Ok(removed)
    }

    fn upsert_credential_health(
        &self,
        state: CredentialHealthState,
    ) -> StoreResult<CredentialHealthState> {
        non_empty("credential_id", &state.credential_id)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        if !inner.credentials.contains_key(&state.credential_id) {
            return Err(StoreError::CredentialNotFound(state.credential_id));
        }
        inner
            .health
            .insert(state.credential_id.clone(), state.clone());
        Ok(state)
    }

    fn credential_health(&self, credential_id: &str) -> StoreResult<Option<CredentialHealthState>> {
        non_empty("credential_id", credential_id)?;
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.health.get(credential_id).cloned())
    }

    fn credential_health_states(&self) -> StoreResult<Vec<CredentialHealthState>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.health.values().cloned().collect())
    }

    fn upsert_cooldown(&self, state: CooldownState) -> StoreResult<CooldownState> {
        non_empty("scope", &state.scope)?;
        non_empty("key", &state.key)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        Self::require_cooldown_credential(&inner, &state.scope, &state.key)?;
        let key = (state.scope.clone(), state.key.clone());
        if let Some(previous) = inner.cooldowns.get(&key) {
            if previous.until > state.until {
                return Ok(previous.clone());
            }
        }
        inner.cooldowns.insert(key, state.clone());
        Self::evict_cooldowns(&mut inner);
        Ok(state)
    }

    fn cooldown(
        &self,
        scope: &str,
        key: &str,
        now: Timestamp,
    ) -> StoreResult<Option<CooldownState>> {
        non_empty("scope", scope)?;
        non_empty("key", key)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        Self::purge_expired_cooldowns(&mut inner, now);
        Ok(inner
            .cooldowns
            .get(&(scope.to_owned(), key.to_owned()))
            .cloned())
    }

    fn cooldowns(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>> {
        let mut inner = self.inner.write().map_err(lock_error)?;
        Self::purge_expired_cooldowns(&mut inner, now);
        Ok(inner.cooldowns.values().cloned().collect())
    }

    fn cooldowns_snapshot(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner
            .cooldowns
            .values()
            .filter(|cooldown| cooldown.until > now)
            .cloned()
            .collect())
    }

    fn remove_cooldown(&self, scope: &str, key: &str) -> StoreResult<bool> {
        non_empty("scope", scope)?;
        non_empty("key", key)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        Ok(inner
            .cooldowns
            .remove(&(scope.to_owned(), key.to_owned()))
            .is_some())
    }

    fn upsert_session_affinity(&self, affinity: SessionAffinity) -> StoreResult<SessionAffinity> {
        Self::validate_affinity(&affinity)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        if !inner.credentials.contains_key(&affinity.credential_id) {
            return Err(StoreError::CredentialNotFound(affinity.credential_id));
        }
        inner
            .affinities
            .insert(affinity.key.clone(), affinity.clone());
        Self::purge_expired(&mut inner, affinity.created_at);
        Self::evict_affinities(&mut inner, self.retention.max_affinities);
        Ok(affinity)
    }

    fn session_affinity(&self, key: &str, now: Timestamp) -> StoreResult<Option<SessionAffinity>> {
        non_empty("key", key)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        Self::purge_expired(&mut inner, now);
        Ok(inner.affinities.get_mut(key).map(|affinity| {
            affinity.last_used_at = affinity.last_used_at.max(now);
            affinity.clone()
        }))
    }

    fn session_affinities(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>> {
        let mut inner = self.inner.write().map_err(lock_error)?;
        Self::purge_expired(&mut inner, now);
        Ok(inner.affinities.values().cloned().collect())
    }

    fn session_affinities_snapshot(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner
            .affinities
            .values()
            .filter(|affinity| affinity.expires_at > now)
            .cloned()
            .collect())
    }

    fn remove_session_affinity(&self, key: &str) -> StoreResult<bool> {
        non_empty("key", key)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        Ok(inner.affinities.remove(key).is_some())
    }

    fn append_decision(&self, mut record: DecisionRecord) -> StoreResult<DecisionRecord> {
        Self::validate_decision(&record)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        let id = if inner.next_decision_id == 0 {
            1
        } else {
            inner
                .next_decision_id
                .checked_add(1)
                .ok_or(StoreError::DecisionIdExhausted)?
        };
        inner.next_decision_id = id;
        record.id = id;
        inner.decisions.push_back(record.clone());
        Self::evict_decisions(&mut inner, self.retention.max_decisions);
        Ok(record)
    }

    fn decisions(&self) -> StoreResult<Vec<DecisionRecord>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.decisions.iter().cloned().collect())
    }

    fn recent_decisions(&self, limit: usize) -> StoreResult<Vec<DecisionRecord>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.decisions.iter().rev().take(limit).cloned().collect())
    }

    fn append_request_event(&self, mut event: RequestEvent) -> StoreResult<RequestEvent> {
        Self::validate_request_event(&event)?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        let id = if inner.next_request_event_id == 0 {
            1
        } else {
            inner
                .next_request_event_id
                .checked_add(1)
                .ok_or(StoreError::RequestEventIdExhausted)?
        };
        inner.next_request_event_id = id;
        event.id = id;
        inner.request_events.push_back(event.clone());

        let matching = inner
            .request_events
            .iter()
            .filter(|candidate| candidate.request_id == event.request_id)
            .map(|candidate| (candidate.event_index, candidate.id))
            .collect::<Vec<_>>();
        if matching.len() > MAX_REQUEST_EVENTS_PER_REQUEST {
            let mut keep = matching;
            keep.sort_unstable_by(|left, right| right.cmp(left));
            keep.truncate(MAX_REQUEST_EVENTS_PER_REQUEST);
            inner.request_events.retain(|candidate| {
                candidate.request_id != event.request_id
                    || keep.contains(&(candidate.event_index, candidate.id))
            });
        }
        let cutoff = event
            .recorded_at
            .saturating_sub(self.retention.request_history_ttl_ms);
        Self::evict_request_events(&mut inner, self.retention.max_request_events, cutoff);
        Ok(event)
    }

    fn request_events(&self) -> StoreResult<Vec<RequestEvent>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.request_events.iter().cloned().collect())
    }

    fn request_events_for(&self, request_id: &str) -> StoreResult<Vec<RequestEvent>> {
        non_empty("request_id", request_id)?;
        let inner = self.inner.read().map_err(lock_error)?;
        let mut events = inner
            .request_events
            .iter()
            .filter(|event| event.request_id == request_id)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by_key(|event| (event.event_index, event.id));
        Ok(events)
    }

    fn append_usage_record(&self, mut record: UsageRecord) -> StoreResult<UsageRecord> {
        record.validate()?;
        let mut inner = self.inner.write().map_err(lock_error)?;
        let id = if inner.next_usage_record_id == 0 {
            1
        } else {
            inner
                .next_usage_record_id
                .checked_add(1)
                .ok_or(StoreError::UsageRecordIdExhausted)?
        };
        inner.next_usage_record_id = id;
        record.id = id;
        inner.usage_records.push_back(record.clone());
        let newest_recorded_at = inner
            .usage_records
            .iter()
            .map(|candidate| candidate.recorded_at)
            .max()
            .unwrap_or(record.recorded_at);
        let cutoff = newest_recorded_at.saturating_sub(self.retention.usage_history_ttl_ms);
        inner
            .usage_records
            .retain(|candidate| candidate.recorded_at >= cutoff);
        while inner.usage_records.len() > self.retention.max_usage_records {
            inner.usage_records.pop_front();
        }
        Ok(record)
    }

    fn usage_records(&self) -> StoreResult<Vec<UsageRecord>> {
        let inner = self.inner.read().map_err(lock_error)?;
        Ok(inner.usage_records.iter().cloned().collect())
    }

    fn prune(&self, now: Timestamp) -> StoreResult<PruneReport> {
        let mut inner = self.inner.write().map_err(lock_error)?;
        Self::purge_expired_cooldowns(&mut inner, now);
        Ok(PruneReport {
            expired_affinities: Self::purge_expired(&mut inner, now),
            evicted_credentials: Self::evict_credentials(
                &mut inner,
                self.retention.max_credentials,
            ),
            evicted_affinities: Self::evict_affinities(&mut inner, self.retention.max_affinities),
            evicted_decisions: Self::evict_decisions(&mut inner, self.retention.max_decisions),
            evicted_request_events: Self::evict_request_events(
                &mut inner,
                self.retention.max_request_events,
                now.saturating_sub(self.retention.request_history_ttl_ms),
            ),
            evicted_usage_records: {
                let before = inner.usage_records.len();
                let cutoff = now.saturating_sub(self.retention.usage_history_ttl_ms);
                inner
                    .usage_records
                    .retain(|record| record.recorded_at >= cutoff);
                while inner.usage_records.len() > self.retention.max_usage_records {
                    inner.usage_records.pop_front();
                }
                before.saturating_sub(inner.usage_records.len())
            },
        })
    }
}

fn non_empty(field: &'static str, value: &str) -> StoreResult<()> {
    if value.is_empty() {
        Err(StoreError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn lock_error<T>(_: PoisonError<T>) -> StoreError {
    StoreError::LockPoisoned
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn policy(credentials: usize, affinities: usize, decisions: usize) -> RetentionPolicy {
        RetentionPolicy::new(credentials, affinities, decisions).expect("valid policy")
    }

    fn affinity(key: &str, created_at: Timestamp, expires_at: Timestamp) -> SessionAffinity {
        SessionAffinity::new(
            key,
            "provider",
            "credential",
            "model",
            created_at,
            expires_at,
        )
    }

    #[test]
    fn credential_fingerprint_covers_oauth_identity_and_normalizes_scope_order() {
        let baseline = CredentialFingerprintInput {
            account_id: "account".to_owned(),
            provider_instance_id: "provider".to_owned(),
            provider_origin: "https://api.example.test/".to_owned(),
            auth_kind: "oauth".to_owned(),
            provider_profile: "codex".to_owned(),
            oauth_client_id: Some("client".to_owned()),
            oauth_grant_type: Some("authorization_code".to_owned()),
            oauth_scopes: vec!["openid".to_owned(), "profile".to_owned()],
            authorization_endpoint: Some("https://auth.example.test/authorize".to_owned()),
            token_endpoint: Some("https://auth.example.test/token".to_owned()),
            revocation_endpoint: Some("https://auth.example.test/revoke".to_owned()),
            identity_endpoint: Some("https://auth.example.test/me".to_owned()),
            callback_endpoint: Some("http://127.0.0.1:8787/callback".to_owned()),
            oauth_client_secret_reference: Some("env:OAUTH_CLIENT_SECRET".to_owned()),
            oauth_additional_identity: Vec::new(),
            auth_placement: "bearer_secret".to_owned(),
        };
        let expected = baseline.fingerprint().expect("baseline fingerprint");

        let reordered = CredentialFingerprintInput {
            oauth_scopes: vec!["profile".to_owned(), "openid".to_owned()],
            ..baseline.clone()
        };
        assert_eq!(reordered.fingerprint().expect("reordered scopes"), expected);

        let provider_behavior = CredentialFingerprintInput {
            oauth_additional_identity: vec![
                ("request_encoding".to_owned(), "form".to_owned()),
                ("device_grant".to_owned(), "codex_accounts".to_owned()),
            ],
            ..baseline.clone()
        };
        let reordered_provider_behavior = CredentialFingerprintInput {
            oauth_additional_identity: vec![
                ("device_grant".to_owned(), "codex_accounts".to_owned()),
                ("request_encoding".to_owned(), "form".to_owned()),
            ],
            ..baseline.clone()
        };
        let provider_behavior_fingerprint = provider_behavior
            .fingerprint()
            .expect("provider behavior fingerprint");
        assert_ne!(provider_behavior_fingerprint, expected);
        assert_eq!(
            reordered_provider_behavior
                .fingerprint()
                .expect("reordered provider behavior"),
            provider_behavior_fingerprint
        );

        let variants = [
            CredentialFingerprintInput {
                oauth_scopes: vec!["openid".to_owned(), "email".to_owned()],
                ..baseline.clone()
            },
            CredentialFingerprintInput {
                revocation_endpoint: Some("https://auth.example.test/revoke-v2".to_owned()),
                ..baseline.clone()
            },
            CredentialFingerprintInput {
                identity_endpoint: Some("https://auth.example.test/userinfo".to_owned()),
                ..baseline.clone()
            },
            CredentialFingerprintInput {
                callback_endpoint: Some("http://127.0.0.1:8788/callback".to_owned()),
                ..baseline.clone()
            },
            CredentialFingerprintInput {
                oauth_additional_identity: vec![("request_encoding".to_owned(), "json".to_owned())],
                ..baseline.clone()
            },
            CredentialFingerprintInput {
                oauth_client_secret_reference: Some("env:OTHER_CLIENT_SECRET".to_owned()),
                ..baseline
            },
        ];
        for variant in variants {
            assert_ne!(
                variant.fingerprint().expect("variant fingerprint"),
                expected
            );
        }
    }

    #[test]
    fn api_key_fingerprint_remains_on_the_version_one_identity() {
        let input = CredentialFingerprintInput {
            account_id: "account".to_owned(),
            provider_instance_id: "provider".to_owned(),
            provider_origin: "https://api.example.test/".to_owned(),
            auth_kind: "api_key".to_owned(),
            provider_profile: "compatible".to_owned(),
            oauth_client_id: Some("unused-client".to_owned()),
            oauth_grant_type: Some("authorization_code".to_owned()),
            oauth_scopes: vec!["unused-scope".to_owned()],
            authorization_endpoint: Some("https://auth.example.test/authorize".to_owned()),
            token_endpoint: Some("https://auth.example.test/token".to_owned()),
            revocation_endpoint: Some("https://auth.example.test/revoke".to_owned()),
            identity_endpoint: Some("https://auth.example.test/me".to_owned()),
            callback_endpoint: Some("http://127.0.0.1:8787/callback".to_owned()),
            oauth_client_secret_reference: Some("env:UNUSED_SECRET".to_owned()),
            oauth_additional_identity: vec![("ignored".to_owned(), "value".to_owned())],
            auth_placement: "bearer_secret".to_owned(),
        };

        assert_eq!(
            input.fingerprint().expect("current fingerprint"),
            input.legacy_fingerprint().expect("legacy fingerprint")
        );
    }

    #[test]
    fn credentials_are_versioned_sorted_and_bounded() {
        let store = MemoryStore::with_retention(policy(2, 2, 2));
        for id in ["z", "a", "b"] {
            store
                .upsert_credential_state(CredentialState::new(id, "provider", true, 1))
                .expect("insert succeeds");
        }
        let states = store.credential_states().expect("list succeeds");
        assert_eq!(
            states
                .iter()
                .map(|state| state.credential_id.as_str())
                .collect::<Vec<_>>(),
            ["b", "z"]
        );
        assert_eq!(states[1].revision, 1);
        let latest_revision = states
            .iter()
            .map(|state| state.revision)
            .max()
            .expect("retained credential revision");
        let updated = store
            .set_credential_enabled("z", false, 2)
            .expect("toggle succeeds");
        assert!(!updated.enabled);
        assert!(updated.revision > latest_revision);
    }

    #[test]
    fn conditional_enablement_rejects_stale_generation_and_identity() {
        let store = MemoryStore::new();
        let fingerprint = "a".repeat(64);
        let inserted = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                1,
            ))
            .expect("credential insert");
        assert_eq!(inserted.revision, 1);

        let replacement_fingerprint = "b".repeat(64);
        for (revision, provider, candidate_fingerprint) in [
            (0, "provider", fingerprint.as_str()),
            (1, "replacement-provider", fingerprint.as_str()),
            (1, "provider", replacement_fingerprint.as_str()),
        ] {
            assert!(matches!(
                store
                    .set_credential_enabled_if_current(
                        "credential",
                        revision,
                        provider,
                        candidate_fingerprint,
                        false,
                        2,
                    )
                    .expect("conditional mutation"),
                ConditionalCredentialMutation::Stale { .. }
            ));
        }
        assert!(
            store
                .credential_state("credential")
                .expect("credential state")
                .expect("credential exists")
                .enabled
        );

        let disabled = store
            .set_credential_enabled_if_current("credential", 1, "provider", &fingerprint, false, 3)
            .expect("current generation disables")
            .into_applied()
            .expect("fence matches");
        assert!(!disabled.enabled);
        assert_eq!(disabled.revision, 2);
        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "credential",
                    1,
                    "provider",
                    &fingerprint,
                    false,
                    4,
                )
                .expect("stale repeated mutation"),
            ConditionalCredentialMutation::Stale { .. }
        ));
        assert_eq!(
            store
                .credential_state("credential")
                .expect("credential state")
                .expect("credential exists")
                .revision,
            2
        );
        assert!(store
            .remove_credential_state("credential")
            .expect("remove credential"));
        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "credential",
                    2,
                    "provider",
                    &fingerprint,
                    false,
                    5,
                )
                .expect("missing conditional mutation is stale"),
            ConditionalCredentialMutation::Missing
        ));
    }

    #[test]
    fn credential_revision_clock_remains_constant_space_after_unique_deletions() {
        let store = MemoryStore::new();
        for index in 0..256 {
            let credential_id = format!("credential-{index}");
            store
                .upsert_credential_state(CredentialState::new(
                    &credential_id,
                    "provider",
                    true,
                    index,
                ))
                .expect("credential insert");
            assert!(store
                .remove_credential_state(&credential_id)
                .expect("credential removal"));
        }
        let inner = store.inner.read().expect("store lock");
        assert!(inner.credentials.is_empty());
        assert_eq!(inner.credential_revision, 256);
    }

    #[test]
    fn credential_generation_is_not_reused_after_removal() {
        let store = MemoryStore::new();
        let fingerprint = "a".repeat(64);
        let first = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                1,
            ))
            .expect("first credential incarnation");
        let old_generation = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                2,
            ))
            .expect("advance first incarnation")
            .revision;
        assert!(old_generation > first.revision);
        assert!(store
            .remove_credential_state("credential")
            .expect("remove first incarnation"));

        let recreated = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                3,
            ))
            .expect("recreate credential");
        assert!(recreated.revision > old_generation);
        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "credential",
                    old_generation,
                    "provider",
                    &fingerprint,
                    false,
                    4,
                )
                .expect("stale mutation"),
            ConditionalCredentialMutation::Stale { .. }
        ));
        assert!(
            store
                .credential_state("credential")
                .expect("credential state")
                .expect("recreated credential exists")
                .enabled
        );
    }

    #[test]
    fn credential_removal_purges_health_affinity_and_cooldowns() {
        let store = MemoryStore::new();
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_credential_health(CredentialHealthState::new(
                "credential",
                CredentialHealthStatus::CoolingDown,
                2,
            ))
            .expect("health");
        store
            .upsert_session_affinity(SessionAffinity::new(
                "session",
                "provider",
                "credential",
                "model",
                1,
                100,
            ))
            .expect("affinity");
        store
            .upsert_cooldown(CooldownState::new("credential", "credential", 100, 2))
            .expect("cooldown");
        store
            .upsert_cooldown(CooldownState::new(
                "credential_model",
                "credential:model",
                100,
                2,
            ))
            .expect("model cooldown");

        assert!(store
            .remove_credential_state("credential")
            .expect("remove credential"));
        assert!(store
            .credential_health("credential")
            .expect("health lookup")
            .is_none());
        assert!(store
            .session_affinity("session", 2)
            .expect("affinity lookup")
            .is_none());
        assert!(store
            .cooldown("credential", "credential", 2)
            .expect("cooldown lookup")
            .is_none());
        assert!(store
            .cooldown("credential_model", "credential:model", 2)
            .expect("model cooldown lookup")
            .is_none());
        assert_eq!(
            store.upsert_credential_health(CredentialHealthState::new(
                "credential",
                CredentialHealthStatus::Healthy,
                3,
            )),
            Err(StoreError::CredentialNotFound("credential".to_owned()))
        );
        assert_eq!(
            store.upsert_cooldown(CooldownState::new("credential", "credential", 100, 3)),
            Err(StoreError::CredentialNotFound("credential".to_owned()))
        );
        assert_eq!(
            store.upsert_session_affinity(SessionAffinity::new(
                "late-session",
                "provider",
                "credential",
                "model",
                3,
                100,
            )),
            Err(StoreError::CredentialNotFound("credential".to_owned()))
        );

        let collision_store = MemoryStore::new();
        collision_store
            .upsert_credential_state(CredentialState::new("a", "provider", true, 1))
            .expect("short credential");
        collision_store
            .upsert_credential_state(CredentialState::new("a:b", "provider", true, 1))
            .expect("long credential");
        collision_store
            .upsert_cooldown(CooldownState::new(
                "credential_model",
                "v2:3:5:a:bmodel",
                100,
                1,
            ))
            .expect("long credential cooldown");
        collision_store
            .remove_credential_state("a")
            .expect("remove short credential");
        assert!(collision_store
            .cooldown("credential_model", "v2:3:5:a:bmodel", 2)
            .expect("long cooldown lookup")
            .is_some());
        collision_store
            .remove_credential_state("a:b")
            .expect("remove long credential");
        assert!(collision_store
            .cooldown("credential_model", "v2:3:5:a:bmodel", 2)
            .expect("removed cooldown lookup")
            .is_none());
    }

    #[test]
    fn memory_identity_fences_enablement_and_atomic_switches() {
        let store = MemoryStore::new();
        let current_fingerprint = "a".repeat(64);
        let stale_fingerprint = "b".repeat(64);
        for (credential_id, enabled) in [("primary", false), ("backup", true)] {
            store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    credential_id,
                    "provider",
                    &current_fingerprint,
                    enabled,
                    1,
                ))
                .expect("credential");
        }
        let primary =
            CredentialConfigurationIdentity::new("primary", "provider", &current_fingerprint)
                .expect("primary identity");
        let backup =
            CredentialConfigurationIdentity::new("backup", "provider", &current_fingerprint)
                .expect("backup identity");
        let stale_primary =
            CredentialConfigurationIdentity::new("primary", "provider", &stale_fingerprint)
                .expect("stale primary identity");
        let stale_backup =
            CredentialConfigurationIdentity::new("backup", "provider", &stale_fingerprint)
                .expect("stale backup identity");

        assert!(matches!(
            store
                .set_credential_enabled_if_identity(&stale_primary, true, 2)
                .expect("stale enablement result"),
            ConditionalCredentialMutation::Stale { .. }
        ));
        assert!(store
            .switch_credential_if_identities(&stale_primary, std::slice::from_ref(&backup), 2)
            .expect("stale selected switch")
            .is_none());
        assert!(store
            .switch_credential_if_identities(&primary, std::slice::from_ref(&stale_backup), 2)
            .expect("stale sibling switch")
            .is_none());
        assert!(
            !store
                .credential_state("primary")
                .expect("primary state")
                .expect("primary exists")
                .enabled
        );
        assert!(
            store
                .credential_state("backup")
                .expect("backup state")
                .expect("backup exists")
                .enabled
        );

        assert!(store
            .switch_credential_if_identities(&primary, std::slice::from_ref(&backup), 3)
            .expect("current switch")
            .is_some());
        assert!(
            store
                .credential_state("primary")
                .expect("primary state")
                .expect("primary exists")
                .enabled
        );
        assert!(
            !store
                .credential_state("backup")
                .expect("backup state")
                .expect("backup exists")
                .enabled
        );
    }

    #[test]
    fn memory_same_state_fences_reconcile_disabled_health() {
        let store = MemoryStore::new();
        let fingerprint = "a".repeat(64);
        let state = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                1,
            ))
            .expect("credential");
        let identity = CredentialConfigurationIdentity::new("credential", "provider", &fingerprint)
            .expect("identity");

        for use_generation_fence in [false, true] {
            store
                .upsert_credential_health(CredentialHealthState::new(
                    "credential",
                    CredentialHealthStatus::Disabled,
                    2,
                ))
                .expect("disabled health");
            let result = if use_generation_fence {
                store.set_credential_enabled_if_current(
                    "credential",
                    state.revision,
                    "provider",
                    &fingerprint,
                    true,
                    3,
                )
            } else {
                store.set_credential_enabled_if_identity(&identity, true, 3)
            }
            .expect("fenced enablement");
            assert!(matches!(
                result,
                ConditionalCredentialMutation::Applied(ref current)
                    if current.revision == state.revision
            ));
            assert_eq!(
                store
                    .credential_health("credential")
                    .expect("health")
                    .expect("health exists")
                    .status,
                CredentialHealthStatus::Healthy
            );
        }
    }

    #[test]
    fn memory_identity_replacement_clears_dependent_state() {
        let store = MemoryStore::new();
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider-a",
                "a".repeat(64),
                true,
                1,
            ))
            .expect("original credential");
        store
            .upsert_credential_health(CredentialHealthState::new(
                "credential",
                CredentialHealthStatus::CoolingDown,
                2,
            ))
            .expect("health");
        store
            .upsert_cooldown(CooldownState::new("credential", "credential", 100, 2))
            .expect("cooldown");
        store
            .upsert_session_affinity(SessionAffinity::new(
                "session",
                "provider-a",
                "credential",
                "model",
                2,
                100,
            ))
            .expect("affinity");

        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider-b",
                "b".repeat(64),
                false,
                3,
            ))
            .expect("replacement credential");
        assert_eq!(
            store
                .credential_health("credential")
                .expect("replacement health")
                .expect("disabled replacement health")
                .status,
            CredentialHealthStatus::Disabled
        );
        assert!(store
            .cooldown("credential", "credential", 3)
            .expect("replacement cooldown")
            .is_none());
        assert!(store
            .session_affinity("session", 3)
            .expect("replacement affinity")
            .is_none());
    }

    #[test]
    fn malformed_and_missing_credentials_are_rejected() {
        let store = MemoryStore::new();
        assert_eq!(
            store.upsert_credential_state(CredentialState::new("", "provider", true, 0)),
            Err(StoreError::EmptyField {
                field: "credential_id"
            })
        );
        assert_eq!(
            store.set_credential_enabled("missing", false, 3),
            Err(StoreError::CredentialNotFound("missing".to_owned()))
        );
    }

    #[test]
    fn affinity_lookup_refreshes_last_use_and_expires() {
        let store = MemoryStore::with_retention(policy(2, 2, 2));
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_session_affinity(affinity("a", 1, 100))
            .expect("insert succeeds");
        let found = store
            .session_affinity("a", 10)
            .expect("lookup succeeds")
            .expect("affinity exists");
        assert_eq!(found.last_used_at, 10);
        assert!(store
            .session_affinity("a", 100)
            .expect("lookup succeeds")
            .is_none());
    }

    #[test]
    fn affinity_retention_uses_last_use_then_key() {
        let store = MemoryStore::with_retention(policy(2, 2, 2));
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        for key in ["b", "a"] {
            store
                .upsert_session_affinity(affinity(key, 1, 100))
                .expect("insert succeeds");
        }
        store.session_affinity("b", 10).expect("lookup succeeds");
        store
            .upsert_session_affinity(affinity("c", 2, 100))
            .expect("insert succeeds");
        let keys: Vec<_> = store
            .session_affinities(10)
            .expect("list succeeds")
            .into_iter()
            .map(|entry| entry.key)
            .collect();
        assert_eq!(keys, ["b", "c"]);
    }

    #[test]
    fn decisions_are_monotonic_bounded_and_recent_is_newest_first() {
        let store = MemoryStore::with_retention(policy(2, 2, 2));
        for request in ["one", "two", "three"] {
            store
                .append_decision(DecisionRecord::new(request, "route", "model", 1))
                .expect("append succeeds");
        }
        assert_eq!(
            store
                .decisions()
                .expect("list succeeds")
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(
            store.recent_decisions(1).expect("recent succeeds")[0].request_id,
            "three"
        );
    }

    #[test]
    fn policy_selection_conversion_preserves_redacted_decision_fields() {
        let provider = pooler_policy::ProviderId::new("provider").expect("provider");
        let model = pooler_policy::ModelId::new("model").expect("model");
        let selection = {
            let mut selection = pooler_policy::SelectionExplanation::new(
                pooler_policy::ModelAliasResolution::exact(model.clone()),
                2,
                pooler_policy::ConfigGeneration::new(7),
            );
            selection.push_candidate(pooler_policy::CandidateExplanation::eligible(
                pooler_policy::SelectionTarget::new(
                    provider.clone(),
                    model.clone(),
                    pooler_policy::CredentialPseudonym::new("cred-redacted"),
                ),
                1.5,
            ));
            selection.set_selected(
                pooler_policy::SelectionTarget::new(
                    provider,
                    model.clone(),
                    pooler_policy::CredentialPseudonym::new("cred-redacted"),
                ),
                Some(1.5),
            );
            selection
        };

        let record = DecisionRecord::from_selection(&selection, "request", "route", 42);
        assert_eq!(record.request_id, "request");
        assert_eq!(record.route_id, "route");
        assert_eq!(record.model, "model");
        assert_eq!(record.configuration_generation, 7);
        assert_eq!(record.selected_credential.as_deref(), Some("cred-redacted"));
        assert_eq!(record.candidates[0].score, 2);
    }

    #[test]
    fn concurrent_writes_remain_bounded() {
        let store = Arc::new(MemoryStore::with_retention(policy(16, 16, 16)));
        let mut threads = Vec::new();
        for worker in 0..8 {
            let store = Arc::clone(&store);
            threads.push(thread::spawn(move || {
                let id = format!("credential-{worker}");
                store
                    .upsert_credential_state(CredentialState::new(
                        id.clone(),
                        "provider",
                        true,
                        worker,
                    ))
                    .expect("credential succeeds");
                store
                    .upsert_session_affinity(SessionAffinity::new(
                        &id, "provider", &id, "model", worker, 100,
                    ))
                    .expect("affinity succeeds");
                store
                    .append_decision(DecisionRecord::new(
                        format!("request-{worker}"),
                        "route",
                        "model",
                        worker,
                    ))
                    .expect("decision succeeds");
            }));
        }
        for thread in threads {
            thread.join().expect("worker succeeds");
        }
        assert_eq!(
            store.len().expect("length succeeds"),
            StoreLengths {
                credentials: 8,
                affinities: 8,
                decisions: 8,
                request_events: 0,
                usage_records: 0,
            }
        );
    }

    #[test]
    fn request_events_share_one_id_and_are_bounded_by_count_request_and_age() {
        let retention = policy(2, 2, 2)
            .with_request_history(3, 100)
            .expect("request retention");
        let store = MemoryStore::with_retention(retention);
        for (request, index, recorded_at) in [
            ("old", 0, 1),
            ("one", 0, 100),
            ("one", 1, 101),
            ("two", 0, 102),
        ] {
            store
                .append_request_event(RequestEvent::new(
                    request,
                    index,
                    RequestEventKind::Attempt,
                    "local",
                    "route",
                    recorded_at,
                ))
                .expect("request event");
        }
        let events = store.request_events().expect("events");
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| event.request_id != "old"));
        assert_eq!(store.request_events_for("one").expect("timeline").len(), 2);
        let report = store.prune(250).expect("prune request history");
        assert_eq!(report.evicted_request_events, 3);
        assert!(store.request_events().expect("pruned events").is_empty());
    }

    #[test]
    fn request_timeline_uses_logical_event_order() {
        let store = MemoryStore::new();
        for event_index in [2, 0, 1] {
            store
                .append_request_event(RequestEvent::new(
                    "request",
                    event_index,
                    RequestEventKind::Attempt,
                    "local",
                    "route",
                    1,
                ))
                .expect("request event");
        }
        assert_eq!(
            store
                .request_events_for("request")
                .expect("request timeline")
                .into_iter()
                .map(|event| event.event_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn request_event_cap_keeps_highest_logical_phases_for_out_of_order_writes() {
        let store = MemoryStore::new();
        for event_index in 0..=MAX_REQUEST_EVENTS_PER_REQUEST as u32 {
            store
                .append_request_event(RequestEvent::new(
                    "request",
                    event_index,
                    RequestEventKind::Attempt,
                    "listener",
                    "route",
                    u64::from(event_index),
                ))
                .expect("event");
        }
        store
            .append_request_event(RequestEvent::new(
                "request",
                0,
                RequestEventKind::Retry,
                "listener",
                "route",
                100,
            ))
            .expect("out-of-order event");
        let events = store.request_events_for("request").expect("timeline");
        assert_eq!(events.len(), MAX_REQUEST_EVENTS_PER_REQUEST);
        assert_eq!(events.first().map(|event| event.event_index), Some(1));
        assert_eq!(events.last().map(|event| event.event_index), Some(64));
    }

    #[test]
    fn request_event_body_hashes_cannot_carry_arbitrary_content() {
        let store = MemoryStore::new();
        let mut event = RequestEvent::new(
            "request",
            0,
            RequestEventKind::Admission,
            "local",
            "route",
            1,
        );
        event.request_body_sha256 = Some("raw prompt content".to_owned());
        assert!(matches!(
            store.append_request_event(event),
            Err(StoreError::Serialization(message))
                if message == "request body hash must be a SHA-256 hex digest"
        ));
    }

    #[test]
    fn usage_history_is_bounded_by_age_and_count() {
        let retention = policy(2, 2, 2)
            .with_usage_history(2, 100)
            .expect("usage retention");
        let store = MemoryStore::with_retention(retention);
        for (request_id, recorded_at) in [("one", 100), ("two", 101), ("old", 0)] {
            store
                .append_usage_record(UsageRecord::new(
                    recorded_at,
                    request_id,
                    "route",
                    "success",
                ))
                .expect("usage record");
        }
        let records = store.usage_records().expect("usage records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request_id, "one");
        let report = store.prune(250).expect("prune usage");
        assert_eq!(report.evicted_usage_records, 2);
        assert!(store.usage_records().expect("pruned usage").is_empty());
    }

    #[test]
    fn prune_reports_expired_affinities() {
        let store = MemoryStore::with_retention(policy(2, 2, 2));
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_session_affinity(affinity("expired", 1, 5))
            .expect("insert succeeds");
        let report = store.prune(5).expect("prune succeeds");
        assert_eq!(report.expired_affinities, 1);
        assert_eq!(report.total(), 1);
        assert!(store
            .session_affinities(5)
            .expect("list succeeds")
            .is_empty());
    }

    #[test]
    fn zero_retention_is_rejected() {
        assert_eq!(
            RetentionPolicy::new(0, 1, 1),
            Err(StoreError::InvalidRetention)
        );
    }
}
