//! Bounded storage contracts for Pooler's mutable state.
//!
//! The crate contains both a deterministic in-memory store and a transactional
//! SQLite store. Callers provide timestamps rather than making the store read a
//! process clock; expiry and retention are therefore deterministic and easy to
//! test. Secret values are deliberately absent from every type in this crate.

use std::collections::{BTreeMap, VecDeque};
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
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub auth_placement: String,
}

impl CredentialFingerprintInput {
    /// Return a stable SHA-256 hex fingerprint over canonical, length-prefixed
    /// identity fields. Secret values are not accepted by this type.
    pub fn fingerprint(&self) -> StoreResult<String> {
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

    fn upsert_credential_state(&self, state: CredentialState) -> StoreResult<CredentialState>;
    fn credential_state(&self, credential_id: &str) -> StoreResult<Option<CredentialState>>;
    fn credential_states(&self) -> StoreResult<Vec<CredentialState>>;
    fn set_credential_enabled(
        &self,
        credential_id: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState>;
    fn switch_credential(
        &self,
        selected: &str,
        siblings: &[String],
        updated_at: Timestamp,
    ) -> StoreResult<Vec<CredentialState>>;
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
    fn remove_cooldown(&self, scope: &str, key: &str) -> StoreResult<bool>;

    fn upsert_session_affinity(&self, affinity: SessionAffinity) -> StoreResult<SessionAffinity>;
    fn session_affinity(&self, key: &str, now: Timestamp) -> StoreResult<Option<SessionAffinity>>;
    fn session_affinities(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>>;
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
        if let Some(previous) = inner.credentials.get(&state.credential_id) {
            if !state.configuration_fingerprint.is_empty()
                && !previous.configuration_fingerprint.is_empty()
                && previous.configuration_fingerprint != state.configuration_fingerprint
            {
                return Err(StoreError::CredentialFingerprintConflict);
            }
            if state.configuration_fingerprint.is_empty() {
                state.configuration_fingerprint = previous.configuration_fingerprint.clone();
            }
        }
        state.revision = inner
            .credentials
            .get(&state.credential_id)
            .map_or(1, |old| old.revision.saturating_add(1));
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
        let state = {
            let state = inner
                .credentials
                .get_mut(credential_id)
                .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
            state.enabled = enabled;
            state.updated_at = updated_at;
            state.revision = state.revision.saturating_add(1);
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
            let Some(state) = inner.credentials.get_mut(credential_id) else {
                return Err(StoreError::CredentialNotFound(credential_id.to_owned()));
            };
            if state.enabled != enabled {
                state.enabled = enabled;
                state.updated_at = updated_at;
                state.revision = state.revision.saturating_add(1);
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
        let updated = store
            .set_credential_enabled("z", false, 2)
            .expect("toggle succeeds");
        assert!(!updated.enabled);
        assert_eq!(updated.revision, 2);
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
