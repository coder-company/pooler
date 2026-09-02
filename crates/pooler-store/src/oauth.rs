//! Encrypted SQLite implementation of Pooler's OAuth token-store contract.
//!
//! Token serialization is deliberately kept at this boundary. The rest of
//! the store contains metadata only, while callers receive protected
//! [`pooler_auth::OAuthTokens`] and a real metadata revision for CAS refresh.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pooler_auth::{
    AuthKind, CredentialId, OAuthCredentialProfile, OAuthIdentity, OAuthStoreError,
    OAuthStoreFuture, OAuthTokenStore, OAuthTokens, SecretValue, TokenSnapshot,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CredentialPayload, SqliteStore, Store, StoreError};

/// SQLite-backed encrypted OAuth token store.
#[derive(Clone)]
pub struct SqliteOAuthTokenStore {
    store: SqliteStore,
}

/// Redacted metadata for one encrypted credential profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialProfileMetadata {
    /// Persisted authentication kind.
    pub auth_kind: AuthKind,
    /// Canonical provider login profile, such as `openai`.
    pub provider_profile: String,
    /// Whether a provider account ID is available for request headers.
    pub account_id_present: bool,
    /// Store revision used as the credential generation.
    pub generation: u64,
    /// Immutable non-secret account/provider configuration identity.
    pub configuration_fingerprint: String,
    /// Provider token expiry, when supplied by the provider.
    pub expires_at: Option<SystemTime>,
    /// Imported provider expiry marker.
    pub expired: bool,
    /// Imported provider disablement marker.
    pub disabled: bool,
}

impl std::fmt::Debug for SqliteOAuthTokenStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteOAuthTokenStore")
            .field("store", &self.store)
            .finish()
    }
}

impl SqliteOAuthTokenStore {
    /// Wrap an encrypted SQLite store for OAuth token operations.
    #[must_use]
    pub const fn new(store: SqliteStore) -> Self {
        Self { store }
    }

    /// Borrow the underlying store for metadata setup or diagnostics.
    #[must_use]
    pub const fn store(&self) -> &SqliteStore {
        &self.store
    }

    /// Atomically import an OAuth profile into the encrypted payload store.
    pub fn compare_and_swap_profile(
        &self,
        credential: &CredentialId,
        expected_generation: u64,
        profile: &OAuthCredentialProfile,
    ) -> Result<TokenSnapshot, OAuthStoreError> {
        self.compare_and_swap_profile_with_fingerprint(
            credential,
            expected_generation,
            None,
            profile,
        )
    }

    /// Atomically import an OAuth profile while fencing the immutable
    /// account/provider configuration identity before decrypting or replacing
    /// an existing token envelope.
    pub fn compare_and_swap_profile_for_fingerprint(
        &self,
        credential: &CredentialId,
        configuration_fingerprint: &str,
        expected_generation: u64,
        profile: &OAuthCredentialProfile,
    ) -> Result<TokenSnapshot, OAuthStoreError> {
        self.compare_and_swap_profile_with_fingerprint(
            credential,
            expected_generation,
            Some(configuration_fingerprint),
            profile,
        )
    }

    fn compare_and_swap_profile_with_fingerprint(
        &self,
        credential: &CredentialId,
        expected_generation: u64,
        configuration_fingerprint: Option<&str>,
        profile: &OAuthCredentialProfile,
    ) -> Result<TokenSnapshot, OAuthStoreError> {
        let payload = Self::encode_profile(profile)?;
        let state = match configuration_fingerprint {
            Some(fingerprint) => self
                .store
                .compare_and_swap_credential_payload_for_fingerprint(
                    credential.as_str(),
                    expected_generation,
                    fingerprint,
                    &payload,
                    now_millis(),
                ),
            None => self.store.compare_and_swap_credential_payload(
                credential.as_str(),
                expected_generation,
                &payload,
                now_millis(),
            ),
        }
        .map_err(Self::map_store_error)?;
        Ok(TokenSnapshot::new(state.revision, profile.tokens().clone()))
    }

    /// Atomically install a validated login profile, optionally replacing one
    /// exact prior configuration fingerprint, and enable the account.
    ///
    /// The optional expectation is absent only when the caller observed no
    /// metadata row. Serialization, encryption, identity adoption, payload
    /// replacement, and enablement either all commit or all roll back.
    pub fn replace_login_profile_for_fingerprint(
        &self,
        credential: &CredentialId,
        provider_id: &str,
        expected_fingerprint: Option<&str>,
        expected_generation: Option<u64>,
        configuration_fingerprint: &str,
        profile: &OAuthCredentialProfile,
    ) -> Result<TokenSnapshot, OAuthStoreError> {
        let payload = Self::encode_profile(profile)?;
        let state = self
            .store
            .replace_credential_payload_for_login(
                credential.as_str(),
                provider_id,
                expected_fingerprint,
                expected_generation,
                configuration_fingerprint,
                &payload,
                now_millis(),
            )
            .map_err(Self::map_store_error)?;
        Ok(TokenSnapshot::new(state.revision, profile.tokens().clone()))
    }

    fn encode_profile(
        profile: &OAuthCredentialProfile,
    ) -> Result<CredentialPayload, OAuthStoreError> {
        let provider_profile = profile.provider_profile().trim();
        if provider_profile.is_empty() || provider_profile.len() > 128 {
            return Err(OAuthStoreError::Unavailable);
        }
        if profile
            .account_id()
            .is_some_and(|account_id| account_id.trim().is_empty() || account_id.len() > 512)
        {
            return Err(OAuthStoreError::Unavailable);
        }
        encode_persisted(&PersistedTokens {
            access_token: profile.tokens().access_token().expose_secret().to_owned(),
            refresh_token: profile
                .tokens()
                .refresh_token()
                .map(|value| value.expose_secret().to_owned()),
            expires_at_seconds: profile.tokens().expires_at().and_then(|value| {
                value
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|duration| duration.as_secs())
            }),
            token_type: profile.tokens().token_type().to_owned(),
            auth_type: AuthKind::OAuth.as_str().to_owned(),
            provider_profile: Some(provider_profile.to_owned()),
            id_token: profile
                .id_token()
                .map(|value| value.expose_secret().to_owned()),
            account_id: profile.account_id().map(ToOwned::to_owned),
            email: profile.email().map(ToOwned::to_owned),
            name: profile.name().map(ToOwned::to_owned),
            expired: profile.is_expired(),
            disabled: profile.is_disabled(),
            last_refresh: profile.last_refresh().and_then(|value| {
                value
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|duration| duration.as_secs())
            }),
        })
    }

    /// Load redacted encrypted-profile metadata without exposing tokens or IDs.
    pub fn profile_metadata(
        &self,
        credential: &CredentialId,
    ) -> Result<Option<CredentialProfileMetadata>, OAuthStoreError> {
        let Some((state, payload)) = self
            .store
            .credential_payload_with_state(credential.as_str())
            .map_err(Self::map_store_error)?
        else {
            return Ok(None);
        };
        let Some((generation, payload)) = payload else {
            return Ok(None);
        };
        let persisted = decode_persisted(payload)?;
        let auth_kind = match persisted.auth_type.as_str() {
            "oauth" | "oauth2" | "codex" => AuthKind::OAuth,
            _ => return Err(OAuthStoreError::Unavailable),
        };
        Ok(Some(CredentialProfileMetadata {
            auth_kind,
            provider_profile: persisted.provider_profile.unwrap_or_default(),
            account_id_present: persisted.account_id.is_some(),
            generation,
            configuration_fingerprint: state.configuration_fingerprint,
            expires_at: persisted.expires_at_seconds.map(|seconds| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(seconds))
                    .unwrap_or(UNIX_EPOCH)
            }),
            expired: persisted.expired,
            disabled: persisted.disabled,
        }))
    }

    /// Load redacted profile metadata only when the immutable identity still
    /// matches the compiled account configuration.
    pub fn profile_metadata_for_fingerprint(
        &self,
        credential: &CredentialId,
        configuration_fingerprint: &str,
    ) -> Result<Option<CredentialProfileMetadata>, OAuthStoreError> {
        let Some((state, payload)) = self
            .store
            .credential_payload_with_state_for_fingerprint(
                credential.as_str(),
                configuration_fingerprint,
            )
            .map_err(Self::map_store_error)?
        else {
            return Ok(None);
        };
        let Some((generation, payload)) = payload else {
            return Ok(None);
        };
        let persisted = decode_persisted(payload)?;
        let auth_kind = match persisted.auth_type.as_str() {
            "oauth" | "oauth2" | "codex" => AuthKind::OAuth,
            _ => return Err(OAuthStoreError::Unavailable),
        };
        Ok(Some(CredentialProfileMetadata {
            auth_kind,
            provider_profile: persisted.provider_profile.unwrap_or_default(),
            account_id_present: persisted.account_id.is_some(),
            generation,
            configuration_fingerprint: state.configuration_fingerprint,
            expires_at: persisted.expires_at_seconds.map(|seconds| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(seconds))
                    .unwrap_or(UNIX_EPOCH)
            }),
            expired: persisted.expired,
            disabled: persisted.disabled,
        }))
    }

    /// Persist the provider identity associated with one encrypted token set.
    /// Native adapters such as Codex require the account identifier on every
    /// request; token material remains encrypted in the same payload.
    pub fn set_identity(
        &self,
        credential: &CredentialId,
        identity: &OAuthIdentity,
    ) -> Result<(), OAuthStoreError> {
        if identity.subject.trim().is_empty() {
            return Err(OAuthStoreError::Unavailable);
        }
        // Read the payload and generation as one snapshot. Reading them
        // separately lets a concurrent token refresh advance the generation
        // between the two reads, after which this identity write could
        // overwrite the refresh payload. A bounded retry preserves both updates when a refresh
        // wins between this snapshot and the CAS commit.
        for _ in 0..8 {
            let Some((_state, Some((generation, payload)))) = self
                .store
                .credential_payload_with_state(credential.as_str())
                .map_err(Self::map_store_error)?
            else {
                return Err(OAuthStoreError::NotFound);
            };
            let mut persisted = decode_persisted(payload)?;
            persisted.account_id = Some(identity.subject.clone());
            persisted.email = identity.email.clone();
            persisted.name = identity.name.clone();
            let payload = encode_persisted(&persisted)?;
            match self.store.compare_and_swap_credential_payload(
                credential.as_str(),
                generation,
                &payload,
                now_millis(),
            ) {
                Ok(_) => return Ok(()),
                Err(StoreError::CredentialRevisionConflict) => continue,
                Err(error) => return Err(Self::map_store_error(error)),
            }
        }
        Err(OAuthStoreError::Conflict)
    }

    /// Return the persisted provider subject without exposing token material.
    pub fn account_id(&self, credential: &CredentialId) -> Result<Option<String>, OAuthStoreError> {
        let payload = self
            .store
            .credential_payload(credential.as_str())
            .map_err(Self::map_store_error)?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        Ok(decode_persisted(payload)?.account_id)
    }

    /// Return the provider subject only after the compiled credential
    /// fingerprint matches the encrypted record metadata.
    pub fn account_id_for_fingerprint(
        &self,
        credential: &CredentialId,
        configuration_fingerprint: &str,
    ) -> Result<Option<String>, OAuthStoreError> {
        let Some(state) = self
            .store
            .credential_state(credential.as_str())
            .map_err(Self::map_store_error)?
        else {
            return Ok(None);
        };
        if state.configuration_fingerprint.is_empty() {
            if self
                .store
                .credential_payload_exists(credential.as_str())
                .map_err(Self::map_store_error)?
            {
                return Err(OAuthStoreError::IdentityConflict);
            }
            return Ok(None);
        }
        if state.configuration_fingerprint != configuration_fingerprint {
            return Err(OAuthStoreError::IdentityConflict);
        }
        let payload = self
            .store
            .credential_payload_for_fingerprint(credential.as_str(), configuration_fingerprint)
            .map_err(Self::map_store_error)?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        Ok(decode_persisted(payload)?.account_id)
    }

    fn decode(payload: CredentialPayload) -> Result<OAuthTokens, OAuthStoreError> {
        let bytes = Zeroizing::new(payload.into_bytes());
        let persisted: PersistedTokens =
            serde_json::from_slice(&bytes).map_err(|_| OAuthStoreError::Unavailable)?;
        if persisted.access_token.trim().is_empty() || persisted.token_type.trim().is_empty() {
            return Err(OAuthStoreError::Unavailable);
        }
        let expires_at = persisted.expires_at_seconds.map(|seconds| {
            UNIX_EPOCH
                .checked_add(Duration::from_secs(seconds))
                .unwrap_or(UNIX_EPOCH)
        });
        Ok(OAuthTokens::new(
            SecretValue::new(persisted.access_token),
            persisted
                .refresh_token
                .filter(|value| !value.trim().is_empty())
                .map(SecretValue::new),
            expires_at,
            persisted.token_type,
        ))
    }

    fn map_store_error(error: StoreError) -> OAuthStoreError {
        match error {
            StoreError::CredentialNotFound(_) => OAuthStoreError::NotFound,
            StoreError::CredentialRevisionConflict => OAuthStoreError::Conflict,
            StoreError::CredentialFingerprintConflict => OAuthStoreError::IdentityConflict,
            _ => OAuthStoreError::Unavailable,
        }
    }
}

impl OAuthTokenStore for SqliteOAuthTokenStore {
    fn load<'a>(
        &'a self,
        credential: &'a CredentialId,
    ) -> OAuthStoreFuture<'a, Option<TokenSnapshot>> {
        let result = (|| {
            let Some((_state, payload)) = self
                .store
                .credential_payload_with_state(credential.as_str())
                .map_err(Self::map_store_error)?
            else {
                return Err(OAuthStoreError::NotFound);
            };
            payload
                .map(|(generation, payload)| {
                    Self::decode(payload).map(|tokens| TokenSnapshot::new(generation, tokens))
                })
                .transpose()
        })();
        Box::pin(async move { result })
    }

    fn load_for_fingerprint<'a>(
        &'a self,
        credential: &'a CredentialId,
        configuration_fingerprint: &'a str,
    ) -> OAuthStoreFuture<'a, Option<TokenSnapshot>> {
        let result = (|| {
            let Some((_state, payload)) = self
                .store
                .credential_payload_with_state_for_fingerprint(
                    credential.as_str(),
                    configuration_fingerprint,
                )
                .map_err(Self::map_store_error)?
            else {
                return Ok(None);
            };
            payload
                .map(|(generation, payload)| {
                    Self::decode(payload).map(|tokens| TokenSnapshot::new(generation, tokens))
                })
                .transpose()
        })();
        Box::pin(async move { result })
    }

    fn compare_and_swap<'a>(
        &'a self,
        credential: &'a CredentialId,
        expected_generation: u64,
        tokens: OAuthTokens,
    ) -> OAuthStoreFuture<'a, TokenSnapshot> {
        let result = (|| {
            let existing = self
                .store
                .credential_payload(credential.as_str())
                .map_err(Self::map_store_error)?;
            let payload = encode_preserving_identity(&tokens, existing)?;
            let state = self
                .store
                .compare_and_swap_credential_payload(
                    credential.as_str(),
                    expected_generation,
                    &payload,
                    now_millis(),
                )
                .map_err(Self::map_store_error)?;
            Ok(TokenSnapshot::new(state.revision, tokens))
        })();
        Box::pin(async move { result })
    }

    fn compare_and_swap_for_fingerprint<'a>(
        &'a self,
        credential: &'a CredentialId,
        expected_generation: u64,
        configuration_fingerprint: &'a str,
        tokens: OAuthTokens,
    ) -> OAuthStoreFuture<'a, TokenSnapshot> {
        let result = (|| {
            let existing = self
                .store
                .credential_payload_with_state_for_fingerprint(
                    credential.as_str(),
                    configuration_fingerprint,
                )
                .map_err(Self::map_store_error)?
                .and_then(|(_, payload)| payload.map(|(_, payload)| payload));
            let payload = encode_preserving_identity(&tokens, existing)?;
            let state = self
                .store
                .compare_and_swap_credential_payload_for_fingerprint(
                    credential.as_str(),
                    expected_generation,
                    configuration_fingerprint,
                    &payload,
                    now_millis(),
                )
                .map_err(Self::map_store_error)?;
            Ok(TokenSnapshot::new(state.revision, tokens))
        })();
        Box::pin(async move { result })
    }

    fn remove<'a>(&'a self, credential: &'a CredentialId) -> OAuthStoreFuture<'a, ()> {
        let result = self
            .store
            .remove_credential_payload(credential.as_str())
            .map(|_| ())
            .map_err(Self::map_store_error);
        Box::pin(async move { result })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedTokens {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_at_seconds: Option<u64>,
    #[serde(default)]
    token_type: String,
    #[serde(rename = "type", default = "default_auth_type")]
    auth_type: String,
    #[serde(default)]
    provider_profile: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    expired: bool,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    last_refresh: Option<u64>,
}

fn default_auth_type() -> String {
    "oauth".to_owned()
}

fn decode_persisted(payload: CredentialPayload) -> Result<PersistedTokens, OAuthStoreError> {
    let bytes = Zeroizing::new(payload.into_bytes());
    serde_json::from_slice(&bytes).map_err(|_| OAuthStoreError::Unavailable)
}

fn encode_persisted(persisted: &PersistedTokens) -> Result<CredentialPayload, OAuthStoreError> {
    let bytes = serde_json::to_vec(persisted).map_err(|_| OAuthStoreError::Unavailable)?;
    CredentialPayload::from_bytes(bytes).map_err(|_| OAuthStoreError::Unavailable)
}

fn encode_preserving_identity(
    tokens: &OAuthTokens,
    existing: Option<CredentialPayload>,
) -> Result<CredentialPayload, OAuthStoreError> {
    let mut persisted = existing
        .map(decode_persisted)
        .transpose()?
        .unwrap_or_else(|| PersistedTokens {
            access_token: String::new(),
            refresh_token: None,
            expires_at_seconds: None,
            token_type: String::new(),
            auth_type: "oauth".to_owned(),
            provider_profile: None,
            id_token: None,
            account_id: None,
            email: None,
            name: None,
            expired: false,
            disabled: false,
            last_refresh: None,
        });
    persisted.access_token = tokens.access_token().expose_secret().to_owned();
    persisted.refresh_token = tokens
        .refresh_token()
        .map(|value| value.expose_secret().to_owned());
    persisted.expires_at_seconds = tokens.expires_at().and_then(|value| {
        value
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
    });
    persisted.token_type = tokens.token_type().to_owned();
    persisted.expired = false;
    persisted.disabled = false;
    persisted.last_refresh = Some(now_millis());
    encode_persisted(&persisted)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use pooler_auth::{
        refresh_with_store_if_generation_for_fingerprint, OAuthError, OAuthFuture, OAuthRefresher,
        RefreshCoordinator,
    };
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        CooldownState, CredentialHealthState, CredentialHealthStatus, CredentialState, MasterKey,
        SessionAffinity, Store,
    };
    use tempfile::tempdir;

    #[tokio::test]
    async fn load_reports_real_revision_and_cas_rotates_payload() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-store-test-key").expect("master key"),
        )
        .expect("store");
        store
            .upsert_credential_state(CredentialState::new("account", "codex", true, 1))
            .expect("metadata");
        let tokens = OAuthTokens::bearer("old-access", Some("old-refresh"), None);
        let payload = encode_preserving_identity(&tokens, None).expect("payload");
        store
            .upsert_credential_payload("account", &payload, 1)
            .expect("payload persisted");
        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new("account").expect("credential");
        let first = token_store
            .load(&credential)
            .await
            .expect("load")
            .expect("snapshot");
        assert_eq!(first.generation(), 2);
        assert_eq!(first.tokens().access_token().expose_secret(), "old-access");

        let next = OAuthTokens::bearer("new-access", Some("new-refresh"), None);
        let second = token_store
            .compare_and_swap(&credential, first.generation(), next)
            .await
            .expect("cas");
        assert_eq!(second.generation(), 3);
        let loaded = token_store
            .load(&credential)
            .await
            .expect("load")
            .expect("snapshot");
        assert_eq!(loaded.generation(), 3);
        assert_eq!(loaded.tokens().access_token().expose_secret(), "new-access");
        assert!(matches!(
            token_store
                .compare_and_swap(
                    &credential,
                    first.generation(),
                    OAuthTokens::bearer("stale", None::<String>, None),
                )
                .await,
            Err(OAuthStoreError::Conflict)
        ));
    }

    #[tokio::test]
    async fn stale_login_replacement_preserves_the_prior_fingerprint_and_payload() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-login-replacement-race-key").expect("master key"),
        )
        .expect("store");
        let legacy = "a".repeat(64);
        let current = "b".repeat(64);
        let state = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account", "provider", &legacy, true, 1,
            ))
            .expect("metadata");
        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new("account").expect("credential");
        let first = token_store
            .compare_and_swap_profile_for_fingerprint(
                &credential,
                &legacy,
                state.revision,
                &OAuthCredentialProfile::new(
                    "provider-profile",
                    OAuthTokens::bearer("old-access", Some("old-refresh"), None),
                ),
            )
            .expect("legacy profile");
        token_store
            .compare_and_swap_profile_for_fingerprint(
                &credential,
                &legacy,
                first.generation(),
                &OAuthCredentialProfile::new(
                    "provider-profile",
                    OAuthTokens::bearer("winner-access", Some("winner-refresh"), None),
                ),
            )
            .expect("concurrent winner");

        assert_eq!(
            token_store.replace_login_profile_for_fingerprint(
                &credential,
                "provider",
                Some(&legacy),
                Some(first.generation()),
                &current,
                &OAuthCredentialProfile::new(
                    "provider-profile",
                    OAuthTokens::bearer("stale-access", Some("stale-refresh"), None),
                ),
            ),
            Err(OAuthStoreError::Conflict)
        );
        let state = store
            .credential_state("account")
            .expect("metadata")
            .expect("credential exists");
        assert_eq!(state.configuration_fingerprint, legacy);
        assert!(state.enabled);
        let loaded = token_store
            .load_for_fingerprint(&credential, &legacy)
            .await
            .expect("load winner")
            .expect("winner exists");
        assert_eq!(
            loaded.tokens().access_token().expose_secret(),
            "winner-access"
        );
    }

    #[tokio::test]
    async fn login_replacement_atomically_adopts_identity_and_clears_dependents() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-login-replacement-success-key").expect("master key"),
        )
        .expect("store");
        let legacy = "a".repeat(64);
        let current = "b".repeat(64);
        let state = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account", "provider", &legacy, false, 1,
            ))
            .expect("metadata");
        store
            .upsert_credential_health(CredentialHealthState::new(
                "account",
                CredentialHealthStatus::CoolingDown,
                2,
            ))
            .expect("legacy health");
        store
            .upsert_cooldown(CooldownState::new("credential", "account", 100, 2))
            .expect("legacy cooldown");
        store
            .upsert_session_affinity(SessionAffinity::new(
                "session", "provider", "account", "model", 1, 100,
            ))
            .expect("legacy affinity");

        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new("account").expect("credential");
        let prior = token_store
            .compare_and_swap_profile_for_fingerprint(
                &credential,
                &legacy,
                state.revision,
                &OAuthCredentialProfile::new(
                    "provider-profile",
                    OAuthTokens::bearer("legacy-access", Some("legacy-refresh"), None),
                ),
            )
            .expect("legacy profile");

        let replacement = token_store
            .replace_login_profile_for_fingerprint(
                &credential,
                "provider",
                Some(&legacy),
                Some(prior.generation()),
                &current,
                &OAuthCredentialProfile::new(
                    "provider-profile",
                    OAuthTokens::bearer("current-access", Some("current-refresh"), None),
                ),
            )
            .expect("atomic login replacement");

        assert!(replacement.generation() > prior.generation());
        assert_eq!(
            replacement.tokens().access_token().expose_secret(),
            "current-access"
        );
        let state = store
            .credential_state("account")
            .expect("metadata")
            .expect("credential exists");
        assert_eq!(state.configuration_fingerprint, current);
        assert!(state.enabled);
        assert!(store
            .credential_health("account")
            .expect("health lookup")
            .is_none());
        assert!(store
            .cooldown("credential", "account", 2)
            .expect("cooldown lookup")
            .is_none());
        assert!(store
            .session_affinity("session", 2)
            .expect("affinity lookup")
            .is_none());
        assert!(matches!(
            token_store.load_for_fingerprint(&credential, &legacy).await,
            Err(OAuthStoreError::IdentityConflict)
        ));
        let loaded = token_store
            .load_for_fingerprint(&credential, &current)
            .await
            .expect("load current profile")
            .expect("current profile exists");
        assert_eq!(
            loaded.tokens().access_token().expose_secret(),
            "current-access"
        );
    }

    #[test]
    fn identity_update_preserves_a_concurrent_token_rotation() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-identity-race-key").expect("master key"),
        )
        .expect("store");
        store
            .upsert_credential_state(CredentialState::new("account", "codex", true, 1))
            .expect("metadata");
        let payload = encode_preserving_identity(
            &OAuthTokens::bearer("old-access", Some("old-refresh"), None),
            None,
        )
        .expect("payload");
        store
            .upsert_credential_payload("account", &payload, 1)
            .expect("payload");
        let token_store = SqliteOAuthTokenStore::new(store);
        let credential = CredentialId::new("account").expect("credential");
        let barrier = Arc::new(Barrier::new(2));

        let identity_store = token_store.clone();
        let identity_credential = credential.clone();
        let identity_barrier = Arc::clone(&barrier);
        let identity_thread = thread::spawn(move || {
            identity_barrier.wait();
            identity_store.set_identity(
                &identity_credential,
                &OAuthIdentity {
                    subject: "chatgpt-account".to_owned(),
                    email: Some("user@example.test".to_owned()),
                    name: Some("User".to_owned()),
                },
            )
        });

        let refresh_store = token_store.clone();
        let refresh_credential = credential.clone();
        let refresh_thread = thread::spawn(move || -> Result<(), StoreError> {
            barrier.wait();
            for _ in 0..8 {
                let Some((_state, Some((generation, existing)))) = refresh_store
                    .store()
                    .credential_payload_with_state(refresh_credential.as_str())
                    .expect("refresh snapshot")
                else {
                    panic!("credential payload disappeared");
                };
                let replacement = encode_preserving_identity(
                    &OAuthTokens::bearer("refreshed-access", Some("refreshed-refresh"), None),
                    Some(existing),
                )
                .expect("replacement payload");
                match refresh_store.store().compare_and_swap_credential_payload(
                    refresh_credential.as_str(),
                    generation,
                    &replacement,
                    2,
                ) {
                    Ok(_) => return Ok(()),
                    Err(StoreError::CredentialRevisionConflict) => continue,
                    Err(error) => panic!("token rotation failed: {error}"),
                }
            }
            panic!("token rotation did not commit");
        });

        identity_thread
            .join()
            .expect("identity thread")
            .expect("identity update");
        refresh_thread
            .join()
            .expect("refresh thread")
            .expect("token rotation");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let snapshot = runtime
            .block_on(token_store.load(&credential))
            .expect("load")
            .expect("snapshot");
        assert_eq!(
            snapshot.tokens().access_token().expose_secret(),
            "refreshed-access"
        );
        assert_eq!(
            token_store
                .account_id(&credential)
                .expect("account ID")
                .as_deref(),
            Some("chatgpt-account")
        );
    }

    #[tokio::test]
    async fn revoke_advances_generation_and_fences_in_flight_refresh() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-revoke-fence-key").expect("master key"),
        )
        .expect("store");
        store
            .upsert_credential_state(CredentialState::new("account", "codex", true, 1))
            .expect("metadata");
        let payload =
            encode_preserving_identity(&OAuthTokens::bearer("access", Some("refresh"), None), None)
                .expect("payload");
        store
            .upsert_credential_payload("account", &payload, 1)
            .expect("payload");
        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new("account").expect("credential");
        let snapshot = token_store
            .load(&credential)
            .await
            .expect("load")
            .expect("snapshot");
        token_store.remove(&credential).await.expect("revoke");

        assert_eq!(
            token_store
                .compare_and_swap(
                    &credential,
                    snapshot.generation(),
                    OAuthTokens::bearer("late-access", Some("late-refresh"), None),
                )
                .await,
            Err(OAuthStoreError::Conflict)
        );
        assert_eq!(
            store
                .credential_state("account")
                .expect("state")
                .expect("credential")
                .revision,
            snapshot.generation() + 1
        );
        assert!(store
            .credential_payload("account")
            .expect("payload")
            .is_none());
    }

    #[derive(Default)]
    struct BlockingNeedsReauthRefresher {
        started: Notify,
        release: Notify,
    }

    impl OAuthRefresher for BlockingNeedsReauthRefresher {
        fn refresh<'a>(
            &'a self,
            _refresh_token: &'a SecretValue,
            _cancellation: CancellationToken,
        ) -> OAuthFuture<'a, OAuthTokens> {
            Box::pin(async move {
                self.started.notify_one();
                self.release.notified().await;
                Err(OAuthError::NeedsReauth)
            })
        }
    }

    #[tokio::test]
    async fn master_key_rotation_does_not_masquerade_as_new_oauth_tokens() {
        let old_key = MasterKey::from_bytes(b"oauth-rotation-old-key").expect("old key");
        let new_key = MasterKey::from_bytes(b"oauth-rotation-new-key").expect("new key");
        let store = SqliteStore::open_in_memory_encrypted(old_key).expect("store");
        let fingerprint = "a".repeat(64);
        let state = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account",
                "codex",
                &fingerprint,
                true,
                1,
            ))
            .expect("metadata");
        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new("account").expect("credential");
        let snapshot = token_store
            .compare_and_swap_profile_for_fingerprint(
                &credential,
                &fingerprint,
                state.revision,
                &OAuthCredentialProfile::new(
                    "openai",
                    OAuthTokens::bearer("stale-access", Some("stale-refresh"), None),
                ),
            )
            .expect("profile");
        let expected_generation = snapshot.generation();
        let provider = Arc::new(BlockingNeedsReauthRefresher::default());
        let refresh = tokio::spawn({
            let provider = Arc::clone(&provider);
            let token_store = token_store.clone();
            let credential = credential.clone();
            let fingerprint = fingerprint.clone();
            async move {
                refresh_with_store_if_generation_for_fingerprint(
                    &RefreshCoordinator::new(),
                    provider.as_ref(),
                    &token_store,
                    credential,
                    fingerprint,
                    Some(expected_generation),
                    CancellationToken::new(),
                )
                .await
            }
        });
        provider.started.notified().await;

        assert_eq!(store.rotate_master_key(new_key).expect("rotate"), 1);
        let rotated = token_store
            .load_for_fingerprint(&credential, &fingerprint)
            .await
            .expect("load after rotation")
            .expect("payload after rotation");
        assert_eq!(rotated.generation(), expected_generation);
        assert_eq!(
            rotated.tokens().access_token().expose_secret(),
            "stale-access"
        );

        provider.release.notify_one();
        assert_eq!(
            refresh.await.expect("refresh task"),
            Err(OAuthError::NeedsReauth)
        );
    }

    #[tokio::test]
    async fn wrong_key_open_leaves_existing_tokens_and_generation_unchanged() {
        let directory = tempdir().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private directory");
        }
        let path = directory.path().join("credentials.sqlite");
        let correct_key = MasterKey::from_bytes(b"oauth-correct-key").expect("key");
        {
            let store = SqliteStore::open_encrypted(&path, correct_key.clone()).expect("store");
            store
                .upsert_credential_state(CredentialState::new("account", "codex", true, 1))
                .expect("metadata");
            let payload = encode_preserving_identity(
                &OAuthTokens::bearer("old-access", Some("old-refresh"), None),
                None,
            )
            .expect("payload");
            store
                .upsert_credential_payload("account", &payload, 1)
                .expect("payload persisted");
        }

        let credential = CredentialId::new("account").expect("credential");
        assert!(matches!(
            SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"oauth-wrong-key").expect("wrong key"),
            ),
            Err(StoreError::WrongMasterKey)
        ));

        let correct_store = SqliteStore::open_encrypted(&path, correct_key).expect("reopen");
        let token_store = SqliteOAuthTokenStore::new(correct_store);
        let snapshot = token_store
            .load(&credential)
            .await
            .expect("load")
            .expect("snapshot");
        assert_eq!(snapshot.generation(), 2);
        assert_eq!(
            snapshot.tokens().access_token().expose_secret(),
            "old-access"
        );
    }

    #[tokio::test]
    async fn identity_is_retained_in_native_credential_shape() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-identity-test-key").expect("master key"),
        )
        .expect("store");
        store
            .upsert_credential_state(CredentialState::new("account", "codex", true, 1))
            .expect("metadata");
        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new("account").expect("credential");
        let payload = encode_preserving_identity(
            &OAuthTokens::bearer("access-token", Some("refresh-token"), None),
            None,
        )
        .expect("payload");
        store
            .upsert_credential_payload("account", &payload, 1)
            .expect("payload");
        token_store
            .set_identity(
                &credential,
                &OAuthIdentity {
                    subject: "chatgpt-account".to_owned(),
                    email: Some("user@example.test".to_owned()),
                    name: Some("User".to_owned()),
                },
            )
            .expect("identity");
        let payload = store
            .credential_payload("account")
            .expect("load")
            .expect("payload");
        let json: serde_json::Value = serde_json::from_slice(payload.expose_bytes()).expect("json");
        assert_eq!(json["account_id"], "chatgpt-account");
        assert_eq!(json["email"], "user@example.test");
        assert_eq!(json["type"], "oauth");
        assert_eq!(
            token_store
                .load(&credential)
                .await
                .expect("load")
                .expect("snapshot")
                .tokens()
                .access_token()
                .expose_secret(),
            "access-token"
        );
    }

    #[test]
    fn profile_metadata_reports_token_expiry_without_exposing_tokens() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"oauth-expiry-test-key").expect("master key"),
        )
        .expect("store");
        let state = store
            .upsert_credential_state(CredentialState::new("account", "codex", true, 1))
            .expect("metadata");
        let token_store = SqliteOAuthTokenStore::new(store);
        let credential = CredentialId::new("account").expect("credential");
        let expires_at = UNIX_EPOCH + Duration::from_secs(4_000_000_000);
        let profile = OAuthCredentialProfile::new(
            "openai",
            OAuthTokens::bearer("access-token", Some("refresh-token"), Some(expires_at)),
        );
        token_store
            .compare_and_swap_profile(&credential, state.revision, &profile)
            .expect("profile");

        let metadata = token_store
            .profile_metadata(&credential)
            .expect("metadata")
            .expect("stored metadata");
        assert_eq!(metadata.expires_at, Some(expires_at));
        assert!(!format!("{metadata:?}").contains("access-token"));
        assert!(!format!("{metadata:?}").contains("refresh-token"));
    }
}
