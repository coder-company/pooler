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
        let persisted = PersistedTokens {
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
        };
        let payload = encode_persisted(&persisted)?;
        let state = self
            .store
            .compare_and_swap_credential_payload(
                credential.as_str(),
                expected_generation,
                &payload,
                now_millis(),
            )
            .map_err(Self::map_store_error)?;
        Ok(TokenSnapshot::new(state.revision, profile.tokens().clone()))
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
        let Some(payload) = payload else {
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
            generation: state.revision,
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
        let payload = self
            .store
            .credential_payload(credential.as_str())
            .map_err(Self::map_store_error)?
            .ok_or(OAuthStoreError::NotFound)?;
        let mut persisted = decode_persisted(payload)?;
        persisted.account_id = Some(identity.subject.clone());
        persisted.email = identity.email.clone();
        persisted.name = identity.name.clone();
        let payload = encode_persisted(&persisted)?;
        let state = self
            .store
            .credential_state(credential.as_str())
            .map_err(Self::map_store_error)?
            .ok_or(OAuthStoreError::NotFound)?;
        self.store
            .compare_and_swap_credential_payload(
                credential.as_str(),
                state.revision,
                &payload,
                now_millis(),
            )
            .map_err(Self::map_store_error)
            .map(|_| ())
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
            let Some((state, payload)) = self
                .store
                .credential_payload_with_state(credential.as_str())
                .map_err(Self::map_store_error)?
            else {
                return Err(OAuthStoreError::NotFound);
            };
            payload
                .map(|payload| {
                    Self::decode(payload).map(|tokens| TokenSnapshot::new(state.revision, tokens))
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
    use super::*;
    use crate::{CredentialState, MasterKey, Store};
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
        assert_eq!(first.generation(), 1);
        assert_eq!(first.tokens().access_token().expose_secret(), "old-access");

        let next = OAuthTokens::bearer("new-access", Some("new-refresh"), None);
        let second = token_store
            .compare_and_swap(&credential, first.generation(), next)
            .await
            .expect("cas");
        assert_eq!(second.generation(), 2);
        let loaded = token_store
            .load(&credential)
            .await
            .expect("load")
            .expect("snapshot");
        assert_eq!(loaded.generation(), 2);
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
    async fn wrong_key_cas_leaves_existing_tokens_and_generation_unchanged() {
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

        let wrong_store = SqliteStore::open_encrypted(
            &path,
            MasterKey::from_bytes(b"oauth-wrong-key").expect("wrong key"),
        )
        .expect("wrong-key store");
        let wrong_token_store = SqliteOAuthTokenStore::new(wrong_store);
        let credential = CredentialId::new("account").expect("credential");
        assert_eq!(
            wrong_token_store
                .compare_and_swap(
                    &credential,
                    1,
                    OAuthTokens::bearer("new-access", Some("new-refresh"), None),
                )
                .await,
            Err(OAuthStoreError::Unavailable)
        );
        drop(wrong_token_store);

        let correct_store = SqliteStore::open_encrypted(&path, correct_key).expect("reopen");
        let token_store = SqliteOAuthTokenStore::new(correct_store);
        let snapshot = token_store
            .load(&credential)
            .await
            .expect("load")
            .expect("snapshot");
        assert_eq!(snapshot.generation(), 1);
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
