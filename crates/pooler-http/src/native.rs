//! Native provider credential materialization and refresh integration.
//!
//! Native adapters receive authorization only for the one outbound attempt.
//! Token stores and refresh coordinators remain behind this runtime boundary;
//! HTTP forwarding never receives raw persisted payloads.

use std::collections::BTreeMap;
use std::sync::Arc;

use adapter_codex::{CodexAuthorization, CodexCredential, CodexQuotaParser, CodexRequestMetadata};
use http::HeaderMap;
use pooler_auth::{
    refresh_with_store_if_generation, CredentialId, HyperOAuthTransport, MemoryOAuthTokenStore,
    OAuthClientConfig, OAuthError, OAuthRefresher, OAuthTokenStore, RefreshCoordinator,
    TokenSnapshot,
};
use pooler_config::{CompiledConfig, OAuthPlan, UpstreamPlan};
use pooler_store::SqliteOAuthTokenStore;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{RuntimeResourceSnapshot, RuntimeResources};

/// Native runtime errors are intentionally coarse and never carry token
/// material, response bodies, or authorization headers.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NativeRuntimeError {
    /// The selected upstream is not backed by a registered native adapter.
    #[error("native provider is not configured")]
    Unsupported,
    /// The selected credential could not be loaded from its store.
    #[error("native credential is unavailable")]
    CredentialUnavailable,
    /// Persisted credential fields could not be converted to safe headers.
    #[error("native authorization could not be materialized")]
    Authorization,
    /// Refresh failed because interactive login is required.
    #[error("native credential needs reauthorization")]
    NeedsReauth,
    /// Refresh failed for a provider or transport reason.
    #[error("native credential refresh failed")]
    Refresh,
    /// The configured native OAuth provider is invalid.
    #[error("native provider configuration is invalid")]
    Configuration,
}

/// Authorization material retained only for the duration of one attempt.
pub struct NativeAuthorization {
    authorization: CodexAuthorization,
    generation: u64,
}

impl std::fmt::Debug for NativeAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthorization")
            .field("authorization", &self.authorization)
            .field("generation", &self.generation)
            .finish()
    }
}

impl NativeAuthorization {
    /// Apply the short-lived material to an outbound request header map.
    pub fn apply_to(&self, headers: &mut HeaderMap) -> Result<(), NativeRuntimeError> {
        self.authorization
            .apply_to(headers)
            .map_err(|_| NativeRuntimeError::Authorization)
    }

    /// Persisted token generation observed before this attempt.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Native provider runtime used by the HTTP proxy.
#[derive(Clone)]
pub struct NativeRuntime {
    token_store: Arc<dyn OAuthTokenStore>,
    refresh: RefreshCoordinator,
    codex: Arc<BTreeMap<String, Arc<dyn OAuthRefresher>>>,
    account_ids: Arc<BTreeMap<String, String>>,
    resources: RuntimeResources,
}

impl std::fmt::Debug for NativeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRuntime")
            .field("codex_providers", &self.codex.len())
            .field("account_id_overrides", &self.account_ids.len())
            .field("active_refresh_leases", &self.refresh.active_leases())
            .finish()
    }
}

impl NativeRuntime {
    /// Build a runtime from compiled native OAuth provider declarations.
    pub fn new(
        config: &CompiledConfig,
        token_store: Arc<dyn OAuthTokenStore>,
    ) -> Result<Self, NativeRuntimeError> {
        let transport = Arc::new(
            HyperOAuthTransport::new(64 * 1024).map_err(|_| NativeRuntimeError::Configuration)?,
        );
        let mut codex = BTreeMap::new();
        for upstream in config.upstreams().values() {
            let Some(native) = upstream.native() else {
                continue;
            };
            if !native.kind().eq_ignore_ascii_case("codex") {
                continue;
            }
            let oauth = upstream.oauth().ok_or(NativeRuntimeError::Configuration)?;
            let provider = build_codex_provider(upstream.id(), oauth, Arc::clone(&transport))?;
            codex.insert(
                upstream.id().to_owned(),
                Arc::new(provider) as Arc<dyn OAuthRefresher>,
            );
        }
        Ok(Self {
            token_store,
            refresh: RefreshCoordinator::new(),
            codex: Arc::new(codex),
            account_ids: Arc::new(BTreeMap::new()),
            resources: RuntimeResources::new(),
        })
    }

    /// Build a runtime from the encrypted SQLite store and hydrate native
    /// account headers from the persisted provider identity records.
    pub fn new_with_sqlite(
        config: &CompiledConfig,
        token_store: Arc<SqliteOAuthTokenStore>,
    ) -> Result<Self, NativeRuntimeError> {
        let mut runtime = Self::new(config, token_store.clone())?;
        for account in config.accounts().values() {
            let credential =
                CredentialId::new(account.id()).map_err(|_| NativeRuntimeError::Configuration)?;
            if let Some(account_id) = token_store
                .account_id(&credential)
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
            {
                runtime = runtime.with_account_id(account.id(), account_id);
            }
        }
        Ok(runtime)
    }

    /// Construct a runtime with one injected Codex refresher. This is useful
    /// for deterministic provider transports and failure-injection tests.
    pub fn with_codex_provider(
        token_store: Arc<dyn OAuthTokenStore>,
        upstream_id: impl Into<String>,
        provider: Arc<dyn OAuthRefresher>,
    ) -> Self {
        let mut codex = BTreeMap::new();
        codex.insert(upstream_id.into(), provider);
        Self {
            token_store,
            refresh: RefreshCoordinator::new(),
            codex: Arc::new(codex),
            account_ids: Arc::new(BTreeMap::new()),
            resources: RuntimeResources::new(),
        }
    }

    /// Construct a disabled runtime for routes that do not use native
    /// providers. The in-memory store is never populated and therefore cannot
    /// expose a credential accidentally.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            token_store: Arc::new(MemoryOAuthTokenStore::new()),
            refresh: RefreshCoordinator::new(),
            codex: Arc::new(BTreeMap::new()),
            account_ids: Arc::new(BTreeMap::new()),
            resources: RuntimeResources::new(),
        }
    }

    /// Add a non-secret provider account identifier override.
    #[must_use]
    pub fn with_account_id(
        mut self,
        credential: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Self {
        let credential = credential.into();
        let account_id = account_id.into();
        if !credential.trim().is_empty() && !account_id.trim().is_empty() {
            Arc::make_mut(&mut self.account_ids).insert(credential, account_id);
        }
        self
    }

    /// Whether an upstream selects the built-in Codex native path.
    #[must_use]
    pub fn supports(&self, upstream: &UpstreamPlan) -> bool {
        upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
            && self.codex.contains_key(upstream.id())
    }

    /// Return the resources owned by native credential handling.
    #[must_use]
    pub fn resource_snapshot(&self) -> RuntimeResourceSnapshot {
        let mut snapshot = self.resources.snapshot();
        let active = u64::try_from(self.refresh.active_leases()).unwrap_or(u64::MAX);
        snapshot.refresh_leases = snapshot.refresh_leases.max(active);
        snapshot.peak_refresh_leases = snapshot.peak_refresh_leases.max(active);
        snapshot
    }

    /// Load and materialize one credential for one outbound attempt.
    pub async fn authorize(
        &self,
        upstream: &UpstreamPlan,
        credential: &CredentialId,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        if !self.supports(upstream) {
            return Err(NativeRuntimeError::Unsupported);
        }
        let snapshot = self
            .token_store
            .load(credential)
            .await
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        let account_id = self
            .account_ids
            .get(credential.as_str())
            .map(String::as_str)
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        let metadata = CodexRequestMetadata::from_headers(request_headers)
            .map_err(|_| NativeRuntimeError::Authorization)?;
        let credential = CodexCredential::new(snapshot.tokens().clone(), account_id)
            .map_err(|_| NativeRuntimeError::Authorization)?;
        let authorization = credential
            .materialize(metadata)
            .map_err(|_| NativeRuntimeError::Authorization)?;
        if cancellation.is_cancelled() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        Ok(NativeAuthorization {
            authorization,
            generation: snapshot.generation(),
        })
    }

    /// Refresh once for a stale generation, persist the rotated token with a
    /// CAS, and return the current persisted snapshot.
    pub async fn refresh(
        &self,
        upstream: &UpstreamPlan,
        credential: &CredentialId,
        expected_generation: u64,
        cancellation: CancellationToken,
    ) -> Result<TokenSnapshot, NativeRuntimeError> {
        if !self.supports(upstream) {
            return Err(NativeRuntimeError::Unsupported);
        }
        let provider = self
            .codex
            .get(upstream.id())
            .ok_or(NativeRuntimeError::Unsupported)?;
        let _lease = self.resources.refresh_lease();
        refresh_with_store_if_generation(
            &self.refresh,
            provider.as_ref(),
            self.token_store.as_ref(),
            credential.clone(),
            Some(expected_generation),
            cancellation,
        )
        .await
        .map_err(map_refresh_error)
    }

    /// Parse bounded Codex quota evidence for policy classification.
    #[must_use]
    pub fn quota_evidence(
        &self,
        upstream: &UpstreamPlan,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> (Option<String>, Option<std::time::Duration>) {
        if !self.supports(upstream) || !matches!(status, 402 | 429) {
            return (None, None);
        }
        CodexQuotaParser::default()
            .parse(headers, body)
            .ok()
            .flatten()
            .map_or((None, None), |quota| {
                (Some(quota.code().to_owned()), quota.retry_after())
            })
    }
}

fn build_codex_provider(
    id: &str,
    oauth: &OAuthPlan,
    transport: Arc<HyperOAuthTransport>,
) -> Result<pooler_auth::StandardOAuthProvider, NativeRuntimeError> {
    let config = OAuthClientConfig::new(
        oauth.client_id().to_owned(),
        oauth.callback().clone(),
        oauth.authorization_endpoint().clone(),
        oauth.token_endpoint().clone(),
    )
    .map_err(|_| NativeRuntimeError::Configuration)?
    .with_scopes(oauth.scopes().iter().map(ToString::to_string));
    let config = if let Some(endpoint) = oauth.revocation_endpoint() {
        config.with_revocation_endpoint(endpoint.clone())
    } else {
        config
    };
    let config = if let Some(endpoint) = oauth.identity_endpoint() {
        config.with_identity_endpoint(endpoint.clone())
    } else {
        config
    };
    pooler_auth::StandardOAuthProvider::new(id.to_owned(), config, transport)
        .map_err(|_| NativeRuntimeError::Configuration)
}

fn map_refresh_error(error: OAuthError) -> NativeRuntimeError {
    match error {
        OAuthError::NeedsReauth => NativeRuntimeError::NeedsReauth,
        OAuthError::Cancelled => NativeRuntimeError::CredentialUnavailable,
        OAuthError::Store(_) | OAuthError::NoRefreshToken => {
            NativeRuntimeError::CredentialUnavailable
        }
        OAuthError::Transport(_) => NativeRuntimeError::Refresh,
        _ => NativeRuntimeError::Refresh,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pooler_auth::{OAuthFuture, OAuthTokens};
    use tokio_util::sync::CancellationToken;

    use super::*;

    struct MockRefresher {
        calls: AtomicUsize,
    }

    impl OAuthRefresher for MockRefresher {
        fn refresh<'a>(
            &'a self,
            _refresh_token: &'a pooler_auth::SecretValue,
            _cancellation: CancellationToken,
        ) -> OAuthFuture<'a, OAuthTokens> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(OAuthTokens::bearer(
                    "rotated-access",
                    Some("rotated-refresh"),
                    None,
                ))
            })
        }
    }

    fn config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-test.yaml",
            r#"
version: 1
upstreams:
  codex:
    url: http://127.0.0.1:8319
    native: {kind: codex}
    oauth:
      authorization_endpoint: https://oauth.example/authorize
      token_endpoint: https://oauth.example/token
      identity_endpoint: https://oauth.example/me
      client_id: pooler-test
      scopes: [openid]
accounts:
  account-a:
    provider: codex
    secret: env:CODEX_TEST_SECRET
"#,
        )
        .expect("native config")
    }

    #[tokio::test]
    async fn concurrent_stale_401_refreshes_share_one_rotation_and_generation() {
        let credential = CredentialId::new("account-a").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        let initial = store.insert(
            credential.clone(),
            OAuthTokens::bearer("stale-access", Some("refresh-token"), None),
        );
        let refresher = Arc::new(MockRefresher {
            calls: AtomicUsize::new(0),
        });
        let runtime = NativeRuntime::with_codex_provider(store.clone(), "codex", refresher.clone())
            .with_account_id("account-a", "chatgpt-account-a");
        let upstream = config().upstreams()["codex"].clone();
        let first = runtime.refresh(
            &upstream,
            &credential,
            initial.generation(),
            CancellationToken::new(),
        );
        let second = runtime.refresh(
            &upstream,
            &credential,
            initial.generation(),
            CancellationToken::new(),
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(refresher.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            first
                .expect("first refresh")
                .tokens()
                .access_token()
                .expose_secret(),
            "rotated-access"
        );
        assert_eq!(
            second
                .expect("second refresh")
                .tokens()
                .access_token()
                .expose_secret(),
            "rotated-access"
        );
        let authorization = runtime
            .authorize(
                &upstream,
                &credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("rotated authorization");
        assert_eq!(authorization.generation(), 1);
        assert_eq!(
            store
                .load(&credential)
                .await
                .expect("load")
                .expect("snapshot")
                .tokens()
                .refresh_token()
                .expect("rotated refresh token")
                .expose_secret(),
            "rotated-refresh"
        );
    }

    #[test]
    fn invalid_request_status_does_not_expose_quota_evidence() {
        let runtime = NativeRuntime::with_codex_provider(
            Arc::new(MemoryOAuthTokenStore::new()),
            "codex",
            Arc::new(MockRefresher {
                calls: AtomicUsize::new(0),
            }),
        );
        let upstream = config().upstreams()["codex"].clone();
        let body = br#"{"error":{"code":"usage_limit_reached"}}"#;
        assert_eq!(
            runtime.quota_evidence(&upstream, 400, &HeaderMap::new(), body),
            (None, None)
        );
        assert!(runtime
            .quota_evidence(&upstream, 429, &HeaderMap::new(), body)
            .0
            .is_some());
    }

    #[tokio::test]
    async fn missing_persisted_account_identity_is_rejected() {
        let credential = CredentialId::new("account-a").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        store.insert(
            credential.clone(),
            OAuthTokens::bearer("access", Some("refresh"), None),
        );
        let runtime = NativeRuntime::with_codex_provider(
            store,
            "codex",
            Arc::new(MockRefresher {
                calls: AtomicUsize::new(0),
            }),
        );
        let upstream = config().upstreams()["codex"].clone();
        assert!(matches!(
            runtime
                .authorize(
                    &upstream,
                    &credential,
                    &HeaderMap::new(),
                    CancellationToken::new(),
                )
                .await,
            Err(NativeRuntimeError::CredentialUnavailable)
        ));
    }
}
