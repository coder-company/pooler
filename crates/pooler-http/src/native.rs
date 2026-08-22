//! Native provider credential materialization and refresh integration.
//!
//! Native adapters receive authorization only for the one outbound attempt.
//! Token stores and refresh coordinators remain behind this runtime boundary;
//! HTTP forwarding never receives raw persisted payloads.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use adapter_codex::{CodexCredential, CodexQuotaParser, CodexRequestMetadata, SESSION_ID_HEADER};
use adapter_providers::AuthPlacement;
use http::{HeaderMap, HeaderName};
use pooler_auth::{
    refresh_with_store_if_generation, CredentialId, HyperOAuthTransport, MemoryOAuthTokenStore,
    OAuthClientConfig, OAuthError, OAuthRefresher, OAuthTokenStore, ProviderLoginMethod,
    ProviderLoginRegistry, ProviderOAuthSettings, RefreshCoordinator, SecretRef as AuthSecretRef,
    SecretValue, StandardOAuthProvider, TokenSnapshot,
};
use pooler_config::{
    AccountAuthKind, AuthPlan, CompiledConfig, OAuthPlan, SecretRef, UpstreamPlan,
    DEFAULT_OAUTH_CALLBACK,
};
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
///
/// The binding materializes provider-specific credentials into this owned
/// header delta before crossing the native transport boundary. No token store
/// snapshot or provider authorization object is retained here.
pub struct NativeAuthorization {
    headers: HeaderMap,
    removals: Vec<HeaderName>,
    generation: u64,
    refreshable: bool,
}

impl std::fmt::Debug for NativeAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names = self
            .headers
            .keys()
            .map(|name| name.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("NativeAuthorization")
            .field("generation", &self.generation)
            .field("header_count", &self.headers.len())
            .field("header_names", &header_names)
            .finish()
    }
}

impl NativeAuthorization {
    /// Apply the short-lived material to an outbound request header map.
    ///
    /// This borrowed compatibility method intentionally remains repeatable for
    /// downstream callers. Cloning a header value preserves its sensitive flag.
    pub fn apply_to(&self, headers: &mut HeaderMap) -> Result<(), NativeRuntimeError> {
        for name in &self.removals {
            headers.remove(name);
        }
        let mut current_name = None;
        for (name, value) in &self.headers {
            if current_name.as_ref() == Some(name) {
                headers.append(name.clone(), value.clone());
            } else {
                headers.insert(name.clone(), value.clone());
                current_name = Some(name.clone());
            }
        }
        Ok(())
    }

    /// Consume and apply the short-lived material to one outbound request.
    pub(crate) fn apply_once(self, headers: &mut HeaderMap) -> Result<(), NativeRuntimeError> {
        let Self {
            headers: delta,
            removals,
            ..
        } = self;
        for name in removals {
            headers.remove(name);
        }
        let mut current_name = None;
        for (name, value) in delta {
            if let Some(name) = name {
                current_name = Some(name.clone());
                headers.insert(name, value);
            } else if let Some(name) = current_name.as_ref() {
                headers.append(name.clone(), value);
            } else {
                return Err(NativeRuntimeError::Authorization);
            }
        }
        Ok(())
    }

    /// Persisted token generation observed before this attempt.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrow the provider-generated authorization delta without exposing it
    /// through the public API.
    pub(crate) fn authorization_delta(&self) -> &HeaderMap {
        &self.headers
    }

    /// Whether this authorization came from the OAuth-refreshing native path.
    pub(crate) const fn is_refreshable(&self) -> bool {
        self.refreshable
    }
}

/// Internal provider-neutral boundary for native provider behavior.
///
/// Implementations borrow token snapshots, configured secret material, and
/// request data for one operation; they retain only provider machinery and
/// bounded parser configuration.
trait NativeProviderBinding: Send + Sync {
    /// Whether this binding handles the configured native kind.
    fn supports_kind(&self, kind: &str) -> bool;

    /// Materialize one OAuth credential for one outbound attempt.
    fn materialize_oauth_authorization(
        &self,
        snapshot: &TokenSnapshot,
        account_id: Option<&str>,
        request_headers: &HeaderMap,
    ) -> Result<NativeAuthorization, NativeRuntimeError>;

    /// Materialize one explicitly configured secret for one outbound attempt.
    fn materialize_configured_authorization(
        &self,
        secret: &SecretValue,
        static_auth: Option<&AuthPlan>,
        request_headers: &HeaderMap,
    ) -> Result<NativeAuthorization, NativeRuntimeError>;

    /// Access the provider-specific OAuth refresh implementation, when any.
    fn refresh_provider(&self) -> Option<&dyn OAuthRefresher>;

    /// Parse bounded provider-specific quota evidence without retaining input.
    fn quota_evidence(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> (Option<String>, Option<std::time::Duration>);
}

/// Inputs for one request-local native authorization operation.
///
/// The fields are private so callers can provide only borrowed configuration
/// references and a cancellation token; secret material is resolved inside the
/// runtime and is never retained by this request object.
pub struct NativeAuthorizationRequest<'a> {
    upstream: &'a UpstreamPlan,
    account_auth_kind: Option<AccountAuthKind>,
    credential: Option<&'a CredentialId>,
    account_secret: Option<&'a SecretRef>,
    static_auth: Option<&'a AuthPlan>,
    request_headers: &'a HeaderMap,
    cancellation: CancellationToken,
}

impl<'a> NativeAuthorizationRequest<'a> {
    /// Construct one request-local authorization operation.
    #[must_use]
    pub fn new(
        upstream: &'a UpstreamPlan,
        account_auth_kind: Option<AccountAuthKind>,
        credential: Option<&'a CredentialId>,
        account_secret: Option<&'a SecretRef>,
        static_auth: Option<&'a AuthPlan>,
        request_headers: &'a HeaderMap,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            upstream,
            account_auth_kind,
            credential,
            account_secret,
            static_auth,
            request_headers,
            cancellation,
        }
    }
}

/// Native provider runtime used by the HTTP proxy.
#[derive(Clone)]
pub struct NativeRuntime {
    token_store: Arc<dyn OAuthTokenStore>,
    refresh: RefreshCoordinator,
    bindings: Arc<BTreeMap<String, Arc<dyn NativeProviderBinding>>>,
    account_ids: Arc<BTreeMap<String, String>>,
    resources: RuntimeResources,
}

impl std::fmt::Debug for NativeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRuntime")
            .field("provider_bindings", &self.bindings.len())
            .field("account_id_overrides", &self.account_ids.len())
            .field("active_refresh_leases", &self.refresh.active_leases())
            .finish()
    }
}

impl NativeRuntime {
    /// Build a runtime from compiled native provider declarations.
    pub fn new(
        config: &CompiledConfig,
        token_store: Arc<dyn OAuthTokenStore>,
    ) -> Result<Self, NativeRuntimeError> {
        let transport = Arc::new(
            HyperOAuthTransport::new(64 * 1024).map_err(|_| NativeRuntimeError::Configuration)?,
        );
        let mut bindings: BTreeMap<String, Arc<dyn NativeProviderBinding>> = BTreeMap::new();
        for upstream in config.upstreams().values() {
            let Some(native) = upstream.native() else {
                continue;
            };
            if native.kind().eq_ignore_ascii_case("codex") {
                let provider =
                    build_codex_provider(upstream.id(), upstream.oauth(), Arc::clone(&transport))?;
                bindings.insert(
                    upstream.id().to_owned(),
                    Arc::new(CodexNativeProviderBinding::new(provider)),
                );
            } else if is_configured_native_kind(native.kind()) {
                let provider = if native.kind().eq_ignore_ascii_case("kimi")
                    || native.kind().eq_ignore_ascii_case("vertex")
                {
                    upstream
                        .oauth()
                        .map(|oauth| {
                            build_configured_oauth_provider(
                                upstream.id(),
                                oauth,
                                Arc::clone(&transport),
                            )
                        })
                        .transpose()?
                } else {
                    None
                };
                bindings.insert(
                    upstream.id().to_owned(),
                    Arc::new(ConfiguredNativeProviderBinding::new(
                        native.kind(),
                        provider,
                    )),
                );
            }
        }
        Ok(Self {
            token_store,
            refresh: RefreshCoordinator::new(),
            bindings: Arc::new(bindings),
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
        hydrate_account_ids(&mut runtime, config, |credential| {
            token_store
                .account_id(credential)
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)
        })?;
        Ok(runtime)
    }

    /// Construct a runtime with one injected Codex refresher. This is useful
    /// for deterministic provider transports and failure-injection tests.
    pub fn with_codex_provider(
        token_store: Arc<dyn OAuthTokenStore>,
        upstream_id: impl Into<String>,
        provider: Arc<dyn OAuthRefresher>,
    ) -> Self {
        let mut bindings: BTreeMap<String, Arc<dyn NativeProviderBinding>> = BTreeMap::new();
        bindings.insert(
            upstream_id.into(),
            Arc::new(CodexNativeProviderBinding::new(provider)),
        );
        Self {
            token_store,
            refresh: RefreshCoordinator::new(),
            bindings: Arc::new(bindings),
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
            bindings: Arc::new(BTreeMap::new()),
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

    /// Whether an upstream selects a registered native provider binding.
    #[must_use]
    pub fn supports(&self, upstream: &UpstreamPlan) -> bool {
        self.binding_for(upstream).is_some()
    }

    fn binding_for(&self, upstream: &UpstreamPlan) -> Option<&dyn NativeProviderBinding> {
        let native = upstream.native()?;
        let binding = self.bindings.get(upstream.id())?;
        binding
            .supports_kind(native.kind())
            .then_some(binding.as_ref())
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

    /// Load and materialize one OAuth credential for one outbound attempt.
    ///
    /// This compatibility entry point intentionally remains OAuth-specific.
    /// Configured API-key bindings are reached through [`Self::authorize_attempt`]
    /// so they cannot accidentally load the OAuth token store.
    pub async fn authorize(
        &self,
        upstream: &UpstreamPlan,
        credential: &CredentialId,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        let binding = self
            .binding_for(upstream)
            .ok_or(NativeRuntimeError::Unsupported)?;
        if binding.refresh_provider().is_none() {
            return Err(NativeRuntimeError::Unsupported);
        }
        self.authorize_oauth(binding, credential, request_headers, cancellation)
            .await
    }

    /// Authorize one selected attempt, rejecting OAuth accounts when no
    /// registered refreshable native binding owns the upstream.
    ///
    /// `Ok(None)` means the caller may continue with the legacy static or
    /// API-key account path. Native declarations never take that fallback.
    pub async fn authorize_selected_attempt(
        &self,
        request: NativeAuthorizationRequest<'_>,
    ) -> Result<Option<NativeAuthorization>, NativeRuntimeError> {
        if request.upstream.native().is_none() {
            if request.account_auth_kind == Some(AccountAuthKind::OAuth) {
                return Err(NativeRuntimeError::Authorization);
            }
            return Ok(None);
        }
        self.authorize_attempt(request).await.map(Some)
    }

    /// Materialize the selected account or static upstream authorization for
    /// one native proxy attempt. Secret references are resolved only in this
    /// method.
    pub async fn authorize_attempt(
        &self,
        request: NativeAuthorizationRequest<'_>,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        let NativeAuthorizationRequest {
            upstream,
            account_auth_kind,
            credential,
            account_secret,
            static_auth,
            request_headers,
            cancellation,
        } = request;
        let binding = self
            .binding_for(upstream)
            .ok_or(NativeRuntimeError::Unsupported)?;
        let mut authorization = match account_auth_kind {
            Some(AccountAuthKind::OAuth) => {
                if binding.refresh_provider().is_none() {
                    return Err(NativeRuntimeError::Authorization);
                }
                let credential = credential.ok_or(NativeRuntimeError::CredentialUnavailable)?;
                self.authorize_oauth(binding, credential, request_headers, cancellation)
                    .await?
            }
            Some(AccountAuthKind::ApiKey) => {
                if binding.refresh_provider().is_some() {
                    return Err(NativeRuntimeError::Authorization);
                }
                let secret = account_secret.ok_or(NativeRuntimeError::CredentialUnavailable)?;
                Self::authorize_configured(
                    binding,
                    secret,
                    static_auth,
                    request_headers,
                    cancellation,
                )?
            }
            None => {
                if credential.is_some() || account_secret.is_some() {
                    return Err(NativeRuntimeError::Authorization);
                }
                if binding.refresh_provider().is_some() {
                    return Err(NativeRuntimeError::CredentialUnavailable);
                }
                let static_auth = static_auth.ok_or(NativeRuntimeError::Authorization)?;
                Self::authorize_configured(
                    binding,
                    static_auth.secret(),
                    Some(static_auth),
                    request_headers,
                    cancellation,
                )?
            }
        };
        for (name, value) in upstream.required_headers() {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| NativeRuntimeError::Configuration)?;
            let value = http::HeaderValue::from_str(value)
                .map_err(|_| NativeRuntimeError::Configuration)?;
            authorization.headers.insert(name, value);
        }
        Ok(authorization)
    }

    async fn authorize_oauth(
        &self,
        binding: &dyn NativeProviderBinding,
        credential: &CredentialId,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        let mut snapshot = self
            .token_store
            .load(credential)
            .await
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        let refresh_before = SystemTime::now()
            .checked_add(Duration::from_secs(30))
            .unwrap_or(SystemTime::now());
        if snapshot
            .tokens()
            .expires_at()
            .is_some_and(|expires_at| expires_at <= refresh_before)
        {
            let provider = binding
                .refresh_provider()
                .ok_or(NativeRuntimeError::Unsupported)?;
            let _lease = self.resources.refresh_lease();
            snapshot = refresh_with_store_if_generation(
                &self.refresh,
                provider,
                self.token_store.as_ref(),
                credential.clone(),
                Some(snapshot.generation()),
                cancellation.clone(),
            )
            .await
            .map_err(map_refresh_error)?;
        }
        let account_id = self
            .account_ids
            .get(credential.as_str())
            .map(String::as_str);
        let authorization =
            binding.materialize_oauth_authorization(&snapshot, account_id, request_headers)?;
        if cancellation.is_cancelled() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        Ok(authorization)
    }

    fn authorize_configured(
        binding: &dyn NativeProviderBinding,
        secret: &SecretRef,
        static_auth: Option<&AuthPlan>,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        if cancellation.is_cancelled() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        let secret = resolve_secret(secret)?;
        let authorization =
            binding.materialize_configured_authorization(&secret, static_auth, request_headers)?;
        if cancellation.is_cancelled() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        Ok(authorization)
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
        let binding = self
            .binding_for(upstream)
            .ok_or(NativeRuntimeError::Unsupported)?;
        let provider = binding
            .refresh_provider()
            .ok_or(NativeRuntimeError::Unsupported)?;
        let _lease = self.resources.refresh_lease();
        refresh_with_store_if_generation(
            &self.refresh,
            provider,
            self.token_store.as_ref(),
            credential.clone(),
            Some(expected_generation),
            cancellation,
        )
        .await
        .map_err(map_refresh_error)
    }

    /// Refresh one configured OAuth account using its persisted generation.
    pub async fn refresh_account(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        cancellation: CancellationToken,
    ) -> Result<TokenSnapshot, NativeRuntimeError> {
        let account = config
            .accounts()
            .get(account_id)
            .ok_or(NativeRuntimeError::Configuration)?;
        if account.auth_kind() != AccountAuthKind::OAuth {
            return Err(NativeRuntimeError::Unsupported);
        }
        let upstream = config
            .upstreams()
            .get(account.provider())
            .ok_or(NativeRuntimeError::Configuration)?;
        let credential =
            CredentialId::new(account.id()).map_err(|_| NativeRuntimeError::Configuration)?;
        let snapshot = self
            .token_store
            .load(&credential)
            .await
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        self.refresh(upstream, &credential, snapshot.generation(), cancellation)
            .await
    }

    /// Revoke one configured OAuth account locally by deleting its token row.
    pub async fn revoke_account(
        &self,
        config: &CompiledConfig,
        account_id: &str,
    ) -> Result<(), NativeRuntimeError> {
        let account = config
            .accounts()
            .get(account_id)
            .ok_or(NativeRuntimeError::Configuration)?;
        if account.auth_kind() != AccountAuthKind::OAuth {
            return Err(NativeRuntimeError::Unsupported);
        }
        let credential =
            CredentialId::new(account.id()).map_err(|_| NativeRuntimeError::Configuration)?;
        self.token_store
            .remove(&credential)
            .await
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)
    }

    /// Parse bounded native quota evidence for policy classification.
    #[must_use]
    pub fn quota_evidence(
        &self,
        upstream: &UpstreamPlan,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> (Option<String>, Option<std::time::Duration>) {
        self.binding_for(upstream).map_or((None, None), |binding| {
            binding.quota_evidence(status, headers, body)
        })
    }
}

fn hydrate_account_ids(
    runtime: &mut NativeRuntime,
    config: &CompiledConfig,
    mut load_account_id: impl FnMut(&CredentialId) -> Result<Option<String>, NativeRuntimeError>,
) -> Result<(), NativeRuntimeError> {
    for account in config.accounts().values() {
        if account.auth_kind() != AccountAuthKind::OAuth {
            continue;
        }
        let Some(upstream) = config.upstreams().get(account.provider()) else {
            continue;
        };
        let refreshable = runtime
            .binding_for(upstream)
            .is_some_and(|binding| binding.refresh_provider().is_some());
        if !refreshable {
            continue;
        }
        let credential =
            CredentialId::new(account.id()).map_err(|_| NativeRuntimeError::Configuration)?;
        if let Some(account_id) = load_account_id(&credential)? {
            if !account_id.trim().is_empty() {
                Arc::make_mut(&mut runtime.account_ids).insert(account.id().to_owned(), account_id);
            }
        }
    }
    Ok(())
}

/// Codex implementation of the provider-neutral native boundary.
struct CodexNativeProviderBinding {
    provider: Arc<dyn OAuthRefresher>,
    quota_parser: CodexQuotaParser,
}

impl CodexNativeProviderBinding {
    fn new(provider: Arc<dyn OAuthRefresher>) -> Self {
        Self {
            provider,
            quota_parser: CodexQuotaParser::default(),
        }
    }
}

impl NativeProviderBinding for CodexNativeProviderBinding {
    fn supports_kind(&self, kind: &str) -> bool {
        kind.eq_ignore_ascii_case("codex")
    }

    fn materialize_oauth_authorization(
        &self,
        snapshot: &TokenSnapshot,
        account_id: Option<&str>,
        request_headers: &HeaderMap,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        let account_id = account_id.ok_or(NativeRuntimeError::CredentialUnavailable)?;
        let metadata = CodexRequestMetadata::from_headers(request_headers)
            .map_err(|_| NativeRuntimeError::Authorization)?;
        // CodexAuthorization removes session_id when metadata omits it. Keep
        // that operation in the delta because this materialization map starts
        // empty, and do not retain the request metadata after this point.
        let removals = if metadata.session_id.is_none() {
            vec![HeaderName::from_static(SESSION_ID_HEADER)]
        } else {
            Vec::new()
        };
        let headers = {
            let credential = CodexCredential::new(snapshot.tokens().clone(), account_id)
                .map_err(|_| NativeRuntimeError::Authorization)?;
            let authorization = credential
                .materialize(metadata)
                .map_err(|_| NativeRuntimeError::Authorization)?;
            let mut headers = HeaderMap::with_capacity(5);
            authorization
                .apply_to(&mut headers)
                .map_err(|_| NativeRuntimeError::Authorization)?;
            drop(authorization);
            for value in headers.values_mut() {
                value.set_sensitive(true);
            }
            headers
        };
        Ok(NativeAuthorization {
            headers,
            removals,
            generation: snapshot.generation(),
            refreshable: true,
        })
    }

    fn materialize_configured_authorization(
        &self,
        _secret: &SecretValue,
        _static_auth: Option<&AuthPlan>,
        _request_headers: &HeaderMap,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        Err(NativeRuntimeError::Unsupported)
    }

    fn refresh_provider(&self) -> Option<&dyn OAuthRefresher> {
        Some(self.provider.as_ref())
    }

    fn quota_evidence(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> (Option<String>, Option<std::time::Duration>) {
        if !matches!(status, 402 | 429) {
            return (None, None);
        }
        self.quota_parser
            .parse(headers, body)
            .ok()
            .flatten()
            .map_or((None, None), |quota| {
                (Some(quota.code().to_owned()), quota.retry_after())
            })
    }
}

/// Configured native binding for explicitly declared API-key upstreams.
///
/// It deliberately contains no provider endpoint or OAuth machinery. The
/// upstream's compiled authentication plan selects the placement at the
/// authorization boundary, and the only retained result is a header delta.
struct ConfiguredNativeProviderBinding {
    kind: String,
    provider: Option<Arc<dyn OAuthRefresher>>,
}

impl ConfiguredNativeProviderBinding {
    fn new(kind: &str, provider: Option<Arc<dyn OAuthRefresher>>) -> Self {
        Self {
            kind: kind.to_owned(),
            provider,
        }
    }
}

impl NativeProviderBinding for ConfiguredNativeProviderBinding {
    fn supports_kind(&self, kind: &str) -> bool {
        is_configured_native_kind(&self.kind) && self.kind.eq_ignore_ascii_case(kind)
    }

    fn materialize_oauth_authorization(
        &self,
        snapshot: &TokenSnapshot,
        _account_id: Option<&str>,
        _request_headers: &HeaderMap,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        if self.provider.is_none() {
            return Err(NativeRuntimeError::Unsupported);
        }
        let authorization = AuthPlacement::from_configured_parts("bearer_secret", None, None)
            .map_err(|_| NativeRuntimeError::Authorization)?
            .materialize(snapshot.tokens().access_token())
            .map_err(|_| NativeRuntimeError::Authorization)?;
        let mut headers = HeaderMap::new();
        authorization.apply_to(&mut headers);
        Ok(NativeAuthorization {
            headers,
            removals: Vec::new(),
            generation: snapshot.generation(),
            refreshable: true,
        })
    }

    fn materialize_configured_authorization(
        &self,
        secret: &SecretValue,
        static_auth: Option<&AuthPlan>,
        _request_headers: &HeaderMap,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        let placement = if let Some(auth) = static_auth {
            AuthPlacement::from_configured_parts(auth.kind(), auth.header(), auth.value_prefix())
        } else {
            AuthPlacement::from_configured_parts("bearer_secret", None, None)
        }
        .map_err(|_| NativeRuntimeError::Authorization)?;
        let authorization = placement
            .materialize(secret)
            .map_err(|_| NativeRuntimeError::Authorization)?;
        let mut headers = HeaderMap::new();
        authorization.apply_to(&mut headers);
        Ok(NativeAuthorization {
            headers,
            removals: Vec::new(),
            generation: 0,
            refreshable: false,
        })
    }

    fn refresh_provider(&self) -> Option<&dyn OAuthRefresher> {
        self.provider.as_deref()
    }

    fn quota_evidence(
        &self,
        _status: u16,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> (Option<String>, Option<std::time::Duration>) {
        (None, None)
    }
}

const CONFIGURED_NATIVE_KINDS: &[&str] = &[
    "anthropic",
    "gemini",
    "vertex",
    "xai",
    "kimi",
    "antigravity",
    "compatible",
    "openai_compatible",
];

fn is_configured_native_kind(kind: &str) -> bool {
    CONFIGURED_NATIVE_KINDS
        .iter()
        .any(|candidate| kind.eq_ignore_ascii_case(candidate))
}

fn resolve_secret(secret: &SecretRef) -> Result<SecretValue, NativeRuntimeError> {
    let reference = match secret {
        SecretRef::Env(name) => AuthSecretRef::Env(name.to_string()),
        SecretRef::File(path) => AuthSecretRef::File(path.as_ref().into()),
        SecretRef::Keyring { service, account } => AuthSecretRef::Keyring {
            service: service.to_string(),
            account: account.to_string(),
        },
    };
    let secret = reference
        .resolve()
        .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
    if secret.expose_secret().chars().any(char::is_whitespace) {
        return Err(NativeRuntimeError::CredentialUnavailable);
    }
    Ok(secret)
}

fn build_configured_oauth_provider(
    id: &str,
    oauth: &OAuthPlan,
    transport: Arc<HyperOAuthTransport>,
) -> Result<Arc<dyn OAuthRefresher>, NativeRuntimeError> {
    let mut config = OAuthClientConfig::new(
        oauth.client_id().to_owned(),
        oauth.callback().clone(),
        oauth.authorization_endpoint().clone(),
        oauth.token_endpoint().clone(),
    )
    .map_err(|_| NativeRuntimeError::Configuration)?
    .with_scopes(oauth.scopes().iter().map(ToString::to_string));
    if let Some(endpoint) = oauth.revocation_endpoint() {
        config = config.with_revocation_endpoint(endpoint.clone());
    }
    if let Some(endpoint) = oauth.identity_endpoint() {
        config = config.with_identity_endpoint(endpoint.clone());
    }
    let provider = StandardOAuthProvider::new(id, config, transport)
        .map_err(|_| NativeRuntimeError::Configuration)?;
    Ok(Arc::new(provider))
}

fn build_codex_provider(
    id: &str,
    oauth: Option<&OAuthPlan>,
    transport: Arc<HyperOAuthTransport>,
) -> Result<Arc<dyn OAuthRefresher>, NativeRuntimeError> {
    if let Some(oauth) = oauth {
        let mut config = OAuthClientConfig::new(
            oauth.client_id().to_owned(),
            oauth.callback().clone(),
            oauth.authorization_endpoint().clone(),
            oauth.token_endpoint().clone(),
        )
        .map_err(|_| NativeRuntimeError::Configuration)?
        .with_scopes(oauth.scopes().iter().map(ToString::to_string));
        if let Some(endpoint) = oauth.revocation_endpoint() {
            config = config.with_revocation_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = oauth.identity_endpoint() {
            config = config.with_identity_endpoint(endpoint.clone());
        }
        let provider = StandardOAuthProvider::new(id, config, transport)
            .map_err(|_| NativeRuntimeError::Configuration)?;
        return Ok(Arc::new(provider));
    }

    let definition = ProviderLoginRegistry::builtin()
        .require("openai")
        .map_err(|_| NativeRuntimeError::Configuration)?;
    let callback = DEFAULT_OAUTH_CALLBACK
        .parse()
        .map_err(|_| NativeRuntimeError::Configuration)?;
    let provider = definition
        .build_oauth_provider(
            ProviderLoginMethod::AuthorizationCodePkce,
            ProviderOAuthSettings::new(String::new(), callback),
            transport,
        )
        .map_err(|_| NativeRuntimeError::Configuration)?;
    Ok(Arc::new(provider))
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
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use http::{header, HeaderValue};
    use pooler_auth::{OAuthFuture, OAuthStoreFuture, OAuthTokens};
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

    struct PanicOAuthStore;

    impl OAuthTokenStore for PanicOAuthStore {
        fn load<'a>(
            &'a self,
            _credential: &'a CredentialId,
        ) -> OAuthStoreFuture<'a, Option<TokenSnapshot>> {
            panic!("configured native authorization must not load OAuth tokens")
        }

        fn compare_and_swap<'a>(
            &'a self,
            _credential: &'a CredentialId,
            _expected_generation: u64,
            _tokens: OAuthTokens,
        ) -> OAuthStoreFuture<'a, TokenSnapshot> {
            panic!("configured native authorization must not refresh OAuth tokens")
        }

        fn remove<'a>(&'a self, _credential: &'a CredentialId) -> OAuthStoreFuture<'a, ()> {
            panic!("configured native authorization must not remove OAuth tokens")
        }
    }

    struct TestSecretFile {
        reference: SecretRef,
        path: PathBuf,
    }

    impl TestSecretFile {
        fn reference(&self) -> &SecretRef {
            &self.reference
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestSecretFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn assert_header_value(headers: &HeaderMap, name: &str, expected: &[u8]) {
        assert!(
            headers
                .get(name)
                .is_some_and(|value| value.as_bytes() == expected),
            "authorization header did not match"
        );
    }

    fn assert_secret_value(actual: &str, expected: &str) {
        assert!(actual == expected, "OAuth token did not match");
    }

    fn secret_file(value: &str) -> TestSecretFile {
        static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pooler-http-native-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, value).expect("native test secret");
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("native test secret permissions");
        TestSecretFile {
            reference: SecretRef::File(Arc::<str>::from(path.to_string_lossy().into_owned())),
            path,
        }
    }

    #[test]
    fn test_secret_file_raii_cleanup_runs_on_drop() {
        let path = {
            let secret = secret_file("raii-secret");
            assert!(secret.path().is_file());
            secret.path().to_owned()
        };
        assert!(!path.exists());
    }

    fn configured_config(static_path: &Path) -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-configured-test.yaml",
            &format!(
                "version: 1\nupstreams:\n  xai:\n    url: http://127.0.0.1:8322\n    native:\n      kind: xai\n    auth:\n      kind: header\n      header: x-provider-key\n      value_prefix: 'Token '\n      secret: 'file:{}'\naccounts:\n  api-account:\n    provider: xai\n    auth_kind: api_key\n    secret: file:/definitely/not/a/native/key\n",
                static_path.display()
            ),
        )
        .expect("configured native config")
    }

    fn compatible_config(static_path: &Path) -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-compatible-test.yaml",
            &format!(
                "version: 1\nupstreams:\n  compatible:\n    url: http://127.0.0.1:8336\n    native: {{kind: compatible}}\n    auth:\n      kind: header\n      header: x-provider-token\n      value_prefix: 'Token '\n      secret: 'file:{}'\n",
                static_path.display()
            ),
        )
        .expect("compatible native config")
    }

    fn kimi_oauth_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-kimi-oauth-test.yaml",
            r#"
version: 1
upstreams:
  kimi-coding:
    url: http://127.0.0.1:8334
    native: {kind: kimi}
    oauth:
      authorization_endpoint: https://auth.kimi.com/api/oauth/authorize
      token_endpoint: https://auth.kimi.com/api/oauth/token
      client_id: operator-owned-client
      scopes: [operator-registered-scope]
accounts:
  kimi-subscription: {provider: kimi-coding, auth_kind: oauth}
"#,
        )
        .expect("Kimi OAuth config")
    }

    fn vertex_oauth_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-vertex-oauth-test.yaml",
            r#"
version: 1
upstreams:
  vertex:
    url: http://127.0.0.1:8335
    native:
      kind: vertex
      project: test-project
      location: us-central1
    oauth:
      authorization_endpoint: https://accounts.google.com/o/oauth2/v2/auth
      token_endpoint: https://oauth2.googleapis.com/token
      client_id: operator-owned-client
      scopes: [https://www.googleapis.com/auth/cloud-platform]
accounts:
  vertex-user: {provider: vertex, auth_kind: oauth}
"#,
        )
        .expect("Vertex OAuth config")
    }

    fn configured_without_auth_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-configured-without-auth-test.yaml",
            "version: 1\nupstreams:\n  xai:\n    url: http://127.0.0.1:8333\n    native: {kind: xai}\n",
        )
        .expect("configured native config without auth")
    }

    fn configured_kinds_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-kinds-test.yaml",
            r#"
version: 1
upstreams:
  anthropic:
    url: http://127.0.0.1:8323
    native: {kind: ANTHROPIC}
  gemini:
    url: http://127.0.0.1:8324
    native: {kind: gemini}
  vertex:
    url: http://127.0.0.1:8325
    native: {kind: vertex}
  xai:
    url: http://127.0.0.1:8326
    native: {kind: xai}
  kimi:
    url: http://127.0.0.1:8327
    native: {kind: kimi}
  antigravity:
    url: http://127.0.0.1:8328
    native: {kind: antigravity}
  compatible:
    url: http://127.0.0.1:8329
    native: {kind: compatible}
  openai-compatible:
    url: http://127.0.0.1:8330
    native: {kind: OPENAI_COMPATIBLE}
  unknown:
    url: http://127.0.0.1:8331
    native: {kind: future_provider}
  plain:
    url: http://127.0.0.1:8332
"#,
        )
        .expect("native kind config")
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

    fn unregistered_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-unregistered-test.yaml",
            r#"
version: 1
upstreams:
  other:
    url: http://127.0.0.1:8320
    native: {kind: codex}
"#,
        )
        .expect("unregistered native config")
    }

    fn mismatched_kind_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-mismatched-kind-test.yaml",
            r#"
version: 1
upstreams:
  codex:
    url: http://127.0.0.1:8321
    native: {kind: other}
"#,
        )
        .expect("mismatched native kind config")
    }

    fn hydration_filter_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-hydration-filter-test.yaml",
            r#"
version: 1
upstreams:
  codex:
    url: http://127.0.0.1:8319
    native: {kind: codex}
    oauth:
      authorization_endpoint: https://oauth.example/authorize
      token_endpoint: https://oauth.example/token
      client_id: pooler-test
      scopes: [openid]
  xai:
    url: http://127.0.0.1:8322
    native: {kind: xai}
    oauth:
      authorization_endpoint: https://oauth.example/authorize
      token_endpoint: https://oauth.example/token
      client_id: pooler-test
      scopes: [openid]
  plain:
    url: http://127.0.0.1:8323
    oauth:
      authorization_endpoint: https://oauth.example/authorize
      token_endpoint: https://oauth.example/token
      client_id: pooler-test
      scopes: [openid]
accounts:
  oauth-codex: {provider: codex, auth_kind: oauth}
  oauth-configured: {provider: xai, auth_kind: oauth}
  oauth-plain: {provider: plain, auth_kind: oauth}
  api-configured: {provider: xai, auth_kind: api_key, secret: env:POOLER_NATIVE_API_KEY}
"#,
        )
        .expect("hydration filter config")
    }

    #[test]
    fn configured_native_kinds_register_case_insensitively_and_unknowns_do_not() {
        let config = configured_kinds_config();
        let runtime = NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime");
        for upstream_id in [
            "anthropic",
            "gemini",
            "vertex",
            "xai",
            "kimi",
            "antigravity",
            "compatible",
            "openai-compatible",
        ] {
            assert!(
                runtime.supports(&config.upstreams()[upstream_id]),
                "{upstream_id}"
            );
        }
        assert!(!runtime.supports(&config.upstreams()["unknown"]));
        assert!(!runtime.supports(&config.upstreams()["plain"]));
    }

    #[test]
    fn sqlite_hydration_reads_only_oauth_accounts_with_refreshable_bindings() {
        let config = hydration_filter_config();
        let mut runtime = NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime");
        let reads = AtomicUsize::new(0);
        hydrate_account_ids(&mut runtime, &config, |credential| {
            reads.fetch_add(1, Ordering::Relaxed);
            assert_eq!(credential.as_str(), "oauth-codex");
            Ok(Some("provider-account".to_owned()))
        })
        .expect("hydrate account IDs");

        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert_eq!(
            runtime.account_ids.get("oauth-codex").map(String::as_str),
            Some("provider-account")
        );
        assert!(!runtime.account_ids.contains_key("oauth-configured"));
        assert!(!runtime.account_ids.contains_key("oauth-plain"));
        assert!(!runtime.account_ids.contains_key("api-configured"));
    }

    #[tokio::test]
    async fn configured_api_key_wins_over_static_auth_and_preserves_placement() {
        let static_secret = secret_file("static-secret");
        let config = configured_config(static_secret.path());
        let upstream = &config.upstreams()["xai"];
        let account_secret = secret_file("account-api-key");
        let credential = CredentialId::new("api-account").expect("credential");
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        let authorization = runtime
            .authorize_attempt(NativeAuthorizationRequest {
                upstream,
                account_auth_kind: Some(AccountAuthKind::ApiKey),
                credential: Some(&credential),
                account_secret: Some(account_secret.reference()),
                static_auth: upstream.auth(),
                request_headers: &HeaderMap::new(),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("configured authorization");
        let debug = format!("{authorization:?}");
        assert!(!debug.contains("account-api-key"));
        assert!(!debug.contains("static-secret"));
        assert!(!authorization.is_refreshable());
        assert_eq!(authorization.generation(), 0);

        let mut outbound = HeaderMap::new();
        outbound.insert("x-provider-key", HeaderValue::from_static("stale"));
        authorization
            .apply_to(&mut outbound)
            .expect("configured headers");
        assert_header_value(&outbound, "x-provider-key", b"Token account-api-key");
        assert!(outbound
            .get("x-provider-key")
            .is_some_and(HeaderValue::is_sensitive));

        drop(authorization);
    }

    #[tokio::test]
    async fn configured_api_key_defaults_to_bearer_without_static_auth() {
        let account_secret = secret_file("account-api-key");
        let config = configured_without_auth_config();
        let upstream = &config.upstreams()["xai"];
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        let authorization = runtime
            .authorize_attempt(NativeAuthorizationRequest {
                upstream,
                account_auth_kind: Some(AccountAuthKind::ApiKey),
                credential: None,
                account_secret: Some(account_secret.reference()),
                static_auth: None,
                request_headers: &HeaderMap::new(),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("configured bearer authorization");
        let mut outbound = HeaderMap::new();
        authorization
            .apply_once(&mut outbound)
            .expect("configured bearer headers");
        assert_header_value(
            &outbound,
            header::AUTHORIZATION.as_str(),
            b"Bearer account-api-key",
        );
        assert!(outbound
            .get(header::AUTHORIZATION)
            .is_some_and(HeaderValue::is_sensitive));
    }

    #[tokio::test]
    async fn configured_static_auth_works_without_selected_account() {
        let static_secret = secret_file("static-api-key");
        let config = configured_config(static_secret.path());
        let upstream = &config.upstreams()["xai"];
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        let authorization = runtime
            .authorize_attempt(NativeAuthorizationRequest {
                upstream,
                account_auth_kind: None,
                credential: None,
                account_secret: None,
                static_auth: upstream.auth(),
                request_headers: &HeaderMap::new(),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("static authorization");
        let mut outbound = HeaderMap::new();
        authorization
            .apply_once(&mut outbound)
            .expect("static headers");
        assert_header_value(&outbound, "x-provider-key", b"Token static-api-key");
        assert!(outbound
            .get("x-provider-key")
            .is_some_and(HeaderValue::is_sensitive));
    }

    #[tokio::test]
    async fn configured_kimi_oauth_materializes_refreshable_bearer_token() {
        let credential = CredentialId::new("kimi-subscription").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        store.insert(
            credential.clone(),
            OAuthTokens::bearer(
                "kimi-oauth-access",
                Some("kimi-oauth-refresh"),
                Some(SystemTime::now() + Duration::from_secs(3600)),
            ),
        );
        let config = kimi_oauth_config();
        let runtime = NativeRuntime::new(&config, store).expect("Kimi native runtime");
        let upstream = &config.upstreams()["kimi-coding"];

        let authorization = runtime
            .authorize(
                upstream,
                &credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("Kimi OAuth authorization");
        let mut headers = HeaderMap::new();
        authorization
            .apply_to(&mut headers)
            .expect("authorization headers");

        assert!(authorization.is_refreshable());
        assert_header_value(&headers, "authorization", b"Bearer kimi-oauth-access");
    }

    #[tokio::test]
    async fn kimi_api_key_and_subscription_oauth_identities_remain_distinct() {
        let api_secret = secret_file("kimi-open-platform-key");
        let api_reference =
            SecretRef::parse(&format!("file:{}", api_secret.path().display())).expect("API ref");
        let api_credential = CredentialId::new("kimi-open-platform").expect("credential");
        let oauth_credential = CredentialId::new("kimi-subscription").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        store.insert(
            oauth_credential.clone(),
            OAuthTokens::bearer(
                "kimi-subscription-access",
                Some("kimi-subscription-refresh"),
                Some(SystemTime::now() + Duration::from_secs(3600)),
            ),
        );
        let config = kimi_oauth_config();
        let runtime = NativeRuntime::new(&config, store).expect("Kimi native runtime");
        let upstream = &config.upstreams()["kimi-coding"];

        assert!(matches!(
            runtime
                .authorize_attempt(NativeAuthorizationRequest {
                    upstream,
                    account_auth_kind: Some(AccountAuthKind::ApiKey),
                    credential: Some(&api_credential),
                    account_secret: Some(&api_reference),
                    static_auth: upstream.auth(),
                    request_headers: &HeaderMap::new(),
                    cancellation: CancellationToken::new(),
                })
                .await,
            Err(NativeRuntimeError::Authorization)
        ));

        let oauth_authorization = runtime
            .authorize(
                upstream,
                &oauth_credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("Kimi subscription authorization");
        let mut oauth_headers = HeaderMap::new();
        oauth_authorization
            .apply_to(&mut oauth_headers)
            .expect("OAuth headers");
        assert!(oauth_authorization.is_refreshable());
        assert_header_value(
            &oauth_headers,
            "authorization",
            b"Bearer kimi-subscription-access",
        );
    }

    #[tokio::test]
    async fn configured_vertex_oauth_materializes_refreshable_access_token() {
        let credential = CredentialId::new("vertex-user").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        store.insert(
            credential.clone(),
            OAuthTokens::bearer(
                "vertex-oauth-access",
                Some("vertex-oauth-refresh"),
                Some(SystemTime::now() + Duration::from_secs(3600)),
            ),
        );
        let config = vertex_oauth_config();
        let runtime = NativeRuntime::new(&config, store).expect("Vertex native runtime");
        let upstream = &config.upstreams()["vertex"];

        let authorization = runtime
            .authorize(
                upstream,
                &credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("Vertex OAuth authorization");
        let mut headers = HeaderMap::new();
        authorization
            .apply_to(&mut headers)
            .expect("authorization headers");

        assert!(authorization.is_refreshable());
        assert_header_value(&headers, "authorization", b"Bearer vertex-oauth-access");
    }

    #[tokio::test]
    async fn configured_oauth_account_fails_closed_without_fallback() {
        let static_secret = secret_file("static-secret");
        let config = configured_config(static_secret.path());
        let upstream = &config.upstreams()["xai"];
        let account_secret = SecretRef::parse("file:/definitely/not/a/native/key").expect("ref");
        let credential = CredentialId::new("oauth-account").expect("credential");
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        assert!(matches!(
            runtime
                .authorize_attempt(NativeAuthorizationRequest {
                    upstream,
                    account_auth_kind: Some(AccountAuthKind::OAuth),
                    credential: Some(&credential),
                    account_secret: Some(&account_secret),
                    static_auth: upstream.auth(),
                    request_headers: &HeaderMap::new(),
                    cancellation: CancellationToken::new(),
                })
                .await,
            Err(NativeRuntimeError::Authorization)
        ));
    }

    #[tokio::test]
    async fn compatible_api_key_and_oauth_identities_do_not_substitute() {
        let static_secret = secret_file("static-fallback");
        let account_secret = secret_file("compatible-account-key");
        let account_reference =
            SecretRef::parse(&format!("file:{}", account_secret.path().display()))
                .expect("account secret reference");
        let config = compatible_config(static_secret.path());
        let upstream = &config.upstreams()["compatible"];
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        let api_credential = CredentialId::new("compatible-api").expect("credential");

        let authorization = runtime
            .authorize_attempt(NativeAuthorizationRequest {
                upstream,
                account_auth_kind: Some(AccountAuthKind::ApiKey),
                credential: Some(&api_credential),
                account_secret: Some(&account_reference),
                static_auth: upstream.auth(),
                request_headers: &HeaderMap::new(),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("compatible API-key authorization");
        let mut headers = HeaderMap::new();
        authorization
            .apply_once(&mut headers)
            .expect("API-key header");
        assert_header_value(
            &headers,
            "x-provider-token",
            b"Token compatible-account-key",
        );
        assert_eq!(headers.get("authorization"), None);

        let oauth_credential = CredentialId::new("compatible-oauth").expect("credential");
        assert!(matches!(
            runtime
                .authorize_attempt(NativeAuthorizationRequest {
                    upstream,
                    account_auth_kind: Some(AccountAuthKind::OAuth),
                    credential: Some(&oauth_credential),
                    account_secret: None,
                    static_auth: upstream.auth(),
                    request_headers: &HeaderMap::new(),
                    cancellation: CancellationToken::new(),
                })
                .await,
            Err(NativeRuntimeError::Authorization)
        ));
    }

    #[tokio::test]
    async fn configured_authorization_never_loads_or_refreshes_oauth_tokens() {
        let static_secret = secret_file("unused-static-secret");
        let config = configured_config(static_secret.path());
        let upstream = &config.upstreams()["xai"];
        let account_secret = secret_file("account-api-key");
        let credential = CredentialId::new("api-account").expect("credential");
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        runtime
            .authorize_attempt(NativeAuthorizationRequest {
                upstream,
                account_auth_kind: Some(AccountAuthKind::ApiKey),
                credential: Some(&credential),
                account_secret: Some(account_secret.reference()),
                static_auth: upstream.auth(),
                request_headers: &HeaderMap::new(),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("configured authorization");
        assert!(matches!(
            runtime
                .refresh(upstream, &credential, 0, CancellationToken::new())
                .await,
            Err(NativeRuntimeError::Unsupported)
        ));
    }

    #[test]
    fn provider_bindings_select_by_upstream_id_and_debug_neutrally() {
        let runtime = NativeRuntime::new(&config(), Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime")
            .with_account_id("account-a", "chatgpt-account-a");
        let registered = config().upstreams()["codex"].clone();
        let unregistered = unregistered_config().upstreams()["other"].clone();

        assert!(runtime.supports(&registered));
        assert!(!runtime.supports(&unregistered));

        let debug = format!("{runtime:?}");
        assert!(debug.contains("NativeRuntime"));
        assert!(!debug.contains("codex"));
        assert!(!debug.contains("account-a"));
        assert!(!debug.contains("access-secret"));
    }

    #[test]
    fn provider_binding_does_not_match_same_id_with_different_native_kind() {
        let runtime = NativeRuntime::new(&config(), Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime");
        let mismatched = mismatched_kind_config().upstreams()["codex"].clone();

        assert!(!runtime.supports(&mismatched));
    }

    #[test]
    fn apply_once_replaces_first_value_and_appends_continuations() {
        let mut delta = HeaderMap::new();
        delta.insert("x-repeated", HeaderValue::from_static("new-first"));
        delta.append("x-repeated", HeaderValue::from_static("new-second"));
        let authorization = NativeAuthorization {
            headers: delta,
            removals: Vec::new(),
            generation: 0,
            refreshable: false,
        };

        let mut outbound = HeaderMap::new();
        outbound.insert("x-repeated", HeaderValue::from_static("stale"));
        authorization
            .apply_once(&mut outbound)
            .expect("native headers");

        let values = outbound
            .get_all("x-repeated")
            .iter()
            .map(|value| value.to_str().expect("header text"))
            .collect::<Vec<_>>();
        assert_eq!(values, vec!["new-first", "new-second"]);
    }

    #[tokio::test]
    async fn codex_authorization_materializes_request_and_account_identity() {
        let credential = CredentialId::new("account-a").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        store.insert(
            credential.clone(),
            OAuthTokens::bearer("access-secret", Some("refresh"), None),
        );
        let runtime = NativeRuntime::with_codex_provider(
            store,
            "codex",
            Arc::new(MockRefresher {
                calls: AtomicUsize::new(0),
            }),
        )
        .with_account_id("account-a", "chatgpt-account-a");
        let upstream = config().upstreams()["codex"].clone();
        let mut request_headers = HeaderMap::new();
        request_headers.insert("originator", HeaderValue::from_static("codex-test"));
        request_headers.insert("session_id", HeaderValue::from_static("session-a"));
        request_headers.insert(header::USER_AGENT, HeaderValue::from_static("client/1"));

        let authorization = runtime
            .authorize(
                &upstream,
                &credential,
                &request_headers,
                CancellationToken::new(),
            )
            .await
            .expect("authorization");
        let debug = format!("{authorization:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("chatgpt-account-a"));
        assert!(!debug.contains("codex-test"));
        assert!(!debug.contains("session-a"));
        assert!(!debug.contains("client/1"));

        let mut outbound = HeaderMap::new();
        outbound.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer conflicting"),
        );
        outbound.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("conflicting-account"),
        );
        authorization
            .apply_to(&mut outbound)
            .expect("native headers");
        authorization
            .apply_to(&mut outbound)
            .expect("repeat native headers");
        assert_header_value(
            &outbound,
            header::AUTHORIZATION.as_str(),
            b"Bearer access-secret",
        );
        for name in [
            "authorization",
            "chatgpt-account-id",
            "originator",
            "session_id",
            "user-agent",
        ] {
            assert!(outbound.get(name).is_some_and(|value| value.is_sensitive()));
        }
        assert_header_value(&outbound, "chatgpt-account-id", b"chatgpt-account-a");
        assert_header_value(&outbound, "originator", b"codex-test");
        assert_header_value(&outbound, "session_id", b"session-a");
        assert_header_value(&outbound, header::USER_AGENT.as_str(), b"client/1");

        let authorization = runtime
            .authorize(
                &upstream,
                &credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("authorization without session");
        let mut stale = HeaderMap::new();
        stale.insert("session_id", HeaderValue::from_static("stale-session"));
        stale.insert("x-unrelated", HeaderValue::from_static("keep-me"));
        authorization
            .apply_to(&mut stale)
            .expect("native headers without session");
        assert!(!stale.contains_key("session_id"));
        assert_eq!(
            stale
                .get("x-unrelated")
                .and_then(|value| value.to_str().ok()),
            Some("keep-me")
        );
    }

    #[tokio::test]
    async fn cancelled_authorization_is_not_returned() {
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
        )
        .with_account_id("account-a", "chatgpt-account-a");
        let upstream = config().upstreams()["codex"].clone();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(matches!(
            runtime
                .authorize(&upstream, &credential, &HeaderMap::new(), cancellation,)
                .await,
            Err(NativeRuntimeError::CredentialUnavailable)
        ));
    }

    #[tokio::test]
    async fn expiring_oauth_is_refreshed_before_authorization_is_materialized() {
        let credential = CredentialId::new("account-a").expect("credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        store.insert(
            credential.clone(),
            OAuthTokens::bearer(
                "expired-access",
                Some("refresh-token"),
                Some(SystemTime::now() - Duration::from_secs(1)),
            ),
        );
        let refresher = Arc::new(MockRefresher {
            calls: AtomicUsize::new(0),
        });
        let runtime = NativeRuntime::with_codex_provider(store, "codex", refresher.clone())
            .with_account_id("account-a", "chatgpt-account-a");
        let upstream = config().upstreams()["codex"].clone();

        let authorization = runtime
            .authorize(
                &upstream,
                &credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("refreshed authorization");
        let mut headers = HeaderMap::new();
        authorization
            .apply_to(&mut headers)
            .expect("authorization headers");

        assert_eq!(refresher.calls.load(Ordering::Relaxed), 1);
        assert_eq!(authorization.generation(), 1);
        assert_header_value(&headers, "authorization", b"Bearer rotated-access");
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
        assert_secret_value(
            first
                .expect("first refresh")
                .tokens()
                .access_token()
                .expose_secret(),
            "rotated-access",
        );
        assert_secret_value(
            second
                .expect("second refresh")
                .tokens()
                .access_token()
                .expose_secret(),
            "rotated-access",
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
        assert_secret_value(
            store
                .load(&credential)
                .await
                .expect("load")
                .expect("snapshot")
                .tokens()
                .refresh_token()
                .expect("rotated refresh token")
                .expose_secret(),
            "rotated-refresh",
        );
    }

    #[tokio::test]
    async fn management_account_refresh_and_local_revoke_use_the_native_store() {
        let config = hydration_filter_config();
        let store = Arc::new(MemoryOAuthTokenStore::new());
        let credential = CredentialId::new("oauth-codex").expect("credential");
        store.insert(
            credential.clone(),
            OAuthTokens::bearer("stale-access", Some("refresh-token"), None),
        );
        let refresher = Arc::new(MockRefresher {
            calls: AtomicUsize::new(0),
        });
        let runtime = NativeRuntime::with_codex_provider(store.clone(), "codex", refresher.clone());

        let refreshed = runtime
            .refresh_account(&config, "oauth-codex", CancellationToken::new())
            .await
            .expect("management refresh");
        assert_eq!(refreshed.generation(), 1);
        assert_eq!(refresher.calls.load(Ordering::Relaxed), 1);
        runtime
            .revoke_account(&config, "oauth-codex")
            .await
            .expect("local revoke");
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn different_accounts_refresh_independently_without_identity_crossover() {
        let first = CredentialId::new("account-a").expect("first credential");
        let second = CredentialId::new("account-b").expect("second credential");
        let store = Arc::new(MemoryOAuthTokenStore::new());
        let first_snapshot = store.insert(
            first.clone(),
            OAuthTokens::bearer("stale-a", Some("refresh-a"), None),
        );
        let second_snapshot = store.insert(
            second.clone(),
            OAuthTokens::bearer("stale-b", Some("refresh-b"), None),
        );
        let refresher = Arc::new(MockRefresher {
            calls: AtomicUsize::new(0),
        });
        let runtime = NativeRuntime::with_codex_provider(store, "codex", refresher.clone())
            .with_account_id("account-a", "chatgpt-account-a")
            .with_account_id("account-b", "chatgpt-account-b");
        let upstream = config().upstreams()["codex"].clone();
        let (first_result, second_result) = tokio::join!(
            runtime.refresh(
                &upstream,
                &first,
                first_snapshot.generation(),
                CancellationToken::new(),
            ),
            runtime.refresh(
                &upstream,
                &second,
                second_snapshot.generation(),
                CancellationToken::new(),
            )
        );
        assert_eq!(refresher.calls.load(Ordering::Relaxed), 2);
        assert_eq!(first_result.expect("first refresh").generation(), 1);
        assert_eq!(second_result.expect("second refresh").generation(), 1);
        for (credential, expected_account) in [
            (&first, "chatgpt-account-a"),
            (&second, "chatgpt-account-b"),
        ] {
            let authorization = runtime
                .authorize(
                    &upstream,
                    credential,
                    &HeaderMap::new(),
                    CancellationToken::new(),
                )
                .await
                .expect("authorization");
            let mut headers = HeaderMap::new();
            authorization
                .apply_to(&mut headers)
                .expect("authorization headers");
            assert_header_value(&headers, "chatgpt-account-id", expected_account.as_bytes());
        }
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
