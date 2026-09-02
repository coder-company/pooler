//! Native provider credential materialization and refresh integration.
//!
//! Native adapters receive authorization only for the one outbound attempt.
//! Token stores and refresh coordinators remain behind this runtime boundary;
//! HTTP forwarding never receives raw persisted payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use adapter_codex::{CodexCredential, CodexQuotaParser, CodexRequestMetadata, SESSION_ID_HEADER};
use adapter_providers::AuthPlacement;
use http::{HeaderMap, HeaderName};
use pooler_auth::{
    renew_with_store_if_generation, renew_with_store_if_generation_for_fingerprint,
    AuthorizationAttempt, CredentialId, DeviceAuthorization, HyperOAuthTransport,
    MemoryOAuthTokenStore, OAuthClientAuth, OAuthClientConfig, OAuthClientCredentials,
    OAuthCodeExchange, OAuthCredentialProfile, OAuthDeviceFlow, OAuthError, OAuthIdentity,
    OAuthIdentityProvider, OAuthProvider, OAuthRefresher, OAuthState, OAuthTokenStore, OAuthTokens,
    PkcePair, ProviderLoginMethod, ProviderLoginRegistry, ProviderOAuthClient,
    ProviderOAuthSettings, RefreshCoordinator, SecretRef as AuthSecretRef, SecretValue,
    StandardOAuthProvider, TokenSnapshot,
};
use pooler_config::{
    AccountAuthKind, AccountPlan, AuthPlan, CompiledConfig, OAuthGrantType, OAuthPlan, SecretRef,
    UpstreamPlan, DEFAULT_OAUTH_CALLBACK,
};
use pooler_store::{
    credential_configuration_fingerprint, CredentialFingerprintInput,
    CredentialFingerprintRetirement,
};
use pooler_store::{CredentialState, SqliteOAuthTokenStore, Store};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{PoolError, PoolingCoordinator, RuntimeResourceSnapshot, RuntimeResources};

const DEVICE_AUTHORIZATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const OAUTH_TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Refresh failed because interactive login is required for the observed
    /// token generation. The generation is non-secret and fences health changes.
    #[error("native credential needs reauthorization")]
    NeedsReauth { generation: u64 },
    /// Refresh failed for a provider or transport reason.
    #[error("native credential refresh failed")]
    Refresh,
    /// The configured native OAuth provider is invalid.
    #[error("native provider configuration is invalid")]
    Configuration,
}

/// Non-secret device authorization details safe to present to an authenticated operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDeviceAuthorization {
    verification_uri: String,
    verification_uri_complete: Option<String>,
    user_code: String,
    expires_in_seconds: u64,
}

impl NativeDeviceAuthorization {
    /// Provider page where the operator completes authorization.
    #[must_use]
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// Provider page with the short code embedded, when supplied by the provider.
    #[must_use]
    pub fn verification_uri_complete(&self) -> Option<&str> {
        self.verification_uri_complete.as_deref()
    }

    /// User-facing short code. The provider's device credential is never exposed.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// Provider-supplied authorization lifetime.
    #[must_use]
    pub const fn expires_in_seconds(&self) -> u64 {
        self.expires_in_seconds
    }
}

/// Opaque server-side continuation for one device authorization.
pub struct NativeDeviceLoginSession {
    provider: ProviderOAuthClient,
    authorization: DeviceAuthorization,
    target: NativeOAuthLoginTarget,
}

impl std::fmt::Debug for NativeDeviceLoginSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDeviceLoginSession")
            .field("profile", &self.provider.definition().id())
            .finish_non_exhaustive()
    }
}

/// Opaque completed device exchange awaiting generation-serialized persistence.
pub struct NativeDeviceLoginResult {
    session: NativeDeviceLoginSession,
    tokens: OAuthTokens,
}

/// Non-secret browser authorization details safe to return to an authenticated operator.
pub struct NativeBrowserAuthorization {
    authorization_url: Url,
}

impl NativeBrowserAuthorization {
    /// HTTPS provider page where the operator completes authorization.
    #[must_use]
    pub const fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }
}

impl std::fmt::Debug for NativeBrowserAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeBrowserAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .finish()
    }
}

/// Opaque server-held PKCE continuation for one configured browser login.
pub struct NativeBrowserLoginSession {
    provider: StandardOAuthProvider,
    attempt: AuthorizationAttempt,
    target: NativeOAuthLoginTarget,
}

impl NativeBrowserLoginSession {
    /// Match callback state without exposing the server-held value.
    #[must_use]
    pub fn matches_state(&self, candidate: &str) -> bool {
        self.attempt.state().matches(candidate)
    }

    /// Borrow the PKCE verifier only at the encrypted management-store
    /// boundary. Callers must not place these bytes in status, logs, or URLs.
    pub fn pkce_verifier(&self) -> &[u8] {
        self.attempt.pkce().verifier().expose_bytes()
    }

    /// Borrow the one-time state from the provider authorization URL while it
    /// is being keyed into the durable flow record.
    pub fn state_value(&self) -> Option<String> {
        self.attempt
            .authorization_url()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
    }
}

impl std::fmt::Debug for NativeBrowserLoginSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeBrowserLoginSession")
            .field("profile", &self.target.provider_profile)
            .finish_non_exhaustive()
    }
}

/// Opaque completed OAuth exchange awaiting generation-serialized persistence.
pub struct NativeOAuthLoginResult {
    target: NativeOAuthLoginTarget,
    tokens: OAuthTokens,
    identity: Option<OAuthIdentity>,
}

impl NativeOAuthLoginResult {
    /// Return the non-secret configured account identifier receiving the login.
    #[must_use]
    pub fn credential(&self) -> &CredentialId {
        &self.target.credential
    }
}

impl std::fmt::Debug for NativeOAuthLoginResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeOAuthLoginResult")
            .field("profile", &self.target.provider_profile)
            .field("identity_present", &self.identity.is_some())
            .finish_non_exhaustive()
    }
}

struct NativeOAuthLoginTarget {
    credential: CredentialId,
    provider_profile: String,
    configuration_fingerprint: String,
    expected_generation: u64,
}

impl std::fmt::Debug for NativeDeviceLoginResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDeviceLoginResult")
            .field("profile", &self.session.provider.definition().id())
            .finish_non_exhaustive()
    }
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
    sqlite_token_store: Option<Arc<SqliteOAuthTokenStore>>,
    refresh: RefreshCoordinator,
    bindings: Arc<BTreeMap<String, Arc<dyn NativeProviderBinding>>>,
    injected_bindings: Arc<BTreeSet<String>>,
    account_ids: Arc<BTreeMap<String, String>>,
    resources: RuntimeResources,
}

/// A fully constructed native runtime candidate whose durable OAuth identity
/// retirements have not yet been committed.
///
/// The runtime and retirement plan contain no credential payloads. Callers may
/// finish every fallible generation build step before combining the retirement
/// plan with pooling identity activation at the publication boundary.
pub struct PreparedNativeRuntime {
    runtime: NativeRuntime,
    retirements: Vec<CredentialFingerprintRetirement>,
}

impl PreparedNativeRuntime {
    /// Borrow the non-secret historical identity retirement plan.
    #[must_use]
    pub fn retirements(&self) -> &[CredentialFingerprintRetirement] {
        &self.retirements
    }

    /// Consume the candidate after its retirement plan has been activated.
    #[must_use]
    pub fn into_runtime(self) -> NativeRuntime {
        self.runtime
    }
}

impl std::fmt::Debug for NativeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRuntime")
            .field("provider_bindings", &self.bindings.len())
            .field("injected_bindings", &self.injected_bindings.len())
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
        Self::build(config, token_store, None)
    }

    fn build(
        config: &CompiledConfig,
        token_store: Arc<dyn OAuthTokenStore>,
        sqlite_token_store: Option<Arc<SqliteOAuthTokenStore>>,
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
                    || native.kind().eq_ignore_ascii_case("palantir_aip")
                {
                    upstream
                        .oauth()
                        .map(|oauth| {
                            build_configured_oauth_provider(
                                upstream.id(),
                                oauth,
                                Arc::clone(&transport),
                                sqlite_token_store.as_deref(),
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
                        is_kimi_coding_upstream(upstream),
                    )),
                );
            }
        }
        Ok(Self {
            token_store,
            sqlite_token_store,
            refresh: RefreshCoordinator::new(),
            bindings: Arc::new(bindings),
            injected_bindings: Arc::new(BTreeSet::new()),
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
        let prepared = Self::prepare_with_sqlite(config, token_store)?;
        if let Some(store) = prepared.runtime.sqlite_token_store.as_ref() {
            store
                .store()
                .retire_credential_fingerprints_atomically(
                    &prepared.retirements,
                    crate::pool::timestamp_now(),
                )
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
        }
        Ok(prepared.runtime)
    }

    fn prepare_with_sqlite(
        config: &CompiledConfig,
        token_store: Arc<SqliteOAuthTokenStore>,
    ) -> Result<PreparedNativeRuntime, NativeRuntimeError> {
        let mut runtime = Self::build(config, token_store.clone(), Some(token_store))?;
        let preparation = prepare_sqlite_runtime_state(&runtime, config)?;
        runtime.account_ids = Arc::new(preparation.account_ids);
        Ok(PreparedNativeRuntime {
            runtime,
            retirements: preparation.retirements,
        })
    }

    /// Build an immutable provider runtime for a new compiled generation.
    ///
    /// The encrypted token store is shared, while provider bindings and
    /// refresh/session state are rebuilt from the candidate. Injected test or
    /// application bindings are retained only when the candidate keeps the
    /// same upstream/native kind; all removed bindings disappear with the old
    /// generation.
    pub fn rebuild_for_config(
        &self,
        previous_config: &CompiledConfig,
        config: &CompiledConfig,
    ) -> Result<Self, NativeRuntimeError> {
        let prepared = self.prepare_rebuild_for_config(previous_config, config)?;
        if let Some(store) = prepared.runtime.sqlite_token_store.as_ref() {
            store
                .store()
                .retire_credential_fingerprints_atomically(
                    &prepared.retirements,
                    crate::pool::timestamp_now(),
                )
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
        }
        Ok(prepared.runtime)
    }

    /// Construct a reload candidate without mutating durable OAuth state.
    pub fn prepare_rebuild_for_config(
        &self,
        previous_config: &CompiledConfig,
        config: &CompiledConfig,
    ) -> Result<PreparedNativeRuntime, NativeRuntimeError> {
        let mut prepared = match &self.sqlite_token_store {
            Some(store) => Self::prepare_with_sqlite(config, Arc::clone(store))?,
            None => PreparedNativeRuntime {
                runtime: Self::new(config, Arc::clone(&self.token_store))?,
                retirements: Vec::new(),
            },
        };
        let runtime = &mut prepared.runtime;
        for (upstream_id, binding) in self.bindings.iter() {
            if !self.injected_bindings.contains(upstream_id) {
                continue;
            }
            let Some(upstream) = config.upstreams().get(upstream_id.as_str()) else {
                continue;
            };
            if upstream
                .native()
                .is_some_and(|native| binding.supports_kind(native.kind()))
            {
                Arc::make_mut(&mut runtime.bindings)
                    .insert(upstream_id.clone(), Arc::clone(binding));
                Arc::make_mut(&mut runtime.injected_bindings).insert(upstream_id.clone());
            }
        }
        for account in config.accounts().values() {
            let Some(account_id) = self.account_ids.get(account.id()) else {
                continue;
            };
            let Some(previous_account) = previous_config.accounts().get(account.id()) else {
                continue;
            };
            let Some(previous_upstream) =
                previous_config.upstreams().get(previous_account.provider())
            else {
                continue;
            };
            let Some(upstream) = config.upstreams().get(account.provider()) else {
                continue;
            };
            let previous_fingerprint = account_configuration_fingerprint(
                previous_upstream,
                previous_account.id(),
                previous_account.auth_kind(),
            )?;
            let fingerprint =
                account_configuration_fingerprint(upstream, account.id(), account.auth_kind())?;
            if previous_fingerprint == fingerprint {
                Arc::make_mut(&mut runtime.account_ids)
                    .insert(account.id().to_owned(), account_id.clone());
            }
        }
        Ok(prepared)
    }

    /// Construct a runtime with one injected Codex refresher. This is useful
    /// for deterministic provider transports and failure-injection tests.
    pub fn with_codex_provider(
        token_store: Arc<dyn OAuthTokenStore>,
        upstream_id: impl Into<String>,
        provider: Arc<dyn OAuthRefresher>,
    ) -> Self {
        let upstream_id = upstream_id.into();
        let mut bindings: BTreeMap<String, Arc<dyn NativeProviderBinding>> = BTreeMap::new();
        bindings.insert(
            upstream_id.clone(),
            Arc::new(CodexNativeProviderBinding::new(provider)),
        );
        let injected_bindings = BTreeSet::from([upstream_id]);
        Self {
            token_store,
            sqlite_token_store: None,
            refresh: RefreshCoordinator::new(),
            bindings: Arc::new(bindings),
            injected_bindings: Arc::new(injected_bindings),
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
            sqlite_token_store: None,
            refresh: RefreshCoordinator::new(),
            bindings: Arc::new(BTreeMap::new()),
            injected_bindings: Arc::new(BTreeSet::new()),
            account_ids: Arc::new(BTreeMap::new()),
            resources: RuntimeResources::new(),
        }
    }

    /// Build account pooling in the same credential generation domain as this
    /// native runtime. The encrypted SQLite handle remains encapsulated inside
    /// the returned coordinator.
    pub fn pooling_coordinator(
        &self,
        config: &CompiledConfig,
    ) -> Result<PoolingCoordinator, PoolError> {
        match &self.sqlite_token_store {
            Some(token_store) => {
                PoolingCoordinator::with_store(config, Arc::new(token_store.store().clone()))
            }
            None => PoolingCoordinator::new(config),
        }
    }

    /// Whether caller-supplied pooling is safe to combine with this runtime.
    /// Runtimes without durable OAuth have no cross-store generation fence to
    /// satisfy; SQLite-backed runtimes must prove one transactional domain.
    #[must_use]
    pub fn pooling_generation_domain_is_compatible(&self, pooling: &PoolingCoordinator) -> bool {
        self.sqlite_token_store.as_ref().is_none_or(|token_store| {
            pooling.shares_credential_generation_domain(Some(token_store.as_ref()))
        })
    }

    /// Return the durable OAuth store whose token generations may share a
    /// compare-and-swap domain with account metadata.
    #[must_use]
    pub(crate) fn sqlite_token_store(&self) -> Option<&SqliteOAuthTokenStore> {
        self.sqlite_token_store.as_deref()
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
        self.authorize_oauth(binding, upstream, credential, request_headers, cancellation)
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
                self.authorize_oauth(binding, upstream, credential, request_headers, cancellation)
                    .await?
            }
            Some(AccountAuthKind::ApiKey) => {
                if binding.refresh_provider().is_some() {
                    return Err(NativeRuntimeError::Authorization);
                }
                if self.sqlite_token_store.is_some() {
                    let credential = credential.ok_or(NativeRuntimeError::CredentialUnavailable)?;
                    self.ensure_account_fingerprint(upstream, credential, AccountAuthKind::ApiKey)?;
                }
                let secret = account_secret.ok_or(NativeRuntimeError::CredentialUnavailable)?;
                self.authorize_configured(
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
                self.authorize_configured(
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
        upstream: &UpstreamPlan,
        credential: &CredentialId,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        let fingerprint = account_configuration_fingerprint(
            upstream,
            credential.as_str(),
            AccountAuthKind::OAuth,
        )?;
        let mut snapshot = self
            .load_oauth_snapshot(credential, &fingerprint)
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
            snapshot = self
                .renew_oauth_snapshot(
                    provider,
                    credential,
                    &fingerprint,
                    snapshot.generation(),
                    cancellation.clone(),
                )
                .await
                .map_err(|error| map_refresh_error(error, snapshot.generation()))?;
        }
        // A completed login can replace the provider subject without changing
        // the immutable configuration fingerprint. SQLite-backed runtimes must
        // therefore read the live encrypted profile on every attempt rather
        // than preferring the subject hydrated when this generation was built.
        // In-memory injected runtimes still use their explicit override map.
        let account_id = match &self.sqlite_token_store {
            Some(store) => store
                .account_id_for_fingerprint(credential, &fingerprint)
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)?,
            None => self.account_ids.get(credential.as_str()).cloned(),
        };
        let authorization = binding.materialize_oauth_authorization(
            &snapshot,
            account_id.as_deref(),
            request_headers,
        )?;
        if cancellation.is_cancelled() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        Ok(authorization)
    }

    async fn load_oauth_snapshot(
        &self,
        credential: &CredentialId,
        fingerprint: &str,
    ) -> Result<Option<TokenSnapshot>, pooler_auth::OAuthStoreError> {
        match &self.sqlite_token_store {
            Some(_) => {
                self.token_store
                    .load_for_fingerprint(credential, fingerprint)
                    .await
            }
            None => self.token_store.load(credential).await,
        }
    }

    async fn renew_oauth_snapshot(
        &self,
        provider: &dyn OAuthRefresher,
        credential: &CredentialId,
        fingerprint: &str,
        expected_generation: u64,
        cancellation: CancellationToken,
    ) -> Result<TokenSnapshot, OAuthError> {
        if self.sqlite_token_store.is_some() {
            renew_with_store_if_generation_for_fingerprint(
                &self.refresh,
                provider,
                self.token_store.as_ref(),
                credential.clone(),
                fingerprint,
                Some(expected_generation),
                cancellation,
            )
            .await
        } else {
            renew_with_store_if_generation(
                &self.refresh,
                provider,
                self.token_store.as_ref(),
                credential.clone(),
                Some(expected_generation),
                cancellation,
            )
            .await
        }
    }

    fn resolve_secret(&self, secret: &SecretRef) -> Result<SecretValue, NativeRuntimeError> {
        let secret = resolve_protected_secret(secret, self.sqlite_token_store.as_deref())?;
        if secret.expose_secret().chars().any(char::is_whitespace) {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        Ok(secret)
    }

    /// Resolve one managed account secret from encrypted storage and apply it
    /// to the current outbound attempt. The plaintext is owned only by this
    /// call; callers never receive or retain a resolved secret value.
    pub fn apply_managed_account_auth(
        &self,
        headers: &mut HeaderMap,
        secret: &SecretRef,
        configured_auth: Option<&AuthPlan>,
        upstream: &UpstreamPlan,
        credential: Option<&CredentialId>,
    ) -> Result<bool, NativeRuntimeError> {
        if !matches!(secret, SecretRef::Managed(_)) {
            return Ok(false);
        }
        if let Some(credential) = credential {
            self.ensure_account_fingerprint(upstream, credential, AccountAuthKind::ApiKey)?;
        }
        let value = self.resolve_secret(secret)?;
        let placement = configured_auth
            .map(|auth| {
                AuthPlacement::from_configured_parts(
                    auth.kind(),
                    auth.header(),
                    auth.value_prefix(),
                )
            })
            .unwrap_or_else(|| AuthPlacement::from_configured_parts("bearer_secret", None, None))
            .map_err(|_| NativeRuntimeError::Authorization)?;
        placement
            .materialize(&value)
            .map_err(|_| NativeRuntimeError::Authorization)?
            .apply_to(headers);
        Ok(true)
    }

    fn ensure_account_fingerprint(
        &self,
        upstream: &UpstreamPlan,
        credential: &CredentialId,
        auth_kind: AccountAuthKind,
    ) -> Result<String, NativeRuntimeError> {
        let fingerprint =
            account_configuration_fingerprint(upstream, credential.as_str(), auth_kind)?;
        let Some(store) = self.sqlite_token_store.as_ref() else {
            return Ok(fingerprint);
        };
        let current = store
            .store()
            .credential_state(credential.as_str())
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
        match current {
            Some(state) if state.provider_id != upstream.id() => {
                Err(NativeRuntimeError::CredentialUnavailable)
            }
            Some(state) if state.configuration_fingerprint.is_empty() => {
                if store
                    .store()
                    .credential_payload_exists(credential.as_str())
                    .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
                {
                    return Err(NativeRuntimeError::CredentialUnavailable);
                }
                store
                    .store()
                    .upsert_credential_state(CredentialState::new_with_fingerprint(
                        credential.as_str(),
                        upstream.id(),
                        fingerprint.clone(),
                        true,
                        state.updated_at,
                    ))
                    .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
                Ok(fingerprint)
            }
            Some(state) if state.configuration_fingerprint != fingerprint => {
                Err(NativeRuntimeError::CredentialUnavailable)
            }
            Some(_) => Ok(fingerprint),
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                store
                    .store()
                    .upsert_credential_state(CredentialState::new_with_fingerprint(
                        credential.as_str(),
                        upstream.id(),
                        fingerprint.clone(),
                        true,
                        now,
                    ))
                    .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
                Ok(fingerprint)
            }
        }
    }

    fn authorize_configured(
        &self,
        binding: &dyn NativeProviderBinding,
        secret: &SecretRef,
        static_auth: Option<&AuthPlan>,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<NativeAuthorization, NativeRuntimeError> {
        if cancellation.is_cancelled() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        let secret = self.resolve_secret(secret)?;
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
        let fingerprint = account_configuration_fingerprint(
            upstream,
            credential.as_str(),
            AccountAuthKind::OAuth,
        )?;
        self.renew_oauth_snapshot(
            provider,
            credential,
            &fingerprint,
            expected_generation,
            cancellation,
        )
        .await
        .map_err(|error| map_refresh_error(error, expected_generation))
    }

    /// Start a configured authorization-code login while retaining state and
    /// the PKCE verifier inside the runtime-owned session.
    pub fn start_browser_login(
        &self,
        config: &CompiledConfig,
        account_id: &str,
    ) -> Result<(NativeBrowserAuthorization, NativeBrowserLoginSession), NativeRuntimeError> {
        let (provider, target) =
            self.configured_oauth_provider(config, account_id, OAuthGrantType::AuthorizationCode)?;
        let attempt = provider.begin_authorization().map_err(map_login_error)?;
        if attempt.authorization_url().scheme() != "https" {
            return Err(NativeRuntimeError::Configuration);
        }
        let prompt = NativeBrowserAuthorization {
            authorization_url: attempt.authorization_url().clone(),
        };
        Ok((
            prompt,
            NativeBrowserLoginSession {
                provider,
                attempt,
                target,
            },
        ))
    }

    /// Restore one browser login from the encrypted, caller-owned PKCE
    /// verifier and the one-time state value recovered by the management
    /// store. The verifier is consumed only by the provider's typed PKCE
    /// boundary and is never represented in a runtime status record.
    pub fn restore_browser_login(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        state: &str,
        verifier: &[u8],
    ) -> Result<(NativeBrowserAuthorization, NativeBrowserLoginSession), NativeRuntimeError> {
        let (provider, target) =
            self.configured_oauth_provider(config, account_id, OAuthGrantType::AuthorizationCode)?;
        let state =
            OAuthState::new(state.to_owned()).map_err(|_| NativeRuntimeError::Configuration)?;
        let verifier =
            String::from_utf8(verifier.to_vec()).map_err(|_| NativeRuntimeError::Configuration)?;
        let pkce =
            PkcePair::from_verifier(verifier).map_err(|_| NativeRuntimeError::Configuration)?;
        let attempt = provider
            .begin_authorization_with(state, pkce)
            .map_err(map_login_error)?;
        if attempt.authorization_url().scheme() != "https" {
            return Err(NativeRuntimeError::Configuration);
        }
        let prompt = NativeBrowserAuthorization {
            authorization_url: attempt.authorization_url().clone(),
        };
        Ok((
            prompt,
            NativeBrowserLoginSession {
                provider,
                attempt,
                target,
            },
        ))
    }

    /// Validate and exchange one browser callback without persisting tokens.
    pub async fn exchange_browser_login(
        &self,
        session: NativeBrowserLoginSession,
        callback: Url,
        cancellation: CancellationToken,
    ) -> Result<NativeOAuthLoginResult, NativeRuntimeError> {
        let NativeBrowserLoginSession {
            provider,
            attempt,
            target,
        } = session;
        let code = attempt
            .validate_callback(&callback)
            .map_err(map_login_error)?;
        let tokens = tokio::time::timeout(
            OAUTH_TOKEN_REQUEST_TIMEOUT,
            provider.exchange_code(
                &code,
                attempt.pkce(),
                attempt.redirect_uri(),
                cancellation.clone(),
            ),
        )
        .await
        .map_err(|_| NativeRuntimeError::Refresh)?
        .map_err(map_login_error)?;
        let identity = if provider.config().identity_endpoint.is_some() {
            Some(
                tokio::time::timeout(
                    OAUTH_TOKEN_REQUEST_TIMEOUT,
                    provider.identity(&tokens, cancellation),
                )
                .await
                .map_err(|_| NativeRuntimeError::Refresh)?
                .map_err(map_login_error)?,
            )
        } else {
            None
        };
        Ok(NativeOAuthLoginResult {
            target,
            tokens,
            identity,
        })
    }

    /// Acquire a configured client-credentials token without persisting it.
    pub async fn acquire_client_credentials(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        cancellation: CancellationToken,
    ) -> Result<NativeOAuthLoginResult, NativeRuntimeError> {
        let (provider, target) =
            self.configured_oauth_provider(config, account_id, OAuthGrantType::ClientCredentials)?;
        let tokens = tokio::time::timeout(
            OAUTH_TOKEN_REQUEST_TIMEOUT,
            provider.acquire_client_credentials(cancellation),
        )
        .await
        .map_err(|_| NativeRuntimeError::Refresh)?
        .map_err(map_login_error)?;
        Ok(NativeOAuthLoginResult {
            target,
            tokens,
            identity: None,
        })
    }

    /// Persist a completed browser or client-credentials exchange in the
    /// encrypted token store while the caller holds reload serialization.
    pub fn persist_oauth_login(
        &self,
        result: NativeOAuthLoginResult,
    ) -> Result<TokenSnapshot, NativeRuntimeError> {
        let NativeOAuthLoginResult {
            target,
            tokens,
            identity,
        } = result;
        let id_token = tokens.id_token().cloned();
        let mut profile =
            OAuthCredentialProfile::new(&target.provider_profile, tokens).with_id_token(id_token);
        if let Some(identity) = identity {
            profile = profile.with_identity(identity);
        }
        self.persist_oauth_profile(&target, &profile)
    }

    fn configured_oauth_provider(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        expected_grant: OAuthGrantType,
    ) -> Result<(StandardOAuthProvider, NativeOAuthLoginTarget), NativeRuntimeError> {
        if self.sqlite_token_store.is_none() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        let account = config
            .accounts()
            .get(account_id)
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        if account.auth_kind() != AccountAuthKind::OAuth {
            return Err(NativeRuntimeError::Unsupported);
        }
        let upstream = config
            .upstreams()
            .get(account.provider())
            .ok_or(NativeRuntimeError::Unsupported)?;
        let native = upstream.native().ok_or(NativeRuntimeError::Unsupported)?;
        if !is_configured_native_kind(native.kind()) || self.binding_for(upstream).is_none() {
            return Err(NativeRuntimeError::Unsupported);
        }
        let oauth = upstream
            .oauth()
            .filter(|oauth| oauth.grant_type() == expected_grant)
            .ok_or(NativeRuntimeError::Unsupported)?;
        let transport = Arc::new(
            HyperOAuthTransport::new(64 * 1024).map_err(|_| NativeRuntimeError::Configuration)?,
        );
        let provider = build_standard_oauth_provider(
            upstream.id(),
            oauth,
            transport,
            self.sqlite_token_store.as_deref(),
        )?;
        let target = self.prepare_oauth_login_target(account, upstream, native.kind())?;
        Ok((provider, target))
    }

    fn prepare_oauth_login_target(
        &self,
        account: &AccountPlan,
        upstream: &UpstreamPlan,
        provider_profile: &str,
    ) -> Result<NativeOAuthLoginTarget, NativeRuntimeError> {
        let store = self
            .sqlite_token_store
            .as_ref()
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        let configuration_fingerprint =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())?;
        match store
            .store()
            .credential_state(account.id())
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
        {
            Some(state) => {
                if state.provider_id != account.provider() {
                    return Err(NativeRuntimeError::CredentialUnavailable);
                }
                if state.configuration_fingerprint.is_empty() {
                    if store
                        .store()
                        .credential_payload_exists(account.id())
                        .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
                    {
                        return Err(NativeRuntimeError::CredentialUnavailable);
                    }
                    store
                        .store()
                        .upsert_credential_state(CredentialState::new_with_fingerprint(
                            account.id(),
                            account.provider(),
                            configuration_fingerprint.clone(),
                            state.enabled,
                            state.updated_at,
                        ))
                        .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
                } else if state.configuration_fingerprint != configuration_fingerprint {
                    return Err(NativeRuntimeError::CredentialUnavailable);
                }
            }
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                store
                    .store()
                    .upsert_credential_state(CredentialState::new_with_fingerprint(
                        account.id(),
                        account.provider(),
                        configuration_fingerprint.clone(),
                        account.enabled(),
                        now,
                    ))
                    .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
            }
        }
        let expected_generation = store
            .store()
            .credential_payload_compare_generation_for_fingerprint(
                account.id(),
                &configuration_fingerprint,
            )
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
        Ok(NativeOAuthLoginTarget {
            credential: CredentialId::new(account.id())
                .map_err(|_| NativeRuntimeError::Configuration)?,
            provider_profile: provider_profile.to_ascii_lowercase(),
            configuration_fingerprint,
            expected_generation,
        })
    }

    fn persist_oauth_profile(
        &self,
        target: &NativeOAuthLoginTarget,
        profile: &OAuthCredentialProfile,
    ) -> Result<TokenSnapshot, NativeRuntimeError> {
        let store = self
            .sqlite_token_store
            .as_ref()
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        store
            .compare_and_swap_profile_for_fingerprint(
                &target.credential,
                &target.configuration_fingerprint,
                target.expected_generation,
                profile,
            )
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)
    }

    /// Start a documented device-code login without exposing its device credential.
    pub async fn start_device_login(
        &self,
        config: &CompiledConfig,
        account_id: &str,
        cancellation: CancellationToken,
    ) -> Result<(NativeDeviceAuthorization, NativeDeviceLoginSession), NativeRuntimeError> {
        if self.sqlite_token_store.is_none() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        let account = config
            .accounts()
            .get(account_id)
            .ok_or(NativeRuntimeError::CredentialUnavailable)?;
        if account.auth_kind() != AccountAuthKind::OAuth {
            return Err(NativeRuntimeError::Unsupported);
        }
        let upstream = config
            .upstreams()
            .get(account.provider())
            .ok_or(NativeRuntimeError::Unsupported)?;
        let is_codex = upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"));
        if !is_codex {
            return Err(NativeRuntimeError::Unsupported);
        }
        let definition = ProviderLoginRegistry::builtin()
            .require("openai")
            .map_err(|_| NativeRuntimeError::Configuration)?;
        let callback = DEFAULT_OAUTH_CALLBACK
            .parse()
            .map_err(|_| NativeRuntimeError::Configuration)?;
        let transport = Arc::new(
            HyperOAuthTransport::new(64 * 1024).map_err(|_| NativeRuntimeError::Configuration)?,
        );
        let provider = definition
            .build_oauth_provider(
                ProviderLoginMethod::DeviceCode,
                ProviderOAuthSettings::new(String::new(), callback),
                transport,
            )
            .map_err(|_| NativeRuntimeError::Configuration)?;
        let target = self.prepare_oauth_login_target(account, upstream, "openai")?;
        let authorization = tokio::time::timeout(
            DEVICE_AUTHORIZATION_REQUEST_TIMEOUT,
            provider.start_device_authorization(cancellation),
        )
        .await
        .map_err(|_| NativeRuntimeError::Refresh)?
        .map_err(|_| NativeRuntimeError::Refresh)?;
        let prompt = NativeDeviceAuthorization {
            verification_uri: authorization.verification_uri().to_string(),
            verification_uri_complete: authorization
                .verification_uri_complete()
                .map(ToString::to_string),
            user_code: authorization.user_code().to_owned(),
            expires_in_seconds: authorization.expires_in().as_secs(),
        };
        Ok((
            prompt,
            NativeDeviceLoginSession {
                provider,
                authorization,
                target,
            },
        ))
    }

    /// Poll a device-code exchange without crossing the token persistence boundary.
    pub async fn poll_device_login(
        &self,
        session: NativeDeviceLoginSession,
        cancellation: CancellationToken,
    ) -> Result<NativeDeviceLoginResult, NativeRuntimeError> {
        let tokens = session
            .provider
            .poll_device(&session.authorization, cancellation)
            .await
            .map_err(|_| NativeRuntimeError::Refresh)?;
        Ok(NativeDeviceLoginResult { session, tokens })
    }

    /// Persist a completed exchange while the caller holds the reload serialization lock.
    pub fn persist_device_login(
        &self,
        result: NativeDeviceLoginResult,
    ) -> Result<TokenSnapshot, NativeRuntimeError> {
        let NativeDeviceLoginResult { session, tokens } = result;
        let id_token = tokens
            .id_token()
            .cloned()
            .ok_or(NativeRuntimeError::Authorization)?;
        let provider_account_id = CodexCredential::account_id_from_id_token(&id_token)
            .map_err(|_| NativeRuntimeError::Authorization)?;
        let profile = OAuthCredentialProfile::new("openai", tokens)
            .with_id_token(Some(id_token))
            .with_account_id(provider_account_id);
        self.persist_oauth_profile(&session.target, &profile)
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
        let fingerprint =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())?;
        let snapshot = self
            .load_oauth_snapshot(&credential, &fingerprint)
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

struct SqliteRuntimePreparation {
    retirements: Vec<CredentialFingerprintRetirement>,
    account_ids: BTreeMap<String, String>,
}

fn prepare_sqlite_runtime_state(
    runtime: &NativeRuntime,
    config: &CompiledConfig,
) -> Result<SqliteRuntimePreparation, NativeRuntimeError> {
    let Some(store) = runtime.sqlite_token_store.as_ref() else {
        return Ok(SqliteRuntimePreparation {
            retirements: Vec::new(),
            account_ids: BTreeMap::new(),
        });
    };
    let mut retirements = Vec::new();
    let mut account_ids = BTreeMap::new();
    for account in config.accounts().values() {
        let Some(upstream) = config.upstreams().get(account.provider()) else {
            return Err(NativeRuntimeError::Configuration);
        };
        if let Some(SecretRef::Managed(secret_id)) = account.secret() {
            store
                .store()
                .managed_secret_payload(secret_id)
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
        }
        let Some(state) = store
            .store()
            .credential_state(account.id())
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
        else {
            continue;
        };
        if state.provider_id != upstream.id() {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        let current =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())?;
        if state.configuration_fingerprint.is_empty() {
            if store
                .store()
                .credential_payload_exists(account.id())
                .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
            {
                return Err(NativeRuntimeError::CredentialUnavailable);
            }
            continue;
        }
        if state.configuration_fingerprint == current {
            let refreshable = account.auth_kind() == AccountAuthKind::OAuth
                && runtime
                    .binding_for(upstream)
                    .is_some_and(|binding| binding.refresh_provider().is_some());
            if refreshable {
                let credential = CredentialId::new(account.id())
                    .map_err(|_| NativeRuntimeError::Configuration)?;
                if let Some(account_id) = store
                    .account_id_for_fingerprint(&credential, &current)
                    .map_err(|_| NativeRuntimeError::CredentialUnavailable)?
                {
                    if !account_id.trim().is_empty() {
                        account_ids.insert(account.id().to_owned(), account_id);
                    }
                }
            }
            continue;
        }
        if account.auth_kind() != AccountAuthKind::OAuth {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        let migration_candidates = account_configuration_fingerprint_migration_candidates(
            upstream,
            account.id(),
            account.auth_kind(),
        )?;
        if !migration_candidates.contains(&state.configuration_fingerprint) {
            return Err(NativeRuntimeError::CredentialUnavailable);
        }
        retirements.push(
            CredentialFingerprintRetirement::new(
                account.id(),
                upstream.id(),
                state.configuration_fingerprint,
                current,
            )
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?,
        );
    }
    Ok(SqliteRuntimePreparation {
        retirements,
        account_ids,
    })
}

#[cfg(test)]
fn hydrate_account_ids(
    runtime: &mut NativeRuntime,
    config: &CompiledConfig,
    mut load_account_id: impl FnMut(&CredentialId, &str) -> Result<Option<String>, NativeRuntimeError>,
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
        let fingerprint =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())?;
        if let Some(account_id) = load_account_id(&credential, &fingerprint)? {
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
    kimi_coding: bool,
}

impl ConfiguredNativeProviderBinding {
    fn new(kind: &str, provider: Option<Arc<dyn OAuthRefresher>>, kimi_coding: bool) -> Self {
        Self {
            kind: kind.to_owned(),
            provider,
            kimi_coding,
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
        if self.kimi_coding {
            apply_kimi_identity_headers(&mut headers);
        }
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
        if self.kimi_coding {
            apply_kimi_identity_headers(&mut headers);
        }
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
    "palantir_aip",
];

fn is_configured_native_kind(kind: &str) -> bool {
    CONFIGURED_NATIVE_KINDS
        .iter()
        .any(|candidate| kind.eq_ignore_ascii_case(candidate))
}

pub(crate) fn account_auth_kind_compatible(
    upstream: &UpstreamPlan,
    auth_kind: AccountAuthKind,
) -> bool {
    let Some(native) = upstream.native() else {
        return auth_kind == AccountAuthKind::ApiKey;
    };
    if !native.kind().eq_ignore_ascii_case("codex") && !is_configured_native_kind(native.kind()) {
        return false;
    }
    let refreshable = native.kind().eq_ignore_ascii_case("codex")
        || ((native.kind().eq_ignore_ascii_case("kimi")
            || native.kind().eq_ignore_ascii_case("vertex")
            || native.kind().eq_ignore_ascii_case("palantir_aip"))
            && upstream.oauth().is_some());
    match auth_kind {
        AccountAuthKind::OAuth => refreshable,
        AccountAuthKind::ApiKey => !refreshable,
    }
}

/// Kimi Code checks the same client identity headers emitted by CLIProxyAPI.
///
/// Device names and IDs in the reference implementation are machine-local
/// values. Pooler intentionally uses a fixed product identity instead: it is
/// stable across retries and accounts, contains no host or credential data,
/// and still satisfies the provider's client contract. Compiled provider
/// headers are applied after this delta and therefore retain operator-defined
/// overrides.
const KIMI_CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const KIMI_DEVICE_ID: &str = "pooler";
const KIMI_DEVICE_MODEL: &str = "pooler";
const KIMI_DEVICE_NAME: &str = "pooler";

fn apply_kimi_identity_headers(headers: &mut HeaderMap) {
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static(concat!("CLIProxyAPI/", env!("CARGO_PKG_VERSION"))),
    );
    headers.insert(
        HeaderName::from_static("x-msh-platform"),
        http::HeaderValue::from_static("CLIProxyAPI"),
    );
    headers.insert(
        HeaderName::from_static("x-msh-version"),
        http::HeaderValue::from_static(KIMI_CLIENT_VERSION),
    );
    headers.insert(
        HeaderName::from_static("x-msh-device-name"),
        http::HeaderValue::from_static(KIMI_DEVICE_NAME),
    );
    headers.insert(
        HeaderName::from_static("x-msh-device-model"),
        http::HeaderValue::from_static(KIMI_DEVICE_MODEL),
    );
    headers.insert(
        HeaderName::from_static("x-msh-device-id"),
        http::HeaderValue::from_static(KIMI_DEVICE_ID),
    );
}

/// Native `kind: kimi` is also used by the public Moonshot API catalog. Only
/// the Kimi Code surface needs CLIProxy's client identity contract; a known
/// public-platform provider remains a regular bearer API-key binding. An
/// operator-configured `kind: kimi` without a known provider is treated as
/// Kimi Code, matching the documented native subscription configuration.
fn is_kimi_coding_upstream(upstream: &UpstreamPlan) -> bool {
    let Some(native) = upstream.native() else {
        return false;
    };
    native.kind().eq_ignore_ascii_case("kimi")
        && upstream
            .known_provider()
            .is_none_or(|provider| provider.eq_ignore_ascii_case("kimi-for-coding"))
}

fn resolve_protected_secret(
    secret: &SecretRef,
    managed_store: Option<&SqliteOAuthTokenStore>,
) -> Result<SecretValue, NativeRuntimeError> {
    if let SecretRef::Managed(id) = secret {
        let store = managed_store.ok_or(NativeRuntimeError::CredentialUnavailable)?;
        let payload = store
            .store()
            .managed_secret_payload(id)
            .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
        return SecretValue::from_bytes(payload.into_bytes())
            .map_err(|_| NativeRuntimeError::CredentialUnavailable);
    }
    let reference = match secret {
        SecretRef::Env(name) => AuthSecretRef::Env(name.to_string()),
        SecretRef::File(path) => AuthSecretRef::File(path.as_ref().into()),
        SecretRef::Keyring { service, account } => AuthSecretRef::Keyring {
            service: service.to_string(),
            account: account.to_string(),
        },
        SecretRef::Managed(_) => unreachable!("managed secrets are resolved above"),
    };
    let secret = reference
        .resolve()
        .map_err(|_| NativeRuntimeError::CredentialUnavailable)?;
    Ok(secret)
}

fn configured_account_configuration_fingerprint_input(
    upstream: &UpstreamPlan,
    account_id: &str,
    auth_kind: AccountAuthKind,
) -> CredentialFingerprintInput {
    let provider_profile = upstream
        .native()
        .map(|native| native.kind())
        .or_else(|| upstream.known_provider())
        .unwrap_or(upstream.id());
    let mut provider_origin = upstream.url().clone();
    provider_origin.set_path("");
    provider_origin.set_query(None);
    provider_origin.set_fragment(None);
    let auth_placement = upstream.auth().map_or_else(
        || "bearer_secret".to_owned(),
        |auth| {
            format!(
                "{}|{}|{}",
                auth.kind(),
                auth.header().unwrap_or_default(),
                auth.value_prefix().unwrap_or_default()
            )
        },
    );
    let oauth = upstream.oauth();
    CredentialFingerprintInput {
        account_id: account_id.to_owned(),
        provider_instance_id: upstream.id().to_owned(),
        provider_origin: provider_origin.to_string(),
        auth_kind: auth_kind.as_str().to_owned(),
        provider_profile: provider_profile.to_owned(),
        oauth_client_id: oauth.map(|value| value.client_id().to_owned()),
        oauth_grant_type: oauth.map(|value| value.grant_type().as_str().to_owned()),
        oauth_scopes: oauth.map_or_else(Vec::new, |value| {
            value.scopes().iter().map(ToString::to_string).collect()
        }),
        authorization_endpoint: oauth.map(|value| value.authorization_endpoint().to_string()),
        token_endpoint: oauth.map(|value| value.token_endpoint().to_string()),
        revocation_endpoint: oauth
            .and_then(OAuthPlan::revocation_endpoint)
            .map(ToString::to_string),
        identity_endpoint: oauth
            .and_then(OAuthPlan::identity_endpoint)
            .map(ToString::to_string),
        callback_endpoint: oauth.map(|value| value.callback().to_string()),
        oauth_client_secret_reference: oauth
            .and_then(OAuthPlan::client_secret)
            .map(SecretRef::redacted),
        oauth_additional_identity: Vec::new(),
        auth_placement,
    }
}

fn builtin_codex_oauth_config() -> Result<OAuthClientConfig, NativeRuntimeError> {
    let definition = ProviderLoginRegistry::builtin()
        .require("openai")
        .map_err(|_| NativeRuntimeError::Configuration)?;
    let callback = DEFAULT_OAUTH_CALLBACK
        .parse()
        .map_err(|_| NativeRuntimeError::Configuration)?;
    definition
        .build_oauth_config(
            ProviderLoginMethod::AuthorizationCodePkce,
            ProviderOAuthSettings::new(String::new(), callback),
        )
        .map_err(|_| NativeRuntimeError::Configuration)
}

fn oauth_grant_type_identity(grant_type: pooler_auth::OAuthGrantType) -> &'static str {
    match grant_type {
        pooler_auth::OAuthGrantType::AuthorizationCode => "authorization_code",
        pooler_auth::OAuthGrantType::ClientCredentials => "client_credentials",
    }
}

fn oauth_request_encoding_identity(encoding: pooler_auth::OAuthRequestEncoding) -> &'static str {
    match encoding {
        pooler_auth::OAuthRequestEncoding::Form => "form",
        pooler_auth::OAuthRequestEncoding::Json => "json",
    }
}

fn oauth_device_grant_identity(grant: pooler_auth::DeviceAuthorizationGrant) -> &'static str {
    match grant {
        pooler_auth::DeviceAuthorizationGrant::Rfc8628 => "rfc8628",
        pooler_auth::DeviceAuthorizationGrant::CodexAccounts => "codex_accounts",
    }
}

fn apply_builtin_codex_oauth_identity(
    input: &mut CredentialFingerprintInput,
    oauth: &OAuthClientConfig,
) {
    input.oauth_client_id = Some(oauth.client_id.clone());
    input.oauth_grant_type = Some(oauth_grant_type_identity(oauth.grant_type).to_owned());
    input.oauth_scopes = oauth.scopes.clone();
    input.authorization_endpoint = Some(oauth.authorization_endpoint.to_string());
    input.token_endpoint = Some(oauth.token_endpoint.to_string());
    input.revocation_endpoint = oauth.revocation_endpoint.as_ref().map(ToString::to_string);
    input.identity_endpoint = oauth.identity_endpoint.as_ref().map(ToString::to_string);
    input.callback_endpoint = Some(oauth.redirect_uri.to_string());
    input.oauth_additional_identity = vec![
        ("provider_definition".to_owned(), "openai".to_owned()),
        (
            "request_encoding".to_owned(),
            oauth_request_encoding_identity(oauth.request_encoding).to_owned(),
        ),
        (
            "device_grant".to_owned(),
            oauth_device_grant_identity(oauth.device_grant).to_owned(),
        ),
    ];
    if let Some(endpoint) = &oauth.device_authorization_endpoint {
        input.oauth_additional_identity.push((
            "device_authorization_endpoint".to_owned(),
            endpoint.to_string(),
        ));
    }
    input.oauth_additional_identity.extend(
        oauth
            .authorization_parameters
            .iter()
            .map(|(name, value)| (format!("authorization_parameter:{name}"), value.clone())),
    );
}

fn account_configuration_fingerprint_input(
    upstream: &UpstreamPlan,
    account_id: &str,
    auth_kind: AccountAuthKind,
) -> Result<CredentialFingerprintInput, NativeRuntimeError> {
    let mut input =
        configured_account_configuration_fingerprint_input(upstream, account_id, auth_kind);
    let uses_builtin_codex_oauth = auth_kind == AccountAuthKind::OAuth
        && upstream.oauth().is_none()
        && upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"));
    if uses_builtin_codex_oauth {
        apply_builtin_codex_oauth_identity(&mut input, &builtin_codex_oauth_config()?);
    }
    Ok(input)
}

/// Compute the stable non-secret identity fence for one compiled account.
pub fn account_configuration_fingerprint(
    upstream: &UpstreamPlan,
    account_id: &str,
    auth_kind: AccountAuthKind,
) -> Result<String, NativeRuntimeError> {
    credential_configuration_fingerprint(&account_configuration_fingerprint_input(
        upstream, account_id, auth_kind,
    )?)
    .map_err(|_| NativeRuntimeError::Configuration)
}

/// Compute exact historical identities that may be retired during a
/// fail-closed store migration.
///
/// The candidates retain the version-1 identity and the version-2 identity
/// that preceded effective built-in provider behavior. They never authorize a
/// payload under the current configuration; callers may only use them as the
/// expected side of an atomic retirement or login replacement.
pub fn account_configuration_fingerprint_migration_candidates(
    upstream: &UpstreamPlan,
    account_id: &str,
    auth_kind: AccountAuthKind,
) -> Result<Vec<String>, NativeRuntimeError> {
    let historical =
        configured_account_configuration_fingerprint_input(upstream, account_id, auth_kind);
    let current = account_configuration_fingerprint(upstream, account_id, auth_kind)?;
    let mut candidates = vec![
        historical
            .legacy_fingerprint()
            .map_err(|_| NativeRuntimeError::Configuration)?,
        credential_configuration_fingerprint(&historical)
            .map_err(|_| NativeRuntimeError::Configuration)?,
    ];
    candidates.retain(|candidate| candidate != &current);
    candidates.sort_unstable();
    candidates.dedup();
    Ok(candidates)
}

/// Compute the exact version-1 account identity for fail-closed store
/// migration. New payloads must always use [`account_configuration_fingerprint`].
pub fn legacy_account_configuration_fingerprint(
    upstream: &UpstreamPlan,
    account_id: &str,
    auth_kind: AccountAuthKind,
) -> Result<String, NativeRuntimeError> {
    configured_account_configuration_fingerprint_input(upstream, account_id, auth_kind)
        .legacy_fingerprint()
        .map_err(|_| NativeRuntimeError::Configuration)
}

fn build_configured_oauth_provider(
    id: &str,
    oauth: &OAuthPlan,
    transport: Arc<HyperOAuthTransport>,
    managed_store: Option<&SqliteOAuthTokenStore>,
) -> Result<Arc<dyn OAuthRefresher>, NativeRuntimeError> {
    Ok(Arc::new(build_standard_oauth_provider(
        id,
        oauth,
        transport,
        managed_store,
    )?))
}

fn build_standard_oauth_provider(
    id: &str,
    oauth: &OAuthPlan,
    transport: Arc<HyperOAuthTransport>,
    managed_store: Option<&SqliteOAuthTokenStore>,
) -> Result<StandardOAuthProvider, NativeRuntimeError> {
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
    if let Some(client_secret) = oauth.client_secret() {
        config = config.with_client_auth(OAuthClientAuth::RequestBody(resolve_protected_secret(
            client_secret,
            managed_store,
        )?));
    }
    if oauth.grant_type() == OAuthGrantType::ClientCredentials {
        config = config.with_client_credentials_grant();
    }
    StandardOAuthProvider::new(id, config, transport).map_err(|_| NativeRuntimeError::Configuration)
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

    let provider = StandardOAuthProvider::new("openai", builtin_codex_oauth_config()?, transport)
        .map_err(|_| NativeRuntimeError::Configuration)?;
    Ok(Arc::new(provider))
}

fn map_refresh_error(error: OAuthError, generation: u64) -> NativeRuntimeError {
    match error {
        OAuthError::NeedsReauth => NativeRuntimeError::NeedsReauth { generation },
        OAuthError::Cancelled => NativeRuntimeError::CredentialUnavailable,
        OAuthError::Store(_) | OAuthError::NoRefreshToken => {
            NativeRuntimeError::CredentialUnavailable
        }
        OAuthError::Transport(_) => NativeRuntimeError::Refresh,
        _ => NativeRuntimeError::Refresh,
    }
}

fn map_login_error(error: OAuthError) -> NativeRuntimeError {
    match error {
        OAuthError::InvalidState
        | OAuthError::RedirectMismatch
        | OAuthError::MissingCode
        | OAuthError::AuthorizationDenied => NativeRuntimeError::Authorization,
        OAuthError::Cancelled => NativeRuntimeError::CredentialUnavailable,
        OAuthError::InvalidConfiguration | OAuthError::Unsupported => {
            NativeRuntimeError::Configuration
        }
        OAuthError::NeedsReauth
        | OAuthError::Provider { .. }
        | OAuthError::Transport(_)
        | OAuthError::InvalidResponse => NativeRuntimeError::Refresh,
        OAuthError::GenerationConflict | OAuthError::NoRefreshToken | OAuthError::Store(_) => {
            NativeRuntimeError::CredentialUnavailable
        }
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
    use pooler_store::{MasterKey, SqliteStore};
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
                "version: 2\nupstreams:\n  xai:\n    url: http://127.0.0.1:8322\n    native:\n      kind: xai\n    auth:\n      kind: header\n      header: x-provider-key\n      value_prefix: 'Token '\n      secret: 'file:{}'\naccounts:\n  api-account:\n    provider: xai\n    auth_kind: api_key\n    secret: file:/definitely/not/a/native/key\n",
                static_path.display()
            ),
        )
        .expect("configured native config")
    }

    fn compatible_config(static_path: &Path) -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-compatible-test.yaml",
            &format!(
                "version: 2\nupstreams:\n  compatible:\n    url: http://127.0.0.1:8336\n    native: {{kind: compatible}}\n    auth:\n      kind: header\n      header: x-provider-token\n      value_prefix: 'Token '\n      secret: 'file:{}'\n",
                static_path.display()
            ),
        )
        .expect("compatible native config")
    }

    fn kimi_oauth_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-kimi-oauth-test.yaml",
            r#"
version: 2
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
version: 2
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

    fn palantir_oauth_config(client_secret: &Path, grant_type: OAuthGrantType) -> CompiledConfig {
        let (grant, scopes) = match grant_type {
            OAuthGrantType::AuthorizationCode => (
                "authorization_code",
                "api:use-language-models-execute, offline_access",
            ),
            OAuthGrantType::ClientCredentials => {
                ("client_credentials", "api:use-language-models-execute")
            }
        };
        pooler_config::compile_yaml(
            "native-palantir-oauth-test.yaml",
            &format!(
                "version: 2\nupstreams:\n  foundry:\n    url: https://example.euw-3.palantirfoundry.co.uk\n    native: {{kind: palantir_aip}}\n    oauth:\n      client_id: operator-client\n      client_secret: 'file:{}'\n      grant_type: {grant}\n      scopes: [{scopes}]\n      callback: http://127.0.0.1:8765/oauth/callback\naccounts:\n  foundry-account: {{provider: foundry, auth_kind: oauth}}\n",
                client_secret.display(),
            ),
        )
        .expect("Palantir OAuth config")
    }

    fn sqlite_native_runtime(
        config: &CompiledConfig,
    ) -> (NativeRuntime, Arc<SqliteOAuthTokenStore>) {
        let store = Arc::new(SqliteOAuthTokenStore::new(
            SqliteStore::open_in_memory_encrypted(
                MasterKey::from_bytes(b"pooler-http-palantir-test-key").expect("master key"),
            )
            .expect("encrypted store"),
        ));
        let runtime =
            NativeRuntime::new_with_sqlite(config, Arc::clone(&store)).expect("native runtime");
        (runtime, store)
    }

    fn configured_without_auth_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-configured-without-auth-test.yaml",
            "version: 2\nupstreams:\n  xai:\n    url: http://127.0.0.1:8333\n    native: {kind: xai}\n",
        )
        .expect("configured native config without auth")
    }

    fn configured_kinds_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-kinds-test.yaml",
            r#"
version: 2
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

    fn builtin_codex_config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-builtin-codex-test.yaml",
            r#"
version: 2
upstreams:
  codex:
    url: https://chatgpt.com/backend-api/codex
    native: {kind: codex}
accounts:
  codex-account: {provider: codex, auth_kind: oauth}
"#,
        )
        .expect("built-in Codex config")
    }

    fn config() -> CompiledConfig {
        pooler_config::compile_yaml(
            "native-test.yaml",
            r#"
version: 2
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
version: 2
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
version: 2
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
version: 2
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
    fn configured_browser_login_keeps_pkce_state_and_client_secret_server_side() {
        let client_secret = secret_file("client secret with spaces");
        let config = palantir_oauth_config(client_secret.path(), OAuthGrantType::AuthorizationCode);
        let (runtime, _) = sqlite_native_runtime(&config);
        let (authorization, session) = runtime
            .start_browser_login(&config, "foundry-account")
            .expect("browser login");
        let query = authorization
            .authorization_url()
            .query_pairs()
            .collect::<BTreeMap<_, _>>();
        let state = query.get("state").expect("OAuth state");

        assert_eq!(authorization.authorization_url().scheme(), "https");
        assert_eq!(
            authorization.authorization_url().path(),
            "/multipass/api/oauth2/authorize"
        );
        assert_eq!(
            query.get("code_challenge_method").map(AsRef::as_ref),
            Some("S256")
        );
        assert!(!query.contains_key("client_secret"));
        assert!(session.matches_state(state));
        assert!(!session.matches_state("wrong-state"));
        let rendered = format!("{authorization:?}{session:?}{runtime:?}");
        assert!(!rendered.contains(state.as_ref()));
        assert!(!rendered.contains("client secret with spaces"));
    }

    #[tokio::test]
    async fn configured_grants_are_flow_locked_and_client_secret_is_request_body_auth() {
        let client_secret = secret_file("service secret with spaces");
        let config = palantir_oauth_config(client_secret.path(), OAuthGrantType::ClientCredentials);
        let (runtime, _) = sqlite_native_runtime(&config);
        assert!(matches!(
            runtime.start_browser_login(&config, "foundry-account"),
            Err(NativeRuntimeError::Unsupported)
        ));
        let (provider, _) = runtime
            .configured_oauth_provider(
                &config,
                "foundry-account",
                OAuthGrantType::ClientCredentials,
            )
            .expect("client-credentials provider");
        assert_eq!(
            provider.config().grant_type,
            pooler_auth::OAuthGrantType::ClientCredentials
        );
        assert!(matches!(
            &provider.config().client_auth,
            OAuthClientAuth::RequestBody(secret)
                if secret.expose_secret() == "service secret with spaces"
        ));
        assert!(!format!("{provider:?}").contains("service secret with spaces"));

        let browser_config =
            palantir_oauth_config(client_secret.path(), OAuthGrantType::AuthorizationCode);
        let (browser_runtime, _) = sqlite_native_runtime(&browser_config);
        assert!(matches!(
            browser_runtime
                .acquire_client_credentials(
                    &browser_config,
                    "foundry-account",
                    CancellationToken::new(),
                )
                .await,
            Err(NativeRuntimeError::Unsupported)
        ));
    }

    #[tokio::test]
    async fn palantir_tokens_persist_encrypted_without_identity_and_inject_sensitive_bearer() {
        let client_secret = secret_file("operator-client-secret");
        let config = palantir_oauth_config(client_secret.path(), OAuthGrantType::AuthorizationCode);
        let (runtime, store) = sqlite_native_runtime(&config);
        let account = &config.accounts()["foundry-account"];
        let result = NativeOAuthLoginResult {
            target: runtime
                .prepare_oauth_login_target(
                    account,
                    &config.upstreams()[account.provider()],
                    "palantir_aip",
                )
                .expect("login target"),
            tokens: OAuthTokens::bearer(
                "palantir-access-token",
                Some("palantir-refresh-token"),
                Some(SystemTime::now() + Duration::from_secs(3600)),
            ),
            identity: None,
        };
        assert!(!format!("{result:?}").contains("palantir-access-token"));
        let snapshot = runtime
            .persist_oauth_login(result)
            .expect("encrypted OAuth persistence");
        assert!(snapshot.generation() > 0);
        let credential = CredentialId::new("foundry-account").expect("credential");
        let metadata = store
            .profile_metadata(&credential)
            .expect("profile metadata")
            .expect("persisted profile");
        assert_eq!(metadata.provider_profile, "palantir_aip");
        assert!(!metadata.account_id_present);

        let authorization = runtime
            .authorize(
                &config.upstreams()["foundry"],
                &credential,
                &HeaderMap::new(),
                CancellationToken::new(),
            )
            .await
            .expect("Palantir bearer authorization");
        let mut headers = HeaderMap::new();
        authorization
            .apply_once(&mut headers)
            .expect("apply authorization");
        assert_header_value(
            &headers,
            header::AUTHORIZATION.as_str(),
            b"Bearer palantir-access-token",
        );
        assert!(headers
            .get(header::AUTHORIZATION)
            .is_some_and(HeaderValue::is_sensitive));
    }

    #[tokio::test]
    async fn concurrent_login_session_cannot_overwrite_a_newer_token_generation() {
        let client_secret = secret_file("operator-client-secret");
        let config = palantir_oauth_config(client_secret.path(), OAuthGrantType::AuthorizationCode);
        let (runtime, store) = sqlite_native_runtime(&config);
        let (_, first_target) = runtime
            .configured_oauth_provider(
                &config,
                "foundry-account",
                OAuthGrantType::AuthorizationCode,
            )
            .expect("first login session");
        let (_, stale_target) = runtime
            .configured_oauth_provider(
                &config,
                "foundry-account",
                OAuthGrantType::AuthorizationCode,
            )
            .expect("concurrent login session");
        runtime
            .persist_oauth_login(NativeOAuthLoginResult {
                target: first_target,
                tokens: OAuthTokens::bearer("winner-access", Some("winner-refresh"), None),
                identity: None,
            })
            .expect("winner persists");
        assert_eq!(
            runtime.persist_oauth_login(NativeOAuthLoginResult {
                target: stale_target,
                tokens: OAuthTokens::bearer("stale-access", Some("stale-refresh"), None),
                identity: None,
            }),
            Err(NativeRuntimeError::CredentialUnavailable)
        );
        let persisted = store
            .load(&CredentialId::new("foundry-account").expect("credential"))
            .await
            .expect("load winner")
            .expect("persisted winner");
        assert_secret_value(
            persisted.tokens().access_token().expose_secret(),
            "winner-access",
        );
    }

    #[test]
    fn builtin_codex_fingerprint_covers_effective_oauth_identity() {
        let config = builtin_codex_config();
        let account = &config.accounts()["codex-account"];
        let upstream = &config.upstreams()[account.provider()];
        let effective = builtin_codex_oauth_config().expect("effective built-in OAuth config");
        let input =
            account_configuration_fingerprint_input(upstream, account.id(), account.auth_kind())
                .expect("effective fingerprint input");

        assert_eq!(
            input.oauth_client_id.as_deref(),
            Some(effective.client_id.as_str())
        );
        assert_eq!(
            input.authorization_endpoint.as_deref(),
            Some(effective.authorization_endpoint.as_str())
        );
        assert_eq!(
            input.token_endpoint.as_deref(),
            Some(effective.token_endpoint.as_str())
        );
        assert_eq!(input.oauth_scopes, effective.scopes);
        assert!(input.oauth_additional_identity.iter().any(|(key, value)| {
            key == "device_authorization_endpoint"
                && effective
                    .device_authorization_endpoint
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.as_str() == value)
        }));
        assert!(input
            .oauth_additional_identity
            .iter()
            .any(|(key, value)| key == "device_grant" && value == "codex_accounts"));

        let current = input.fingerprint().expect("current fingerprint");
        let historical = configured_account_configuration_fingerprint_input(
            upstream,
            account.id(),
            account.auth_kind(),
        );
        let historical_v1 = historical
            .legacy_fingerprint()
            .expect("historical version-one fingerprint");
        let historical_v2 = historical
            .fingerprint()
            .expect("historical version-two fingerprint");
        assert_ne!(current, historical_v1);
        assert_ne!(current, historical_v2);
        let migration_candidates = account_configuration_fingerprint_migration_candidates(
            upstream,
            account.id(),
            account.auth_kind(),
        )
        .expect("migration candidates");
        assert!(migration_candidates.contains(&historical_v1));
        assert!(migration_candidates.contains(&historical_v2));

        let mut changed_effective = effective;
        changed_effective.token_endpoint =
            Url::parse("https://auth.openai.com/oauth/token-v2").expect("changed endpoint");
        let mut changed_input = historical.clone();
        apply_builtin_codex_oauth_identity(&mut changed_input, &changed_effective);
        assert_ne!(
            changed_input.fingerprint().expect("changed fingerprint"),
            current
        );

        let explicit = hydration_filter_config();
        let explicit_account = &explicit.accounts()["oauth-codex"];
        let explicit_upstream = &explicit.upstreams()[explicit_account.provider()];
        let explicit_input = account_configuration_fingerprint_input(
            explicit_upstream,
            explicit_account.id(),
            explicit_account.auth_kind(),
        )
        .expect("explicit fingerprint input");
        assert!(explicit_input.oauth_additional_identity.is_empty());
        assert_eq!(
            explicit_input.fingerprint().expect("explicit fingerprint"),
            configured_account_configuration_fingerprint_input(
                explicit_upstream,
                explicit_account.id(),
                explicit_account.auth_kind(),
            )
            .fingerprint()
            .expect("historical explicit fingerprint")
        );
    }

    #[test]
    fn sqlite_runtime_retires_pre_effective_codex_payload_for_reauthentication() {
        let config = builtin_codex_config();
        let account = &config.accounts()["codex-account"];
        let upstream = &config.upstreams()[account.provider()];
        let old_fingerprint = configured_account_configuration_fingerprint_input(
            upstream,
            account.id(),
            account.auth_kind(),
        )
        .fingerprint()
        .expect("pre-effective fingerprint");
        let current =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())
                .expect("current fingerprint");
        assert_ne!(old_fingerprint, current);

        let sqlite = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"builtin-codex-fingerprint-migration-key").expect("master key"),
        )
        .expect("encrypted store");
        let state = sqlite
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                account.id(),
                account.provider(),
                &old_fingerprint,
                true,
                1,
            ))
            .expect("old credential state");
        let credential = CredentialId::new(account.id()).expect("credential");
        let token_store = Arc::new(SqliteOAuthTokenStore::new(sqlite));
        token_store
            .compare_and_swap_profile_for_fingerprint(
                &credential,
                &old_fingerprint,
                state.revision,
                &OAuthCredentialProfile::new(
                    "openai",
                    OAuthTokens::bearer("old-access", Some("old-refresh"), None),
                )
                .with_account_id("old-chatgpt-account"),
            )
            .expect("old OAuth payload");

        let runtime = NativeRuntime::new_with_sqlite(&config, Arc::clone(&token_store))
            .expect("runtime starts after fail-closed retirement");
        let migrated = token_store
            .store()
            .credential_state(account.id())
            .expect("credential state")
            .expect("credential exists");
        assert_eq!(migrated.configuration_fingerprint, current);
        assert!(!migrated.enabled);
        assert!(!token_store
            .store()
            .credential_payload_exists(account.id())
            .expect("payload existence"));
        assert!(!runtime.account_ids.contains_key(account.id()));
    }

    #[test]
    fn sqlite_runtime_retires_version_one_oauth_payload_for_reauthentication() {
        let config = kimi_oauth_config();
        let account = &config.accounts()["kimi-subscription"];
        let upstream = &config.upstreams()[account.provider()];
        let legacy =
            legacy_account_configuration_fingerprint(upstream, account.id(), account.auth_kind())
                .expect("legacy fingerprint");
        let current =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())
                .expect("current fingerprint");
        assert_ne!(legacy, current);

        let directory = tempfile::tempdir().expect("temporary directory");
        #[cfg(unix)]
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("owner-private directory");
        let path = directory.path().join("credentials.db");
        {
            let store = SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"legacy-fingerprint-upgrade-key").expect("master key"),
            )
            .expect("legacy encrypted store");
            let state = store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    account.id(),
                    account.provider(),
                    &legacy,
                    true,
                    1,
                ))
                .expect("legacy credential state");
            let credential = CredentialId::new(account.id()).expect("credential");
            SqliteOAuthTokenStore::new(store)
                .compare_and_swap_profile_for_fingerprint(
                    &credential,
                    &legacy,
                    state.revision,
                    &OAuthCredentialProfile::new(
                        "kimi",
                        OAuthTokens::bearer("legacy-access", Some("legacy-refresh"), None),
                    )
                    .with_account_id("legacy-provider-subject"),
                )
                .expect("legacy OAuth payload");
        }

        let store = Arc::new(SqliteOAuthTokenStore::new(
            SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"legacy-fingerprint-upgrade-key").expect("master key"),
            )
            .expect("reopened encrypted store"),
        ));
        let runtime = NativeRuntime::new_with_sqlite(&config, Arc::clone(&store))
            .expect("runtime starts after fail-closed upgrade");

        let migrated = store
            .store()
            .credential_state(account.id())
            .expect("credential state")
            .expect("credential exists");
        assert_eq!(migrated.configuration_fingerprint, current);
        assert!(!migrated.enabled);
        assert!(!store
            .store()
            .credential_payload_exists(account.id())
            .expect("payload existence"));
        assert!(!runtime.account_ids.contains_key(account.id()));
    }

    #[tokio::test]
    async fn sqlite_runtime_preflight_failure_preserves_every_pending_retirement() {
        let config = pooler_config::compile_yaml(
            "native-atomic-retirement-rollback-test.yaml",
            r#"
version: 2
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
  legacy-a: {provider: kimi-coding, auth_kind: oauth}
  invalid-z: {provider: kimi-coding, auth_kind: oauth}
"#,
        )
        .expect("atomic retirement rollback config");
        let legacy_account = &config.accounts()["legacy-a"];
        let upstream = &config.upstreams()[legacy_account.provider()];
        let legacy = legacy_account_configuration_fingerprint(
            upstream,
            legacy_account.id(),
            legacy_account.auth_kind(),
        )
        .expect("legacy fingerprint");

        let sqlite = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"native-atomic-retirement-rollback-key").expect("master key"),
        )
        .expect("encrypted store");
        let state = sqlite
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                legacy_account.id(),
                legacy_account.provider(),
                &legacy,
                true,
                1,
            ))
            .expect("legacy credential state");
        let legacy_credential = CredentialId::new(legacy_account.id()).expect("credential");
        let token_store = Arc::new(SqliteOAuthTokenStore::new(sqlite));
        token_store
            .compare_and_swap_profile_for_fingerprint(
                &legacy_credential,
                &legacy,
                state.revision,
                &OAuthCredentialProfile::new(
                    "kimi",
                    OAuthTokens::bearer("legacy-access", Some("legacy-refresh"), None),
                )
                .with_account_id("legacy-provider-subject"),
            )
            .expect("legacy OAuth payload");
        token_store
            .store()
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "invalid-z",
                "wrong-provider",
                "f".repeat(64),
                true,
                2,
            ))
            .expect("later invalid state");
        let legacy_before = token_store
            .store()
            .credential_state(legacy_account.id())
            .expect("legacy state")
            .expect("legacy state");

        assert!(matches!(
            NativeRuntime::new_with_sqlite(&config, Arc::clone(&token_store)),
            Err(NativeRuntimeError::CredentialUnavailable)
        ));

        assert_eq!(
            token_store
                .store()
                .credential_state(legacy_account.id())
                .expect("legacy state after failed preflight")
                .expect("legacy state after failed preflight"),
            legacy_before
        );
        let persisted = token_store
            .load(&legacy_credential)
            .await
            .expect("load legacy profile")
            .expect("legacy profile remains");
        assert_secret_value(
            persisted.tokens().access_token().expose_secret(),
            "legacy-access",
        );
    }

    #[test]
    fn sqlite_hydration_reads_only_oauth_accounts_with_refreshable_bindings() {
        let config = hydration_filter_config();
        let mut runtime = NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime");
        let reads = AtomicUsize::new(0);
        hydrate_account_ids(&mut runtime, &config, |credential, _fingerprint| {
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
        assert_header_value(
            &headers,
            "user-agent",
            concat!("CLIProxyAPI/", env!("CARGO_PKG_VERSION")).as_bytes(),
        );
        assert_header_value(&headers, "x-msh-platform", b"CLIProxyAPI");
        assert_header_value(
            &headers,
            "x-msh-version",
            env!("CARGO_PKG_VERSION").as_bytes(),
        );
        for name in ["x-msh-device-name", "x-msh-device-model", "x-msh-device-id"] {
            assert_header_value(&headers, name, b"pooler");
            assert!(headers.get(name).is_some_and(|value| !value.is_sensitive()));
        }
    }

    #[tokio::test]
    async fn known_kimi_open_platform_does_not_receive_kimi_code_identity() {
        let api_secret = secret_file("moonshot-api-key");
        let config = pooler_config::compile_yaml(
            "native-kimi-open-platform-test.yaml",
            &format!(
                "version: 2\nupstreams:\n  moonshot:\n    known_provider: moonshotai\naccounts:\n  moonshot-key:\n    provider: moonshot\n    auth_kind: api_key\n    secret: file:{}\n",
                api_secret.path().display()
            ),
        )
        .expect("Kimi Open Platform config");
        let upstream = &config.upstreams()["moonshot"];
        let runtime =
            NativeRuntime::new(&config, Arc::new(PanicOAuthStore)).expect("native runtime");
        let credential = CredentialId::new("moonshot-key").expect("credential");
        let authorization = runtime
            .authorize_attempt(NativeAuthorizationRequest {
                upstream,
                account_auth_kind: Some(AccountAuthKind::ApiKey),
                credential: Some(&credential),
                account_secret: config.accounts()["moonshot-key"].secret(),
                static_auth: upstream.auth(),
                request_headers: &HeaderMap::new(),
                cancellation: CancellationToken::new(),
            })
            .await
            .expect("Open Platform authorization");
        let mut headers = HeaderMap::new();
        authorization
            .apply_to(&mut headers)
            .expect("authorization headers");

        assert_header_value(&headers, "authorization", b"Bearer moonshot-api-key");
        for name in [
            "user-agent",
            "x-msh-platform",
            "x-msh-version",
            "x-msh-device-name",
            "x-msh-device-model",
            "x-msh-device-id",
        ] {
            assert!(
                !headers.contains_key(name),
                "unexpected Kimi Code header {name}"
            );
        }
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
    fn runtime_rebuild_preserves_injected_binding_across_generations() {
        let config = config();
        let runtime = NativeRuntime::with_codex_provider(
            Arc::new(MemoryOAuthTokenStore::new()),
            "codex",
            Arc::new(MockRefresher {
                calls: AtomicUsize::new(0),
            }),
        );
        let injected = runtime.bindings["codex"].clone();

        let first = runtime
            .rebuild_for_config(&config, &config)
            .expect("first runtime rebuild");
        assert!(first.injected_bindings.contains("codex"));
        assert!(Arc::ptr_eq(&first.bindings["codex"], &injected));

        let second = first
            .rebuild_for_config(&config, &config)
            .expect("second runtime rebuild");
        assert!(second.injected_bindings.contains("codex"));
        assert!(Arc::ptr_eq(&second.bindings["codex"], &injected));
    }

    #[test]
    fn runtime_rebuild_drops_account_identity_when_oauth_configuration_changes() {
        let compile = |scope: &str| {
            pooler_config::compile_yaml(
                "native-account-identity-rebuild-test.yaml",
                &format!(
                    r#"
version: 2
upstreams:
  codex:
    url: https://api.example.test
    native: {{kind: codex}}
    oauth:
      authorization_endpoint: https://auth.example.test/authorize
      token_endpoint: https://auth.example.test/token
      client_id: registered-client
      scopes: [{scope}]
accounts:
  account-a: {{provider: codex, auth_kind: oauth}}
"#,
                ),
            )
            .expect("native account identity config")
        };
        let previous = compile("scope-a");
        let unchanged = compile("scope-a");
        let changed = compile("scope-b");
        let runtime = NativeRuntime::with_codex_provider(
            Arc::new(MemoryOAuthTokenStore::new()),
            "codex",
            Arc::new(MockRefresher {
                calls: AtomicUsize::new(0),
            }),
        )
        .with_account_id("account-a", "chatgpt-account-a");

        let unchanged_runtime = runtime
            .rebuild_for_config(&previous, &unchanged)
            .expect("unchanged runtime rebuild");
        assert_eq!(
            unchanged_runtime
                .account_ids
                .get("account-a")
                .map(String::as_str),
            Some("chatgpt-account-a")
        );

        let changed_runtime = runtime
            .rebuild_for_config(&previous, &changed)
            .expect("changed runtime rebuild");
        assert!(!changed_runtime.account_ids.contains_key("account-a"));
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
    async fn sqlite_authorization_uses_live_provider_subject_after_same_identity_login() {
        let config = builtin_codex_config();
        let account = &config.accounts()["codex-account"];
        let upstream = &config.upstreams()[account.provider()];
        let fingerprint =
            account_configuration_fingerprint(upstream, account.id(), account.auth_kind())
                .expect("configuration fingerprint");
        let sqlite = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"live-provider-subject-test-key").expect("master key"),
        )
        .expect("encrypted store");
        let state = sqlite
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                account.id(),
                account.provider(),
                &fingerprint,
                true,
                1,
            ))
            .expect("credential state");
        let credential = CredentialId::new(account.id()).expect("credential");
        let token_store = Arc::new(SqliteOAuthTokenStore::new(sqlite));
        token_store
            .compare_and_swap_profile_for_fingerprint(
                &credential,
                &fingerprint,
                state.revision,
                &OAuthCredentialProfile::new(
                    "openai",
                    OAuthTokens::bearer("old-access", Some("old-refresh"), None),
                )
                .with_account_id("old-chatgpt-account"),
            )
            .expect("old OAuth profile");

        let runtime = NativeRuntime::new_with_sqlite(&config, Arc::clone(&token_store))
            .expect("native runtime");
        assert_eq!(
            runtime.account_ids.get(account.id()).map(String::as_str),
            Some("old-chatgpt-account")
        );
        let target = runtime
            .prepare_oauth_login_target(account, upstream, "openai")
            .expect("replacement login target");
        runtime
            .persist_oauth_login(NativeOAuthLoginResult {
                target,
                tokens: OAuthTokens::bearer("new-access", Some("new-refresh"), None),
                identity: Some(OAuthIdentity {
                    subject: "new-chatgpt-account".to_owned(),
                    email: None,
                    name: None,
                }),
            })
            .expect("replacement OAuth profile");

        for candidate in [
            runtime,
            NativeRuntime::new_with_sqlite(&config, Arc::clone(&token_store))
                .expect("unchanged runtime rebuild"),
        ] {
            let authorization = candidate
                .authorize(
                    upstream,
                    &credential,
                    &HeaderMap::new(),
                    CancellationToken::new(),
                )
                .await
                .expect("Codex authorization");
            let mut headers = HeaderMap::new();
            authorization
                .apply_once(&mut headers)
                .expect("apply authorization");
            assert_header_value(&headers, "chatgpt-account-id", b"new-chatgpt-account");
            assert_header_value(
                &headers,
                header::AUTHORIZATION.as_str(),
                b"Bearer new-access",
            );
        }
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
