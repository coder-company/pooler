//! Provider-specific login profiles over Pooler's generic OAuth contracts.
//!
//! This module separates verified provider facts from OAuth mechanics. Browser
//! login is offered only when a public installed-app client identifier and
//! HTTPS endpoints are known. Codex uses the official Codex CLI installed-app
//! client ID so `pooler auth login openai` does not import another proxy's
//! tokens or require an operator-owned OAuth app. First-party client secrets
//! and undocumented subscription grants remain unsupported.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use super::oauth::{
    AuthorizationAttempt, AuthorizationCode, DeviceAuthorization, DeviceAuthorizationGrant,
    OAuthClientConfig, OAuthCodeExchange, OAuthDeviceFlow, OAuthError, OAuthFuture, OAuthIdentity,
    OAuthIdentityProvider, OAuthProvider, OAuthRefresher, OAuthRequestEncoding, OAuthRevoker,
    OAuthState, OAuthTransport, PkcePair, StandardOAuthProvider,
};
use super::{OAuthTokens, SecretValue};

/// Login mechanisms understood by the provider registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderLoginMethod {
    /// A provider API key acquired outside Pooler.
    ApiKey,
    /// OAuth authorization-code flow with mandatory S256 PKCE and state.
    AuthorizationCodePkce,
    /// OAuth device authorization grant with bounded polling.
    DeviceCode,
}

impl fmt::Display for ProviderLoginMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ApiKey => "api_key",
            Self::AuthorizationCodePkce => "authorization_code_pkce",
            Self::DeviceCode => "device_code",
        })
    }
}

/// Whether Pooler can safely offer a login mechanism for a provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLoginSupport {
    /// The published protocol has enough information for a built-in profile.
    Supported,
    /// The flow is published, but endpoints or a client registration must be
    /// provided explicitly by the operator.
    RequiresExplicitConfiguration,
    /// Pooler must not offer the flow for this provider.
    Unsupported,
}

/// One provider login capability and its operator-facing rationale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLoginCapability {
    method: ProviderLoginMethod,
    support: ProviderLoginSupport,
    note: &'static str,
}

impl ProviderLoginCapability {
    /// Define a provider login capability.
    #[must_use]
    pub const fn new(
        method: ProviderLoginMethod,
        support: ProviderLoginSupport,
        note: &'static str,
    ) -> Self {
        Self {
            method,
            support,
            note,
        }
    }

    /// Login mechanism.
    #[must_use]
    pub const fn method(&self) -> ProviderLoginMethod {
        self.method
    }

    /// Support level.
    #[must_use]
    pub const fn support(&self) -> ProviderLoginSupport {
        self.support
    }

    /// Short explanation suitable for a CLI or management UI.
    #[must_use]
    pub const fn note(&self) -> &'static str {
        self.note
    }
}

/// Published OAuth endpoints that may be safely used as provider defaults.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderOAuthDefaults {
    authorization_endpoint: Option<&'static str>,
    token_endpoint: Option<&'static str>,
    device_authorization_endpoint: Option<&'static str>,
    revocation_endpoint: Option<&'static str>,
    identity_endpoint: Option<&'static str>,
    client_id: Option<&'static str>,
    authorization_parameters: &'static [(&'static str, &'static str)],
    device_grant: DeviceAuthorizationGrant,
}

impl ProviderOAuthDefaults {
    /// Empty defaults. Every endpoint must be supplied by the operator.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            revocation_endpoint: None,
            identity_endpoint: None,
            client_id: None,
            authorization_parameters: &[],
            device_grant: DeviceAuthorizationGrant::Rfc8628,
        }
    }

    /// Select the device-authorization dialect.
    #[must_use]
    pub const fn with_device_grant(mut self, grant: DeviceAuthorizationGrant) -> Self {
        self.device_grant = grant;
        self
    }

    /// Set the public installed-app client identifier.
    #[must_use]
    pub const fn with_client_id(mut self, client_id: &'static str) -> Self {
        self.client_id = Some(client_id);
        self
    }

    /// Set extra authorization-query parameters the provider requires.
    #[must_use]
    pub const fn with_authorization_parameters(
        mut self,
        parameters: &'static [(&'static str, &'static str)],
    ) -> Self {
        self.authorization_parameters = parameters;
        self
    }

    /// Set the published authorization endpoint.
    #[must_use]
    pub const fn with_authorization_endpoint(mut self, endpoint: &'static str) -> Self {
        self.authorization_endpoint = Some(endpoint);
        self
    }

    /// Set the published token endpoint.
    #[must_use]
    pub const fn with_token_endpoint(mut self, endpoint: &'static str) -> Self {
        self.token_endpoint = Some(endpoint);
        self
    }

    /// Set the published device authorization endpoint.
    #[must_use]
    pub const fn with_device_authorization_endpoint(mut self, endpoint: &'static str) -> Self {
        self.device_authorization_endpoint = Some(endpoint);
        self
    }

    /// Set the published token revocation endpoint.
    #[must_use]
    pub const fn with_revocation_endpoint(mut self, endpoint: &'static str) -> Self {
        self.revocation_endpoint = Some(endpoint);
        self
    }

    /// Set the published identity endpoint.
    #[must_use]
    pub const fn with_identity_endpoint(mut self, endpoint: &'static str) -> Self {
        self.identity_endpoint = Some(endpoint);
        self
    }

    /// Published authorization endpoint.
    #[must_use]
    pub const fn authorization_endpoint(&self) -> Option<&'static str> {
        self.authorization_endpoint
    }

    /// Published token endpoint.
    #[must_use]
    pub const fn token_endpoint(&self) -> Option<&'static str> {
        self.token_endpoint
    }

    /// Published device authorization endpoint.
    #[must_use]
    pub const fn device_authorization_endpoint(&self) -> Option<&'static str> {
        self.device_authorization_endpoint
    }

    /// Published revocation endpoint.
    #[must_use]
    pub const fn revocation_endpoint(&self) -> Option<&'static str> {
        self.revocation_endpoint
    }

    /// Published identity endpoint.
    #[must_use]
    pub const fn identity_endpoint(&self) -> Option<&'static str> {
        self.identity_endpoint
    }

    /// Public installed-app client identifier, when the provider publishes one.
    #[must_use]
    pub const fn client_id(&self) -> Option<&'static str> {
        self.client_id
    }

    /// Extra authorization-query parameters required by the provider.
    #[must_use]
    pub const fn authorization_parameters(&self) -> &'static [(&'static str, &'static str)] {
        self.authorization_parameters
    }

    /// Device-authorization dialect.
    #[must_use]
    pub const fn device_grant(&self) -> DeviceAuthorizationGrant {
        self.device_grant
    }
}

/// Static provider login metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLoginDefinition {
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    api_key_environment_variables: &'static [&'static str],
    capabilities: &'static [ProviderLoginCapability],
    oauth_defaults: ProviderOAuthDefaults,
    oauth_host_suffixes: &'static [&'static str],
    suggested_scopes: &'static [&'static str],
    documentation_url: &'static str,
}

impl ProviderLoginDefinition {
    /// Start a definition with no aliases, login capabilities, or OAuth
    /// defaults. Registry construction validates the finished definition.
    #[must_use]
    pub const fn new(
        id: &'static str,
        display_name: &'static str,
        documentation_url: &'static str,
    ) -> Self {
        Self {
            id,
            display_name,
            aliases: &[],
            api_key_environment_variables: &[],
            capabilities: &[],
            oauth_defaults: ProviderOAuthDefaults::none(),
            oauth_host_suffixes: &[],
            suggested_scopes: &[],
            documentation_url,
        }
    }

    /// Set case-insensitive provider aliases.
    #[must_use]
    pub const fn with_aliases(mut self, aliases: &'static [&'static str]) -> Self {
        self.aliases = aliases;
        self
    }

    /// Set provider-documented API-key environment variable names.
    #[must_use]
    pub const fn with_api_key_environment_variables(
        mut self,
        variables: &'static [&'static str],
    ) -> Self {
        self.api_key_environment_variables = variables;
        self
    }

    /// Set the complete login support matrix.
    #[must_use]
    pub const fn with_capabilities(
        mut self,
        capabilities: &'static [ProviderLoginCapability],
    ) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set provider-published OAuth endpoint defaults.
    #[must_use]
    pub const fn with_oauth_defaults(mut self, defaults: ProviderOAuthDefaults) -> Self {
        self.oauth_defaults = defaults;
        self
    }

    /// Restrict every OAuth endpoint to these exact DNS suffixes.
    ///
    /// Built-in profiles always declare an allowlist. An empty allowlist marks
    /// a custom profile and requires an explicit dangerous trust decision in
    /// [`ProviderOAuthSettings`]. IP literals are never accepted by a profiled
    /// OAuth flow.
    #[must_use]
    pub const fn with_oauth_host_suffixes(mut self, suffixes: &'static [&'static str]) -> Self {
        self.oauth_host_suffixes = suffixes;
        self
    }

    /// Set documented scopes as suggestions. Pooler never requests these
    /// implicitly; the operator must choose scopes for each client registration.
    #[must_use]
    pub const fn with_suggested_scopes(mut self, scopes: &'static [&'static str]) -> Self {
        self.suggested_scopes = scopes;
        self
    }

    /// Stable canonical provider identifier.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Human-readable provider name.
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        self.display_name
    }

    /// Case-insensitive aliases accepted by the registry.
    #[must_use]
    pub const fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }

    /// Provider-documented API-key environment variable names.
    #[must_use]
    pub const fn api_key_environment_variables(&self) -> &'static [&'static str] {
        self.api_key_environment_variables
    }

    /// Login capabilities declared for this provider.
    #[must_use]
    pub const fn capabilities(&self) -> &'static [ProviderLoginCapability] {
        self.capabilities
    }

    /// Return a declared login capability.
    #[must_use]
    pub fn capability(&self, method: ProviderLoginMethod) -> Option<&ProviderLoginCapability> {
        self.capabilities
            .iter()
            .find(|capability| capability.method == method)
    }

    /// Return the support level, treating an omitted capability as unsupported.
    #[must_use]
    pub fn support(&self, method: ProviderLoginMethod) -> ProviderLoginSupport {
        self.capability(method).map_or(
            ProviderLoginSupport::Unsupported,
            ProviderLoginCapability::support,
        )
    }

    /// Published OAuth defaults. Missing values must not be guessed.
    #[must_use]
    pub const fn oauth_defaults(&self) -> &ProviderOAuthDefaults {
        &self.oauth_defaults
    }

    /// Allowed OAuth endpoint DNS suffixes.
    #[must_use]
    pub const fn oauth_host_suffixes(&self) -> &'static [&'static str] {
        self.oauth_host_suffixes
    }

    /// Documented scopes that an operator may explicitly select.
    #[must_use]
    pub const fn suggested_scopes(&self) -> &'static [&'static str] {
        self.suggested_scopes
    }

    /// Authoritative provider documentation used for this definition.
    #[must_use]
    pub const fn documentation_url(&self) -> &'static str {
        self.documentation_url
    }

    /// Build the generic OAuth configuration for one supported flow.
    ///
    /// Browser flows always require a strict loopback redirect and are executed
    /// by [`StandardOAuthProvider`] with S256 PKCE and state validation. OAuth
    /// endpoints are HTTPS-only and may not contain userinfo, query values, or
    /// fragments. No client secret is accepted at this installed-app boundary.
    pub fn build_oauth_config(
        &self,
        method: ProviderLoginMethod,
        settings: ProviderOAuthSettings,
    ) -> Result<OAuthClientConfig, ProviderLoginError> {
        if method == ProviderLoginMethod::ApiKey {
            return Err(ProviderLoginError::NotOAuthMethod);
        }
        match self.support(method) {
            ProviderLoginSupport::Unsupported => {
                return Err(ProviderLoginError::Unsupported {
                    provider: self.id,
                    method,
                });
            }
            ProviderLoginSupport::RequiresExplicitConfiguration
                if !settings.has_explicit_flow_endpoints(method) =>
            {
                return Err(ProviderLoginError::ExplicitConfigurationRequired {
                    provider: self.id,
                    method,
                });
            }
            ProviderLoginSupport::Supported
            | ProviderLoginSupport::RequiresExplicitConfiguration => {}
        }

        let mut settings = settings;
        if settings.client_id.is_empty() {
            if let Some(client_id) = self.oauth_defaults.client_id {
                settings.client_id = client_id.to_owned();
            }
        }
        if settings.scopes.is_empty()
            && self.oauth_defaults.client_id.is_some()
            && !self.suggested_scopes.is_empty()
        {
            settings.scopes = self
                .suggested_scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect();
        }

        validate_oauth_settings(&settings)?;
        let dangerous_custom_endpoint_hosts = settings.dangerous_custom_endpoint_hosts;
        validate_loopback_redirect(&settings.redirect_uri)?;
        validate_scopes(&settings.scopes)?;

        let authorization_endpoint = required_endpoint(
            settings.authorization_endpoint,
            self.oauth_defaults.authorization_endpoint,
            OAuthEndpointKind::Authorization,
        )?;
        let token_endpoint = required_endpoint(
            settings.token_endpoint,
            self.oauth_defaults.token_endpoint,
            OAuthEndpointKind::Token,
        )?;
        let device_authorization_endpoint = optional_endpoint(
            settings.device_authorization_endpoint,
            self.oauth_defaults.device_authorization_endpoint,
            OAuthEndpointKind::DeviceAuthorization,
        )?;
        if method == ProviderLoginMethod::DeviceCode && device_authorization_endpoint.is_none() {
            return Err(ProviderLoginError::MissingEndpoint(
                OAuthEndpointKind::DeviceAuthorization,
            ));
        }
        let revocation_endpoint = optional_endpoint(
            settings.revocation_endpoint,
            self.oauth_defaults.revocation_endpoint,
            OAuthEndpointKind::Revocation,
        )?;
        let identity_endpoint = optional_endpoint(
            settings.identity_endpoint,
            self.oauth_defaults.identity_endpoint,
            OAuthEndpointKind::Identity,
        )?;
        validate_endpoint_host_policy(
            self.oauth_host_suffixes,
            [
                Some(&authorization_endpoint),
                Some(&token_endpoint),
                device_authorization_endpoint.as_ref(),
                revocation_endpoint.as_ref(),
                identity_endpoint.as_ref(),
            ],
            dangerous_custom_endpoint_hosts,
        )?;

        let mut config = OAuthClientConfig::new(
            settings.client_id,
            settings.redirect_uri,
            authorization_endpoint,
            token_endpoint,
        )?
        .with_scopes(settings.scopes);
        if let Some(endpoint) = device_authorization_endpoint {
            config = config.with_device_authorization_endpoint(endpoint);
        }
        if let Some(endpoint) = revocation_endpoint {
            config = config.with_revocation_endpoint(endpoint);
        }
        if let Some(endpoint) = identity_endpoint {
            config = config.with_identity_endpoint(endpoint);
        }
        if settings.request_encoding == OAuthRequestEncoding::Json {
            config = config.with_json_requests();
        }
        for (name, value) in self.oauth_defaults.authorization_parameters {
            config = config.with_authorization_parameter(*name, *value);
        }
        if self.oauth_defaults.device_grant != DeviceAuthorizationGrant::Rfc8628 {
            config = config.with_device_grant(self.oauth_defaults.device_grant);
        }
        config.validate().map_err(Into::into)
    }

    /// Build a provider over an explicit transport after applying this profile.
    pub fn build_oauth_provider(
        &self,
        method: ProviderLoginMethod,
        settings: ProviderOAuthSettings,
        transport: Arc<dyn OAuthTransport>,
    ) -> Result<ProviderOAuthClient, ProviderLoginError> {
        let config = self.build_oauth_config(method, settings)?;
        let inner = StandardOAuthProvider::new(self.id, config, transport)?;
        Ok(ProviderOAuthClient {
            definition: *self,
            method,
            inner,
        })
    }
}

/// Flow-locked provider client built from a verified provider definition.
///
/// The wrapper prevents a complete generic OAuth configuration from enabling a
/// login flow that its provider definition marks unsupported. Refresh,
/// revocation, and identity operations remain available after either OAuth
/// login flow.
#[derive(Clone)]
pub struct ProviderOAuthClient {
    definition: ProviderLoginDefinition,
    method: ProviderLoginMethod,
    inner: StandardOAuthProvider,
}

impl ProviderOAuthClient {
    /// Provider definition used to build this client.
    #[must_use]
    pub const fn definition(&self) -> &ProviderLoginDefinition {
        &self.definition
    }

    /// The only interactive login flow enabled on this client.
    #[must_use]
    pub const fn login_method(&self) -> ProviderLoginMethod {
        self.method
    }

    /// Resolved generic OAuth configuration.
    #[must_use]
    pub const fn config(&self) -> &OAuthClientConfig {
        self.inner.config()
    }

    /// Build a deterministic authorization attempt while retaining the flow
    /// lock. Production callers should use [`OAuthProvider::begin_authorization`].
    pub fn begin_authorization_with(
        &self,
        state: OAuthState,
        pkce: PkcePair,
    ) -> Result<AuthorizationAttempt, OAuthError> {
        if self.method != ProviderLoginMethod::AuthorizationCodePkce {
            return Err(OAuthError::Unsupported);
        }
        self.inner.begin_authorization_with(state, pkce)
    }
}

impl fmt::Debug for ProviderOAuthClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOAuthClient")
            .field("provider_id", &self.definition.id)
            .field("login_method", &self.method)
            .finish_non_exhaustive()
    }
}

impl OAuthProvider for ProviderOAuthClient {
    fn provider_id(&self) -> &str {
        self.definition.id
    }

    fn begin_authorization(&self) -> Result<AuthorizationAttempt, OAuthError> {
        if self.method != ProviderLoginMethod::AuthorizationCodePkce {
            return Err(OAuthError::Unsupported);
        }
        self.inner.begin_authorization()
    }
}

impl OAuthCodeExchange for ProviderOAuthClient {
    fn exchange_code<'a>(
        &'a self,
        code: &'a AuthorizationCode,
        pkce: &'a PkcePair,
        redirect_uri: &'a Url,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        if self.method != ProviderLoginMethod::AuthorizationCodePkce {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        self.inner
            .exchange_code(code, pkce, redirect_uri, cancellation)
    }
}

impl OAuthDeviceFlow for ProviderOAuthClient {
    fn start_device_authorization(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, DeviceAuthorization> {
        if self.method != ProviderLoginMethod::DeviceCode {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        self.inner.start_device_authorization(cancellation)
    }

    fn poll_device<'a>(
        &'a self,
        authorization: &'a DeviceAuthorization,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        if self.method != ProviderLoginMethod::DeviceCode {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        self.inner.poll_device(authorization, cancellation)
    }
}

impl OAuthRefresher for ProviderOAuthClient {
    fn refresh<'a>(
        &'a self,
        refresh_token: &'a SecretValue,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        self.inner.refresh(refresh_token, cancellation)
    }
}

impl OAuthRevoker for ProviderOAuthClient {
    fn revoke<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, ()> {
        self.inner.revoke(tokens, cancellation)
    }
}

impl OAuthIdentityProvider for ProviderOAuthClient {
    fn identity<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthIdentity> {
        self.inner.identity(tokens, cancellation)
    }
}

/// Explicit OAuth settings for a provider login.
///
/// Debug output reports only which values are present. It does not render the
/// client identifier, scopes, redirect, or endpoint URLs because operator
/// input may accidentally contain sensitive query material before validation.
#[derive(Clone)]
pub struct ProviderOAuthSettings {
    client_id: String,
    redirect_uri: Url,
    scopes: Vec<String>,
    authorization_endpoint: Option<Url>,
    token_endpoint: Option<Url>,
    device_authorization_endpoint: Option<Url>,
    revocation_endpoint: Option<Url>,
    identity_endpoint: Option<Url>,
    request_encoding: OAuthRequestEncoding,
    dangerous_custom_endpoint_hosts: bool,
}

impl ProviderOAuthSettings {
    /// Create settings for a public installed-app client.
    #[must_use]
    pub fn new(client_id: impl Into<String>, redirect_uri: Url) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri,
            scopes: Vec::new(),
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            revocation_endpoint: None,
            identity_endpoint: None,
            request_encoding: OAuthRequestEncoding::Form,
            dangerous_custom_endpoint_hosts: false,
        }
    }

    /// Set the exact scopes selected for this client registration.
    #[must_use]
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Override the authorization endpoint.
    #[must_use]
    pub fn with_authorization_endpoint(mut self, endpoint: Url) -> Self {
        self.authorization_endpoint = Some(endpoint);
        self
    }

    /// Override the token endpoint.
    #[must_use]
    pub fn with_token_endpoint(mut self, endpoint: Url) -> Self {
        self.token_endpoint = Some(endpoint);
        self
    }

    /// Override the device authorization endpoint.
    #[must_use]
    pub fn with_device_authorization_endpoint(mut self, endpoint: Url) -> Self {
        self.device_authorization_endpoint = Some(endpoint);
        self
    }

    /// Override the revocation endpoint.
    #[must_use]
    pub fn with_revocation_endpoint(mut self, endpoint: Url) -> Self {
        self.revocation_endpoint = Some(endpoint);
        self
    }

    /// Override the identity endpoint.
    #[must_use]
    pub fn with_identity_endpoint(mut self, endpoint: Url) -> Self {
        self.identity_endpoint = Some(endpoint);
        self
    }

    /// Use JSON request bodies for a provider that explicitly requires them.
    #[must_use]
    pub const fn with_json_requests(mut self) -> Self {
        self.request_encoding = OAuthRequestEncoding::Json;
        self
    }

    /// Trust endpoint hosts for a custom profile with no allowlist.
    ///
    /// This is intentionally verbose and cannot bypass a non-empty built-in
    /// profile allowlist.
    #[must_use]
    pub const fn dangerously_allow_custom_endpoint_hosts(mut self) -> Self {
        self.dangerous_custom_endpoint_hosts = true;
        self
    }

    fn has_explicit_flow_endpoints(&self, method: ProviderLoginMethod) -> bool {
        self.authorization_endpoint.is_some()
            && self.token_endpoint.is_some()
            && (method != ProviderLoginMethod::DeviceCode
                || self.device_authorization_endpoint.is_some())
    }
}

impl fmt::Debug for ProviderOAuthSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOAuthSettings")
            .field("client_id", &"[REDACTED]")
            .field("redirect_uri", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field(
                "authorization_endpoint_configured",
                &self.authorization_endpoint.is_some(),
            )
            .field("token_endpoint_configured", &self.token_endpoint.is_some())
            .field(
                "device_authorization_endpoint_configured",
                &self.device_authorization_endpoint.is_some(),
            )
            .field(
                "revocation_endpoint_configured",
                &self.revocation_endpoint.is_some(),
            )
            .field(
                "identity_endpoint_configured",
                &self.identity_endpoint.is_some(),
            )
            .field("request_encoding", &self.request_encoding)
            .field(
                "dangerous_custom_endpoint_hosts",
                &self.dangerous_custom_endpoint_hosts,
            )
            .finish()
    }
}

/// OAuth endpoint role used in safe errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthEndpointKind {
    /// Browser authorization endpoint.
    Authorization,
    /// Token exchange and refresh endpoint.
    Token,
    /// Device authorization endpoint.
    DeviceAuthorization,
    /// Token revocation endpoint.
    Revocation,
    /// User identity endpoint.
    Identity,
}

impl fmt::Display for OAuthEndpointKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Authorization => "authorization",
            Self::Token => "token",
            Self::DeviceAuthorization => "device authorization",
            Self::Revocation => "revocation",
            Self::Identity => "identity",
        })
    }
}

/// Provider profile and configuration errors. Values that could contain
/// credentials or callback material are deliberately omitted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderLoginError {
    /// A provider definition contains invalid static metadata.
    #[error("provider login definition is invalid")]
    InvalidDefinition,
    /// Two provider definitions claim the same case-insensitive name.
    #[error("provider login alias collision: {0}")]
    AliasCollision(String),
    /// A registry lookup did not match a provider or alias.
    #[error("provider login definition was not found")]
    UnknownProvider,
    /// API-key acquisition is not an OAuth operation.
    #[error("api-key login does not build an OAuth provider")]
    NotOAuthMethod,
    /// The provider does not expose this login mechanism to Pooler.
    #[error("provider {provider} does not support {method} login")]
    Unsupported {
        /// Canonical provider ID.
        provider: &'static str,
        /// Requested login mechanism.
        method: ProviderLoginMethod,
    },
    /// A documented flow has no safe built-in endpoint/client defaults.
    #[error("provider {provider} {method} login requires explicit OAuth configuration")]
    ExplicitConfigurationRequired {
        /// Canonical provider ID.
        provider: &'static str,
        /// Requested login mechanism.
        method: ProviderLoginMethod,
    },
    /// A required endpoint is absent.
    #[error("provider OAuth {0} endpoint is required")]
    MissingEndpoint(OAuthEndpointKind),
    /// A provider endpoint was not an HTTPS URL without embedded values.
    #[error("provider OAuth {0} endpoint is unsafe")]
    UnsafeEndpoint(OAuthEndpointKind),
    /// A provider endpoint did not match the profile's DNS allowlist.
    #[error("provider OAuth endpoint host is not allowed")]
    EndpointHostNotAllowed,
    /// A custom profile with no endpoint allowlist needs an explicit trust
    /// decision from the caller.
    #[error("custom provider OAuth endpoint hosts require explicit dangerous trust")]
    CustomEndpointTrustRequired,
    /// A browser callback was not an explicit local loopback HTTP target.
    #[error("provider OAuth redirect must use HTTP on an explicit loopback port")]
    UnsafeRedirect,
    /// Scopes were empty, duplicated, or contained whitespace.
    #[error("provider OAuth scopes must be non-empty and unique")]
    InvalidScopes,
    /// Operator input exceeded a hard client, scope, URL, or aggregate limit.
    #[error("provider OAuth settings exceed their input limits")]
    InputLimitExceeded,
    /// The generic OAuth contract rejected the resolved configuration.
    #[error(transparent)]
    OAuth(#[from] OAuthError),
}

/// Immutable lookup table for provider definitions and aliases.
#[derive(Clone, Debug)]
pub struct ProviderLoginRegistry {
    definitions: &'static [ProviderLoginDefinition],
    lookup: HashMap<String, usize>,
}

impl ProviderLoginRegistry {
    /// Validate and index provider definitions.
    pub fn new(
        definitions: &'static [ProviderLoginDefinition],
    ) -> Result<Self, ProviderLoginError> {
        let mut lookup = HashMap::new();
        for (index, definition) in definitions.iter().enumerate() {
            validate_definition(definition)?;
            for name in std::iter::once(definition.id).chain(definition.aliases.iter().copied()) {
                let normalized = normalize_provider_name(name)?;
                if lookup.insert(normalized.clone(), index).is_some() {
                    return Err(ProviderLoginError::AliasCollision(normalized));
                }
            }
        }
        Ok(Self {
            definitions,
            lookup,
        })
    }

    /// Registry containing Pooler's verified built-in definitions.
    #[must_use]
    pub fn builtin() -> Self {
        Self::new(&BUILTIN_PROVIDER_LOGIN_DEFINITIONS)
            .expect("built-in provider login definitions must be valid")
    }

    /// Resolve a canonical ID or alias without network or secret access.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&'static ProviderLoginDefinition> {
        let normalized = normalize_provider_name(name).ok()?;
        self.lookup
            .get(&normalized)
            .and_then(|index| self.definitions.get(*index))
    }

    /// Resolve a provider or return a value-free error.
    pub fn require(
        &self,
        name: &str,
    ) -> Result<&'static ProviderLoginDefinition, ProviderLoginError> {
        self.resolve(name)
            .ok_or(ProviderLoginError::UnknownProvider)
    }

    /// Canonical provider definitions in deterministic declaration order.
    #[must_use]
    pub const fn definitions(&self) -> &'static [ProviderLoginDefinition] {
        self.definitions
    }
}

impl Default for ProviderLoginRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

fn normalize_provider_name(name: &str) -> Result<String, ProviderLoginError> {
    if name.is_empty()
        || name.len() > 128
        || !name.is_ascii()
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"._-".contains(&byte))
    {
        return Err(ProviderLoginError::InvalidDefinition);
    }
    Ok(name.to_ascii_lowercase())
}

fn validate_definition(definition: &ProviderLoginDefinition) -> Result<(), ProviderLoginError> {
    normalize_provider_name(definition.id)?;
    if definition.display_name.trim().is_empty()
        || !valid_documentation_url(definition.documentation_url)
        || definition
            .oauth_host_suffixes
            .iter()
            .any(|suffix| !valid_host_suffix(suffix))
        || definition
            .api_key_environment_variables
            .iter()
            .any(|name| !valid_environment_variable(name))
        || definition
            .suggested_scopes
            .iter()
            .any(|scope| !valid_scope(scope))
    {
        return Err(ProviderLoginError::InvalidDefinition);
    }

    let mut methods = HashSet::new();
    if definition
        .capabilities
        .iter()
        .any(|capability| !methods.insert(capability.method))
    {
        return Err(ProviderLoginError::InvalidDefinition);
    }
    let mut host_suffixes = HashSet::new();
    if definition
        .oauth_host_suffixes
        .iter()
        .any(|suffix| !host_suffixes.insert(*suffix))
    {
        return Err(ProviderLoginError::InvalidDefinition);
    }

    for endpoint in [
        definition.oauth_defaults.authorization_endpoint,
        definition.oauth_defaults.token_endpoint,
        definition.oauth_defaults.device_authorization_endpoint,
        definition.oauth_defaults.revocation_endpoint,
        definition.oauth_defaults.identity_endpoint,
    ] {
        if endpoint.is_some_and(|value| {
            value.parse::<Url>().map_or(true, |url| {
                !valid_provider_endpoint(&url)
                    || (!definition.oauth_host_suffixes.is_empty()
                        && !endpoint_host_allowed(&url, definition.oauth_host_suffixes))
            })
        }) {
            return Err(ProviderLoginError::InvalidDefinition);
        }
    }
    Ok(())
}

fn valid_host_suffix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && !value.contains("..")
}

fn valid_documentation_url(value: &str) -> bool {
    value
        .parse::<Url>()
        .is_ok_and(|url| valid_provider_endpoint(&url))
}

fn valid_environment_variable(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty() && !scope.chars().any(char::is_whitespace)
}

const MAX_CLIENT_ID_BYTES: usize = 512;
const MAX_SCOPE_COUNT: usize = 32;
const MAX_SCOPE_BYTES: usize = 512;
const MAX_SCOPE_TOTAL_BYTES: usize = 4 * 1024;
const MAX_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_SETTINGS_TOTAL_BYTES: usize = 16 * 1024;

fn validate_oauth_settings(settings: &ProviderOAuthSettings) -> Result<(), ProviderLoginError> {
    if settings.client_id.is_empty()
        || settings.client_id.len() > MAX_CLIENT_ID_BYTES
        || settings.client_id.chars().any(char::is_whitespace)
        || settings.client_id.chars().any(char::is_control)
        || settings.scopes.len() > MAX_SCOPE_COUNT
    {
        return Err(ProviderLoginError::InputLimitExceeded);
    }

    let scope_bytes = settings.scopes.iter().try_fold(0_usize, |total, scope| {
        if scope.len() > MAX_SCOPE_BYTES {
            return Err(ProviderLoginError::InputLimitExceeded);
        }
        total
            .checked_add(scope.len())
            .ok_or(ProviderLoginError::InputLimitExceeded)
    })?;
    if scope_bytes > MAX_SCOPE_TOTAL_BYTES {
        return Err(ProviderLoginError::InputLimitExceeded);
    }

    let endpoint_bytes = [
        Some(&settings.redirect_uri),
        settings.authorization_endpoint.as_ref(),
        settings.token_endpoint.as_ref(),
        settings.device_authorization_endpoint.as_ref(),
        settings.revocation_endpoint.as_ref(),
        settings.identity_endpoint.as_ref(),
    ]
    .into_iter()
    .flatten()
    .try_fold(0_usize, |total, endpoint| {
        if endpoint.as_str().len() > MAX_ENDPOINT_BYTES {
            return Err(ProviderLoginError::InputLimitExceeded);
        }
        total
            .checked_add(endpoint.as_str().len())
            .ok_or(ProviderLoginError::InputLimitExceeded)
    })?;
    let total = settings
        .client_id
        .len()
        .checked_add(scope_bytes)
        .and_then(|total| total.checked_add(endpoint_bytes))
        .ok_or(ProviderLoginError::InputLimitExceeded)?;
    if total > MAX_SETTINGS_TOTAL_BYTES {
        return Err(ProviderLoginError::InputLimitExceeded);
    }
    Ok(())
}

fn validate_scopes(scopes: &[String]) -> Result<(), ProviderLoginError> {
    let mut seen = HashSet::new();
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|scope| !valid_scope(scope) || !seen.insert(scope.as_str()))
    {
        return Err(ProviderLoginError::InvalidScopes);
    }
    Ok(())
}

fn validate_endpoint_host_policy<'a>(
    allowed_suffixes: &[&str],
    endpoints: impl IntoIterator<Item = Option<&'a Url>>,
    dangerous_custom_endpoint_hosts: bool,
) -> Result<(), ProviderLoginError> {
    if allowed_suffixes.is_empty() {
        return if dangerous_custom_endpoint_hosts {
            Ok(())
        } else {
            Err(ProviderLoginError::CustomEndpointTrustRequired)
        };
    }
    if endpoints
        .into_iter()
        .flatten()
        .any(|endpoint| !endpoint_host_allowed(endpoint, allowed_suffixes))
    {
        return Err(ProviderLoginError::EndpointHostNotAllowed);
    }
    Ok(())
}

fn endpoint_host_allowed(endpoint: &Url, allowed_suffixes: &[&str]) -> bool {
    let Some(Host::Domain(host)) = endpoint.host() else {
        return false;
    };
    allowed_suffixes.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn required_endpoint(
    explicit: Option<Url>,
    default: Option<&str>,
    kind: OAuthEndpointKind,
) -> Result<Url, ProviderLoginError> {
    optional_endpoint(explicit, default, kind)?.ok_or(ProviderLoginError::MissingEndpoint(kind))
}

fn optional_endpoint(
    explicit: Option<Url>,
    default: Option<&str>,
    kind: OAuthEndpointKind,
) -> Result<Option<Url>, ProviderLoginError> {
    let endpoint = match explicit {
        Some(endpoint) => Some(endpoint),
        None => default
            .map(str::parse::<Url>)
            .transpose()
            .map_err(|_| ProviderLoginError::InvalidDefinition)?,
    };
    if endpoint
        .as_ref()
        .is_some_and(|url| !valid_provider_endpoint(url))
    {
        return Err(ProviderLoginError::UnsafeEndpoint(kind));
    }
    Ok(endpoint)
}

fn valid_provider_endpoint(endpoint: &Url) -> bool {
    endpoint.scheme() == "https"
        && endpoint.host().is_some()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
}

fn validate_loopback_redirect(redirect: &Url) -> Result<(), ProviderLoginError> {
    let loopback = match redirect.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if redirect.scheme() != "http"
        || !loopback
        || redirect.port().is_none()
        || redirect.port() == Some(0)
        || !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.query().is_some()
        || redirect.fragment().is_some()
    {
        return Err(ProviderLoginError::UnsafeRedirect);
    }
    Ok(())
}

/// Official Codex CLI installed-app client ID. This is a public native-app
/// identifier, not a secret. Pooler ships it so login talks to OpenAI
/// directly instead of importing another proxy's tokens.
pub const CODEX_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// Codex authorization endpoint used by the official CLI.
pub const CODEX_OAUTH_AUTHORIZATION_ENDPOINT: &str = "https://auth.openai.com/oauth/authorize";
/// Codex token endpoint used by the official CLI.
pub const CODEX_OAUTH_TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
/// Codex revocation endpoint used by the official CLI.
pub const CODEX_OAUTH_REVOCATION_ENDPOINT: &str = "https://auth.openai.com/oauth/revoke";
/// Codex device user-code endpoint used by the official CLI.
pub const CODEX_OAUTH_DEVICE_USERCODE_ENDPOINT: &str =
    "https://auth.openai.com/api/accounts/deviceauth/usercode";
/// Codex CLI originator query value required for the ChatGPT consent screen.
pub const CODEX_OAUTH_ORIGINATOR: &str = "codex_cli_rs";
/// Space-joined Codex CLI scopes, for authorize-query assertions.
pub const CODEX_OAUTH_SCOPES: &str =
    "openid profile email offline_access api.connectors.read api.connectors.invoke";

const CODEX_OAUTH_SCOPE_LIST: &[&str] = &[
    "openid",
    "profile",
    "email",
    "offline_access",
    "api.connectors.read",
    "api.connectors.invoke",
];

const CODEX_OAUTH_AUTHORIZE_PARAMETERS: &[(&str, &str)] = &[
    ("id_token_add_organizations", "true"),
    ("codex_cli_simplified_flow", "true"),
    ("originator", CODEX_OAUTH_ORIGINATOR),
];

const OPENAI_CAPABILITIES: &[ProviderLoginCapability] = &[
    ProviderLoginCapability::new(
        ProviderLoginMethod::ApiKey,
        ProviderLoginSupport::Supported,
        "OpenAI documents API-key authentication for API usage.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::AuthorizationCodePkce,
        ProviderLoginSupport::Supported,
        "Pooler ships the official Codex CLI installed-app client and browser PKCE flow.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::DeviceCode,
        ProviderLoginSupport::Supported,
        "Pooler ships the official Codex CLI device-code flow for headless sign-in.",
    ),
];

const ANTHROPIC_CAPABILITIES: &[ProviderLoginCapability] = &[
    ProviderLoginCapability::new(
        ProviderLoginMethod::ApiKey,
        ProviderLoginSupport::Supported,
        "Anthropic documents API keys for third-party developer products.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::AuthorizationCodePkce,
        ProviderLoginSupport::Unsupported,
        "Anthropic reserves Claude subscription OAuth for its native applications and directs third-party products to API keys or supported cloud providers.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::DeviceCode,
        ProviderLoginSupport::Unsupported,
        "No third-party Claude subscription device grant is supported.",
    ),
];

const GOOGLE_CAPABILITIES: &[ProviderLoginCapability] = &[
    ProviderLoginCapability::new(
        ProviderLoginMethod::ApiKey,
        ProviderLoginSupport::Supported,
        "Google documents API-key authentication for the Gemini API.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::AuthorizationCodePkce,
        ProviderLoginSupport::Supported,
        "Google documents desktop installed-app OAuth with loopback redirects and PKCE.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::DeviceCode,
        ProviderLoginSupport::Unsupported,
        "Google documents device authorization for limited-input devices; Pooler desktop login uses the installed-app loopback flow.",
    ),
];

const XAI_CAPABILITIES: &[ProviderLoginCapability] = &[
    ProviderLoginCapability::new(
        ProviderLoginMethod::ApiKey,
        ProviderLoginSupport::Supported,
        "xAI documents API-key authentication for API access.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::AuthorizationCodePkce,
        ProviderLoginSupport::Unsupported,
        "No provider-documented third-party xAI authorization-code grant is configured.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::DeviceCode,
        ProviderLoginSupport::Unsupported,
        "No provider-documented third-party xAI device grant is configured.",
    ),
];

const KIMI_CAPABILITIES: &[ProviderLoginCapability] = &[
    ProviderLoginCapability::new(
        ProviderLoginMethod::ApiKey,
        ProviderLoginSupport::Supported,
        "Kimi documents API-key setup for its coding and open-platform APIs.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::AuthorizationCodePkce,
        ProviderLoginSupport::Unsupported,
        "Kimi documents device-code login rather than a third-party authorization-code profile.",
    ),
    ProviderLoginCapability::new(
        ProviderLoginMethod::DeviceCode,
        ProviderLoginSupport::RequiresExplicitConfiguration,
        "Kimi documents a device-code flow, but reusable endpoints and a Pooler client registration are not published.",
    ),
];

const GOOGLE_OAUTH_DEFAULTS: ProviderOAuthDefaults = ProviderOAuthDefaults::none()
    .with_authorization_endpoint("https://accounts.google.com/o/oauth2/v2/auth")
    .with_token_endpoint("https://oauth2.googleapis.com/token")
    .with_revocation_endpoint("https://oauth2.googleapis.com/revoke");

const OPENAI_OAUTH_DEFAULTS: ProviderOAuthDefaults = ProviderOAuthDefaults::none()
    .with_client_id(CODEX_OAUTH_CLIENT_ID)
    .with_authorization_endpoint(CODEX_OAUTH_AUTHORIZATION_ENDPOINT)
    .with_token_endpoint(CODEX_OAUTH_TOKEN_ENDPOINT)
    .with_revocation_endpoint(CODEX_OAUTH_REVOCATION_ENDPOINT)
    .with_device_authorization_endpoint(CODEX_OAUTH_DEVICE_USERCODE_ENDPOINT)
    .with_authorization_parameters(CODEX_OAUTH_AUTHORIZE_PARAMETERS)
    .with_device_grant(DeviceAuthorizationGrant::CodexAccounts);

/// Verified provider login definitions. Declaration order is stable for CLI
/// and management presentation.
pub static BUILTIN_PROVIDER_LOGIN_DEFINITIONS: [ProviderLoginDefinition; 5] = [
    ProviderLoginDefinition::new(
        "openai",
        "OpenAI",
        "https://developers.openai.com/codex/auth",
    )
    .with_aliases(&["codex"])
    .with_api_key_environment_variables(&["OPENAI_API_KEY"])
    .with_oauth_host_suffixes(&["openai.com"])
    .with_oauth_defaults(OPENAI_OAUTH_DEFAULTS)
    .with_suggested_scopes(CODEX_OAUTH_SCOPE_LIST)
    .with_capabilities(OPENAI_CAPABILITIES),
    ProviderLoginDefinition::new(
        "anthropic",
        "Anthropic",
        "https://code.claude.com/docs/en/authentication",
    )
    .with_aliases(&["claude"])
    .with_api_key_environment_variables(&["ANTHROPIC_API_KEY"])
    .with_oauth_host_suffixes(&["anthropic.com"])
    .with_capabilities(ANTHROPIC_CAPABILITIES),
    ProviderLoginDefinition::new(
        "google",
        "Google",
        "https://ai.google.dev/gemini-api/docs/oauth",
    )
    .with_aliases(&["gemini"])
    .with_api_key_environment_variables(&["GEMINI_API_KEY", "GOOGLE_API_KEY"])
    .with_oauth_host_suffixes(&["google.com", "googleapis.com"])
    .with_capabilities(GOOGLE_CAPABILITIES)
    .with_oauth_defaults(GOOGLE_OAUTH_DEFAULTS)
    .with_suggested_scopes(&[
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/generative-language.retriever",
    ]),
    ProviderLoginDefinition::new("xai", "xAI", "https://docs.x.ai/developers/quickstart")
        .with_aliases(&["grok"])
        .with_api_key_environment_variables(&["XAI_API_KEY"])
        .with_oauth_host_suffixes(&["x.ai"])
        .with_capabilities(XAI_CAPABILITIES),
    ProviderLoginDefinition::new(
        "kimi",
        "Kimi",
        "https://www.kimi.com/resources/kimi-code-introduction",
    )
    .with_aliases(&["moonshot", "moonshot-ai"])
    .with_oauth_host_suffixes(&["kimi.com", "moonshot.cn"])
    .with_capabilities(KIMI_CAPABILITIES),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OAuthHttpRequest, OAuthProvider, OAuthState, OAuthTransportError, OAuthTransportFuture,
        PkcePair,
    };
    use tokio_util::sync::CancellationToken;

    struct NoopTransport;

    impl OAuthTransport for NoopTransport {
        fn send(
            &self,
            _request: OAuthHttpRequest,
            _cancellation: CancellationToken,
        ) -> OAuthTransportFuture<'_> {
            Box::pin(async { Err(OAuthTransportError::Failed) })
        }
    }

    fn loopback_redirect() -> Url {
        "http://127.0.0.1:1455/oauth/callback"
            .parse()
            .expect("loopback redirect")
    }

    fn google_settings() -> ProviderOAuthSettings {
        ProviderOAuthSettings::new("public-client-id", loopback_redirect()).with_scopes([
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/generative-language.retriever",
        ])
    }

    #[test]
    fn builtins_resolve_aliases_to_stable_canonical_ids() {
        let registry = ProviderLoginRegistry::builtin();
        for (alias, expected) in [
            ("CODEX", "openai"),
            ("claude", "anthropic"),
            ("Gemini", "google"),
            ("grok", "xai"),
            ("moonshot-ai", "kimi"),
        ] {
            assert_eq!(registry.require(alias).expect("provider").id(), expected);
        }
        assert_eq!(registry.definitions().len(), 5);
        assert!(registry.resolve("unknown").is_none());
        assert!(registry.resolve(" google ").is_none());
    }

    #[test]
    fn registry_rejects_case_insensitive_alias_collisions() {
        static COLLIDING: [ProviderLoginDefinition; 2] = [
            ProviderLoginDefinition::new("first", "First", "https://example.test/docs/first")
                .with_aliases(&["shared"]),
            ProviderLoginDefinition::new("second", "Second", "https://example.test/docs/second")
                .with_aliases(&["SHARED"]),
        ];
        assert_eq!(
            ProviderLoginRegistry::new(&COLLIDING).expect_err("alias collision"),
            ProviderLoginError::AliasCollision("shared".to_owned())
        );
    }

    #[test]
    fn openai_profile_builds_codex_login_from_first_party_defaults() {
        let openai = ProviderLoginRegistry::builtin()
            .require("codex")
            .expect("Codex");
        assert_eq!(
            openai.support(ProviderLoginMethod::AuthorizationCodePkce),
            ProviderLoginSupport::Supported
        );
        let provider = openai
            .build_oauth_provider(
                ProviderLoginMethod::AuthorizationCodePkce,
                ProviderOAuthSettings::new(String::new(), loopback_redirect()),
                Arc::new(NoopTransport),
            )
            .expect("Codex login should not need an operator-owned client");
        let attempt = provider
            .begin_authorization_with(
                OAuthState::new("state-value").expect("state"),
                PkcePair::from_verifier(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
                )
                .expect("PKCE"),
            )
            .expect("authorization attempt");
        let query = attempt
            .authorization_url()
            .query_pairs()
            .collect::<HashMap<_, _>>();
        assert_eq!(
            attempt.authorization_url().as_str().split('?').next(),
            Some(CODEX_OAUTH_AUTHORIZATION_ENDPOINT)
        );
        assert_eq!(
            query.get("client_id").map(AsRef::as_ref),
            Some(CODEX_OAUTH_CLIENT_ID)
        );
        assert_eq!(
            query.get("redirect_uri").map(AsRef::as_ref),
            Some("http://127.0.0.1:1455/oauth/callback")
        );
        assert_eq!(
            query.get("scope").map(AsRef::as_ref),
            Some(CODEX_OAUTH_SCOPES)
        );
        assert_eq!(
            query.get("id_token_add_organizations").map(AsRef::as_ref),
            Some("true")
        );
        assert_eq!(
            query.get("codex_cli_simplified_flow").map(AsRef::as_ref),
            Some("true")
        );
        assert_eq!(
            query.get("originator").map(AsRef::as_ref),
            Some(CODEX_OAUTH_ORIGINATOR)
        );
        assert!(!query.contains_key("client_secret"));
    }

    #[test]
    fn openai_profile_enables_codex_device_code_login() {
        let openai = ProviderLoginRegistry::builtin()
            .require("codex")
            .expect("Codex");
        assert_eq!(
            openai.support(ProviderLoginMethod::DeviceCode),
            ProviderLoginSupport::Supported
        );
        let config = openai
            .build_oauth_config(
                ProviderLoginMethod::DeviceCode,
                ProviderOAuthSettings::new(String::new(), loopback_redirect()),
            )
            .expect("Codex device login should not need an operator-owned client");
        assert_eq!(config.device_grant, DeviceAuthorizationGrant::CodexAccounts);
        assert_eq!(
            config
                .device_authorization_endpoint
                .as_ref()
                .map(Url::as_str),
            Some(CODEX_OAUTH_DEVICE_USERCODE_ENDPOINT)
        );
        assert_eq!(config.client_id, CODEX_OAUTH_CLIENT_ID);
        assert_eq!(config.token_endpoint.as_str(), CODEX_OAUTH_TOKEN_ENDPOINT);
    }

    #[test]
    fn support_matrix_does_not_claim_undocumented_subscription_flows() {
        let registry = ProviderLoginRegistry::builtin();
        let openai = registry.require("openai").expect("OpenAI");
        assert_eq!(
            openai.support(ProviderLoginMethod::AuthorizationCodePkce),
            ProviderLoginSupport::Supported
        );
        assert_eq!(
            openai.support(ProviderLoginMethod::DeviceCode),
            ProviderLoginSupport::Supported
        );

        let anthropic = registry.require("anthropic").expect("Anthropic");
        assert_eq!(
            anthropic.support(ProviderLoginMethod::AuthorizationCodePkce),
            ProviderLoginSupport::Unsupported
        );

        let google = registry.require("google").expect("Google");
        assert_eq!(
            google.support(ProviderLoginMethod::AuthorizationCodePkce),
            ProviderLoginSupport::Supported
        );
        assert_eq!(
            google.support(ProviderLoginMethod::DeviceCode),
            ProviderLoginSupport::Unsupported
        );

        let xai = registry.require("xai").expect("xAI");
        assert_eq!(
            xai.support(ProviderLoginMethod::AuthorizationCodePkce),
            ProviderLoginSupport::Unsupported
        );

        let kimi = registry.require("kimi").expect("Kimi");
        assert_eq!(
            kimi.support(ProviderLoginMethod::DeviceCode),
            ProviderLoginSupport::RequiresExplicitConfiguration
        );

        for provider in registry.definitions() {
            assert_eq!(
                provider.support(ProviderLoginMethod::ApiKey),
                ProviderLoginSupport::Supported
            );
        }
    }

    #[test]
    fn google_profile_builds_a_stateful_s256_pkce_attempt() {
        let definition = ProviderLoginRegistry::builtin()
            .require("gemini")
            .expect("Gemini");
        let provider = definition
            .build_oauth_provider(
                ProviderLoginMethod::AuthorizationCodePkce,
                google_settings(),
                Arc::new(NoopTransport),
            )
            .expect("provider");
        let pkce = PkcePair::from_verifier(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        .expect("PKCE");
        let attempt = provider
            .begin_authorization_with(OAuthState::new("state-value").expect("state"), pkce)
            .expect("authorization attempt");
        let query = attempt
            .authorization_url()
            .query_pairs()
            .collect::<HashMap<_, _>>();
        assert_eq!(
            attempt.authorization_url().as_str().split('?').next(),
            Some("https://accounts.google.com/o/oauth2/v2/auth")
        );
        assert_eq!(query.get("response_type").map(AsRef::as_ref), Some("code"));
        assert_eq!(
            query.get("code_challenge_method").map(AsRef::as_ref),
            Some("S256")
        );
        assert_eq!(query.get("state").map(AsRef::as_ref), Some("state-value"));
        assert!(query.contains_key("code_challenge"));
        assert!(!query.contains_key("client_secret"));
    }

    #[test]
    fn proprietary_flows_require_complete_explicit_configuration() {
        let registry = ProviderLoginRegistry::builtin();
        let kimi = registry.require("kimi").expect("Kimi");
        assert_eq!(
            kimi.build_oauth_config(
                ProviderLoginMethod::DeviceCode,
                ProviderOAuthSettings::new("registered-client", loopback_redirect())
                    .with_scopes(["explicit-scope"]),
            )
            .expect_err("explicit endpoints"),
            ProviderLoginError::ExplicitConfigurationRequired {
                provider: "kimi",
                method: ProviderLoginMethod::DeviceCode,
            }
        );
    }

    #[test]
    fn explicit_kimi_device_configuration_mounts_on_generic_oauth_contract() {
        let kimi = ProviderLoginRegistry::builtin()
            .require("kimi")
            .expect("Kimi");
        let settings = ProviderOAuthSettings::new("registered-client", loopback_redirect())
            .with_scopes(["explicit-scope"])
            .with_authorization_endpoint(
                "https://auth.kimi.com/authorize"
                    .parse()
                    .expect("authorization endpoint"),
            )
            .with_token_endpoint(
                "https://auth.kimi.com/token"
                    .parse()
                    .expect("token endpoint"),
            )
            .with_device_authorization_endpoint(
                "https://auth.kimi.com/device"
                    .parse()
                    .expect("device endpoint"),
            );
        let config = kimi
            .build_oauth_config(ProviderLoginMethod::DeviceCode, settings.clone())
            .expect("explicit device configuration");
        assert_eq!(
            config
                .device_authorization_endpoint
                .as_ref()
                .map(Url::as_str),
            Some("https://auth.kimi.com/device")
        );
        let client = kimi
            .build_oauth_provider(
                ProviderLoginMethod::DeviceCode,
                settings,
                Arc::new(NoopTransport),
            )
            .expect("device client");
        assert_eq!(client.login_method(), ProviderLoginMethod::DeviceCode);
        assert_eq!(client.begin_authorization(), Err(OAuthError::Unsupported));
    }

    #[test]
    fn provider_profile_rejects_unsafe_redirects() {
        let google = ProviderLoginRegistry::builtin()
            .require("google")
            .expect("Google");
        for redirect in [
            "https://example.test/callback",
            "http://192.0.2.1:1455/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:1455/callback?code=value",
            "http://user@127.0.0.1:1455/callback",
        ] {
            let error = google
                .build_oauth_config(
                    ProviderLoginMethod::AuthorizationCodePkce,
                    ProviderOAuthSettings::new(
                        "public-client",
                        redirect.parse().expect("test redirect"),
                    )
                    .with_scopes(["explicit-scope"]),
                )
                .expect_err("unsafe redirect");
            assert_eq!(error, ProviderLoginError::UnsafeRedirect);
        }
    }

    #[test]
    fn provider_profile_rejects_unsafe_endpoint_overrides() {
        let google = ProviderLoginRegistry::builtin()
            .require("google")
            .expect("Google");
        for endpoint in [
            "http://identity.example.test/authorize",
            "https://user@identity.example.test/authorize",
            "https://identity.example.test/authorize?value=embedded",
            "https://identity.example.test/authorize#fragment",
        ] {
            let error = google
                .build_oauth_config(
                    ProviderLoginMethod::AuthorizationCodePkce,
                    google_settings()
                        .with_authorization_endpoint(endpoint.parse().expect("test endpoint")),
                )
                .expect_err("unsafe endpoint");
            assert_eq!(
                error,
                ProviderLoginError::UnsafeEndpoint(OAuthEndpointKind::Authorization)
            );
        }
    }

    #[test]
    fn provider_settings_debug_never_renders_operator_values() {
        let settings = ProviderOAuthSettings::new(
            "sentinel-client-material",
            "http://127.0.0.1:1455/callback?sentinel-redirect-material"
                .parse()
                .expect("redirect"),
        )
        .with_scopes(["sentinel-scope-material"])
        .with_authorization_endpoint(
            "https://identity.example.test/authorize?sentinel-endpoint-material"
                .parse()
                .expect("endpoint"),
        );
        let rendered = format!("{settings:?}");
        for sentinel in [
            "sentinel-client-material",
            "sentinel-redirect-material",
            "sentinel-scope-material",
            "sentinel-endpoint-material",
        ] {
            assert!(!rendered.contains(sentinel));
        }
        assert!(rendered.contains("scope_count"));
        assert!(rendered.contains("authorization_endpoint_configured"));
    }

    #[test]
    fn duplicate_or_empty_scopes_are_rejected_without_echoing_them() {
        let google = ProviderLoginRegistry::builtin()
            .require("google")
            .expect("Google");
        for scopes in [vec![], vec!["duplicate", "duplicate"], vec!["two words"]] {
            let error = google
                .build_oauth_config(
                    ProviderLoginMethod::AuthorizationCodePkce,
                    ProviderOAuthSettings::new("public-client", loopback_redirect())
                        .with_scopes(scopes),
                )
                .expect_err("invalid scopes");
            assert_eq!(error, ProviderLoginError::InvalidScopes);
            assert!(!error.to_string().contains("duplicate"));
            assert!(!error.to_string().contains("two words"));
        }
    }

    #[test]
    fn api_key_and_unsupported_flows_cannot_build_oauth_clients() {
        let registry = ProviderLoginRegistry::builtin();
        let google = registry.require("google").expect("Google");
        assert_eq!(
            google
                .build_oauth_config(ProviderLoginMethod::ApiKey, google_settings())
                .expect_err("API key is not OAuth"),
            ProviderLoginError::NotOAuthMethod
        );

        let anthropic = registry.require("claude").expect("Claude");
        assert_eq!(
            anthropic
                .build_oauth_config(
                    ProviderLoginMethod::AuthorizationCodePkce,
                    google_settings(),
                )
                .expect_err("unsupported flow"),
            ProviderLoginError::Unsupported {
                provider: "anthropic",
                method: ProviderLoginMethod::AuthorizationCodePkce,
            }
        );
    }

    #[test]
    fn built_in_profiles_reject_unlisted_and_non_dns_endpoint_hosts() {
        let google = ProviderLoginRegistry::builtin()
            .require("google")
            .expect("Google");
        for endpoint in [
            "https://notgoogleapis.com/authorize",
            "https://attacker.example/authorize",
            "https://127.0.0.1/authorize",
            "https://169.254.169.254/authorize",
            "https://10.0.0.1/authorize",
            "https://[::1]/authorize",
        ] {
            let error = google
                .build_oauth_config(
                    ProviderLoginMethod::AuthorizationCodePkce,
                    google_settings()
                        .with_authorization_endpoint(endpoint.parse().expect("test endpoint"))
                        .dangerously_allow_custom_endpoint_hosts(),
                )
                .expect_err("built-in allowlist must be unbypassable");
            assert_eq!(error, ProviderLoginError::EndpointHostNotAllowed);
        }
    }

    #[test]
    fn custom_profile_requires_an_explicit_endpoint_trust_boundary() {
        let custom =
            ProviderLoginDefinition::new("custom", "Custom", "https://operator.example/docs")
                .with_capabilities(GOOGLE_CAPABILITIES);
        let settings = ProviderOAuthSettings::new("public-client", loopback_redirect())
            .with_scopes(["scope"])
            .with_authorization_endpoint(
                "https://identity.operator.example/authorize"
                    .parse()
                    .expect("authorization endpoint"),
            )
            .with_token_endpoint(
                "https://identity.operator.example/token"
                    .parse()
                    .expect("token endpoint"),
            );
        assert_eq!(
            custom
                .build_oauth_config(ProviderLoginMethod::AuthorizationCodePkce, settings.clone(),)
                .expect_err("custom host trust must be explicit"),
            ProviderLoginError::CustomEndpointTrustRequired
        );
        custom
            .build_oauth_config(
                ProviderLoginMethod::AuthorizationCodePkce,
                settings.dangerously_allow_custom_endpoint_hosts(),
            )
            .expect("explicitly trusted custom endpoints");
    }

    #[test]
    fn provider_oauth_inputs_have_hard_non_echoing_limits() {
        let google = ProviderLoginRegistry::builtin()
            .require("google")
            .expect("Google");
        let oversized_inputs = [
            ProviderOAuthSettings::new("x".repeat(MAX_CLIENT_ID_BYTES + 1), loopback_redirect())
                .with_scopes(["scope"]),
            ProviderOAuthSettings::new("client", loopback_redirect())
                .with_scopes((0..=MAX_SCOPE_COUNT).map(|index| format!("scope-{index}"))),
            ProviderOAuthSettings::new("client", loopback_redirect())
                .with_scopes(["x".repeat(MAX_SCOPE_BYTES + 1)]),
            ProviderOAuthSettings::new("client", loopback_redirect())
                .with_scopes((0..9).map(|index| format!("{index}{}", "x".repeat(500)))),
        ];
        for settings in oversized_inputs {
            let error = google
                .build_oauth_config(ProviderLoginMethod::AuthorizationCodePkce, settings)
                .expect_err("input limit");
            assert_eq!(error, ProviderLoginError::InputLimitExceeded);
            assert!(!error.to_string().contains("xxxx"));
        }
    }

    #[test]
    fn generated_pkce_attempt_uses_core_provider_contract() {
        let google = ProviderLoginRegistry::builtin()
            .require("google")
            .expect("Google");
        let provider = google
            .build_oauth_provider(
                ProviderLoginMethod::AuthorizationCodePkce,
                google_settings(),
                Arc::new(NoopTransport),
            )
            .expect("provider");
        let attempt = provider
            .begin_authorization()
            .expect("authorization attempt");
        assert_eq!(
            attempt
                .authorization_url()
                .query_pairs()
                .find(|(name, _)| name == "code_challenge_method")
                .map(|(_, value)| value.into_owned()),
            Some("S256".to_owned())
        );
        assert!(!format!("{attempt:?}").contains("state="));
    }
}
