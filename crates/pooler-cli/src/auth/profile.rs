use std::fmt;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use pooler_auth::{
    AuthorizationAttempt, HyperOAuthTransport, OAuthClientConfig, OAuthCodeExchange,
    OAuthDeviceFlow, OAuthIdentityProvider, OAuthProvider, OAuthState, PkcePair,
    ProviderLoginDefinition, ProviderLoginMethod, ProviderLoginRegistry, ProviderLoginSupport,
    ProviderOAuthClient, ProviderOAuthSettings, StandardOAuthProvider,
};
use pooler_config::{CompiledConfig, OAuthPlan};
use url::Url;

use super::{require_response_state, AuthLoginMethod, OAuthEncodingArgument, OAuthOverrideArgs};

pub(super) fn selected_profile(
    registry: &ProviderLoginRegistry,
    provider: &str,
    requested_profile: Option<&str>,
) -> Result<Option<&'static ProviderLoginDefinition>> {
    match requested_profile {
        Some(profile) => registry
            .require(profile)
            .map(Some)
            .context("unknown provider login profile"),
        None => Ok(registry.resolve(provider)),
    }
}

pub(super) fn validate_login_method(
    profile: Option<&ProviderLoginDefinition>,
    method: AuthLoginMethod,
    expected_state: Option<&str>,
    response: Option<&str>,
    overrides: &OAuthOverrideArgs,
) -> Result<()> {
    match method {
        AuthLoginMethod::AuthorizationCodePkce => {
            require_response_state(response, expected_state)?;
        }
        AuthLoginMethod::DeviceCode => {
            if expected_state.is_some() || response.is_some() {
                bail!("device-code login does not accept --state or --response");
            }
        }
        AuthLoginMethod::ApiKey => {
            if expected_state.is_some() || response.is_some() || overrides.any_explicit_value() {
                bail!("API-key guidance does not accept OAuth options");
            }
        }
    }

    let Some(profile) = profile else {
        return Ok(());
    };
    let provider_method = ProviderLoginMethod::from(method);
    match profile.support(provider_method) {
        ProviderLoginSupport::Supported | ProviderLoginSupport::RequiresExplicitConfiguration => {
            Ok(())
        }
        ProviderLoginSupport::Unsupported => {
            let note = profile
                .capability(provider_method)
                .map(|capability| capability.note())
                .unwrap_or("This login flow is not supported.");
            if method == AuthLoginMethod::ApiKey {
                bail!(
                    "{} does not support API-key login. {note}",
                    profile.display_name()
                );
            }
            bail!(
                "{} does not support {} login. {note} {}",
                profile.display_name(),
                method_label(method),
                api_key_guidance(Some(profile))
            );
        }
    }
}

fn method_label(method: AuthLoginMethod) -> &'static str {
    match method {
        AuthLoginMethod::AuthorizationCodePkce => "OAuth authorization-code",
        AuthLoginMethod::DeviceCode => "OAuth device-code",
        AuthLoginMethod::ApiKey => "API-key",
    }
}

pub(super) fn configured_provider_id(
    config: &CompiledConfig,
    requested: &str,
    profile: Option<&ProviderLoginDefinition>,
    profile_was_explicit: bool,
) -> Result<String> {
    if config.upstreams().contains_key(requested) {
        return Ok(requested.to_owned());
    }
    if !profile_was_explicit {
        if let Some(profile) = profile {
            for candidate in std::iter::once(profile.id()).chain(profile.aliases().iter().copied())
            {
                if config.upstreams().contains_key(candidate) {
                    return Ok(candidate.to_owned());
                }
            }
        }
    }
    bail!("provider `{requested}` is not configured")
}

const MAX_OAUTH_CLIENT_ID_BYTES: usize = 512;
const MAX_OAUTH_SCOPE_COUNT: usize = 32;
const MAX_OAUTH_SCOPE_BYTES: usize = 512;
const MAX_OAUTH_SCOPE_TOTAL_BYTES: usize = 4 * 1024;
const MAX_OAUTH_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_OAUTH_OVERRIDE_TOTAL_BYTES: usize = 16 * 1024;

pub(super) struct ResolvedOAuthSettings {
    client_id: String,
    callback: Url,
    scopes: Vec<String>,
    authorization_endpoint: Option<Url>,
    token_endpoint: Option<Url>,
    device_authorization_endpoint: Option<Url>,
    revocation_endpoint: Option<Url>,
    identity_endpoint: Option<Url>,
    request_encoding: OAuthEncodingArgument,
}

impl fmt::Debug for ResolvedOAuthSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedOAuthSettings")
            .field("client_id", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
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
            .finish_non_exhaustive()
    }
}

impl ResolvedOAuthSettings {
    pub(super) fn new(
        oauth: &OAuthPlan,
        callback: Url,
        overrides: &OAuthOverrideArgs,
        profile: Option<&ProviderLoginDefinition>,
    ) -> Result<Self> {
        validate_override_budget(overrides)?;
        if profile.is_some() && overrides.dangerously_allow_custom_oauth_endpoints {
            bail!("the custom-provider endpoint override cannot bypass a built-in profile");
        }
        if profile.is_none()
            && overrides.any_endpoint_override()
            && !overrides.dangerously_allow_custom_oauth_endpoints
        {
            bail!(
                "custom-provider endpoint overrides require --dangerously-allow-custom-oauth-endpoints"
            );
        }

        let client_id = overrides
            .client_id
            .clone()
            .unwrap_or_else(|| oauth.client_id().to_owned());
        let scopes = if overrides.scopes.is_empty() {
            oauth.scopes().iter().map(ToString::to_string).collect()
        } else {
            overrides.scopes.clone()
        };
        validate_client_and_scopes(&client_id, &scopes)?;

        Ok(Self {
            client_id,
            callback,
            scopes,
            authorization_endpoint: Some(endpoint_override(
                overrides.authorization_endpoint.as_deref(),
                oauth.authorization_endpoint(),
                "authorization",
            )?),
            token_endpoint: Some(endpoint_override(
                overrides.token_endpoint.as_deref(),
                oauth.token_endpoint(),
                "token",
            )?),
            device_authorization_endpoint: optional_endpoint_override(
                overrides.device_authorization_endpoint.as_deref(),
                None,
                "device authorization",
            )?,
            revocation_endpoint: optional_endpoint_override(
                overrides.revocation_endpoint.as_deref(),
                oauth.revocation_endpoint(),
                "revocation",
            )?,
            identity_endpoint: optional_endpoint_override(
                overrides.identity_endpoint.as_deref(),
                oauth.identity_endpoint(),
                "identity",
            )?,
            request_encoding: overrides.request_encoding,
        })
    }

    pub(super) fn from_cli_overrides(callback: Url, overrides: &OAuthOverrideArgs) -> Result<Self> {
        validate_override_budget(overrides)?;
        if overrides.dangerously_allow_custom_oauth_endpoints {
            bail!("the custom-provider endpoint override cannot bypass a built-in profile");
        }
        Ok(Self {
            client_id: overrides.client_id.clone().unwrap_or_default(),
            callback,
            scopes: overrides.scopes.clone(),
            authorization_endpoint: optional_endpoint_override(
                overrides.authorization_endpoint.as_deref(),
                None,
                "authorization",
            )?,
            token_endpoint: optional_endpoint_override(
                overrides.token_endpoint.as_deref(),
                None,
                "token",
            )?,
            device_authorization_endpoint: optional_endpoint_override(
                overrides.device_authorization_endpoint.as_deref(),
                None,
                "device authorization",
            )?,
            revocation_endpoint: optional_endpoint_override(
                overrides.revocation_endpoint.as_deref(),
                None,
                "revocation",
            )?,
            identity_endpoint: optional_endpoint_override(
                overrides.identity_endpoint.as_deref(),
                None,
                "identity",
            )?,
            request_encoding: overrides.request_encoding,
        })
    }

    fn standard_config(&self, method: AuthLoginMethod) -> Result<OAuthClientConfig> {
        if method == AuthLoginMethod::DeviceCode && self.device_authorization_endpoint.is_none() {
            bail!("OAuth device authorization endpoint is required");
        }
        let authorization = self
            .authorization_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OAuth authorization endpoint is required"))?;
        let token = self
            .token_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OAuth token endpoint is required"))?;
        let mut config = OAuthClientConfig::new(
            self.client_id.clone(),
            self.callback.clone(),
            authorization.clone(),
            token.clone(),
        )?
        .with_scopes(self.scopes.clone());
        if let Some(endpoint) = &self.device_authorization_endpoint {
            config = config.with_device_authorization_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = &self.revocation_endpoint {
            config = config.with_revocation_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = &self.identity_endpoint {
            config = config.with_identity_endpoint(endpoint.clone());
        }
        if self.request_encoding == OAuthEncodingArgument::Json {
            config = config.with_json_requests();
        }
        config.validate().map_err(Into::into)
    }

    fn provider_settings(&self) -> ProviderOAuthSettings {
        let mut settings =
            ProviderOAuthSettings::new(self.client_id.clone(), self.callback.clone())
                .with_scopes(self.scopes.clone());
        if let Some(endpoint) = &self.authorization_endpoint {
            settings = settings.with_authorization_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = &self.token_endpoint {
            settings = settings.with_token_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = &self.device_authorization_endpoint {
            settings = settings.with_device_authorization_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = &self.revocation_endpoint {
            settings = settings.with_revocation_endpoint(endpoint.clone());
        }
        if let Some(endpoint) = &self.identity_endpoint {
            settings = settings.with_identity_endpoint(endpoint.clone());
        }
        if self.request_encoding == OAuthEncodingArgument::Json {
            settings = settings.with_json_requests();
        }
        settings
    }
}

fn validate_override_budget(overrides: &OAuthOverrideArgs) -> Result<()> {
    if overrides
        .client_id
        .as_ref()
        .is_some_and(|value| value.len() > MAX_OAUTH_CLIENT_ID_BYTES)
        || overrides.scopes.len() > MAX_OAUTH_SCOPE_COUNT
    {
        bail!("OAuth override input exceeds its size limit");
    }
    let endpoint_bytes = [
        overrides.authorization_endpoint.as_deref(),
        overrides.token_endpoint.as_deref(),
        overrides.device_authorization_endpoint.as_deref(),
        overrides.revocation_endpoint.as_deref(),
        overrides.identity_endpoint.as_deref(),
    ]
    .into_iter()
    .flatten()
    .try_fold(0_usize, |total, endpoint| {
        if endpoint.len() > MAX_OAUTH_ENDPOINT_BYTES {
            bail!("OAuth endpoint override exceeds its size limit");
        }
        total
            .checked_add(endpoint.len())
            .ok_or_else(|| anyhow::anyhow!("OAuth override input exceeds its total size limit"))
    })?;
    let scope_bytes = overrides.scopes.iter().try_fold(0_usize, |total, scope| {
        total
            .checked_add(scope.len())
            .ok_or_else(|| anyhow::anyhow!("OAuth override input exceeds its total size limit"))
    })?;
    let total = overrides
        .client_id
        .as_ref()
        .map_or(0, String::len)
        .checked_add(scope_bytes)
        .and_then(|total| total.checked_add(endpoint_bytes))
        .ok_or_else(|| anyhow::anyhow!("OAuth override input exceeds its total size limit"))?;
    if total > MAX_OAUTH_OVERRIDE_TOTAL_BYTES {
        bail!("OAuth override input exceeds its total size limit");
    }
    Ok(())
}

pub(super) fn validate_client_and_scopes(client_id: &str, scopes: &[String]) -> Result<()> {
    if client_id.is_empty()
        || client_id.len() > MAX_OAUTH_CLIENT_ID_BYTES
        || client_id.chars().any(char::is_whitespace)
        || client_id.chars().any(char::is_control)
    {
        bail!("OAuth client identifier is invalid or exceeds its size limit");
    }
    if scopes.is_empty() || scopes.len() > MAX_OAUTH_SCOPE_COUNT {
        bail!("OAuth scope count is outside the supported limit");
    }
    let mut total = 0_usize;
    let mut unique = std::collections::HashSet::with_capacity(scopes.len());
    for scope in scopes {
        total = total
            .checked_add(scope.len())
            .ok_or_else(|| anyhow::anyhow!("OAuth scopes exceed their total size limit"))?;
        if scope.is_empty()
            || scope.len() > MAX_OAUTH_SCOPE_BYTES
            || scope.chars().any(char::is_whitespace)
            || scope.chars().any(char::is_control)
            || !unique.insert(scope.as_str())
        {
            bail!("OAuth scopes are invalid or exceed their size limits");
        }
    }
    if total > MAX_OAUTH_SCOPE_TOTAL_BYTES {
        bail!("OAuth scopes exceed their total size limit");
    }
    Ok(())
}

fn endpoint_override(value: Option<&str>, fallback: &Url, label: &str) -> Result<Url> {
    optional_endpoint_override(value, Some(fallback), label)?
        .ok_or_else(|| anyhow::anyhow!("OAuth {label} endpoint is required"))
}

fn optional_endpoint_override(
    value: Option<&str>,
    fallback: Option<&Url>,
    label: &str,
) -> Result<Option<Url>> {
    let Some(value) = value else {
        return Ok(fallback.cloned());
    };
    let endpoint =
        Url::parse(value).with_context(|| format!("OAuth {label} endpoint is invalid"))?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("OAuth {label} endpoint override is unsafe");
    }
    Ok(Some(endpoint))
}

pub(super) trait LoginOAuthProvider:
    OAuthProvider + OAuthCodeExchange + OAuthDeviceFlow + OAuthIdentityProvider
{
    fn begin_authorization_with_cli(
        &self,
        state: OAuthState,
        pkce: PkcePair,
    ) -> Result<AuthorizationAttempt, pooler_auth::OAuthError>;

    fn identity_endpoint_configured(&self) -> bool;
}

impl LoginOAuthProvider for StandardOAuthProvider {
    fn begin_authorization_with_cli(
        &self,
        state: OAuthState,
        pkce: PkcePair,
    ) -> Result<AuthorizationAttempt, pooler_auth::OAuthError> {
        self.begin_authorization_with(state, pkce)
    }

    fn identity_endpoint_configured(&self) -> bool {
        self.config().identity_endpoint.is_some()
    }
}

impl LoginOAuthProvider for ProviderOAuthClient {
    fn begin_authorization_with_cli(
        &self,
        state: OAuthState,
        pkce: PkcePair,
    ) -> Result<AuthorizationAttempt, pooler_auth::OAuthError> {
        self.begin_authorization_with(state, pkce)
    }

    fn identity_endpoint_configured(&self) -> bool {
        self.config().identity_endpoint.is_some()
    }
}

pub(super) fn build_login_provider(
    provider_id: &str,
    profile: Option<&ProviderLoginDefinition>,
    method: AuthLoginMethod,
    settings: &ResolvedOAuthSettings,
) -> Result<Box<dyn LoginOAuthProvider>> {
    let transport = Arc::new(HyperOAuthTransport::new(64 * 1024)?);
    match profile {
        Some(profile) => profile
            .build_oauth_provider(method.into(), settings.provider_settings(), transport)
            .map(|provider| Box::new(provider) as Box<dyn LoginOAuthProvider>)
            .map_err(Into::into),
        None => StandardOAuthProvider::new(
            provider_id.to_owned(),
            settings.standard_config(method)?,
            transport,
        )
        .map(|provider| Box::new(provider) as Box<dyn LoginOAuthProvider>)
        .map_err(Into::into),
    }
}

pub(super) fn providers(profile: Option<&str>) -> Result<()> {
    let registry = ProviderLoginRegistry::builtin();
    if let Some(profile) = profile {
        let definition = registry
            .require(profile)
            .context("unknown provider login profile")?;
        print!("{}", render_provider_support(definition));
        return Ok(());
    }
    for definition in registry.definitions() {
        print!("{}", render_provider_support(definition));
    }
    Ok(())
}

pub(super) fn render_provider_support(profile: &ProviderLoginDefinition) -> String {
    let aliases = if profile.aliases().is_empty() {
        "none".to_owned()
    } else {
        profile.aliases().join(",")
    };
    let api_key_environment = if profile.api_key_environment_variables().is_empty() {
        "none".to_owned()
    } else {
        profile.api_key_environment_variables().join(",")
    };
    let mut output = format!(
        "provider={} name={} aliases={} api_key_env={}\n",
        profile.id(),
        profile.display_name(),
        aliases,
        api_key_environment
    );
    for method in [
        ProviderLoginMethod::ApiKey,
        ProviderLoginMethod::AuthorizationCodePkce,
        ProviderLoginMethod::DeviceCode,
    ] {
        let support = support_label(profile.support(method));
        let note = profile
            .capability(method)
            .map(|capability| capability.note())
            .unwrap_or("This login flow is not supported.");
        output.push_str(&format!(
            "  method={method} support={support} note={note}\n"
        ));
    }
    output.push_str(&format!("  docs={}\n", profile.documentation_url()));
    output
}

fn support_label(support: ProviderLoginSupport) -> &'static str {
    match support {
        ProviderLoginSupport::Supported => "supported",
        ProviderLoginSupport::RequiresExplicitConfiguration => "requires_explicit_configuration",
        ProviderLoginSupport::Unsupported => "unsupported",
    }
}

pub(super) fn api_key_guidance(profile: Option<&ProviderLoginDefinition>) -> String {
    let Some(profile) = profile else {
        return "Pooler never accepts API keys on the command line. Configure the custom upstream auth.secret with an env:, file:, or keyring: reference."
            .to_owned();
    };
    let source = profile.api_key_environment_variables().first().map_or_else(
        || "an env:, file:, or keyring: secret reference".to_owned(),
        |variable| format!("env:{variable}"),
    );
    format!(
        "Use an API key through upstream auth.secret={source}; Pooler never accepts API keys on the command line. See {}",
        profile.documentation_url()
    )
}

pub(super) fn provider_filter_matches(
    registry: &ProviderLoginRegistry,
    filter: &str,
    candidate: &str,
) -> bool {
    if filter == candidate {
        return true;
    }
    match (registry.resolve(filter), registry.resolve(candidate)) {
        (Some(expected), Some(actual)) => expected.id() == actual.id(),
        _ => false,
    }
}

#[cfg(test)]
pub(super) const TEST_MAX_OAUTH_CLIENT_ID_BYTES: usize = MAX_OAUTH_CLIENT_ID_BYTES;

#[cfg(test)]
pub(super) const TEST_MAX_OAUTH_SCOPE_COUNT: usize = MAX_OAUTH_SCOPE_COUNT;
