//! Provider endpoint and short-lived authorization materialization.

use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use http::{header, HeaderMap, HeaderName, HeaderValue};
use pooler_auth::SecretValue;
use pooler_core::{IdentifierError, ProviderId};
use pooler_policy::FailureClassification;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::{
    antigravity_compatibility_profile, kimi_coding_profile, kimi_open_platform_profile,
    openai_compatible_profile, vertex_profile, ProviderKind, ProviderOperation, ProviderProfile,
    ProviderResponseClassifier,
};

/// Errors raised before a provider request is sent.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AdapterError {
    /// A configured provider URL is malformed or unsafe for path construction.
    #[error("provider base URL is invalid")]
    InvalidBaseUrl,
    /// A built-in adapter override points outside the provider-owned host allow-list.
    #[error("provider endpoint host is outside the built-in allow-list")]
    ProviderHostNotAllowed,
    /// A credential-bearing endpoint resolves directly to a local or special-use address.
    #[error("provider endpoint targets a forbidden local or special-use address")]
    ForbiddenNetworkTarget,
    /// An override path is ambiguous or contains URL metacharacters.
    #[error("provider endpoint override path is invalid")]
    InvalidOverridePath,
    /// A provider, project, location, publisher, or model identifier is invalid.
    #[error("provider identifier is invalid: {field}")]
    InvalidIdentifier { field: &'static str },
    /// A requested endpoint is not established for this provider surface.
    #[error("provider operation {operation:?} is unsupported")]
    UnsupportedOperation { operation: ProviderOperation },
    /// Antigravity's pinned internal contract was not explicitly enabled.
    #[error("Antigravity compatibility profile requires explicit opt-in")]
    CompatibilityNotEnabled,
    /// A provider credential is empty or cannot be represented as an HTTP header.
    #[error("provider authorization material is invalid")]
    InvalidAuthorization,
    /// A configured custom authentication header name is invalid.
    #[error("provider authentication header name is invalid")]
    InvalidHeaderName,
}

/// Explicit acknowledgement required before a built-in adapter targets an unrelated public host.
///
/// This boundary never permits loopback, private, link-local, multicast, or
/// other special-use IP targets. It only relaxes the provider-owned DNS allow-list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DangerousCustomEndpoint(());

impl DangerousCustomEndpoint {
    /// Acknowledge that provider credentials will be sent to an unrelated public HTTPS host.
    #[must_use]
    pub const fn acknowledge_risk() -> Self {
        Self(())
    }
}

impl From<IdentifierError> for AdapterError {
    fn from(_: IdentifierError) -> Self {
        Self::InvalidIdentifier {
            field: "provider_id",
        }
    }
}

/// Where short-lived credential material is placed on an outbound request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthPlacement {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// A caller-selected header and non-secret prefix.
    Header {
        name: HeaderName,
        value_prefix: String,
    },
    /// No credential header. Intended for explicitly unauthenticated local services.
    None,
}

impl AuthPlacement {
    /// Resolve one strict configured provider authentication kind.
    pub fn from_configured_kind(kind: &str) -> Result<Self, AdapterError> {
        Self::from_configured_parts(kind, None, None)
    }

    /// Resolve a configured authentication kind together with the header name
    /// and prefix that `kind: header` supplies.
    ///
    /// The named kinds stay as shorthands for the headers providers converged
    /// on. A provider that names its own credential header is configuration
    /// rather than a new shorthand.
    pub fn from_configured_parts(
        kind: &str,
        header: Option<&str>,
        value_prefix: Option<&str>,
    ) -> Result<Self, AdapterError> {
        match kind.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "bearer" | "bearer_secret" => Ok(Self::Bearer),
            "x_api_key" => Self::custom("x-api-key", ""),
            "x_goog_api_key" => Self::custom("x-goog-api-key", ""),
            "header" => Self::custom(
                header.ok_or(AdapterError::InvalidAuthorization)?,
                value_prefix.unwrap_or_default(),
            ),
            _ => Err(AdapterError::InvalidAuthorization),
        }
    }

    /// Construct a custom header placement after validating its name and prefix.
    pub fn custom(name: &str, value_prefix: impl Into<String>) -> Result<Self, AdapterError> {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| AdapterError::InvalidHeaderName)?;
        let value_prefix = value_prefix.into();
        if value_prefix.contains(['\r', '\n']) {
            return Err(AdapterError::InvalidAuthorization);
        }
        Ok(Self::Header { name, value_prefix })
    }

    /// Materialize one secret into a redacted outbound authorization value.
    pub fn materialize(&self, secret: &SecretValue) -> Result<ProviderAuthorization, AdapterError> {
        if matches!(self, Self::None) {
            return Ok(ProviderAuthorization { header: None });
        }
        if secret.is_empty() {
            return Err(AdapterError::InvalidAuthorization);
        }
        let (name, prefix) = match self {
            Self::Bearer => (header::AUTHORIZATION, "Bearer "),
            Self::Header { name, value_prefix } => (name.clone(), value_prefix.as_str()),
            Self::None => unreachable!("handled above"),
        };
        let mut raw = Zeroizing::new(Vec::with_capacity(
            prefix.len().saturating_add(secret.len()),
        ));
        raw.extend_from_slice(prefix.as_bytes());
        raw.extend_from_slice(secret.expose_bytes());
        let mut value =
            HeaderValue::from_bytes(&raw).map_err(|_| AdapterError::InvalidAuthorization)?;
        value.set_sensitive(true);
        Ok(ProviderAuthorization {
            header: Some((name, value)),
        })
    }
}

/// Authorization retained only until it is applied to one outbound attempt.
pub struct ProviderAuthorization {
    header: Option<(HeaderName, HeaderValue)>,
}

impl fmt::Debug for ProviderAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAuthorization")
            .field(
                "header",
                &self.header.as_ref().map(|(name, _)| name.as_str()),
            )
            .field("value", &self.header.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl ProviderAuthorization {
    /// Apply the materialized header, replacing an existing value of the same name.
    pub fn apply_to(self, headers: &mut HeaderMap) {
        if let Some((name, value)) = self.header {
            headers.insert(name, value);
        }
    }

    /// Header name used by this authorization, if authentication is enabled.
    #[must_use]
    pub fn header_name(&self) -> Option<&HeaderName> {
        self.header.as_ref().map(|(name, _)| name)
    }
}

/// Common integration surface consumed by a native-provider runtime registry.
pub trait ProviderAdapter: Send + Sync {
    /// Stable provider family.
    fn kind(&self) -> ProviderKind;

    /// Serializable provider metadata.
    fn profile(&self) -> ProviderProfile;

    /// Ordered endpoint candidates. Multiple entries express measured fallback order.
    fn endpoint_candidates(
        &self,
        operation: ProviderOperation,
        model: Option<&str>,
    ) -> Result<Vec<Url>, AdapterError>;

    /// Materialize one secret at the outbound request boundary.
    fn authorization(&self, secret: &SecretValue) -> Result<ProviderAuthorization, AdapterError>;

    /// Normalize a routed model ID for this provider surface.
    fn normalize_model(&self, requested: &str) -> Result<String, AdapterError>;

    /// Classify one bounded provider response without retaining the raw body.
    fn classify_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> FailureClassification {
        ProviderResponseClassifier::new(self.kind()).classify_response(status, headers, body)
    }
}

/// Kimi product surface selected by one upstream declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KimiSurface {
    /// Public Open Platform, API key, and `api.moonshot.ai`.
    OpenPlatform,
    /// Kimi Code subscription surface observed in the pinned CLIProxyAPI revision.
    CodingSubscription,
}

/// Endpoint/auth adapter for the two distinct Kimi surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KimiAdapter {
    surface: KimiSurface,
    base_url: Url,
}

impl KimiAdapter {
    /// Official public Kimi Open Platform adapter.
    pub fn open_platform() -> Result<Self, AdapterError> {
        Ok(Self {
            surface: KimiSurface::OpenPlatform,
            base_url: parse_base_url("https://api.moonshot.ai")?,
        })
    }

    /// Kimi Code subscription compatibility adapter from the pinned reference.
    pub fn coding_subscription() -> Result<Self, AdapterError> {
        Ok(Self {
            surface: KimiSurface::CodingSubscription,
            base_url: parse_base_url("https://api.kimi.com/coding")?,
        })
    }

    /// Replace the inference base URL for a compatible deployment or test fixture.
    pub fn with_base_url(mut self, base_url: Url) -> Result<Self, AdapterError> {
        validate_kimi_base_url(self.surface, &base_url)?;
        self.base_url = base_url;
        Ok(self)
    }

    /// Replace the base URL with an unrelated public HTTPS host after explicit acknowledgement.
    pub fn dangerously_with_custom_base_url(
        mut self,
        base_url: Url,
        _acknowledgement: DangerousCustomEndpoint,
    ) -> Result<Self, AdapterError> {
        validate_public_credential_base_url(&base_url)?;
        self.base_url = base_url;
        Ok(self)
    }

    /// Selected Kimi product surface.
    #[must_use]
    pub const fn surface(&self) -> KimiSurface {
        self.surface
    }

    /// Rewrite one OpenAI-compatible `/v1/...` route to this surface's
    /// provider-owned endpoint path.
    ///
    /// Kimi Code documents `/coding/v1` as its OpenAI base while a number of
    /// clients expose `/v1/...` as the route they append to that base. Keep
    /// the product path and collapse an already-versioned base to one `/v1`.
    pub fn openai_endpoint_path(&self, path: &str) -> Result<String, AdapterError> {
        validate_override_path(path)?;
        let suffix = path
            .strip_prefix("/v1")
            .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            .ok_or(AdapterError::InvalidOverridePath)?;
        let base = self.base_url.path().trim_end_matches('/');
        let base = base.strip_suffix("/v1").unwrap_or(base);
        let mut endpoint = format!("{base}/v1");
        endpoint.push_str(suffix);
        Ok(endpoint)
    }
}

impl ProviderAdapter for KimiAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Kimi
    }

    fn profile(&self) -> ProviderProfile {
        let mut profile = match self.surface {
            KimiSurface::OpenPlatform => kimi_open_platform_profile(),
            KimiSurface::CodingSubscription => kimi_coding_profile(),
        };
        profile.default_base_urls = vec![self.base_url.as_str().trim_end_matches('/').to_owned()];
        profile
    }

    fn endpoint_candidates(
        &self,
        operation: ProviderOperation,
        _model: Option<&str>,
    ) -> Result<Vec<Url>, AdapterError> {
        let suffix = match (self.surface, operation) {
            (_, ProviderOperation::ChatCompletions) => "chat/completions",
            (KimiSurface::OpenPlatform, ProviderOperation::ListModels) => "models",
            (KimiSurface::OpenPlatform, ProviderOperation::EstimateTokens) => {
                "tokenizers/estimate-token-count"
            }
            (KimiSurface::OpenPlatform, ProviderOperation::Balance) => "users/me/balance",
            (KimiSurface::OpenPlatform, ProviderOperation::Files) => "files",
            (KimiSurface::OpenPlatform, ProviderOperation::Batches) => "batches",
            _ => return Err(AdapterError::UnsupportedOperation { operation }),
        };
        // The catalog may provide either the product root (`/coding`) or the
        // already-versioned endpoint root (`/coding/v1`). Treat `/v1` as part
        // of the base when it is present so endpoint construction never emits
        // `/coding/v1/v1/...` and never loses the `/coding` product path.
        let path = if self
            .base_url
            .path()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            == Some("v1")
        {
            suffix.to_owned()
        } else {
            format!("v1/{suffix}")
        };
        Ok(vec![append_path(&self.base_url, &path)?])
    }

    fn authorization(&self, secret: &SecretValue) -> Result<ProviderAuthorization, AdapterError> {
        AuthPlacement::Bearer.materialize(secret)
    }

    fn normalize_model(&self, requested: &str) -> Result<String, AdapterError> {
        let requested = validated_model(requested)?;
        if self.surface == KimiSurface::OpenPlatform {
            return Ok(requested.to_owned());
        }
        normalize_kimi_coding_model(requested)
    }
}

/// Authentication mode used after the Google auth layer has materialized a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VertexAuthentication {
    /// OAuth access token obtained from ADC or a service account.
    AccessToken,
    /// Google API/authorization key.
    ApiKey,
}

/// Vertex resource addressing mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VertexAddressing {
    /// Standard project/location publisher-model resource.
    Project {
        project: String,
        location: String,
        publisher: String,
    },
    /// Express/compatible publisher-model resource without project/location segments.
    Express { publisher: String },
}

/// Endpoint/auth adapter for Vertex publisher models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VertexAdapter {
    base_url: Url,
    addressing: VertexAddressing,
    authentication: VertexAuthentication,
}

impl VertexAdapter {
    /// Standard Vertex adapter using ADC or a service-account access token.
    pub fn project(
        project: impl Into<String>,
        location: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        Self::project_with_auth(project, location, VertexAuthentication::AccessToken)
    }

    /// Standard project/location adapter with an explicit auth placement.
    pub fn project_with_auth(
        project: impl Into<String>,
        location: impl Into<String>,
        authentication: VertexAuthentication,
    ) -> Result<Self, AdapterError> {
        let project = project.into();
        let location = location.into();
        validate_path_identifier(&project, "project")?;
        validate_dns_label_or_global(&location, "location")?;
        let base = if location.eq_ignore_ascii_case("global") {
            "https://aiplatform.googleapis.com".to_owned()
        } else {
            format!("https://{location}-aiplatform.googleapis.com")
        };
        Ok(Self {
            base_url: parse_base_url(&base)?,
            addressing: VertexAddressing::Project {
                project,
                location,
                publisher: "google".to_owned(),
            },
            authentication,
        })
    }

    /// Vertex express/compatible addressing with an `x-goog-api-key` credential.
    pub fn express_api_key(base_url: Url) -> Result<Self, AdapterError> {
        validate_vertex_base_url(&base_url)?;
        Ok(Self {
            base_url,
            addressing: VertexAddressing::Express {
                publisher: "google".to_owned(),
            },
            authentication: VertexAuthentication::ApiKey,
        })
    }

    /// Construct a Vertex-compatible API-key adapter on an unrelated public HTTPS host.
    pub fn dangerously_express_api_key(
        base_url: Url,
        _acknowledgement: DangerousCustomEndpoint,
    ) -> Result<Self, AdapterError> {
        validate_public_credential_base_url(&base_url)?;
        Ok(Self {
            base_url,
            addressing: VertexAddressing::Express {
                publisher: "google".to_owned(),
            },
            authentication: VertexAuthentication::ApiKey,
        })
    }

    /// Replace the endpoint base while retaining validated addressing and auth mode.
    pub fn with_base_url(mut self, base_url: Url) -> Result<Self, AdapterError> {
        validate_vertex_base_url(&base_url)?;
        self.base_url = base_url;
        Ok(self)
    }

    /// Replace the base URL with an unrelated public HTTPS host after explicit acknowledgement.
    pub fn dangerously_with_custom_base_url(
        mut self,
        base_url: Url,
        _acknowledgement: DangerousCustomEndpoint,
    ) -> Result<Self, AdapterError> {
        validate_public_credential_base_url(&base_url)?;
        self.base_url = base_url;
        Ok(self)
    }

    /// Replace the publisher path segment.
    pub fn with_publisher(mut self, publisher: impl Into<String>) -> Result<Self, AdapterError> {
        let publisher = publisher.into();
        validate_path_identifier(&publisher, "publisher")?;
        match &mut self.addressing {
            VertexAddressing::Project {
                publisher: target, ..
            }
            | VertexAddressing::Express { publisher: target } => *target = publisher,
        }
        Ok(self)
    }

    /// Addressing selected for this credential.
    #[must_use]
    pub fn addressing(&self) -> &VertexAddressing {
        &self.addressing
    }

    /// Auth placement selected for this credential.
    #[must_use]
    pub const fn authentication(&self) -> VertexAuthentication {
        self.authentication
    }
}

impl ProviderAdapter for VertexAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Vertex
    }

    fn profile(&self) -> ProviderProfile {
        let mut profile = vertex_profile();
        profile.default_base_urls = vec![self.base_url.as_str().trim_end_matches('/').to_owned()];
        profile.authentication = vec![match self.authentication {
            VertexAuthentication::AccessToken => crate::AuthMode::GoogleAccessToken,
            VertexAuthentication::ApiKey => crate::AuthMode::GoogleApiKey,
        }];
        profile
    }

    fn endpoint_candidates(
        &self,
        operation: ProviderOperation,
        model: Option<&str>,
    ) -> Result<Vec<Url>, AdapterError> {
        let action = match operation {
            ProviderOperation::GenerateContent => "generateContent",
            ProviderOperation::StreamGenerateContent => "streamGenerateContent",
            ProviderOperation::CountTokens => "countTokens",
            ProviderOperation::Predict => "predict",
            _ => return Err(AdapterError::UnsupportedOperation { operation }),
        };
        let model =
            self.normalize_model(model.ok_or(AdapterError::InvalidIdentifier { field: "model" })?)?;
        let path = match &self.addressing {
            VertexAddressing::Project {
                project,
                location,
                publisher,
            } => format!(
                "v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model}:{action}"
            ),
            VertexAddressing::Express { publisher } => {
                format!("v1/publishers/{publisher}/models/{model}:{action}")
            }
        };
        let mut endpoint = append_path(&self.base_url, &path)?;
        if operation == ProviderOperation::StreamGenerateContent {
            endpoint.query_pairs_mut().append_pair("alt", "sse");
        }
        Ok(vec![endpoint])
    }

    fn authorization(&self, secret: &SecretValue) -> Result<ProviderAuthorization, AdapterError> {
        match self.authentication {
            VertexAuthentication::AccessToken => AuthPlacement::Bearer.materialize(secret),
            VertexAuthentication::ApiKey => AuthPlacement::Header {
                name: HeaderName::from_static("x-goog-api-key"),
                value_prefix: String::new(),
            }
            .materialize(secret),
        }
    }

    fn normalize_model(&self, requested: &str) -> Result<String, AdapterError> {
        let requested = validated_model(requested)?;
        let model = requested
            .rsplit_once("/models/")
            .map_or(requested, |(_, model)| model);
        validate_path_identifier(model, "model")?;
        Ok(model.to_owned())
    }
}

/// Overrideable internal paths observed in the pinned Antigravity reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntigravityCompatibilityPaths {
    pub generate: String,
    pub stream_generate: String,
    pub count_tokens: String,
    pub fetch_models: String,
    pub load_code_assist: String,
    pub onboard_user: String,
}

impl AntigravityCompatibilityPaths {
    /// Paths from the pinned CLIProxyAPI reference. No stability is implied.
    #[must_use]
    pub fn pinned_reference() -> Self {
        Self {
            generate: "/v1internal:generateContent".to_owned(),
            stream_generate: "/v1internal:streamGenerateContent".to_owned(),
            count_tokens: "/v1internal:countTokens".to_owned(),
            fetch_models: "/v1internal:fetchAvailableModels".to_owned(),
            load_code_assist: "/v1internal:loadCodeAssist".to_owned(),
            onboard_user: "/v1internal:onboardUser".to_owned(),
        }
    }

    fn validate(&self) -> Result<(), AdapterError> {
        for path in [
            &self.generate,
            &self.stream_generate,
            &self.count_tokens,
            &self.fetch_models,
            &self.load_code_assist,
            &self.onboard_user,
        ] {
            validate_override_path(path)?;
        }
        Ok(())
    }
}

/// Explicit opt-in configuration for the pinned Antigravity compatibility surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntigravityCompatibilityConfig {
    pub enabled: bool,
    pub inference_base_urls: Vec<Url>,
    pub control_base_url: Url,
    pub onboarding_base_url: Url,
    pub paths: AntigravityCompatibilityPaths,
    dangerous_custom_endpoints: bool,
}

impl AntigravityCompatibilityConfig {
    /// Load pinned defaults in the disabled state. Call [`Self::enable`] explicitly.
    pub fn pinned_reference() -> Result<Self, AdapterError> {
        let config = Self {
            enabled: false,
            inference_base_urls: vec![
                parse_base_url("https://daily-cloudcode-pa.googleapis.com")?,
                parse_base_url("https://cloudcode-pa.googleapis.com")?,
            ],
            control_base_url: parse_base_url("https://cloudcode-pa.googleapis.com")?,
            onboarding_base_url: parse_base_url("https://daily-cloudcode-pa.googleapis.com")?,
            paths: AntigravityCompatibilityPaths::pinned_reference(),
            dangerous_custom_endpoints: false,
        };
        config.paths.validate()?;
        Ok(config)
    }

    /// Explicitly acknowledge and enable the unstable pinned compatibility contract.
    #[must_use]
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Permit unrelated public HTTPS endpoint overrides after explicit acknowledgement.
    #[must_use]
    pub fn dangerously_allow_custom_endpoints(
        mut self,
        _acknowledgement: DangerousCustomEndpoint,
    ) -> Self {
        self.dangerous_custom_endpoints = true;
        self
    }

    fn validate(&self) -> Result<(), AdapterError> {
        if !self.enabled {
            return Err(AdapterError::CompatibilityNotEnabled);
        }
        if self.inference_base_urls.is_empty() {
            return Err(AdapterError::InvalidBaseUrl);
        }
        for base in &self.inference_base_urls {
            validate_antigravity_base_url(base, self.dangerous_custom_endpoints)?;
        }
        validate_antigravity_base_url(&self.control_base_url, self.dangerous_custom_endpoints)?;
        validate_antigravity_base_url(&self.onboarding_base_url, self.dangerous_custom_endpoints)?;
        self.paths.validate()
    }
}

/// Explicitly enabled compatibility adapter for Antigravity's pinned internal API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntigravityAdapter {
    config: AntigravityCompatibilityConfig,
}

impl AntigravityAdapter {
    /// Construct only from an enabled, fully overrideable compatibility config.
    pub fn new(config: AntigravityCompatibilityConfig) -> Result<Self, AdapterError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Validated compatibility configuration.
    #[must_use]
    pub const fn config(&self) -> &AntigravityCompatibilityConfig {
        &self.config
    }
}

impl ProviderAdapter for AntigravityAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Antigravity
    }

    fn profile(&self) -> ProviderProfile {
        let mut profile = antigravity_compatibility_profile();
        profile.default_base_urls = self
            .config
            .inference_base_urls
            .iter()
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
            .collect();
        profile
    }

    fn endpoint_candidates(
        &self,
        operation: ProviderOperation,
        _model: Option<&str>,
    ) -> Result<Vec<Url>, AdapterError> {
        let paths = &self.config.paths;
        let (bases, path): (Vec<&Url>, &str) = match operation {
            ProviderOperation::GenerateContent => (
                self.config.inference_base_urls.iter().collect(),
                &paths.generate,
            ),
            ProviderOperation::StreamGenerateContent => (
                self.config.inference_base_urls.iter().collect(),
                &paths.stream_generate,
            ),
            ProviderOperation::CountTokens => (
                self.config.inference_base_urls.iter().collect(),
                &paths.count_tokens,
            ),
            ProviderOperation::FetchAvailableModels => (
                self.config.inference_base_urls.iter().collect(),
                &paths.fetch_models,
            ),
            ProviderOperation::LoadCodeAssist => {
                (vec![&self.config.control_base_url], &paths.load_code_assist)
            }
            ProviderOperation::OnboardUser => {
                (vec![&self.config.onboarding_base_url], &paths.onboard_user)
            }
            _ => return Err(AdapterError::UnsupportedOperation { operation }),
        };
        bases
            .into_iter()
            .map(|base| {
                let mut endpoint = append_path(base, path)?;
                if operation == ProviderOperation::StreamGenerateContent {
                    endpoint.query_pairs_mut().append_pair("alt", "sse");
                }
                Ok(endpoint)
            })
            .collect()
    }

    fn authorization(&self, secret: &SecretValue) -> Result<ProviderAuthorization, AdapterError> {
        AuthPlacement::Bearer.materialize(secret)
    }

    fn normalize_model(&self, requested: &str) -> Result<String, AdapterError> {
        Ok(validated_model(requested)?.to_owned())
    }
}

/// Adapter for one operator-configured OpenAI-compatible provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiCompatibleAdapter {
    provider: ProviderId,
    base_url: Url,
    auth: AuthPlacement,
    operations: BTreeSet<ProviderOperation>,
}

impl OpenAiCompatibleAdapter {
    /// Construct with an explicit operation allow-list.
    pub fn new<I>(
        provider: impl Into<String>,
        base_url: Url,
        auth: AuthPlacement,
        operations: I,
    ) -> Result<Self, AdapterError>
    where
        I: IntoIterator<Item = ProviderOperation>,
    {
        if matches!(auth, AuthPlacement::None) {
            validate_base_url(&base_url)?;
        } else {
            validate_public_credential_base_url(&base_url)?;
        }
        let provider = ProviderId::new(provider.into())?;
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(AdapterError::UnsupportedOperation {
                operation: ProviderOperation::ChatCompletions,
            });
        }
        Ok(Self {
            provider,
            base_url,
            auth,
            operations,
        })
    }

    /// Configured provider identifier.
    #[must_use]
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider
    }

    /// Explicit operation allow-list.
    #[must_use]
    pub fn operations(&self) -> &BTreeSet<ProviderOperation> {
        &self.operations
    }
}

impl ProviderAdapter for OpenAiCompatibleAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenAiCompatible
    }

    fn profile(&self) -> ProviderProfile {
        let mut profile = openai_compatible_profile(self.operations.iter().copied().collect());
        profile.default_base_urls = vec![self.base_url.as_str().trim_end_matches('/').to_owned()];
        profile.authentication = match &self.auth {
            AuthPlacement::Bearer => vec![crate::AuthMode::ApiKeyBearer],
            AuthPlacement::Header { .. } => vec![crate::AuthMode::CustomHeader],
            AuthPlacement::None => Vec::new(),
        };
        profile
    }

    fn endpoint_candidates(
        &self,
        operation: ProviderOperation,
        _model: Option<&str>,
    ) -> Result<Vec<Url>, AdapterError> {
        if !self.operations.contains(&operation) {
            return Err(AdapterError::UnsupportedOperation { operation });
        }
        let path = match operation {
            ProviderOperation::ListModels => "models",
            ProviderOperation::ChatCompletions => "chat/completions",
            ProviderOperation::Responses => "responses",
            ProviderOperation::ResponsesCompact => "responses/compact",
            ProviderOperation::Embeddings => "embeddings",
            ProviderOperation::ImageGenerations => "images/generations",
            ProviderOperation::ImageEdits => "images/edits",
            ProviderOperation::AudioTranscriptions => "audio/transcriptions",
            ProviderOperation::AudioTranslations => "audio/translations",
            ProviderOperation::AudioSpeech => "audio/speech",
            ProviderOperation::Files => "files",
            ProviderOperation::Batches => "batches",
            _ => return Err(AdapterError::UnsupportedOperation { operation }),
        };
        Ok(vec![append_path(&self.base_url, path)?])
    }

    fn authorization(&self, secret: &SecretValue) -> Result<ProviderAuthorization, AdapterError> {
        self.auth.materialize(secret)
    }

    fn normalize_model(&self, requested: &str) -> Result<String, AdapterError> {
        Ok(validated_model(requested)?.to_owned())
    }
}

fn parse_base_url(value: &str) -> Result<Url, AdapterError> {
    let url = Url::parse(value).map_err(|_| AdapterError::InvalidBaseUrl)?;
    validate_base_url(&url)?;
    Ok(url)
}

fn validate_base_url(url: &Url) -> Result<(), AdapterError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AdapterError::InvalidBaseUrl);
    }
    Ok(())
}

fn validate_public_credential_base_url(url: &Url) -> Result<(), AdapterError> {
    validate_base_url(url)?;
    if url.scheme() != "https" {
        return Err(AdapterError::InvalidBaseUrl);
    }
    match url.host() {
        Some(Host::Domain(host)) if is_forbidden_domain(host) => {
            Err(AdapterError::ForbiddenNetworkTarget)
        }
        Some(Host::Ipv4(address)) if is_forbidden_ipv4(address) => {
            Err(AdapterError::ForbiddenNetworkTarget)
        }
        Some(Host::Ipv6(address)) if is_forbidden_ipv6(address) => {
            Err(AdapterError::ForbiddenNetworkTarget)
        }
        Some(_) => Ok(()),
        None => Err(AdapterError::InvalidBaseUrl),
    }
}

fn validate_kimi_base_url(surface: KimiSurface, url: &Url) -> Result<(), AdapterError> {
    validate_public_credential_base_url(url)?;
    let expected = match surface {
        KimiSurface::OpenPlatform => "api.moonshot.ai",
        KimiSurface::CodingSubscription => "api.kimi.com",
    };
    if url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(expected))
    {
        Ok(())
    } else {
        Err(AdapterError::ProviderHostNotAllowed)
    }
}

fn validate_vertex_base_url(url: &Url) -> Result<(), AdapterError> {
    validate_public_credential_base_url(url)?;
    let allowed = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("aiplatform.googleapis.com")
            || host
                .to_ascii_lowercase()
                .strip_suffix("-aiplatform.googleapis.com")
                .is_some_and(|location| {
                    !location.is_empty()
                        && location
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-')
                })
    });
    if allowed {
        Ok(())
    } else {
        Err(AdapterError::ProviderHostNotAllowed)
    }
}

fn validate_antigravity_base_url(
    url: &Url,
    dangerous_custom_endpoints: bool,
) -> Result<(), AdapterError> {
    validate_public_credential_base_url(url)?;
    let allowed = url.host_str().is_some_and(|host| {
        [
            "daily-cloudcode-pa.googleapis.com",
            "cloudcode-pa.googleapis.com",
        ]
        .into_iter()
        .any(|expected| host.eq_ignore_ascii_case(expected))
    });
    if allowed || dangerous_custom_endpoints {
        Ok(())
    } else {
        Err(AdapterError::ProviderHostNotAllowed)
    }
}

fn is_forbidden_domain(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    !host.contains('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || host.ends_with(".test")
        || host.ends_with(".example")
        || host.ends_with(".invalid")
        || host == "metadata.google.internal"
}

fn is_forbidden_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_broadcast()
        || first == 0
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && matches!(second, 18 | 19))
}

fn is_forbidden_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] == 0x2001 && segments[1] == 0x0db8
        || address.to_ipv4_mapped().is_some_and(is_forbidden_ipv4)
}

fn append_path(base: &Url, path: &str) -> Result<Url, AdapterError> {
    validate_base_url(base)?;
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| AdapterError::InvalidBaseUrl)?;
        segments.pop_if_empty();
        for segment in path.trim_matches('/').split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(AdapterError::InvalidBaseUrl);
            }
            segments.push(segment);
        }
    }
    Ok(url)
}

fn validate_override_path(path: &str) -> Result<(), AdapterError> {
    if path.len() > 1024
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#', '%', '\\', '\r', '\n'])
        || path.chars().any(char::is_whitespace)
    {
        return Err(AdapterError::InvalidOverridePath);
    }
    for segment in path.trim_start_matches('/').split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '-' | '_' | '.' | '~' | ':')
            })
        {
            return Err(AdapterError::InvalidOverridePath);
        }
    }
    Ok(())
}

fn validated_model(value: &str) -> Result<&str, AdapterError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AdapterError::InvalidIdentifier { field: "model" });
    }
    Ok(value)
}

fn validate_path_identifier(value: &str, field: &'static str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > 256
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AdapterError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_dns_label_or_global(value: &str, field: &'static str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(AdapterError::InvalidIdentifier { field });
    }
    Ok(())
}

fn normalize_kimi_coding_model(model: &str) -> Result<String, AdapterError> {
    let (base, suffix) = model
        .strip_suffix(')')
        .and_then(|without_close| without_close.rsplit_once('('))
        .map_or((model, None), |(base, suffix)| (base, Some(suffix)));
    let mut base = base.to_ascii_lowercase();
    if let Some(without_context) = base.strip_suffix("[1m]") {
        base = without_context.to_owned();
    }
    let normalized = match base.as_str() {
        "kimi-k2.7-code" | "k2.7-code" | "kimi-for-coding" | "for-coding" => "kimi-for-coding",
        "kimi-k2.7-code-highspeed"
        | "k2.7-code-highspeed"
        | "kimi-for-coding-highspeed"
        | "for-coding-highspeed" => "kimi-for-coding-highspeed",
        _ => base.strip_prefix("kimi-").unwrap_or(&base),
    };
    validate_path_identifier(normalized, "model")?;
    match suffix {
        Some(suffix)
            if !suffix.is_empty()
                && suffix.len() <= 32
                && suffix.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                }) =>
        {
            Ok(format!("{normalized}({suffix})"))
        }
        Some(_) => Err(AdapterError::InvalidIdentifier { field: "model" }),
        None => Ok(normalized.to_owned()),
    }
}
