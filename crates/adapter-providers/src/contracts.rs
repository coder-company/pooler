//! Serializable provider metadata for configuration, diagnostics, and management.

use serde::{Deserialize, Serialize};

/// CLIProxyAPI revision used to establish the compatibility-only contracts.
pub const CLI_PROXY_API_REFERENCE_REVISION: &str = "2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e";

/// Provider family understood by the integration helpers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Moonshot AI / Kimi.
    Kimi,
    /// Google AI Studio Gemini API.
    AiStudio,
    /// Google Cloud Vertex AI.
    Vertex,
    /// Google Antigravity's compatibility-only internal surface.
    Antigravity,
    /// A caller-configured OpenAI-compatible service.
    OpenAiCompatible,
}

/// A concrete product surface within a provider family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSurface {
    /// Kimi Open Platform API-key service.
    KimiOpenPlatform,
    /// Kimi Code subscription service observed in the pinned reference.
    KimiCodingSubscription,
    /// Google Cloud Vertex AI publisher-model API.
    VertexPublisherModels,
    /// Antigravity internal API observed in the pinned reference.
    AntigravityPinnedCompatibility,
    /// A caller-supplied OpenAI-compatible base URL.
    OpenAiCompatible,
}

/// Stability level of one encoded provider contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStability {
    /// The provider publishes the contract as a supported public API.
    OfficialPublic,
    /// The contract was measured in a pinned implementation and may change without notice.
    PinnedCompatibility,
    /// The contract is supplied by the operator and must be validated against that service.
    OperatorConfigured,
}

/// Authentication material expected by a provider surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// API key carried as an HTTP bearer credential.
    ApiKeyBearer,
    /// OAuth access token carried as an HTTP bearer credential.
    OAuthBearer,
    /// OAuth device authorization grant.
    OAuthDeviceCode,
    /// Browser authorization-code grant with a loopback callback.
    OAuthAuthorizationCode,
    /// Google Application Default Credentials or service-account token exchange.
    GoogleAccessToken,
    /// Google API or authorization key in `x-goog-api-key`.
    GoogleApiKey,
    /// Operator-selected header name and optional value prefix.
    CustomHeader,
}

/// OAuth or identity endpoint purpose. Client identifiers and secrets are never metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEndpointKind {
    DeviceAuthorization,
    Authorization,
    Token,
    UserInfo,
}

/// Non-secret provider authentication endpoint metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderAuthEndpoint {
    pub kind: AuthEndpointKind,
    pub url: String,
    pub stability: ContractStability,
}

/// Provider-native wire family. Semantic codecs live in their dedicated crates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireProtocol {
    /// OpenAI Chat Completions JSON and SSE.
    OpenAiChatCompletions,
    /// OpenAI Responses JSON and SSE.
    OpenAiResponses,
    /// OpenAI-compatible images surface.
    OpenAiImages,
    /// OpenAI-compatible audio surface.
    OpenAiAudio,
    /// OpenAI-compatible embeddings surface.
    OpenAiEmbeddings,
    /// Vertex publisher-model GenerateContent JSON and SSE.
    VertexGenerateContent,
    /// Vertex publisher-model prediction API (for example Imagen).
    VertexPredict,
    /// Compatibility-only Antigravity internal envelope.
    AntigravityInternal,
}

/// Operation whose endpoint can be constructed by a provider adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOperation {
    ListModels,
    ChatCompletions,
    Responses,
    ResponsesCompact,
    Embeddings,
    ImageGenerations,
    ImageEdits,
    AudioTranscriptions,
    AudioTranslations,
    AudioSpeech,
    Files,
    Batches,
    Balance,
    EstimateTokens,
    GenerateContent,
    StreamGenerateContent,
    CountTokens,
    Predict,
    FetchAvailableModels,
    LoadCodeAssist,
    OnboardUser,
}

/// How a provider's model catalog can be populated.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// A public endpoint returns the available model objects.
    RemoteList,
    /// A configured/static catalog is augmented by remote capability hints.
    StaticCatalogWithRemoteHints,
    /// Model availability comes from a provider-published catalog or an operator snapshot.
    ProviderCatalog,
    /// Model identifiers and aliases are declared by the operator.
    OperatorConfigured,
}

/// Explicit quota evidence understood for one provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaSignal {
    /// OpenAI-style rate-limit headers and bounded JSON error codes.
    OpenAiRateHeaders,
    /// Google RPC `RESOURCE_EXHAUSTED`, ErrorInfo, and RetryInfo details.
    GoogleRpcDetails,
    /// Antigravity `paidTier.availableCredits` compatibility response.
    AntigravityCredits,
    /// Provider does not advertise a normalized quota endpoint.
    StatusOnly,
}

/// Source that establishes one profile contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractEvidence {
    pub stability: ContractStability,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

impl ContractEvidence {
    fn official(source: &str) -> Self {
        Self {
            stability: ContractStability::OfficialPublic,
            source: source.to_owned(),
            revision: None,
        }
    }

    fn pinned(source: &str) -> Self {
        Self {
            stability: ContractStability::PinnedCompatibility,
            source: source.to_owned(),
            revision: Some(CLI_PROXY_API_REFERENCE_REVISION.to_owned()),
        }
    }

    fn configured() -> Self {
        Self {
            stability: ContractStability::OperatorConfigured,
            source: "operator configuration".to_owned(),
            revision: None,
        }
    }
}

/// Provider metadata exposed to runtime registration and management surfaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub kind: ProviderKind,
    pub surface: ProviderSurface,
    pub stability: ContractStability,
    pub authentication: Vec<AuthMode>,
    /// Provider defaults or templates. Adapter overrides replace these at runtime.
    pub default_base_urls: Vec<String>,
    /// Non-secret login endpoints; never contains OAuth client credentials.
    pub auth_endpoints: Vec<ProviderAuthEndpoint>,
    /// Provider-required OAuth scopes when established by the contract.
    pub oauth_scopes: Vec<String>,
    pub protocols: Vec<WireProtocol>,
    pub operations: Vec<ProviderOperation>,
    pub discovery: DiscoveryMode,
    pub quota_signals: Vec<QuotaSignal>,
    pub evidence: Vec<ContractEvidence>,
}

/// Official Kimi Open Platform API-key profile.
#[must_use]
pub fn kimi_open_platform_profile() -> ProviderProfile {
    ProviderProfile {
        kind: ProviderKind::Kimi,
        surface: ProviderSurface::KimiOpenPlatform,
        stability: ContractStability::OfficialPublic,
        authentication: vec![AuthMode::ApiKeyBearer],
        default_base_urls: vec!["https://api.moonshot.ai".to_owned()],
        auth_endpoints: Vec::new(),
        oauth_scopes: Vec::new(),
        protocols: vec![WireProtocol::OpenAiChatCompletions],
        operations: vec![
            ProviderOperation::ListModels,
            ProviderOperation::ChatCompletions,
            ProviderOperation::EstimateTokens,
            ProviderOperation::Balance,
            ProviderOperation::Files,
            ProviderOperation::Batches,
        ],
        discovery: DiscoveryMode::RemoteList,
        quota_signals: vec![QuotaSignal::OpenAiRateHeaders],
        evidence: vec![
            ContractEvidence::official("https://platform.kimi.ai/docs/api/overview"),
            ContractEvidence::official("https://platform.kimi.ai/docs/api/list-models"),
            ContractEvidence::official("https://platform.kimi.ai/docs/introduction"),
        ],
    }
}

/// Kimi Code subscription compatibility profile from the pinned reference.
#[must_use]
pub fn kimi_coding_profile() -> ProviderProfile {
    ProviderProfile {
        kind: ProviderKind::Kimi,
        surface: ProviderSurface::KimiCodingSubscription,
        stability: ContractStability::PinnedCompatibility,
        authentication: vec![AuthMode::OAuthDeviceCode, AuthMode::OAuthBearer],
        default_base_urls: vec!["https://api.kimi.com/coding".to_owned()],
        auth_endpoints: vec![
            ProviderAuthEndpoint {
                kind: AuthEndpointKind::DeviceAuthorization,
                url: "https://auth.kimi.com/api/oauth/device_authorization".to_owned(),
                stability: ContractStability::PinnedCompatibility,
            },
            ProviderAuthEndpoint {
                kind: AuthEndpointKind::Token,
                url: "https://auth.kimi.com/api/oauth/token".to_owned(),
                stability: ContractStability::PinnedCompatibility,
            },
        ],
        oauth_scopes: Vec::new(),
        protocols: vec![WireProtocol::OpenAiChatCompletions],
        operations: vec![ProviderOperation::ChatCompletions],
        discovery: DiscoveryMode::StaticCatalogWithRemoteHints,
        quota_signals: vec![QuotaSignal::OpenAiRateHeaders],
        evidence: vec![
            ContractEvidence::pinned("internal/auth/kimi/kimi.go"),
            ContractEvidence::pinned("internal/runtime/executor/kimi_executor.go"),
        ],
    }
}

/// Official Vertex AI publisher-model profile.
#[must_use]
pub fn vertex_profile() -> ProviderProfile {
    ProviderProfile {
        kind: ProviderKind::Vertex,
        surface: ProviderSurface::VertexPublisherModels,
        stability: ContractStability::OfficialPublic,
        authentication: vec![AuthMode::GoogleAccessToken, AuthMode::GoogleApiKey],
        default_base_urls: vec![
            "https://aiplatform.googleapis.com".to_owned(),
            "https://{location}-aiplatform.googleapis.com".to_owned(),
        ],
        auth_endpoints: Vec::new(),
        oauth_scopes: vec!["https://www.googleapis.com/auth/cloud-platform".to_owned()],
        protocols: vec![
            WireProtocol::VertexGenerateContent,
            WireProtocol::VertexPredict,
        ],
        operations: vec![
            ProviderOperation::GenerateContent,
            ProviderOperation::StreamGenerateContent,
            ProviderOperation::CountTokens,
            ProviderOperation::Predict,
        ],
        discovery: DiscoveryMode::ProviderCatalog,
        quota_signals: vec![QuotaSignal::GoogleRpcDetails],
        evidence: vec![
            ContractEvidence::official(
                "https://cloud.google.com/vertex-ai/generative-ai/docs/start/quickstart",
            ),
            ContractEvidence::official(
                "https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/api-errors",
            ),
            ContractEvidence::official(
                "https://cloud.google.com/vertex-ai/generative-ai/docs/resources/throughput-quota",
            ),
        ],
    }
}

/// Pinned, opt-in Antigravity compatibility profile.
///
/// This is not an official public API claim. Endpoint defaults are used only
/// when an operator explicitly creates the corresponding compatibility config.
#[must_use]
pub fn antigravity_compatibility_profile() -> ProviderProfile {
    ProviderProfile {
        kind: ProviderKind::Antigravity,
        surface: ProviderSurface::AntigravityPinnedCompatibility,
        stability: ContractStability::PinnedCompatibility,
        authentication: vec![AuthMode::OAuthAuthorizationCode, AuthMode::OAuthBearer],
        default_base_urls: vec![
            "https://daily-cloudcode-pa.googleapis.com".to_owned(),
            "https://cloudcode-pa.googleapis.com".to_owned(),
        ],
        auth_endpoints: vec![
            ProviderAuthEndpoint {
                kind: AuthEndpointKind::Authorization,
                url: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
                stability: ContractStability::PinnedCompatibility,
            },
            ProviderAuthEndpoint {
                kind: AuthEndpointKind::Token,
                url: "https://oauth2.googleapis.com/token".to_owned(),
                stability: ContractStability::PinnedCompatibility,
            },
            ProviderAuthEndpoint {
                kind: AuthEndpointKind::UserInfo,
                url: "https://www.googleapis.com/oauth2/v2/userinfo?alt=json".to_owned(),
                stability: ContractStability::PinnedCompatibility,
            },
        ],
        oauth_scopes: Vec::new(),
        protocols: vec![WireProtocol::AntigravityInternal],
        operations: vec![
            ProviderOperation::GenerateContent,
            ProviderOperation::StreamGenerateContent,
            ProviderOperation::CountTokens,
            ProviderOperation::FetchAvailableModels,
            ProviderOperation::LoadCodeAssist,
            ProviderOperation::OnboardUser,
        ],
        discovery: DiscoveryMode::StaticCatalogWithRemoteHints,
        quota_signals: vec![
            QuotaSignal::GoogleRpcDetails,
            QuotaSignal::AntigravityCredits,
        ],
        evidence: vec![
            ContractEvidence::pinned("internal/auth/antigravity/constants.go"),
            ContractEvidence::pinned("internal/runtime/executor/antigravity_executor_request.go"),
            ContractEvidence::pinned("internal/runtime/executor/antigravity_executor_credits.go"),
            ContractEvidence::pinned("sdk/cliproxy/antigravity_models.go"),
        ],
    }
}

/// Operator-configured OpenAI-compatible provider profile.
#[must_use]
pub fn openai_compatible_profile(operations: Vec<ProviderOperation>) -> ProviderProfile {
    let mut protocols = Vec::new();
    if operations.contains(&ProviderOperation::ChatCompletions) {
        protocols.push(WireProtocol::OpenAiChatCompletions);
    }
    if operations.contains(&ProviderOperation::Responses)
        || operations.contains(&ProviderOperation::ResponsesCompact)
    {
        protocols.push(WireProtocol::OpenAiResponses);
    }
    if operations.contains(&ProviderOperation::ImageGenerations)
        || operations.contains(&ProviderOperation::ImageEdits)
    {
        protocols.push(WireProtocol::OpenAiImages);
    }
    if operations.contains(&ProviderOperation::AudioTranscriptions)
        || operations.contains(&ProviderOperation::AudioTranslations)
        || operations.contains(&ProviderOperation::AudioSpeech)
    {
        protocols.push(WireProtocol::OpenAiAudio);
    }
    if operations.contains(&ProviderOperation::Embeddings) {
        protocols.push(WireProtocol::OpenAiEmbeddings);
    }
    ProviderProfile {
        kind: ProviderKind::OpenAiCompatible,
        surface: ProviderSurface::OpenAiCompatible,
        stability: ContractStability::OperatorConfigured,
        authentication: vec![AuthMode::ApiKeyBearer, AuthMode::CustomHeader],
        default_base_urls: Vec::new(),
        auth_endpoints: Vec::new(),
        oauth_scopes: Vec::new(),
        protocols,
        operations,
        discovery: DiscoveryMode::OperatorConfigured,
        quota_signals: vec![QuotaSignal::OpenAiRateHeaders, QuotaSignal::StatusOnly],
        evidence: vec![
            ContractEvidence::configured(),
            ContractEvidence::official("https://developers.openai.com/api/reference/overview"),
            ContractEvidence::official(
                "https://developers.openai.com/api/reference/resources/models",
            ),
        ],
    }
}
