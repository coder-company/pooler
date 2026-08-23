//! Serializable provider metadata for configuration, diagnostics, and management.

use pooler_core::Capability;

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

/// Provenance retained for one provider fact.
///
/// `Unknown` is intentional: a missing observation must not be presented as a
/// verified provider capability by a later routing policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataProvenance {
    /// Established by a provider-owned public contract or a pinned native
    /// implementation that Pooler explicitly records as evidence.
    Verified,
    /// Declared by the operator for one custom provider instance.
    OperatorDeclared,
    /// No trustworthy fact is available.
    #[default]
    Unknown,
}

/// Backwards-compatible name for callers that refer to provider facts as
/// generic provenance.
pub type FactProvenance = MetadataProvenance;

/// A value together with the evidence level that permits Pooler to use it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderFact<T> {
    /// The value is absent when the fact is unknown.
    pub value: Option<T>,
    /// Evidence level for `value`.
    pub provenance: MetadataProvenance,
}

impl<T> ProviderFact<T> {
    /// Construct a fact backed by Pooler's verified provider evidence.
    #[must_use]
    pub fn verified(value: T) -> Self {
        Self {
            value: Some(value),
            provenance: MetadataProvenance::Verified,
        }
    }

    /// Construct a fact explicitly supplied by an operator.
    #[must_use]
    pub fn operator_declared(value: T) -> Self {
        Self {
            value: Some(value),
            provenance: MetadataProvenance::OperatorDeclared,
        }
    }

    /// Construct an intentionally unknown fact.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            value: None,
            provenance: MetadataProvenance::Unknown,
        }
    }

    /// Whether this fact has a usable value at the declared provenance.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        self.value.is_some()
    }
}

impl<T> Default for ProviderFact<T> {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Wire dialect supported by a provider profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderWireFamily {
    OpenAiChatCompletions,
    OpenAiResponses,
    AnthropicMessages,
    VertexGenerateContent,
    VertexPredict,
    AntigravityInternal,
}

/// Bounded endpoint family advertised by a provider profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEndpointFamily {
    Models,
    ChatCompletions,
    Responses,
    Messages,
    Embeddings,
    Images,
    Audio,
    GenerateContent,
    Predict,
}

/// Fixed credential placement understood by the provider boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthPlacementKind {
    None,
    Bearer,
    XApiKey,
    XGoogApiKey,
}

/// Request parameter whose support can be established independently of a
/// model's capability list.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderParameter {
    Temperature,
    TopP,
    MaxTokens,
    Tools,
    ResponseFormat,
    Reasoning,
}

/// Model weight representation reported by a provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuantization {
    Fp32,
    Fp16,
    Bf16,
    Int8,
    Int4,
    Gguf,
}

/// Provider privacy posture, only populated where evidence exists.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPrivacy {
    Standard,
    NoTraining,
    NoRetention,
}

/// Data handling policy used by hard routing filters.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDataPolicy {
    Standard,
    TrainingDisallowed,
    RetentionBounded,
    ZeroDataRetention,
}

/// Bounded, integer-priced provider rates. Values are micro-units per one
/// million tokens so floating-point prices never affect deterministic routing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderPricing {
    pub input_micros_per_million: u64,
    pub output_micros_per_million: u64,
    pub currency: String,
}

/// Reusable facts associated with one provider surface.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub wire_family: ProviderFact<ProviderWireFamily>,
    pub endpoint_families: ProviderFact<Vec<ProviderEndpointFamily>>,
    pub auth_placement: ProviderFact<AuthPlacementKind>,
    pub parameters: ProviderFact<Vec<ProviderParameter>>,
    pub capabilities: ProviderFact<Vec<Capability>>,
    pub context_window: ProviderFact<u32>,
    pub quantization: ProviderFact<Vec<ProviderQuantization>>,
    pub privacy: ProviderFact<ProviderPrivacy>,
    pub zdr: ProviderFact<bool>,
    pub data_policy: ProviderFact<ProviderDataPolicy>,
    pub pricing: ProviderFact<ProviderPricing>,
}

impl ProviderMetadata {
    /// Facts common to an OpenAI Chat Completions provider with no fabricated
    /// model, price, privacy, or context claims.
    #[must_use]
    pub fn verified_openai_chat(auth: AuthPlacementKind, endpoints: Vec<ProviderEndpointFamily>) -> Self {
        Self {
            wire_family: ProviderFact::verified(ProviderWireFamily::OpenAiChatCompletions),
            endpoint_families: ProviderFact::verified(endpoints),
            auth_placement: ProviderFact::verified(auth),
            ..Self::default()
        }
    }

    /// Facts declared by an operator for a custom OpenAI-compatible profile.
    #[must_use]
    pub fn operator_openai(operations: &[ProviderOperation]) -> Self {
        let endpoints = operations
            .iter()
            .filter_map(|operation| match operation {
                ProviderOperation::ListModels => Some(ProviderEndpointFamily::Models),
                ProviderOperation::ChatCompletions => Some(ProviderEndpointFamily::ChatCompletions),
                ProviderOperation::Responses | ProviderOperation::ResponsesCompact => {
                    Some(ProviderEndpointFamily::Responses)
                }
                ProviderOperation::Embeddings => Some(ProviderEndpointFamily::Embeddings),
                ProviderOperation::ImageGenerations | ProviderOperation::ImageEdits => {
                    Some(ProviderEndpointFamily::Images)
                }
                ProviderOperation::AudioTranscriptions
                | ProviderOperation::AudioTranslations
                | ProviderOperation::AudioSpeech => Some(ProviderEndpointFamily::Audio),
                _ => None,
            })
            .collect();
        Self {
            wire_family: ProviderFact::operator_declared(ProviderWireFamily::OpenAiChatCompletions),
            endpoint_families: ProviderFact::operator_declared(endpoints),
            ..Self::default()
        }
    }
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
    /// Structured facts used by policy filters. Unknown values are omitted,
    /// never inferred from a provider name.
    #[serde(default)]
    pub metadata: ProviderMetadata,
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
        metadata: ProviderMetadata::verified_openai_chat(
            AuthPlacementKind::Bearer,
            vec![ProviderEndpointFamily::Models, ProviderEndpointFamily::ChatCompletions],
        ),
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
        metadata: ProviderMetadata::verified_openai_chat(
            AuthPlacementKind::Bearer,
            vec![ProviderEndpointFamily::ChatCompletions],
        ),
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
        metadata: ProviderMetadata {
            wire_family: ProviderFact::verified(ProviderWireFamily::VertexGenerateContent),
            endpoint_families: ProviderFact::verified(vec![
                ProviderEndpointFamily::GenerateContent,
                ProviderEndpointFamily::Predict,
            ]),
            // This surface accepts both bearer and x-goog-api-key forms, so
            // there is no single placement fact to publish.
            ..ProviderMetadata::default()
        },
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
        metadata: ProviderMetadata {
            wire_family: ProviderFact::verified(ProviderWireFamily::AntigravityInternal),
            endpoint_families: ProviderFact::verified(vec![
                ProviderEndpointFamily::GenerateContent,
            ]),
            auth_placement: ProviderFact::verified(AuthPlacementKind::Bearer),
            ..ProviderMetadata::default()
        },
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
    let metadata = ProviderMetadata::operator_openai(&operations);
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
        metadata,
    }
}
