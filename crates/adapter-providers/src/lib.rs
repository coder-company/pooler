//! Provider-specific routing contracts that stay outside Pooler's protocol core.
//!
//! This crate deliberately does not translate OpenAI, Gemini, or other semantic
//! payloads. It supplies the provider integration details that cannot be safely
//! inferred from a wire format: endpoint construction, authentication placement,
//! bounded model discovery, and quota/failure classification.

#![forbid(unsafe_code)]

mod contracts;
mod endpoint;
mod failure;
mod models;

pub use contracts::{
    antigravity_compatibility_profile, kimi_coding_profile, kimi_open_platform_profile,
    openai_compatible_profile, vertex_profile, AuthEndpointKind, AuthMode, ContractEvidence,
    AuthPlacementKind, ContractStability, DiscoveryMode, FactProvenance, MetadataProvenance,
    ProviderAuthEndpoint, ProviderDataPolicy, ProviderEndpointFamily, ProviderFact, ProviderKind,
    ProviderMetadata, ProviderOperation, ProviderParameter, ProviderPricing, ProviderPrivacy,
    ProviderProfile, ProviderQuantization, ProviderSurface, ProviderWireFamily, QuotaSignal,
    WireProtocol, CLI_PROXY_API_REFERENCE_REVISION,
};
pub use endpoint::{
    AdapterError, AntigravityAdapter, AntigravityCompatibilityConfig,
    AntigravityCompatibilityPaths, AuthPlacement, DangerousCustomEndpoint, KimiAdapter,
    KimiSurface, OpenAiCompatibleAdapter, ProviderAdapter, ProviderAuthorization, VertexAdapter,
    VertexAddressing, VertexAuthentication,
};
pub use failure::{
    AntigravityCreditParser, AntigravityCredits, ProviderParseError, ProviderQuota,
    ProviderQuotaScope, ProviderQuotaWindow, ProviderResponseClassifier,
};
pub use models::{
    try_into_catalog_response, AntigravityModelHints, DiscoveredModel, ModelDiscoveryError,
    ProviderModelParser,
};
