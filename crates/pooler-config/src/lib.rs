//! Source-aware Pooler configuration.
//!
//! This crate owns the administrative configuration boundary. YAML is parsed
//! into simple declarations, validated, and compiled once into immutable plans.
//! Secret values are never read here: only typed references are retained.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http::{uri::PathAndQuery, HeaderName, HeaderValue, Method};
pub use pooler_core::{
    BodyMode, Capability, CapabilitySet, ConfigGeneration, LossPolicy, RouteLimits,
};
use pooler_protocol::{
    DEFAULT_JSON_PATCH_MAX_POINTER_BYTES, DEFAULT_JSON_PATCH_MAX_POINTER_DEPTH,
    DEFAULT_JSON_PATCH_MAX_VALUE_BYTES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

mod loader;
mod route_match;
mod schema;
mod watch;

pub use loader::{load_path, render_path, ConfigLoader, LoadedConfig, DEFAULT_MAX_IMPORT_DEPTH};
pub use pooler_model_catalog::{
    AliasConfig as CatalogAliasConfig, KnownProvider, ProviderCatalog,
    RefreshConfig as CatalogRefreshConfig,
};
use route_match::{prefix_matches, template_matches};
pub use route_match::{RouteMatchError, RouteRequest};
pub use schema::{config_schema, render_config_schema, CONFIG_SCHEMA_VERSION};
pub use watch::{
    ConfigCandidate, ConfigWatcher, DEFAULT_RELOAD_DEBOUNCE, DEFAULT_RELOAD_POLL_INTERVAL,
};

/// Current configuration schema version.
pub const CONFIG_VERSION: u32 = 1;
/// Maximum number of transforms accepted for one route.
pub const MAX_REQUEST_STEPS: usize = 32;
/// Maximum aggregate serialized replacement bytes accepted for one route.
pub const MAX_REQUEST_STEP_TOTAL_VALUE_BYTES: usize = 1024 * 1024;
/// Default callback used by the local OAuth login flow when a provider does
/// not override it.
pub const DEFAULT_OAUTH_CALLBACK: &str = "http://localhost:1455/auth/callback";
/// Default maximum bytes sent to one external extension.
pub const DEFAULT_EXTENSION_MAX_INPUT_BYTES: u64 = 1024 * 1024;
/// Default maximum bytes accepted from one external extension.
pub const DEFAULT_EXTENSION_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
/// Default external extension timeout in milliseconds.
pub const DEFAULT_EXTENSION_TIMEOUT_MS: u64 = 5_000;
/// Default external extension RSS bound.
pub const DEFAULT_EXTENSION_MAX_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// Default number of concurrently supervised extension processes.
pub const DEFAULT_EXTENSION_MAX_CONCURRENCY: u32 = 4;
/// Default lifetime for an explicitly enabled route response cache.
pub const DEFAULT_ROUTE_CACHE_TTL: Duration = Duration::from_secs(1);
/// Default completed entries retained by one route response cache.
pub const DEFAULT_ROUTE_CACHE_MAX_ENTRIES: usize = 64;
/// Default response bytes retained by one route response cache.
pub const DEFAULT_ROUTE_CACHE_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum response-cache lifetime accepted by the strict configuration.
pub const MAX_ROUTE_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
/// Maximum completed entries accepted by the strict configuration.
pub const MAX_ROUTE_CACHE_ENTRIES: usize = 4096;
/// Maximum response bytes accepted by the strict configuration.
pub const MAX_ROUTE_CACHE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum request headers used in a response-cache key.
pub const MAX_ROUTE_CACHE_KEY_HEADERS: usize = 16;
/// Default maximum bytes accepted from one provider model-list response.
pub const DEFAULT_CATALOG_MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
/// Hard maximum bytes accepted from one provider model-list response.
pub const MAX_CATALOG_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Location of a declaration in its source document.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceLabel {
    /// Source name, normally a path or `stdin`.
    pub source: Arc<str>,
    /// Parser-provided one-based line, when exact coordinates are available.
    pub line: Option<usize>,
    /// Parser-provided one-based column, when exact coordinates are available.
    pub column: Option<usize>,
    /// Canonical configuration path of the declaration.
    pub path: Arc<str>,
}

impl SourceLabel {
    fn new(
        source: &Source,
        line: Option<usize>,
        column: Option<usize>,
        path: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            source: Arc::clone(&source.name),
            line,
            column,
            path: path.into(),
        }
    }

    /// Label the start of a source.
    #[must_use]
    pub fn start(source: &str) -> Self {
        Self {
            source: Arc::from(source),
            line: Some(1),
            column: Some(1),
            path: Arc::from("$"),
        }
    }
}

impl Display for SourceLabel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(
                formatter,
                "{}:{}:{} ({})",
                self.source, line, column, self.path
            )
        } else {
            write!(formatter, "{} ({})", self.source, self.path)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Source {
    name: Arc<str>,
    origins: Arc<BTreeMap<String, Arc<str>>>,
}

impl Source {
    fn new(name: impl Into<Arc<str>>, _text: impl Into<Arc<str>>) -> Self {
        Self {
            name: name.into(),
            origins: Arc::new(BTreeMap::new()),
        }
    }
}

/// A reference to a secret. This type intentionally has no value variant.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretRef {
    /// Environment variable name.
    Env(Arc<str>),
    /// File path.
    File(Arc<str>),
    /// Keyring service and account.
    Keyring {
        service: Arc<str>,
        account: Arc<str>,
    },
}

impl SecretRef {
    /// Parses a supported secret reference without reading it.
    pub fn parse(value: &str) -> Result<Self, SecretRefError> {
        let (scheme, payload) = value
            .split_once(':')
            .ok_or(SecretRefError::InvalidReference)?;
        if payload.is_empty() {
            return Err(SecretRefError::InvalidReference);
        }
        match scheme.to_ascii_lowercase().as_str() {
            "env" if valid_env_name(payload) => Ok(Self::Env(Arc::from(payload))),
            "env" => Err(SecretRefError::InvalidEnvironmentName),
            "file" => Ok(Self::File(Arc::from(payload))),
            "keyring" => {
                let (service, account) = payload
                    .split_once('/')
                    .filter(|(service, account)| !service.is_empty() && !account.is_empty())
                    .ok_or(SecretRefError::InvalidReference)?;
                Ok(Self::Keyring {
                    service: Arc::from(service),
                    account: Arc::from(account),
                })
            }
            "external" => Err(SecretRefError::UnknownScheme),
            "literal" | "raw" | "value" => Err(SecretRefError::LiteralNotAllowed),
            _ => Err(SecretRefError::UnknownScheme),
        }
    }

    /// Redacted reference representation for logs and rendering.
    #[must_use]
    pub fn redacted(&self) -> String {
        match self {
            Self::Env(name) => format!("env:{name}"),
            Self::File(path) => format!("file:{path}"),
            Self::Keyring { service, account } => format!("keyring:{service}/{account}"),
        }
    }

    /// Reference scheme.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Env(_) => "env",
            Self::File(_) => "file",
            Self::Keyring { .. } => "keyring",
        }
    }
}

impl Display for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted())
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretRef")
            .field(&self.redacted())
            .finish()
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Sanitized secret-reference error. It never contains the input string.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretRefError {
    /// Missing scheme or payload.
    #[error("invalid secret reference")]
    InvalidReference,
    /// Unsafe environment variable name.
    #[error("invalid environment secret name")]
    InvalidEnvironmentName,
    /// Literal secret values are forbidden.
    #[error("literal secret values are not allowed; use env:, file:, or keyring:")]
    LiteralNotAllowed,
    /// Unsupported scheme.
    #[error("unknown secret reference scheme")]
    UnknownScheme,
}

/// YAML configuration declarations.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Schema version.
    pub version: u32,
    /// Listener declarations keyed by ID.
    pub listeners: BTreeMap<String, ListenerConfig>,
    /// Upstream declarations keyed by ID. `providers` is accepted as an alias.
    #[serde(alias = "providers")]
    pub upstreams: BTreeMap<String, UpstreamConfig>,
    /// Public model declarations and their static upstream targets.
    pub models: Vec<ModelConfig>,
    /// Optional remote model discovery and public exposure policy.
    pub catalog: Option<ModelCatalogConfig>,
    /// Credential-bearing account declarations keyed by stable ID.
    pub accounts: BTreeMap<String, AccountConfig>,
    /// Compatibility alias for account declarations.
    #[serde(alias = "credentials")]
    pub credentials: BTreeMap<String, AccountConfig>,
    /// Named account pools used by selection policies.
    #[serde(alias = "pools")]
    pub account_pools: BTreeMap<String, AccountPoolConfig>,
    /// Named target-selection and retry policies.
    pub policies: BTreeMap<String, PolicyConfig>,
    /// Routes in declaration order.
    pub routes: Vec<RouteConfig>,
    /// Supervised external extension declarations keyed by stable ID.
    pub extensions: BTreeMap<String, ExtensionConfig>,
    /// Optional secure management listener. It is disabled by default.
    pub management: ManagementConfig,
    #[serde(skip)]
    source: Option<Source>,
}

impl Config {
    /// Parses a named YAML source.
    pub fn from_yaml(name: impl Into<Arc<str>>, text: &str) -> Result<Self, ConfigError> {
        let source = Source::new(name, text);
        let mut config: Self =
            serde_yml::from_str(text).map_err(|error| parse_error(&source, error))?;
        config.source = Some(source);
        validate_version(
            &config,
            config.source.as_ref().expect("source was just set"),
        )?;
        Ok(config)
    }

    /// Parses a configuration file path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        load_path(path)
    }

    pub(crate) fn set_origins(&mut self, origins: BTreeMap<String, Arc<str>>) {
        if let Some(source) = &mut self.source {
            source.origins = Arc::new(origins);
        }
    }

    /// Validates and compiles with generation one.
    pub fn compile(&self) -> Result<CompiledConfig, ConfigError> {
        self.compile_with_generation(1)
    }

    /// Validates and compiles with a caller-owned generation.
    pub fn compile_with_generation(&self, generation: u64) -> Result<CompiledConfig, ConfigError> {
        let source = self
            .source
            .clone()
            .unwrap_or_else(|| Source::new("<config>", ""));
        compile_config(self, &source, generation)
    }
}

/// Listener declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    /// TCP socket address or Unix path.
    pub bind: String,
    /// Inbound protocol policy. HTTP/1 is the safe default; `h2c` and
    /// `http2` explicitly opt into prior-knowledge HTTP/2 on cleartext
    /// listeners. `auto` accepts either HTTP/1 or an HTTP/2 preface.
    pub protocol: Option<String>,
    /// Convenience spelling for an explicit prior-knowledge HTTP/2 listener.
    /// This remains separate from `protocol` so configurations can be evolved
    /// without making cleartext HTTP/2 an accidental default.
    pub h2c: bool,
    /// Optional inbound TLS identity and handshake policy.
    pub tls: Option<ListenerTlsConfig>,
}

/// Inbound TLS configuration for a TCP listener.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerTlsConfig {
    /// PEM certificate chain. The file must be owner-readable and owner-only.
    #[serde(alias = "certificate", alias = "certificate_file", alias = "cert_file")]
    pub cert: String,
    /// PEM private key. The file must be owner-readable and owner-only.
    #[serde(alias = "private_key", alias = "private_key_file", alias = "key_file")]
    pub key: String,
    /// ALPN protocol identifiers offered by this listener.
    #[serde(default = "default_tls_alpn", alias = "alpn_protocols")]
    pub alpn: Vec<String>,
    /// Maximum time allowed for one TLS handshake.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub handshake_timeout: Option<Duration>,
    /// Optional client certificate verification policy.
    pub client_auth: Option<ListenerClientAuthConfig>,
}

/// Optional mTLS trust configuration for an inbound TLS listener.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerClientAuthConfig {
    /// PEM certificate-authority bundle used to verify client certificates.
    #[serde(alias = "ca_file", alias = "certificate_authority")]
    pub ca: String,
    /// Require a client certificate when true; otherwise allow anonymous TLS.
    #[serde(default)]
    pub required: bool,
}

/// Upstream/provider declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Direct URL shorthand.
    pub url: Option<String>,
    /// Direct base URL shorthand.
    pub base_url: Option<String>,
    /// Transport object.
    pub transport: Option<TransportConfig>,
    /// Authentication reference.
    pub auth: Option<AuthConfig>,
    /// OAuth provider declaration.
    pub oauth: Option<OAuthConfig>,
    /// Native provider declaration.
    pub native: Option<NativeProviderConfig>,
    /// Query parameters this upstream requires on every request, such as Azure
    /// OpenAI's `api-version`. A parameter the caller already sent is left
    /// alone, so these act as defaults rather than overrides.
    pub query: BTreeMap<String, String>,
    /// Known provider whose base URL addresses this upstream, such as `groq`.
    /// An explicit `url` or `transport.base_url` takes precedence.
    pub known_provider: Option<String>,
}

/// Supervised external extension declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionConfig {
    /// Absolute executable path.
    pub command: Option<String>,
    /// Absolute path to a no-import WebAssembly module. Exactly one of
    /// `command` and `wasm` is required.
    pub wasm: Option<String>,
    /// Fixed arguments passed to every invocation.
    pub args: Vec<String>,
    /// Explicit operation grants (`inspect`, `transform`).
    pub capabilities: Vec<String>,
    /// Resource bounds for child processes.
    pub limits: Option<ExtensionLimitsConfig>,
}

/// Resource bounds for one external extension.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionLimitsConfig {
    /// Maximum serialized request bytes.
    pub max_input_bytes: Option<u64>,
    /// Maximum serialized response bytes.
    pub max_output_bytes: Option<u64>,
    /// Maximum invocation wall-clock duration.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub timeout: Option<Duration>,
    /// Maximum child RSS where supported by the host.
    pub max_memory_bytes: Option<u64>,
    /// Maximum concurrent child processes.
    pub max_concurrency: Option<u32>,
}

/// Public model declaration.
///
/// Models are deliberately represented as a list in the source schema.  This
/// keeps the stable public model ID next to its targets and leaves room for
/// source-aware duplicate diagnostics during compilation.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    /// Stable public model ID.
    pub id: String,
    /// Static upstream targets tried in declaration order.
    pub targets: Vec<ModelTargetConfig>,
}

/// Static target for a public model.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ModelTargetConfig {
    /// Upstream/provider ID.
    #[serde(alias = "upstream")]
    pub provider: Option<String>,
    /// Model name sent to the upstream.
    pub upstream_model: Option<String>,
    /// Capabilities advertised by this target.
    pub capabilities: Vec<String>,
    /// Semantic codecs advertised by this target.
    pub codecs: Vec<String>,
}

/// Optional remote model-catalog declaration.
///
/// Sources reference existing upstream IDs. Authentication therefore stays on
/// the upstream/account boundary and is never copied into catalog policy.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelCatalogConfig {
    /// Discovery sources and their public exposure policy.
    pub sources: Vec<ModelCatalogSourceConfig>,
    /// Bounds shared by fetch, parse, merge, and publication.
    pub refresh: CatalogRefreshConfig,
    /// Per-model overrides applied after the merge, keyed by public model ID.
    ///
    /// These are the operator's last word: they withhold a discovered model,
    /// rename it, or restate its capabilities and request-shaping facts
    /// regardless of what the provider reported.
    pub overrides: Vec<pooler_model_catalog::ModelOverrideConfig>,
}

/// Provider response parser selected for one catalog source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogParserKind {
    /// OpenAI-compatible `data[]` model list.
    #[serde(rename = "openai", alias = "open_ai")]
    OpenAi,
    /// Kimi Open Platform model list with documented baseline capabilities.
    Kimi,
    /// Google Gemini `models[]` list.
    Gemini,
    /// Vertex publisher-model catalog export.
    Vertex,
    /// Antigravity compatibility model-hint response.
    Antigravity,
}

impl CatalogParserKind {
    /// Stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Kimi => "kimi",
            Self::Gemini => "gemini",
            Self::Vertex => "vertex",
            Self::Antigravity => "antigravity",
        }
    }

    const fn default_path(self) -> Option<&'static str> {
        match self {
            Self::OpenAi | Self::Kimi => Some("/v1/models"),
            Self::Gemini => Some("/v1beta/models"),
            Self::Vertex => None,
            Self::Antigravity => Some("/v1internal:fetchAvailableModels"),
        }
    }
}

/// One remote discovery source plus its public exposure rules.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelCatalogSourceConfig {
    /// Stable, non-secret source ID.
    pub id: String,
    /// Existing upstream/provider ID used for transport and authentication.
    pub provider: String,
    /// Optional existing account used for account or native OAuth auth.
    pub account: Option<String>,
    /// Bounded provider response parser.
    pub parser: Option<CatalogParserKind>,
    /// Relative provider endpoint. OpenAI/Kimi/Antigravity have safe defaults.
    pub path: Option<String>,
    /// Maximum response bytes for this source.
    pub max_response_bytes: Option<u64>,
    /// Provider key used to look up vendored request-shaping facts. Omitted
    /// means the source `provider` ID, which matches the upstream catalog for
    /// conventionally named providers such as `openai` or `anthropic`.
    pub model_facts_provider: Option<String>,
    /// Optional client-visible namespace, emitted as `prefix/model`.
    pub prefix: Option<String>,
    /// Higher-priority targets are listed first.
    pub priority: i32,
    /// Exact upstream-to-public aliases.
    pub aliases: Vec<CatalogAliasConfig>,
    /// Optional case-sensitive exact or `*` wildcard allow-list.
    pub included_models: Vec<String>,
    /// Case-sensitive exact or `*` wildcard deny-list.
    pub excluded_models: Vec<String>,
}

/// One credential-bearing account.
///
/// The secret remains a [`SecretRef`].  Configuration compilation never reads
/// or materializes the referenced value.  `provider` is required so account
/// selection cannot accidentally cross provider boundaries.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AccountConfig {
    /// Provider/upstream ID that owns this account.
    #[serde(alias = "upstream")]
    pub provider: Option<String>,
    /// Reference to the account's credential material.
    pub secret: Option<SecretRef>,
    /// Explicit credential kind. OAuth is inferred for legacy native OAuth
    /// accounts; all other accounts default to API keys.
    pub auth_kind: Option<AccountAuthKind>,
    /// Whether selection may use this account. Omitted means enabled.
    pub enabled: Option<bool>,
    /// Relative selection weight. Omitted means one.
    pub weight: Option<u32>,
    /// Optional per-account in-flight bound.
    pub max_concurrency: Option<u32>,
    /// Optional provider-local project, organization, tenant, or billing ID
    /// used only to group project-scoped quota state.
    pub quota_project: Option<String>,
}

/// Authentication material configured for an account.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccountAuthKind {
    /// Usage-based API key resolved from `secret`.
    ApiKey,
    /// Encrypted OAuth credential, including subscription accounts.
    #[serde(rename = "oauth", alias = "o_auth", alias = "subscription")]
    OAuth,
}

impl AccountAuthKind {
    /// Stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::OAuth => "oauth",
        }
    }
}

/// A named, explicit account pool.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AccountPoolConfig {
    /// Account IDs in selection order.
    #[serde(alias = "members")]
    pub accounts: Vec<String>,
}

/// Named target-selection and retry policy declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Selection strategy and affinity settings.
    pub selection: Option<SelectionConfig>,
    /// Retry and replay budget.
    pub retry: Option<RetryConfig>,
    /// Stream bootstrap budget used before commitment.
    pub stream: Option<StreamConfig>,
    /// Optional health cooldown applied by policy consumers.
    pub cooldown: Option<CooldownConfig>,
    /// Optional named account pool. A policy without this field may still be
    /// used for static provider targets.
    #[serde(alias = "pool")]
    pub account_pool: Option<String>,
}

/// Target-selection declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SelectionConfig {
    /// One of the documented deterministic strategies.
    pub strategy: Option<String>,
    /// Named account pool to use for this selection policy.
    #[serde(alias = "pool")]
    pub account_pool: Option<String>,
    /// Inline account IDs. Prefer a named account pool for reusable policy.
    pub accounts: Vec<String>,
    /// Compatibility shorthand for an affinity lifetime.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub session_affinity: Option<Duration>,
    /// Full affinity declaration.
    pub affinity: Option<AffinityConfig>,
}

/// Session-affinity declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AffinityConfig {
    /// Deterministic key source, for example `header:x-session-id`.
    pub key: Option<String>,
    /// Lifetime of an affinity binding.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub ttl: Option<Duration>,
    /// Whether an unavailable target may be safely rebound.
    pub rebind: Option<bool>,
}

/// Retry and replay budget declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RetryConfig {
    /// Total attempts, including the initial attempt.
    #[serde(alias = "max_attempts")]
    pub maximum_attempts: Option<u32>,
    /// Maximum distinct accounts used by one request.
    #[serde(alias = "max_credentials")]
    pub maximum_credentials: Option<u32>,
    /// Maximum distinct providers used by one request.
    #[serde(alias = "max_providers")]
    pub maximum_providers: Option<u32>,
    /// Maximum wall time spent waiting between attempts.
    #[serde(
        default,
        alias = "max_elapsed",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub maximum_elapsed: Option<Duration>,
    /// Maximum provider recovery delay honored by one request.
    #[serde(
        default,
        alias = "max_recovery_wait",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub maximum_recovery_wait: Option<Duration>,
    /// Lower bound for exponential retry delay.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub base_delay: Option<Duration>,
    /// Upper bound for one retry delay.
    #[serde(
        default,
        alias = "max_delay",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub maximum_delay: Option<Duration>,
    /// Upper bound for the sum of retry delays.
    #[serde(
        default,
        alias = "max_total_delay",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub maximum_total_delay: Option<Duration>,
    /// Retries are legal only before downstream commitment. Must be true when
    /// more than one attempt is configured.
    pub before_commit_only: Option<bool>,
    /// Explicit upstream statuses eligible for a retry classification.
    #[serde(alias = "retryable_statuses")]
    pub statuses: Vec<u16>,
}

/// Stream bootstrap budget declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct StreamConfig {
    /// Number of events retained before commitment.
    pub bootstrap_events: Option<u32>,
    /// Number of bytes retained before commitment.
    #[serde(default, deserialize_with = "deserialize_optional_byte_size")]
    pub bootstrap_bytes: Option<u64>,
    /// Maximum time spent waiting for the initial response/events.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub bootstrap_timeout: Option<Duration>,
}

/// A policy-directed health cooldown declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct CooldownConfig {
    /// One of credential, credential_model, model, provider, provider_model,
    /// or route.
    pub scope: Option<String>,
    /// Positive cooldown lifetime.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub duration: Option<Duration>,
}

/// Upstream transport declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Transport kind, normally `http`, `https`, `ws`, or `wss`.
    pub kind: Option<String>,
    /// Base URL.
    pub base_url: Option<String>,
    /// Connection timeout such as `5s`.
    pub connect_timeout: Option<String>,
    /// Request timeout such as `30m`.
    pub request_timeout: Option<String>,
    /// Require HTTP/2 for this upstream connection. For cleartext `http`
    /// URLs this enables prior-knowledge h2c; it is never enabled by default.
    pub http2: bool,
}

/// Upstream authentication declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Authentication kind.
    pub kind: Option<String>,
    /// Secret reference.
    pub secret: Option<SecretRef>,
    /// Credential header name, required by and exclusive to `kind: header`.
    /// Providers that name their own credential header, such as Azure OpenAI
    /// with `api-key`, are configured here rather than compiled in.
    pub header: Option<String>,
    /// Non-secret prefix placed before the secret in a `kind: header` value,
    /// such as `Token ` for providers that expect a scheme they do not share
    /// with bearer authentication.
    pub value_prefix: Option<String>,
}

/// OAuth provider endpoints and public client configuration.
///
/// Token material is never part of configuration. The CLI and provider
/// implementation obtain it through the authentication boundary and retain
/// only protected handles.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthConfig {
    /// Authorization endpoint used to start an authorization-code flow.
    pub authorization_endpoint: Option<String>,
    /// Token endpoint used to exchange an authorization code.
    pub token_endpoint: Option<String>,
    /// Optional endpoint used to revoke a provider token.
    #[serde(alias = "revoke_endpoint")]
    pub revocation_endpoint: Option<String>,
    /// Optional identity endpoint used to discover the native account ID.
    pub identity_endpoint: Option<String>,
    /// Public OAuth client identifier.
    pub client_id: Option<String>,
    /// Requested OAuth scopes.
    pub scopes: Vec<String>,
    /// Loopback callback URI used by the local login flow.
    pub callback: Option<String>,
}

/// Native provider declaration.
///
/// `kind` identifies a compiled-in provider adapter. Provider-specific
/// behavior stays in the adapter; configuration contains only endpoints and
/// stable identifiers.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NativeProviderConfig {
    /// Compiled-in provider adapter identifier.
    pub kind: Option<String>,
    /// Optional provider quota endpoint.
    pub quota_endpoint: Option<String>,
}

/// Downstream authentication declaration.
///
/// Downstream authentication currently accepts the same secret-reference
/// shape as upstream authentication, but only bearer authentication is
/// compiled into a route plan.
pub type DownstreamAuthConfig = AuthConfig;

/// Secure management HTTP listener declaration.
///
/// Management is disabled unless `enabled` is true (or `bind` is supplied).
/// A loopback listener may run without authentication. Remote management is
/// rejected until a management TLS plan is available; raw bearer HTTP is not
/// a supported remote transport.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ManagementConfig {
    /// Whether the management listener is enabled.
    pub enabled: Option<bool>,
    /// TCP socket address or Unix socket path.
    #[serde(alias = "listen")]
    pub bind: Option<String>,
    /// Explicitly permit a non-loopback management listener.
    #[serde(alias = "allow_remote")]
    pub remote: Option<bool>,
    /// Bearer authentication for remote management access.
    #[serde(alias = "authentication")]
    pub auth: Option<AuthConfig>,
}

/// Route-level resource and timeout limits.
///
/// Numeric limits are expressed in their native units. Durations accept the
/// same `ms`, `s`, `m`, and `h` suffixes used by transport settings, or an
/// integer number of milliseconds.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RouteLimitsConfig {
    /// Maximum decompressed request body size.
    pub max_request_body_bytes: Option<u64>,
    /// Maximum buffered response body size.
    pub max_response_body_bytes: Option<u64>,
    /// Maximum number of request headers.
    pub max_header_count: Option<u32>,
    /// Maximum total request header bytes.
    pub max_header_bytes: Option<u64>,
    /// Maximum one transport frame or message.
    pub max_frame_bytes: Option<u64>,
    /// Maximum one SSE/event-semantic event.
    pub max_event_bytes: Option<u64>,
    /// Maximum bytes retained while deciding whether a stream is committed.
    pub max_bootstrap_bytes: Option<u64>,
    /// Maximum events retained while deciding whether a stream is committed.
    pub max_bootstrap_events: Option<u32>,
    /// Maximum bytes waiting in one bounded channel.
    pub max_queue_bytes: Option<u64>,
    /// Maximum items waiting in one bounded channel.
    pub max_queue_items: Option<u32>,
    /// End-to-end request timeout.
    #[serde(
        default = "default_request_timeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub request_timeout: Option<Duration>,
    /// Upstream connection/header timeout.
    #[serde(
        default = "default_connect_timeout",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub connect_timeout: Option<Duration>,
}

/// Route declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    /// Stable route ID.
    pub id: String,
    /// Listener ID.
    pub listen: Option<String>,
    /// Listener alias.
    pub listener: Option<String>,
    /// Match dimensions.
    #[serde(rename = "match")]
    pub route_match: Option<MatchConfig>,
    /// Optional downstream bearer authentication.
    #[serde(alias = "auth")]
    pub downstream_auth: Option<DownstreamAuthConfig>,
    /// Route-level resource and timeout limits.
    pub limits: Option<RouteLimitsConfig>,
    /// Optional short cache for fully buffered responses.
    pub cache: Option<CacheConfig>,
    /// Ingress body handling.
    pub ingress: Option<BodyConfig>,
    /// Ordered request transforms.
    pub request: Option<RequestConfig>,
    /// Response body handling.
    pub response: Option<BodyConfig>,
    /// Target declaration.
    pub target: Option<TargetValue>,
    /// Optional named selection/retry policy.
    pub policy: Option<String>,
    /// Upstream ID shorthand.
    pub upstream: Option<String>,
    /// Loss policy.
    pub loss_policy: Option<LossPolicy>,
    /// Explicit precedence override.
    pub priority: Option<i32>,
}

/// Optional bounded cache and in-flight coalescing policy for one route.
///
/// The cache is disabled unless `enabled: true` is explicit. Request-key
/// headers are an allowlist and are validated as non-sensitive names during
/// compilation.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Enable completed-response caching for this route.
    pub enabled: bool,
    /// Lifetime of a completed response. Defaults to one second.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub ttl: Option<Duration>,
    /// Maximum completed responses retained by this route.
    pub max_entries: Option<u32>,
    /// Maximum aggregate response bytes retained by this route.
    #[serde(default, deserialize_with = "deserialize_optional_byte_size")]
    pub max_bytes: Option<u64>,
    /// Allow equivalent misses to share one in-flight fetch.
    pub coalesce: Option<bool>,
    /// Additional non-sensitive request headers included in the cache key.
    pub key_headers: Vec<String>,
}

/// Route match dimensions.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MatchConfig {
    /// HTTP methods; empty means all methods.
    pub methods: Vec<String>,
    /// Singular method shorthand.
    pub method: Option<String>,
    /// Host constraint.
    pub host: Option<String>,
    /// Exact path.
    pub path: Option<String>,
    /// Template path.
    pub path_template: Option<String>,
    /// Prefix path.
    pub path_prefix: Option<String>,
    /// Header equality constraints.
    pub headers: BTreeMap<String, String>,
    /// Content-type constraints.
    pub content_types: Vec<String>,
    /// WebSocket upgrade constraint.
    pub websocket: Option<bool>,
}

/// Body mode and optional component IDs.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BodyConfig {
    /// Body mode.
    pub mode: Option<BodyMode>,
    /// Optional framing component applied before semantic decoding.
    pub framing: Option<String>,
    /// Decoder component.
    pub decoder: Option<String>,
    /// Encoder component.
    pub encoder: Option<String>,
    /// Inspector components.
    pub inspectors: Vec<String>,
}

/// Request-side transforms applied in declaration order.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RequestConfig {
    /// Ordered transform steps.
    pub steps: Vec<RequestStepConfig>,
}

/// One request transform declaration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStepConfig {
    /// Built-in transform identifier.
    #[serde(rename = "use")]
    pub transform: String,
    /// Transform parameters from the `with` mapping.
    #[serde(rename = "with")]
    pub parameters: TransformParameters,
}

/// Parameters accepted by the built-in JSON request transforms.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformParameters {
    /// RFC 6901 JSON pointer to replace.
    pub pointer: Option<String>,
    /// Replacement JSON value.
    pub value: serde_json::Value,
    /// Required model prefix for conditional transforms.
    #[serde(alias = "model_prefix")]
    pub prefix: Option<String>,
}

/// Target may be an upstream ID or an object.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum TargetValue {
    /// Upstream ID shorthand.
    Name(String),
    /// Structured target.
    Config(TargetConfig),
}

/// Structured route target.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TargetConfig {
    /// Upstream ID (`provider` is accepted as an alias).
    #[serde(alias = "provider")]
    pub upstream: Option<String>,
    /// Upstream path override.
    #[serde(alias = "upstream_path")]
    pub path: Option<String>,
    /// Extract a public model ID from the JSON request and select its first
    /// static registry target.
    pub model_from: Option<String>,
    /// Named selection/retry policy.
    pub policy: Option<String>,
    /// Capabilities advertised by this route target.
    pub capabilities: Vec<String>,
    /// Semantic codecs advertised by this route target.
    pub codecs: Vec<String>,
    /// Provider endpoint family this route speaks on the wire.
    ///
    /// When the target upstream names a known provider, compilation rejects a
    /// route whose family that provider does not document. This is what stops
    /// a gateway from mounting an Anthropic path against an OpenAI upstream
    /// and calling the result compatibility.
    pub endpoint_family: Option<String>,
}

/// Immutable listener plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ListenerProtocol {
    /// Accept only HTTP/1.1 requests.
    #[default]
    Http1,
    /// Detect HTTP/1.1 or an HTTP/2 prior-knowledge preface.
    Auto,
    /// Require an HTTP/2 prior-knowledge preface on cleartext connections.
    H2c,
}

/// Immutable inbound TLS plan for a listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerTlsPlan {
    cert: Arc<str>,
    key: Arc<str>,
    alpn: Vec<Arc<str>>,
    handshake_timeout: Duration,
    client_auth: Option<ListenerClientAuthPlan>,
}

impl ListenerTlsPlan {
    /// PEM certificate-chain path.
    #[must_use]
    pub fn cert(&self) -> &str {
        &self.cert
    }

    /// PEM private-key path.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Configured ALPN protocol identifiers.
    #[must_use]
    pub fn alpn(&self) -> &[Arc<str>] {
        &self.alpn
    }

    /// Maximum time allowed for one handshake.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Optional client certificate policy.
    #[must_use]
    pub const fn client_auth(&self) -> Option<&ListenerClientAuthPlan> {
        self.client_auth.as_ref()
    }
}

/// Immutable client certificate verification plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerClientAuthPlan {
    ca: Arc<str>,
    required: bool,
}

impl ListenerClientAuthPlan {
    /// PEM trust-bundle path.
    #[must_use]
    pub fn ca(&self) -> &str {
        &self.ca
    }

    /// Whether a client certificate is mandatory.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerPlan {
    id: Arc<str>,
    bind: Arc<str>,
    protocol: ListenerProtocol,
    tls: Option<ListenerTlsPlan>,
    source: SourceLabel,
}

impl ListenerPlan {
    /// Listener ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Bind address/path.
    #[must_use]
    pub fn bind(&self) -> &str {
        &self.bind
    }

    /// Inbound protocol policy.
    #[must_use]
    pub const fn protocol(&self) -> ListenerProtocol {
        self.protocol
    }

    /// Optional inbound TLS plan.
    #[must_use]
    pub const fn tls(&self) -> Option<&ListenerTlsPlan> {
        self.tls.as_ref()
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Immutable upstream plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamPlan {
    id: Arc<str>,
    url: Url,
    transport: Arc<str>,
    http2: bool,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    auth: Option<AuthPlan>,
    oauth: Option<OAuthPlan>,
    native: Option<NativeProviderPlan>,
    known_provider: Option<Arc<str>>,
    required_headers: BTreeMap<Arc<str>, Arc<str>>,
    query: UpstreamQuery,
    source: SourceLabel,
}

impl UpstreamPlan {
    /// Upstream ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Validated URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Transport kind.
    #[must_use]
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Whether this upstream requires HTTP/2, including cleartext h2c prior
    /// knowledge when its transport is `http`.
    #[must_use]
    pub const fn http2(&self) -> bool {
        self.http2
    }

    /// Optional connection timeout.
    #[must_use]
    pub const fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }

    /// Optional request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Option<Duration> {
        self.request_timeout
    }

    /// Authentication plan.
    #[must_use]
    pub fn auth(&self) -> Option<&AuthPlan> {
        self.auth.as_ref()
    }

    /// OAuth provider configuration, when this upstream is OAuth-backed.
    #[must_use]
    pub fn oauth(&self) -> Option<&OAuthPlan> {
        self.oauth.as_ref()
    }

    /// Native provider configuration, when this upstream uses a compiled-in
    /// provider adapter.
    #[must_use]
    pub fn native(&self) -> Option<&NativeProviderPlan> {
        self.native.as_ref()
    }

    /// Vendored provider integration selected by this upstream.
    #[must_use]
    pub fn known_provider(&self) -> Option<&str> {
        self.known_provider.as_deref()
    }

    /// Non-secret headers required by the selected provider integration.
    #[must_use]
    pub fn required_headers(&self) -> &BTreeMap<Arc<str>, Arc<str>> {
        &self.required_headers
    }

    /// Query parameters this upstream requires, in declaration order.
    #[must_use]
    pub fn query(&self) -> &[(Arc<str>, Arc<str>)] {
        &self.query
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Immutable OAuth provider configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthPlan {
    authorization_endpoint: Url,
    token_endpoint: Url,
    revocation_endpoint: Option<Url>,
    identity_endpoint: Option<Url>,
    client_id: Arc<str>,
    scopes: Vec<Arc<str>>,
    callback: Url,
}

impl OAuthPlan {
    /// Authorization endpoint.
    #[must_use]
    pub const fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Token exchange endpoint.
    #[must_use]
    pub const fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Optional token revocation endpoint.
    #[must_use]
    pub fn revocation_endpoint(&self) -> Option<&Url> {
        self.revocation_endpoint.as_ref()
    }

    /// Optional identity endpoint used to associate a native account.
    #[must_use]
    pub fn identity_endpoint(&self) -> Option<&Url> {
        self.identity_endpoint.as_ref()
    }

    /// Public OAuth client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Requested OAuth scopes.
    #[must_use]
    pub fn scopes(&self) -> &[Arc<str>] {
        &self.scopes
    }

    /// Loopback callback URI.
    #[must_use]
    pub const fn callback(&self) -> &Url {
        &self.callback
    }
}

/// Immutable native provider configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderPlan {
    kind: Arc<str>,
    quota_endpoint: Option<Url>,
}

impl NativeProviderPlan {
    /// Compiled-in provider adapter identifier.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Optional quota endpoint.
    #[must_use]
    pub fn quota_endpoint(&self) -> Option<&Url> {
        self.quota_endpoint.as_ref()
    }
}

/// Immutable account plan containing only a secret reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountPlan {
    id: Arc<str>,
    provider: Arc<str>,
    secret: Option<SecretRef>,
    auth_kind: AccountAuthKind,
    enabled: bool,
    weight: u32,
    max_concurrency: Option<u32>,
    quota_project: Option<Arc<str>>,
    source: SourceLabel,
}

impl AccountPlan {
    /// Stable account ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Owning provider/upstream ID.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Secret reference. The referenced value is never held in this plan.
    #[must_use]
    pub const fn secret(&self) -> Option<&SecretRef> {
        self.secret.as_ref()
    }

    /// Explicit credential kind used by runtime authorization.
    #[must_use]
    pub const fn auth_kind(&self) -> AccountAuthKind {
        self.auth_kind
    }

    /// Whether selection may use this account.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Relative selection weight.
    #[must_use]
    pub const fn weight(&self) -> u32 {
        self.weight
    }

    /// Optional in-flight bound.
    #[must_use]
    pub const fn max_concurrency(&self) -> Option<u32> {
        self.max_concurrency
    }

    /// Optional provider-local project grouping for scoped quota state.
    ///
    /// The value is configuration metadata, not credential material. Runtime
    /// policy hashes it before it enters diagnostics or persisted quota state.
    #[must_use]
    pub fn quota_project(&self) -> Option<&str> {
        self.quota_project.as_deref()
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Compatibility name for credential-oriented callers.
pub type CredentialPlan = AccountPlan;

/// Immutable account pool plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountPoolPlan {
    id: Arc<str>,
    accounts: Vec<Arc<str>>,
    source: SourceLabel,
}

impl AccountPoolPlan {
    /// Stable pool ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Account IDs in deterministic selection order.
    #[must_use]
    pub fn accounts(&self) -> &[Arc<str>] {
        &self.accounts
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Supported deterministic account-selection strategies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionStrategy {
    /// Rotate through eligible accounts in declaration order.
    RoundRobin,
    /// Smoothly distribute weighted traffic.
    SmoothWeightedRoundRobin,
    /// Keep using the first eligible account.
    FillFirst,
    /// Choose the account with the fewest in-flight requests.
    LeastInFlight,
    /// Score health, weight, and current eligibility.
    HealthWeighted,
    /// Try accounts in explicit declaration order.
    OrderedFallback,
}

impl SelectionStrategy {
    /// Parse the documented configuration spelling.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "round_robin" => Some(Self::RoundRobin),
            "smooth_weighted_round_robin" => Some(Self::SmoothWeightedRoundRobin),
            "fill_first" => Some(Self::FillFirst),
            "least_in_flight" => Some(Self::LeastInFlight),
            "health_weighted" => Some(Self::HealthWeighted),
            "ordered_fallback" => Some(Self::OrderedFallback),
            _ => None,
        }
    }

    /// Stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::SmoothWeightedRoundRobin => "smooth_weighted_round_robin",
            Self::FillFirst => "fill_first",
            Self::LeastInFlight => "least_in_flight",
            Self::HealthWeighted => "health_weighted",
            Self::OrderedFallback => "ordered_fallback",
        }
    }
}

/// Immutable session-affinity plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinityPlan {
    key: Arc<str>,
    ttl: Duration,
    rebind: bool,
}

impl AffinityPlan {
    /// Deterministic key source.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Affinity lifetime.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Whether unavailable targets may be safely rebound.
    #[must_use]
    pub const fn rebind(&self) -> bool {
        self.rebind
    }
}

/// Immutable target-selection plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionPlan {
    strategy: SelectionStrategy,
    account_pool: Option<Arc<str>>,
    accounts: Vec<Arc<str>>,
    affinity: Option<AffinityPlan>,
}

impl SelectionPlan {
    /// Selection strategy.
    #[must_use]
    pub const fn strategy(&self) -> SelectionStrategy {
        self.strategy
    }

    /// Referenced named account pool, if any.
    #[must_use]
    pub fn account_pool(&self) -> Option<&str> {
        self.account_pool.as_deref()
    }

    /// Inline account IDs in declaration order.
    #[must_use]
    pub fn accounts(&self) -> &[Arc<str>] {
        &self.accounts
    }

    /// Session-affinity plan, if enabled.
    #[must_use]
    pub const fn affinity(&self) -> Option<&AffinityPlan> {
        self.affinity.as_ref()
    }
}

/// Immutable retry and replay budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPlan {
    maximum_attempts: u32,
    maximum_credentials: u32,
    maximum_providers: u32,
    maximum_elapsed: Option<Duration>,
    maximum_recovery_wait: Option<Duration>,
    base_delay: Duration,
    maximum_delay: Duration,
    maximum_total_delay: Duration,
    before_commit_only: bool,
    statuses: Vec<u16>,
}

impl RetryPlan {
    /// Total attempts, including the initial attempt.
    #[must_use]
    pub const fn maximum_attempts(&self) -> u32 {
        self.maximum_attempts
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.maximum_attempts
    }

    /// Maximum distinct accounts used by a request.
    #[must_use]
    pub const fn maximum_credentials(&self) -> u32 {
        self.maximum_credentials
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_credentials(&self) -> u32 {
        self.maximum_credentials
    }

    /// Maximum distinct providers used by a request.
    #[must_use]
    pub const fn maximum_providers(&self) -> u32 {
        self.maximum_providers
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_providers(&self) -> u32 {
        self.maximum_providers
    }

    /// Maximum elapsed retry wait.
    #[must_use]
    pub const fn maximum_elapsed(&self) -> Option<Duration> {
        self.maximum_elapsed
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_elapsed(&self) -> Option<Duration> {
        self.maximum_elapsed
    }

    /// Maximum provider recovery delay honored.
    #[must_use]
    pub const fn maximum_recovery_wait(&self) -> Option<Duration> {
        self.maximum_recovery_wait
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_recovery_wait(&self) -> Option<Duration> {
        self.maximum_recovery_wait
    }

    /// Base retry delay.
    #[must_use]
    pub const fn base_delay(&self) -> Duration {
        self.base_delay
    }

    /// Maximum delay for one retry.
    #[must_use]
    pub const fn maximum_delay(&self) -> Duration {
        self.maximum_delay
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_delay(&self) -> Duration {
        self.maximum_delay
    }

    /// Maximum sum of retry delays.
    #[must_use]
    pub const fn maximum_total_delay(&self) -> Duration {
        self.maximum_total_delay
    }

    /// Alias for callers using the shorter policy vocabulary.
    #[must_use]
    pub const fn max_total_delay(&self) -> Duration {
        self.maximum_total_delay
    }

    /// Whether retry is restricted to the pre-commit stage.
    #[must_use]
    pub const fn before_commit_only(&self) -> bool {
        self.before_commit_only
    }

    /// Explicit retryable status set.
    #[must_use]
    pub fn statuses(&self) -> &[u16] {
        &self.statuses
    }

    /// Whether the status is explicitly eligible for retry classification.
    #[must_use]
    pub fn allows_status(&self, status: u16) -> bool {
        self.statuses.binary_search(&status).is_ok()
    }
}

/// Immutable stream bootstrap budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamPlan {
    bootstrap_events: u32,
    bootstrap_bytes: u64,
    bootstrap_timeout: Duration,
}

impl StreamPlan {
    /// Event bound before downstream commitment.
    #[must_use]
    pub const fn bootstrap_events(&self) -> u32 {
        self.bootstrap_events
    }

    /// Byte bound before downstream commitment.
    #[must_use]
    pub const fn bootstrap_bytes(&self) -> u64 {
        self.bootstrap_bytes
    }

    /// Time bound before downstream commitment.
    #[must_use]
    pub const fn bootstrap_timeout(&self) -> Duration {
        self.bootstrap_timeout
    }
}

/// Supported health-cooldown scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CooldownScopePlan {
    Credential,
    CredentialModel,
    Model,
    Provider,
    ProviderModel,
    Route,
}

impl CooldownScopePlan {
    /// Parse a documented cooldown scope.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "credential" => Some(Self::Credential),
            "credential_model" => Some(Self::CredentialModel),
            "model" => Some(Self::Model),
            "provider" => Some(Self::Provider),
            "provider_model" => Some(Self::ProviderModel),
            "route" => Some(Self::Route),
            _ => None,
        }
    }

    /// Stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::CredentialModel => "credential_model",
            Self::Model => "model",
            Self::Provider => "provider",
            Self::ProviderModel => "provider_model",
            Self::Route => "route",
        }
    }
}

/// Immutable cooldown declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CooldownPlan {
    scope: CooldownScopePlan,
    duration: Duration,
}

impl CooldownPlan {
    /// Cooldown scope.
    #[must_use]
    pub const fn scope(&self) -> CooldownScopePlan {
        self.scope
    }

    /// Cooldown duration.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }
}

/// Immutable named policy plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPlan {
    id: Arc<str>,
    selection: SelectionPlan,
    retry: RetryPlan,
    stream: StreamPlan,
    cooldown: Option<CooldownPlan>,
    account_pool: Option<Arc<str>>,
    source: SourceLabel,
}

impl PolicyPlan {
    /// Stable policy ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Selection plan.
    #[must_use]
    pub const fn selection(&self) -> &SelectionPlan {
        &self.selection
    }

    /// Retry plan.
    #[must_use]
    pub const fn retry(&self) -> &RetryPlan {
        &self.retry
    }

    /// Stream bootstrap plan.
    #[must_use]
    pub const fn stream(&self) -> &StreamPlan {
        &self.stream
    }

    /// Optional cooldown plan.
    #[must_use]
    pub const fn cooldown(&self) -> Option<&CooldownPlan> {
        self.cooldown.as_ref()
    }

    /// Named account pool, if configured.
    #[must_use]
    pub fn account_pool(&self) -> Option<&str> {
        self.account_pool.as_deref()
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Immutable static target for a public model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelTargetPlan {
    provider: Arc<str>,
    upstream_model: Arc<str>,
    capabilities: CapabilitySet,
    codecs: Vec<Arc<str>>,
}

impl ModelTargetPlan {
    /// Upstream/provider ID.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Model name sent to the upstream.
    #[must_use]
    pub fn upstream_model(&self) -> &str {
        &self.upstream_model
    }

    /// Capabilities advertised by the target.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// Semantic codecs advertised by this target.
    #[must_use]
    pub fn codecs(&self) -> &[Arc<str>] {
        &self.codecs
    }
}

/// Immutable public model registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPlan {
    id: Arc<str>,
    targets: Vec<ModelTargetPlan>,
    source: SourceLabel,
}

impl ModelPlan {
    /// Public model ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Static targets in declaration order.
    #[must_use]
    pub fn targets(&self) -> &[ModelTargetPlan] {
        &self.targets
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Immutable remote model-catalog plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCatalogPlan {
    limits: pooler_model_catalog::RefreshLimits,
    sources: Vec<ModelCatalogSourcePlan>,
    overrides: pooler_model_catalog::ModelOverrides,
}

impl ModelCatalogPlan {
    /// Bounds shared by fetch, parse, merge, and publication.
    #[must_use]
    pub const fn limits(&self) -> pooler_model_catalog::RefreshLimits {
        self.limits
    }

    /// Sources in deterministic priority/source-ID order.
    #[must_use]
    pub fn sources(&self) -> &[ModelCatalogSourcePlan] {
        &self.sources
    }

    /// Per-model operator overrides applied after every merge.
    #[must_use]
    pub const fn overrides(&self) -> &pooler_model_catalog::ModelOverrides {
        &self.overrides
    }
}

/// Immutable transport/parser plan for one catalog source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCatalogSourcePlan {
    source: pooler_model_catalog::CatalogSource,
    parser: CatalogParserKind,
    account: Option<Arc<str>>,
    path: Arc<str>,
    max_response_bytes: u64,
    model_facts_provider: Arc<str>,
    source_label: SourceLabel,
}

impl ModelCatalogSourcePlan {
    /// Public exposure policy compiled by `pooler-model-catalog`.
    #[must_use]
    pub const fn source(&self) -> &pooler_model_catalog::CatalogSource {
        &self.source
    }

    /// Provider response parser.
    #[must_use]
    pub const fn parser(&self) -> CatalogParserKind {
        self.parser
    }

    /// Explicit account used for discovery authentication.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Relative provider endpoint including an optional query string.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Maximum response bytes accepted before parser allocation.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    /// Provider key used against the vendored model-facts snapshot.
    #[must_use]
    pub fn model_facts_provider(&self) -> &str {
        &self.model_facts_provider
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source_label(&self) -> &SourceLabel {
        &self.source_label
    }
}

/// Immutable resource bounds for a supervised external extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionLimitsPlan {
    max_input_bytes: u64,
    max_output_bytes: u64,
    timeout: Duration,
    max_memory_bytes: u64,
    max_concurrency: u32,
}

impl ExtensionLimitsPlan {
    /// Maximum serialized request bytes.
    #[must_use]
    pub const fn max_input_bytes(&self) -> u64 {
        self.max_input_bytes
    }

    /// Maximum serialized response bytes.
    #[must_use]
    pub const fn max_output_bytes(&self) -> u64 {
        self.max_output_bytes
    }

    /// Maximum invocation duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Maximum child RSS where supported by the host.
    #[must_use]
    pub const fn max_memory_bytes(&self) -> u64 {
        self.max_memory_bytes
    }

    /// Maximum concurrent child processes.
    #[must_use]
    pub const fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }
}

/// Immutable supervised external extension plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionPlan {
    id: Arc<str>,
    command: Option<Arc<str>>,
    wasm: Option<Arc<str>>,
    args: Vec<Arc<str>>,
    capabilities: BTreeSet<Arc<str>>,
    limits: ExtensionLimitsPlan,
    source: SourceLabel,
}

impl ExtensionPlan {
    /// Stable extension ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Absolute executable path.
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    /// Absolute WebAssembly module path, when this is a WASM extension.
    #[must_use]
    pub fn wasm(&self) -> Option<&str> {
        self.wasm.as_deref()
    }

    /// Fixed executable arguments.
    #[must_use]
    pub fn args(&self) -> &[Arc<str>] {
        &self.args
    }

    /// Granted capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &BTreeSet<Arc<str>> {
        &self.capabilities
    }

    /// Whether a capability is granted.
    #[must_use]
    pub fn allows(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    /// Resource bounds.
    #[must_use]
    pub const fn limits(&self) -> ExtensionLimitsPlan {
        self.limits
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// A compiled request transform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestTransform {
    /// Replace a value at a JSON pointer.
    JsonSet {
        /// RFC 6901 pointer.
        pointer: Arc<str>,
        /// Replacement value.
        value: serde_json::Value,
    },
    /// Replace a value when the request model starts with a prefix.
    JsonSetWhenModelPrefix {
        /// Required model prefix.
        prefix: Arc<str>,
        /// RFC 6901 pointer.
        pointer: Arc<str>,
        /// Replacement value.
        value: serde_json::Value,
    },
}

impl RequestTransform {
    /// JSON pointer targeted by this transform.
    #[must_use]
    pub fn pointer(&self) -> &str {
        match self {
            Self::JsonSet { pointer, .. } | Self::JsonSetWhenModelPrefix { pointer, .. } => pointer,
        }
    }

    /// Replacement value.
    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        match self {
            Self::JsonSet { value, .. } | Self::JsonSetWhenModelPrefix { value, .. } => value,
        }
    }

    /// Conditional model prefix, when this transform has one.
    #[must_use]
    pub fn model_prefix(&self) -> Option<&str> {
        match self {
            Self::JsonSet { .. } => None,
            Self::JsonSetWhenModelPrefix { prefix, .. } => Some(prefix),
        }
    }
}

/// Immutable authentication plan containing only a secret reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPlan {
    kind: Arc<str>,
    secret: SecretRef,
    header: Option<CredentialHeader>,
}

/// Query parameters an upstream requires, in declaration order.
pub type UpstreamQuery = Arc<[(Arc<str>, Arc<str>)]>;

/// A credential header named by configuration rather than by an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialHeader {
    name: Arc<str>,
    value_prefix: Option<Arc<str>>,
}

impl AuthPlan {
    /// Authentication kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Secret reference.
    #[must_use]
    pub const fn secret(&self) -> &SecretRef {
        &self.secret
    }

    /// Credential header name for `kind: header`, absent for every other kind.
    #[must_use]
    pub fn header(&self) -> Option<&str> {
        self.header.as_ref().map(|header| header.name.as_ref())
    }

    /// Non-secret prefix placed before the secret in a `kind: header` value.
    #[must_use]
    pub fn value_prefix(&self) -> Option<&str> {
        self.header
            .as_ref()
            .and_then(|header| header.value_prefix.as_deref())
    }
}

/// Immutable read-only management listener plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementPlan {
    bind: Arc<str>,
    remote: bool,
    auth: Option<AuthPlan>,
    source: SourceLabel,
}

impl ManagementPlan {
    /// Bound TCP socket address or Unix socket path.
    #[must_use]
    pub fn bind(&self) -> &str {
        &self.bind
    }

    /// Whether remote management access was explicitly enabled.
    #[must_use]
    pub const fn remote(&self) -> bool {
        self.remote
    }

    /// Bearer authentication plan, when configured.
    #[must_use]
    pub fn auth(&self) -> Option<&AuthPlan> {
        self.auth.as_ref()
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Immutable path matcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathPattern {
    /// Exact path.
    Exact(Arc<str>),
    /// Template path.
    Template(Arc<str>),
    /// Prefix path.
    Prefix(Arc<str>),
    /// Any path.
    Any,
}

impl PathPattern {
    /// Pattern text (`/` for any path).
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Exact(path) | Self::Template(path) | Self::Prefix(path) => path,
            Self::Any => "/",
        }
    }

    /// Path precedence rank.
    #[must_use]
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Exact(_) => 3,
            Self::Template(_) => 2,
            Self::Prefix(_) => 1,
            Self::Any => 0,
        }
    }
}

/// Immutable route matcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchPlan {
    methods: Vec<Arc<str>>,
    host: Option<Arc<str>>,
    path: PathPattern,
    headers: BTreeMap<Arc<str>, Arc<str>>,
    content_types: Vec<Arc<str>>,
    websocket: Option<bool>,
}

impl MatchPlan {
    /// Methods, canonicalized to uppercase.
    #[must_use]
    pub fn methods(&self) -> &[Arc<str>] {
        &self.methods
    }

    /// Host constraint.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Path pattern.
    #[must_use]
    pub const fn path(&self) -> &PathPattern {
        &self.path
    }

    /// Header constraints.
    #[must_use]
    pub const fn headers(&self) -> &BTreeMap<Arc<str>, Arc<str>> {
        &self.headers
    }

    /// Number of header constraints.
    #[must_use]
    pub fn header_specificity(&self) -> usize {
        self.headers.len()
    }

    /// Content-type constraints.
    #[must_use]
    pub fn content_types(&self) -> &[Arc<str>] {
        &self.content_types
    }

    /// WebSocket constraint.
    #[must_use]
    pub const fn websocket(&self) -> Option<bool> {
        self.websocket
    }
}

fn is_template_segment(segment: &str) -> bool {
    segment.len() > 2
        && segment.starts_with('{')
        && segment.ends_with('}')
        && segment[1..segment.len() - 1]
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
}

/// Immutable body plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyPlan {
    mode: BodyMode,
    framing: Option<Arc<str>>,
    decoder: Option<Arc<str>>,
    encoder: Option<Arc<str>>,
    inspectors: Vec<Arc<str>>,
}

/// Immutable bounded response-cache policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePlan {
    enabled: bool,
    ttl: Duration,
    max_entries: usize,
    max_bytes: u64,
    coalesce: bool,
    key_headers: Vec<Arc<str>>,
}

impl CachePlan {
    /// Whether completed-response caching is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Completed-response lifetime.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Maximum completed entries.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Maximum aggregate response bytes.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Whether equivalent misses may share one in-flight fetch.
    #[must_use]
    pub const fn coalesce(&self) -> bool {
        self.coalesce
    }

    /// Additional non-sensitive request headers included in cache keys.
    #[must_use]
    pub fn key_headers(&self) -> &[Arc<str>] {
        &self.key_headers
    }
}

impl BodyPlan {
    /// Body mode.
    #[must_use]
    pub const fn mode(&self) -> BodyMode {
        self.mode
    }

    /// Framing component.
    #[must_use]
    pub fn framing(&self) -> Option<&str> {
        self.framing.as_deref()
    }

    /// Decoder component.
    #[must_use]
    pub fn decoder(&self) -> Option<&str> {
        self.decoder.as_deref()
    }

    /// Encoder component.
    #[must_use]
    pub fn encoder(&self) -> Option<&str> {
        self.encoder.as_deref()
    }

    /// Inspector components.
    #[must_use]
    pub fn inspectors(&self) -> &[Arc<str>] {
        &self.inspectors
    }
}

/// Immutable target plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPlan {
    upstream: Arc<str>,
    path: Option<Arc<str>>,
    model_source: Option<ModelSource>,
    policy: Option<Arc<str>>,
    capabilities: CapabilitySet,
    codecs: Vec<Arc<str>>,
}

/// JSON model value used for static model-registry selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelSource {
    /// Model after configured request transforms have run.
    Request,
    /// Model captured before any request transform runs.
    Inspected,
}

impl TargetPlan {
    /// Upstream ID.
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Optional path override.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Whether the request model selects a static model-registry target.
    #[must_use]
    pub const fn model_source(&self) -> Option<ModelSource> {
        self.model_source
    }

    /// Named selection/retry policy.
    #[must_use]
    pub fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }

    /// Capabilities advertised by this route target.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// Semantic codecs advertised by this route target.
    #[must_use]
    pub fn codecs(&self) -> &[Arc<str>] {
        &self.codecs
    }
}

/// Immutable route plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    id: Arc<str>,
    listener: Arc<str>,
    matcher: MatchPlan,
    ingress: BodyPlan,
    request_steps: Vec<RequestTransform>,
    external_transforms: Vec<Arc<str>>,
    response: BodyPlan,
    cache: Option<CachePlan>,
    target: TargetPlan,
    downstream_auth: Option<AuthPlan>,
    limits: RouteLimits,
    loss_policy: LossPolicy,
    priority: i32,
    order: usize,
    source: SourceLabel,
}

impl RoutePlan {
    /// Route ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Listener ID.
    #[must_use]
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// Match plan.
    #[must_use]
    pub const fn matcher(&self) -> &MatchPlan {
        &self.matcher
    }

    /// Ingress plan.
    #[must_use]
    pub const fn ingress(&self) -> &BodyPlan {
        &self.ingress
    }

    /// Ordered request transforms.
    #[must_use]
    pub fn request_steps(&self) -> &[RequestTransform] {
        &self.request_steps
    }

    /// Ordered supervised external transform IDs.
    #[must_use]
    pub fn external_transforms(&self) -> &[Arc<str>] {
        &self.external_transforms
    }

    /// Response plan.
    #[must_use]
    pub const fn response(&self) -> &BodyPlan {
        &self.response
    }

    /// Optional bounded response-cache policy.
    #[must_use]
    pub const fn cache(&self) -> Option<&CachePlan> {
        self.cache.as_ref()
    }

    /// Target plan.
    #[must_use]
    pub const fn target(&self) -> &TargetPlan {
        &self.target
    }

    /// Optional downstream bearer authentication.
    #[must_use]
    pub fn downstream_auth(&self) -> Option<&AuthPlan> {
        self.downstream_auth.as_ref()
    }

    /// Route-level resource and timeout limits.
    #[must_use]
    pub const fn limits(&self) -> &RouteLimits {
        &self.limits
    }

    /// Loss policy.
    #[must_use]
    pub const fn loss_policy(&self) -> LossPolicy {
        self.loss_policy
    }

    /// Explicit priority.
    #[must_use]
    pub const fn priority(&self) -> i32 {
        self.priority
    }

    /// Original declaration order.
    #[must_use]
    pub const fn config_order(&self) -> usize {
        self.order
    }

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }

    /// Precedence key used by the route table.
    #[must_use]
    pub fn precedence(&self) -> Precedence {
        Precedence {
            path_specificity: self.matcher.path.specificity(),
            header_specificity: self.matcher.headers.len(),
            priority: self.priority,
            config_order: self.order,
        }
    }
}

/// Route precedence. Higher path/header/priority wins; lower config order wins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Precedence {
    /// Exact/template/prefix/any rank.
    pub path_specificity: u8,
    /// Number of header constraints.
    pub header_specificity: usize,
    /// Explicit priority.
    pub priority: i32,
    /// Original declaration order.
    pub config_order: usize,
}

/// Immutable compiled configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
    generation: u64,
    listeners: BTreeMap<Arc<str>, ListenerPlan>,
    upstreams: BTreeMap<Arc<str>, UpstreamPlan>,
    accounts: BTreeMap<Arc<str>, AccountPlan>,
    account_pools: BTreeMap<Arc<str>, AccountPoolPlan>,
    policies: BTreeMap<Arc<str>, PolicyPlan>,
    models: BTreeMap<Arc<str>, ModelPlan>,
    catalog: Option<ModelCatalogPlan>,
    extensions: BTreeMap<Arc<str>, ExtensionPlan>,
    routes: Vec<RoutePlan>,
    management: Option<ManagementPlan>,
}

impl CompiledConfig {
    /// Generation associated with this plan.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Return a copy tagged with a different runtime generation.
    ///
    /// The route plans themselves remain immutable. A server uses this when
    /// publishing a successfully reloaded candidate so selection records and
    /// diagnostics can identify the generation that admitted a request.
    #[must_use]
    pub fn with_generation(&self, generation: u64) -> Self {
        let mut config = self.clone();
        config.generation = generation;
        config
    }

    /// Compare route plans while deliberately ignoring the generation marker.
    #[must_use]
    pub fn equivalent(&self, other: &Self) -> bool {
        self.listeners == other.listeners
            && self.upstreams == other.upstreams
            && self.accounts == other.accounts
            && self.account_pools == other.account_pools
            && self.policies == other.policies
            && self.models == other.models
            && self.catalog == other.catalog
            && self.extensions == other.extensions
            && self.routes == other.routes
            && self.management == other.management
    }

    /// Listener plans keyed by ID.
    #[must_use]
    pub const fn listeners(&self) -> &BTreeMap<Arc<str>, ListenerPlan> {
        &self.listeners
    }

    /// Upstream plans keyed by ID.
    #[must_use]
    pub const fn upstreams(&self) -> &BTreeMap<Arc<str>, UpstreamPlan> {
        &self.upstreams
    }

    /// Account plans keyed by stable ID.
    #[must_use]
    pub const fn accounts(&self) -> &BTreeMap<Arc<str>, AccountPlan> {
        &self.accounts
    }

    /// Compatibility alias for credential-oriented callers.
    #[must_use]
    pub const fn credentials(&self) -> &BTreeMap<Arc<str>, AccountPlan> {
        &self.accounts
    }

    /// Named account pool plans keyed by stable ID.
    #[must_use]
    pub const fn account_pools(&self) -> &BTreeMap<Arc<str>, AccountPoolPlan> {
        &self.account_pools
    }

    /// Named selection/retry policies keyed by stable ID.
    #[must_use]
    pub const fn policies(&self) -> &BTreeMap<Arc<str>, PolicyPlan> {
        &self.policies
    }

    /// Public model plans keyed by ID.
    #[must_use]
    pub const fn models(&self) -> &BTreeMap<Arc<str>, ModelPlan> {
        &self.models
    }

    /// Optional remote model discovery plan.
    #[must_use]
    pub const fn catalog(&self) -> Option<&ModelCatalogPlan> {
        self.catalog.as_ref()
    }

    /// Supervised external extension plans keyed by ID.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeMap<Arc<str>, ExtensionPlan> {
        &self.extensions
    }

    /// Routes sorted by deterministic precedence.
    #[must_use]
    pub fn routes(&self) -> &[RoutePlan] {
        &self.routes
    }

    /// Route lookup by ID.
    #[must_use]
    pub fn route(&self, id: &str) -> Option<&RoutePlan> {
        self.routes.iter().find(|route| route.id() == id)
    }

    /// Optional secure management listener.
    #[must_use]
    pub const fn management(&self) -> Option<&ManagementPlan> {
        self.management.as_ref()
    }
}

/// Configuration errors with source labels on every validation failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// YAML syntax/type failure.
    #[error("failed to parse YAML in {source_name}:{line}:{column}: {message}")]
    Parse {
        /// Source name.
        source_name: String,
        /// One-based line.
        line: usize,
        /// One-based column.
        column: usize,
        /// Sanitized parser message.
        message: String,
    },
    /// File read failure.
    #[error("failed to read configuration {path}: {message}")]
    Io {
        /// Source path.
        path: String,
        /// OS message.
        message: String,
    },
    /// Schema version mismatch.
    #[error("unsupported configuration version {version} at {label}; expected {expected}")]
    UnsupportedVersion {
        /// Found version.
        version: u32,
        /// Source label.
        label: SourceLabel,
        /// Expected version.
        expected: u32,
    },
    /// Invalid declaration.
    #[error("invalid configuration at {label}: {message}")]
    Invalid {
        /// Source label.
        label: SourceLabel,
        /// Safe message.
        message: String,
    },
    /// Named reference was not declared.
    #[error("missing {kind} `{name}` referenced at {label}")]
    MissingReference {
        /// Declaration kind.
        kind: &'static str,
        /// Referenced ID.
        name: String,
        /// Reference label.
        label: SourceLabel,
    },
    /// Duplicate route ID.
    #[error("duplicate route `{id}` at {second}; first declaration is at {first}")]
    DuplicateRoute {
        /// Route ID.
        id: String,
        /// First declaration.
        first: Box<SourceLabel>,
        /// Second declaration.
        second: Box<SourceLabel>,
    },
    /// Duplicate public model ID.
    #[error("duplicate model `{id}` at {second}; first declaration is at {first}")]
    DuplicateModel {
        /// Model ID.
        id: String,
        /// First declaration.
        first: Box<SourceLabel>,
        /// Second declaration.
        second: Box<SourceLabel>,
    },
    /// Indistinguishable routes at equal precedence.
    #[error("route conflict between `{first_route}` at {first} and `{second_route}` at {second}")]
    RouteConflict {
        /// First route ID.
        first_route: String,
        /// First declaration.
        first: Box<SourceLabel>,
        /// Second route ID.
        second_route: String,
        /// Second declaration.
        second: Box<SourceLabel>,
    },
}

/// Parse one source.
pub fn parse_yaml(name: impl Into<Arc<str>>, text: &str) -> Result<Config, ConfigError> {
    Config::from_yaml(name, text)
}

/// Parse and compile one source.
pub fn compile_yaml(name: impl Into<Arc<str>>, text: &str) -> Result<CompiledConfig, ConfigError> {
    Config::from_yaml(name, text)?.compile()
}

fn compile_config(
    config: &Config,
    source: &Source,
    generation: u64,
) -> Result<CompiledConfig, ConfigError> {
    validate_version(config, source)?;
    let mut listeners = BTreeMap::new();
    for (id, declaration) in &config.listeners {
        let label = declaration_label(source, "listeners", id, listeners.len());
        validate_id("listener", id, &label)?;
        validate_bind(&declaration.bind, &label)?;
        let protocol = compile_listener_protocol(declaration, &label)?;
        let tls = compile_listener_tls(declaration, protocol, &label)?;
        listeners.insert(
            Arc::from(id.as_str()),
            ListenerPlan {
                id: Arc::from(id.as_str()),
                bind: Arc::from(declaration.bind.trim()),
                protocol,
                tls,
                source: label,
            },
        );
    }

    let mut upstreams = BTreeMap::new();
    for (id, declaration) in &config.upstreams {
        let label = upstream_label(source, id, upstreams.len());
        validate_id("upstream", id, &label)?;
        let known = compile_known_provider(declaration, &label)?;
        let known_entry = known.map(|(_, provider)| provider);
        let (url, transport, http2, connect_timeout, request_timeout) =
            compile_upstream(declaration, known_entry, &label)?;
        let (oauth, native) = compile_provider_auth(declaration, known_entry, &label)?;
        let auth = compile_upstream_auth(declaration, known_entry, &label)?;
        let required_headers = known_entry.map_or_else(
            || Ok(BTreeMap::new()),
            |provider| compile_headers(&provider.integration.required_headers, &label),
        )?;
        let query = compile_upstream_query(declaration, known_entry, &label)?;
        upstreams.insert(
            Arc::from(id.as_str()),
            UpstreamPlan {
                id: Arc::from(id.as_str()),
                url,
                transport,
                http2,
                connect_timeout,
                request_timeout,
                auth,
                oauth,
                native,
                known_provider: known.map(|(id, _)| Arc::from(id)),
                required_headers,
                query,
                source: label,
            },
        );
    }

    let accounts = compile_accounts(config, source, &upstreams)?;
    let account_pools = compile_account_pools(config, source, &accounts)?;
    let policies = compile_policies(config, source, &accounts, &account_pools)?;
    let models = compile_models(config, source, &upstreams)?;
    let catalog = compile_catalog(config.catalog.as_ref(), source, &upstreams, &accounts)?;
    let extensions = compile_extensions(config, source)?;
    let management = compile_management(&config.management, source)?;

    let mut routes = Vec::with_capacity(config.routes.len());
    let mut route_ids = BTreeMap::new();
    for (order, declaration) in config.routes.iter().enumerate() {
        let label = route_label(source, order, &declaration.id);
        validate_id("route", &declaration.id, &label)?;
        if let Some(first) = route_ids.insert(declaration.id.clone(), label.clone()) {
            return Err(ConfigError::DuplicateRoute {
                id: declaration.id.clone(),
                first: Box::new(first),
                second: Box::new(label),
            });
        }
        let listener = declaration
            .listen
            .as_deref()
            .or(declaration.listener.as_deref())
            .ok_or_else(|| invalid(&label, "route requires listen"))?;
        if !listeners.contains_key(listener) {
            return Err(ConfigError::MissingReference {
                kind: "listener",
                name: listener.to_owned(),
                label: label.clone(),
            });
        }
        let matcher = compile_match(declaration.route_match.as_ref(), &label)?;
        let ingress = compile_body(
            declaration.ingress.as_ref(),
            BodyMode::Opaque,
            &label,
            "ingress",
        )?;
        validate_external_inspectors(&ingress, &extensions, &label, "ingress")?;
        let (request_steps, external_transforms) =
            compile_request(declaration.request.as_ref(), &label, &extensions)?;
        if (!request_steps.is_empty() || !external_transforms.is_empty())
            && ingress.mode() != BodyMode::Patch
        {
            return Err(invalid(
                &label,
                "JSON request transforms require patch ingress mode",
            ));
        }
        let needs_model_inspector = request_steps
            .iter()
            .any(|step| matches!(step, RequestTransform::JsonSetWhenModelPrefix { .. }));
        if needs_model_inspector
            && !ingress
                .inspectors()
                .iter()
                .any(|inspector| inspector.as_ref() == "inspect.openai.model")
        {
            return Err(invalid(
                &label,
                "model-prefix transforms require inspect.openai.model",
            ));
        }
        let response = compile_body(
            declaration.response.as_ref(),
            ingress.mode(),
            &label,
            "response",
        )?;
        validate_external_inspectors(&response, &extensions, &label, "response")?;
        let cache = compile_cache(declaration.cache.as_ref(), ingress.mode(), &label)?;
        let target = compile_target(declaration, &label, &upstreams, &policies)?;
        if cache.is_some() && target.model_source().is_some() {
            return Err(invalid(
                &label,
                "response cache cannot be used with dynamic model target selection",
            ));
        }
        if cache.is_some() && target.policy().is_some() {
            return Err(invalid(
                &label,
                "response cache cannot be used with selection policy routes",
            ));
        }
        if cache.is_some() && target.policy().is_some() {
            return Err(invalid(
                &label,
                "response cache cannot be used with policy-based target selection",
            ));
        }
        if matcher.websocket() == Some(true)
            && target.model_source().is_none()
            && !matches!(upstreams[target.upstream()].transport(), "ws" | "wss")
        {
            return Err(invalid(
                &label,
                "WebSocket routes require a ws or wss upstream transport",
            ));
        }
        if target.model_source().is_some()
            && !matches!(ingress.mode(), BodyMode::Patch | BodyMode::Semantic)
        {
            return Err(invalid(
                &label,
                "request model target selection requires patch or semantic ingress mode",
            ));
        }
        if target.model_source() == Some(ModelSource::Inspected)
            && (ingress.mode() == BodyMode::Semantic || !has_model_inspector(&ingress))
        {
            return Err(invalid(
                &label,
                "inspected model target selection requires patch ingress with inspect.openai.model",
            ));
        }
        let downstream_auth =
            compile_downstream_auth(declaration.downstream_auth.as_ref(), &label)?;
        if listener_requires_auth(&listeners[listener]) && downstream_auth.is_none() {
            return Err(invalid(
                &label,
                "routes on non-loopback listeners require downstream authentication",
            ));
        }
        let limits = compile_limits(declaration.limits.as_ref(), &label)?;
        if declaration.loss_policy.is_some()
            && !matches!(ingress.mode(), BodyMode::Semantic | BodyMode::Patch)
        {
            return Err(invalid(
                &label,
                "loss_policy requires semantic or patch ingress",
            ));
        }
        // Semantic ingress converts between protocols, where an unrepresentable
        // field means the caller's request cannot be honored, so the default
        // rejects. Patch ingress forwards the caller's own body and only rewrites
        // what reaching the selected target requires; rejecting by default there
        // would fail requests the provider serves once the body is shaped for it.
        let default_loss_policy = if ingress.mode() == BodyMode::Patch {
            LossPolicy::Degrade
        } else {
            LossPolicy::Reject
        };
        routes.push(RoutePlan {
            id: Arc::from(declaration.id.as_str()),
            listener: Arc::from(listener),
            matcher,
            ingress,
            request_steps,
            external_transforms,
            response,
            cache,
            target,
            downstream_auth,
            limits,
            loss_policy: declaration.loss_policy.unwrap_or(default_loss_policy),
            priority: declaration.priority.unwrap_or(0),
            order,
            source: label,
        });
    }

    detect_conflicts(&routes)?;
    routes.sort_by(compare_routes);
    Ok(CompiledConfig {
        generation,
        listeners,
        upstreams,
        accounts,
        account_pools,
        policies,
        models,
        catalog,
        extensions,
        routes,
        management,
    })
}

fn compile_listener_protocol(
    declaration: &ListenerConfig,
    label: &SourceLabel,
) -> Result<ListenerProtocol, ConfigError> {
    let Some(protocol) = declaration.protocol.as_deref() else {
        return Ok(if declaration.h2c {
            ListenerProtocol::H2c
        } else {
            ListenerProtocol::Http1
        });
    };
    let protocol = protocol.trim().to_ascii_lowercase();
    let selected = match protocol.as_str() {
        "http1" | "http/1.1" | "h1" => ListenerProtocol::Http1,
        "auto" | "http1+http2" | "http1-or-http2" => ListenerProtocol::Auto,
        "h2c" | "http2" | "http/2" | "h2" => ListenerProtocol::H2c,
        _ => return Err(invalid(label, "unsupported listener protocol")),
    };
    if declaration.h2c && selected != ListenerProtocol::H2c {
        return Err(invalid(
            label,
            "listener h2c cannot be combined with a non-HTTP/2 protocol",
        ));
    }
    Ok(selected)
}

fn compile_listener_tls(
    declaration: &ListenerConfig,
    protocol: ListenerProtocol,
    label: &SourceLabel,
) -> Result<Option<ListenerTlsPlan>, ConfigError> {
    let Some(tls) = declaration.tls.as_ref() else {
        return Ok(None);
    };
    if declaration.bind.starts_with('/') || declaration.bind.starts_with("unix:") {
        return Err(invalid(label, "TLS is supported only on TCP listeners"));
    }
    if protocol == ListenerProtocol::H2c {
        return Err(invalid(
            label,
            "TLS listeners cannot use cleartext h2c protocol",
        ));
    }
    let cert = nonempty(Some(tls.cert.clone()))
        .ok_or_else(|| invalid(label, "TLS certificate path must not be empty"))?;
    let key = nonempty(Some(tls.key.clone()))
        .ok_or_else(|| invalid(label, "TLS private-key path must not be empty"))?;
    if tls.alpn.is_empty() {
        return Err(invalid(label, "TLS ALPN list must not be empty"));
    }
    let mut alpn = Vec::with_capacity(tls.alpn.len());
    for protocol in &tls.alpn {
        let protocol = protocol.trim();
        if protocol.is_empty()
            || protocol.len() > 255
            || !protocol.is_ascii()
            || protocol.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid(label, "TLS ALPN protocol is invalid"));
        }
        alpn.push(Arc::from(protocol));
    }
    let offers_h2 = alpn
        .iter()
        .any(|protocol: &Arc<str>| protocol.as_ref() == "h2");
    if offers_h2 && protocol != ListenerProtocol::Auto {
        return Err(invalid(
            label,
            "TLS ALPN h2 requires listener protocol auto",
        ));
    }
    let handshake_timeout = tls
        .handshake_timeout
        .unwrap_or_else(default_tls_handshake_timeout);
    if handshake_timeout.is_zero() || handshake_timeout > Duration::from_secs(300) {
        return Err(invalid(
            label,
            "TLS handshake timeout must be between 1ms and 5m",
        ));
    }
    let client_auth = tls
        .client_auth
        .as_ref()
        .map(|client_auth| {
            let ca = nonempty(Some(client_auth.ca.clone()))
                .ok_or_else(|| invalid(label, "TLS client CA path must not be empty"))?;
            Ok(ListenerClientAuthPlan {
                ca,
                required: client_auth.required,
            })
        })
        .transpose()?;
    Ok(Some(ListenerTlsPlan {
        cert,
        key,
        alpn,
        handshake_timeout,
        client_auth,
    }))
}

fn default_tls_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}

fn listener_requires_auth(listener: &ListenerPlan) -> bool {
    listener
        .bind()
        .parse::<SocketAddr>()
        .map_or(true, |address| !address.ip().is_loopback())
}

type CompiledTransport = (Url, Arc<str>, bool, Option<Duration>, Option<Duration>);

const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);
const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);
const DEFAULT_RETRY_TOTAL_DELAY: Duration = Duration::from_secs(60);
const DEFAULT_STREAM_BOOTSTRAP_EVENTS: u32 = 1;
const DEFAULT_STREAM_BOOTSTRAP_BYTES: u64 = 64 * 1024;
const DEFAULT_STREAM_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

fn compile_accounts(
    config: &Config,
    source: &Source,
    upstreams: &BTreeMap<Arc<str>, UpstreamPlan>,
) -> Result<BTreeMap<Arc<str>, AccountPlan>, ConfigError> {
    let mut accounts = BTreeMap::new();
    for (declarations, collection) in [
        (&config.accounts, "accounts"),
        (&config.credentials, "credentials"),
    ] {
        for (id, declaration) in declarations {
            let label = account_label(source, collection, id);
            validate_id("account", id, &label)?;
            if accounts.contains_key(id.as_str()) {
                return Err(invalid(&label, "duplicate account declaration"));
            }
            let provider = declaration
                .provider
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid(&label, "account requires provider"))?;
            if !upstreams.contains_key(provider) {
                return Err(ConfigError::MissingReference {
                    kind: "upstream",
                    name: provider.to_owned(),
                    label,
                });
            }
            let upstream = &upstreams[provider];
            let inferred_oauth = upstream.oauth().is_some()
                || upstream
                    .native()
                    .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"));
            let auth_kind = declaration.auth_kind.unwrap_or(if inferred_oauth {
                AccountAuthKind::OAuth
            } else {
                AccountAuthKind::ApiKey
            });
            let secret = declaration.secret.as_ref();
            if auth_kind == AccountAuthKind::ApiKey && secret.is_none() {
                return Err(invalid(
                    &label,
                    "API-key account requires a secret reference",
                ));
            }
            if secret.is_some_and(|secret| {
                !matches!(
                    secret,
                    SecretRef::Env(_) | SecretRef::File(_) | SecretRef::Keyring { .. }
                )
            }) {
                return Err(invalid(&label, "account secret reference is unsupported"));
            }
            if auth_kind == AccountAuthKind::OAuth
                && upstream.oauth().is_none()
                && upstream
                    .native()
                    .is_none_or(|native| !native.kind().eq_ignore_ascii_case("codex"))
            {
                return Err(invalid(
                    &label,
                    "OAuth account requires explicit upstream oauth configuration",
                ));
            }
            if auth_kind == AccountAuthKind::ApiKey
                && upstream
                    .native()
                    .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
            {
                return Err(invalid(
                    &label,
                    "API-key account cannot use the native Codex subscription upstream",
                ));
            }
            let weight = declaration.weight.unwrap_or(1);
            if weight == 0 {
                return Err(invalid(&label, "account weight must be greater than zero"));
            }
            if declaration.max_concurrency == Some(0) {
                return Err(invalid(
                    &label,
                    "account max_concurrency must be greater than zero",
                ));
            }
            let quota_project = declaration
                .quota_project
                .as_deref()
                .map(|value| {
                    validate_id("quota project", value, &label)?;
                    Ok::<Arc<str>, ConfigError>(Arc::from(value))
                })
                .transpose()?;
            accounts.insert(
                Arc::from(id.as_str()),
                AccountPlan {
                    id: Arc::from(id.as_str()),
                    provider: Arc::from(provider),
                    secret: secret.cloned(),
                    auth_kind,
                    enabled: declaration.enabled.unwrap_or(true),
                    weight,
                    max_concurrency: declaration.max_concurrency,
                    quota_project,
                    source: label,
                },
            );
        }
    }
    Ok(accounts)
}

fn compile_account_pools(
    config: &Config,
    source: &Source,
    accounts: &BTreeMap<Arc<str>, AccountPlan>,
) -> Result<BTreeMap<Arc<str>, AccountPoolPlan>, ConfigError> {
    let mut pools = BTreeMap::new();
    for (id, declaration) in &config.account_pools {
        let label = pool_label(source, id);
        validate_id("account pool", id, &label)?;
        if declaration.accounts.is_empty() {
            return Err(invalid(
                &label,
                "account pool requires at least one account",
            ));
        }
        let mut members = Vec::with_capacity(declaration.accounts.len());
        let mut seen = BTreeSet::new();
        for account in &declaration.accounts {
            let account = account.trim();
            if account.is_empty() || !seen.insert(account.to_owned()) {
                return Err(invalid(
                    &label,
                    "account pool contains an empty or duplicate account ID",
                ));
            }
            if !accounts.contains_key(account) {
                return Err(ConfigError::MissingReference {
                    kind: "account",
                    name: account.to_owned(),
                    label: label.clone(),
                });
            }
            members.push(Arc::from(account.to_owned()));
        }
        pools.insert(
            Arc::from(id.as_str()),
            AccountPoolPlan {
                id: Arc::from(id.as_str()),
                accounts: members,
                source: label,
            },
        );
    }
    Ok(pools)
}

fn compile_policies(
    config: &Config,
    source: &Source,
    accounts: &BTreeMap<Arc<str>, AccountPlan>,
    pools: &BTreeMap<Arc<str>, AccountPoolPlan>,
) -> Result<BTreeMap<Arc<str>, PolicyPlan>, ConfigError> {
    let mut policies = BTreeMap::new();
    for (id, declaration) in &config.policies {
        let label = policy_label(source, id);
        validate_id("policy", id, &label)?;
        let (selection, selection_pool) = compile_selection(
            declaration.selection.as_ref(),
            declaration.account_pool.as_deref(),
            accounts,
            pools,
            &label,
        )?;
        let retry = compile_retry(declaration.retry.as_ref(), &label)?;
        let stream = compile_stream(declaration.stream.as_ref(), &label)?;
        let cooldown = compile_cooldown(declaration.cooldown.as_ref(), &label)?;
        policies.insert(
            Arc::from(id.as_str()),
            PolicyPlan {
                id: Arc::from(id.as_str()),
                selection,
                retry,
                stream,
                cooldown,
                account_pool: selection_pool,
                source: label,
            },
        );
    }
    Ok(policies)
}

fn compile_selection(
    declaration: Option<&SelectionConfig>,
    policy_pool: Option<&str>,
    accounts: &BTreeMap<Arc<str>, AccountPlan>,
    pools: &BTreeMap<Arc<str>, AccountPoolPlan>,
    label: &SourceLabel,
) -> Result<(SelectionPlan, Option<Arc<str>>), ConfigError> {
    let selection_is_explicit = declaration.is_some();
    let declaration = declaration.cloned().unwrap_or_default();
    let strategy = match declaration.strategy.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => SelectionStrategy::parse(value).ok_or_else(|| {
            invalid(
                label,
                "unknown selection strategy; expected round_robin, smooth_weighted_round_robin, fill_first, least_in_flight, health_weighted, or ordered_fallback",
            )
        })?,
        Some(_) => return Err(invalid(label, "selection strategy must not be empty")),
        None if selection_is_explicit => {
            return Err(invalid(label, "selection requires strategy"));
        }
        None => SelectionStrategy::OrderedFallback,
    };
    let nested_pool = declaration
        .account_pool
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let policy_pool = policy_pool.map(str::trim).filter(|v| !v.is_empty());
    if nested_pool.is_some() && policy_pool.is_some() {
        return Err(invalid(
            label,
            "selection.account_pool and policy.account_pool cannot both be set",
        ));
    }
    let pool = nested_pool.or(policy_pool);
    if let Some(pool) = pool {
        if !pools.contains_key(pool) {
            return Err(ConfigError::MissingReference {
                kind: "account pool",
                name: pool.to_owned(),
                label: label.clone(),
            });
        }
    }
    let mut inline_accounts = Vec::with_capacity(declaration.accounts.len());
    let mut seen = BTreeSet::new();
    for account in &declaration.accounts {
        let account = account.trim();
        if account.is_empty() || !seen.insert(account.to_owned()) {
            return Err(invalid(
                label,
                "selection accounts must be non-empty and unique",
            ));
        }
        if !accounts.contains_key(account) {
            return Err(ConfigError::MissingReference {
                kind: "account",
                name: account.to_owned(),
                label: label.clone(),
            });
        }
        inline_accounts.push(Arc::from(account.to_owned()));
    }
    if pool.is_some() && !inline_accounts.is_empty() {
        return Err(invalid(
            label,
            "selection cannot combine account_pool with inline accounts",
        ));
    }
    let affinity = compile_affinity(&declaration, label)?;
    let pool = pool.map(Arc::from);
    Ok((
        SelectionPlan {
            strategy,
            account_pool: pool.clone(),
            accounts: inline_accounts,
            affinity,
        },
        pool,
    ))
}

fn compile_affinity(
    declaration: &SelectionConfig,
    label: &SourceLabel,
) -> Result<Option<AffinityPlan>, ConfigError> {
    if declaration.session_affinity.is_some() && declaration.affinity.is_some() {
        return Err(invalid(
            label,
            "selection.session_affinity and selection.affinity cannot both be set",
        ));
    }
    if let Some(duration) = declaration.session_affinity {
        if duration.is_zero() {
            return Err(invalid(label, "session_affinity must be greater than zero"));
        }
        return Ok(Some(AffinityPlan {
            key: Arc::from("request.session_id"),
            ttl: duration,
            rebind: true,
        }));
    }
    let Some(affinity) = declaration.affinity.as_ref() else {
        return Ok(None);
    };
    let key = affinity
        .key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(label, "affinity requires key"))?;
    validate_affinity_key(key, label)?;
    let ttl = affinity
        .ttl
        .ok_or_else(|| invalid(label, "affinity requires ttl"))?;
    if ttl.is_zero() {
        return Err(invalid(label, "affinity ttl must be greater than zero"));
    }
    Ok(Some(AffinityPlan {
        key: Arc::from(key),
        ttl,
        rebind: affinity.rebind.unwrap_or(true),
    }))
}

fn validate_affinity_key(value: &str, label: &SourceLabel) -> Result<(), ConfigError> {
    if value.chars().any(char::is_control) || value.chars().any(char::is_whitespace) {
        return Err(invalid(
            label,
            "affinity key contains whitespace or control characters",
        ));
    }
    if let Some(header) = value.strip_prefix("header:") {
        if header.is_empty() || http::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
            return Err(invalid(label, "affinity header key is invalid"));
        }
        return Ok(());
    }
    let known = [
        "request.session_id",
        "semantic.session_id",
        "devin.conversation_id",
        "devin.cascade_id",
        "devin.execution_id",
        "openai.previous_response_id",
        "anthropic.metadata",
        "hash:selected_fields",
    ];
    if known.contains(&value) {
        Ok(())
    } else {
        Err(invalid(
            label,
            "unsupported affinity key; use header:<name> or a documented semantic key",
        ))
    }
}

fn compile_retry(
    declaration: Option<&RetryConfig>,
    label: &SourceLabel,
) -> Result<RetryPlan, ConfigError> {
    let declaration = declaration.cloned().unwrap_or_default();
    let maximum_attempts = declaration.maximum_attempts.unwrap_or(1);
    if maximum_attempts == 0 {
        return Err(invalid(
            label,
            "retry maximum_attempts must be greater than zero",
        ));
    }
    if maximum_attempts > 1 {
        if declaration.before_commit_only != Some(true) {
            return Err(invalid(
                label,
                "retry before_commit_only: true is required when maximum_attempts exceeds one",
            ));
        }
        if declaration.maximum_credentials.is_none() {
            return Err(invalid(
                label,
                "retry maximum_credentials is required when retries are enabled",
            ));
        }
        if declaration.statuses.is_empty() {
            return Err(invalid(
                label,
                "retry statuses are required when retries are enabled",
            ));
        }
    } else if declaration.before_commit_only == Some(false) {
        return Err(invalid(label, "retry before_commit_only must be true"));
    }
    let maximum_credentials = declaration.maximum_credentials.unwrap_or(1);
    let maximum_providers = declaration.maximum_providers.unwrap_or(maximum_attempts);
    if maximum_credentials == 0 || maximum_credentials > maximum_attempts {
        return Err(invalid(
            label,
            "retry maximum_credentials must be between one and maximum_attempts",
        ));
    }
    if maximum_providers == 0 || maximum_providers > maximum_attempts {
        return Err(invalid(
            label,
            "retry maximum_providers must be between one and maximum_attempts",
        ));
    }
    let base_delay = declaration.base_delay.unwrap_or(DEFAULT_RETRY_BASE_DELAY);
    let maximum_delay = declaration.maximum_delay.unwrap_or(DEFAULT_RETRY_MAX_DELAY);
    let maximum_total_delay = declaration
        .maximum_total_delay
        .unwrap_or(DEFAULT_RETRY_TOTAL_DELAY);
    if base_delay > maximum_delay || maximum_delay > maximum_total_delay {
        return Err(invalid(
            label,
            "retry delays must satisfy base_delay <= maximum_delay <= maximum_total_delay",
        ));
    }
    if declaration
        .maximum_elapsed
        .is_some_and(|value| value.is_zero())
        || declaration
            .maximum_recovery_wait
            .is_some_and(|value| value.is_zero())
    {
        return Err(invalid(
            label,
            "retry elapsed and recovery budgets must be greater than zero",
        ));
    }
    let mut statuses = declaration.statuses;
    for status in &statuses {
        if !matches!(*status, 408 | 425 | 429 | 500..=599) {
            return Err(invalid(
                label,
                "retry statuses must be 408, 425, 429, or a 5xx status",
            ));
        }
    }
    statuses.sort_unstable();
    statuses.dedup();
    Ok(RetryPlan {
        maximum_attempts,
        maximum_credentials,
        maximum_providers,
        maximum_elapsed: declaration
            .maximum_elapsed
            .or(Some(DEFAULT_RETRY_TOTAL_DELAY)),
        maximum_recovery_wait: declaration
            .maximum_recovery_wait
            .or(Some(DEFAULT_RETRY_TOTAL_DELAY)),
        base_delay,
        maximum_delay,
        maximum_total_delay,
        before_commit_only: true,
        statuses,
    })
}

fn compile_stream(
    declaration: Option<&StreamConfig>,
    label: &SourceLabel,
) -> Result<StreamPlan, ConfigError> {
    let declaration = declaration.cloned().unwrap_or_default();
    let bootstrap_events = declaration
        .bootstrap_events
        .unwrap_or(DEFAULT_STREAM_BOOTSTRAP_EVENTS);
    let bootstrap_bytes = declaration
        .bootstrap_bytes
        .unwrap_or(DEFAULT_STREAM_BOOTSTRAP_BYTES);
    let bootstrap_timeout = declaration
        .bootstrap_timeout
        .unwrap_or(DEFAULT_STREAM_BOOTSTRAP_TIMEOUT);
    if bootstrap_events == 0 || bootstrap_bytes == 0 || bootstrap_timeout.is_zero() {
        return Err(invalid(
            label,
            "stream bootstrap events, bytes, and timeout must be greater than zero",
        ));
    }
    Ok(StreamPlan {
        bootstrap_events,
        bootstrap_bytes,
        bootstrap_timeout,
    })
}

fn compile_cooldown(
    declaration: Option<&CooldownConfig>,
    label: &SourceLabel,
) -> Result<Option<CooldownPlan>, ConfigError> {
    let Some(declaration) = declaration else {
        return Ok(None);
    };
    let scope = declaration
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(label, "cooldown requires scope"))?;
    let scope =
        CooldownScopePlan::parse(scope).ok_or_else(|| invalid(label, "unknown cooldown scope"))?;
    let duration = declaration
        .duration
        .ok_or_else(|| invalid(label, "cooldown requires duration"))?;
    if duration.is_zero() {
        return Err(invalid(
            label,
            "cooldown duration must be greater than zero",
        ));
    }
    Ok(Some(CooldownPlan { scope, duration }))
}

/// Resolve the base URL a named known provider supplies.
///
/// An unrecognized ID fails compilation rather than falling through to a
/// missing-URL error, because the operator named a provider they expect Pooler
/// to know and a generic message would not say why it did not work.
fn compile_known_provider<'a>(
    declaration: &'a UpstreamConfig,
    label: &SourceLabel,
) -> Result<Option<(&'a str, &'static KnownProvider)>, ConfigError> {
    let Some(id) = declaration
        .known_provider
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    else {
        return Ok(None);
    };
    ProviderCatalog::builtin()
        .get(id)
        .map(|provider| Some((id, provider)))
        .ok_or_else(|| {
            invalid(
                label,
                &format!("known_provider `{id}` is not a provider Pooler ships an endpoint for"),
            )
        })
}

fn compile_upstream(
    declaration: &UpstreamConfig,
    known: Option<&KnownProvider>,
    label: &SourceLabel,
) -> Result<CompiledTransport, ConfigError> {
    let transport = declaration.transport.as_ref();
    let explicit_url = transport
        .and_then(|value| value.base_url.as_deref())
        .or(declaration.base_url.as_deref())
        .or(declaration.url.as_deref());
    let native_codex_default = declaration
        .native
        .as_ref()
        .and_then(|native| native.kind.as_deref())
        .filter(|kind| kind.trim().eq_ignore_ascii_case("codex"))
        .map(|_| "https://chatgpt.com");
    let raw_url = explicit_url
        .or(native_codex_default)
        .or_else(|| known.map(|provider| provider.base_url.as_str()))
        .ok_or_else(|| {
            invalid(
                label,
                "upstream requires url, transport.base_url, or known_provider",
            )
        })?;
    let url = Url::parse(raw_url).map_err(|_| invalid(label, "upstream URL is invalid"))?;
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") || url.host_str().is_none() {
        return Err(invalid(
            label,
            "upstream URL must use http(s) or ws(s) and include a host",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(label, "upstream URL must not contain userinfo"));
    }
    let transport_kind = transport
        .and_then(|value| value.kind.as_deref())
        .unwrap_or(url.scheme())
        .trim()
        .to_ascii_lowercase();
    if transport_kind != url.scheme() {
        return Err(invalid(label, "transport kind does not match URL scheme"));
    }
    if !matches!(transport_kind.as_str(), "http" | "https" | "ws" | "wss") {
        return Err(invalid(label, "unsupported upstream transport kind"));
    }
    let connect_timeout = parse_duration(
        transport.and_then(|value| value.connect_timeout.as_deref()),
        label,
        "connect_timeout",
    )?;
    let request_timeout = parse_duration(
        transport.and_then(|value| value.request_timeout.as_deref()),
        label,
        "request_timeout",
    )?;
    let http2 = transport.is_some_and(|value| value.http2);
    if http2 && !matches!(transport_kind.as_str(), "http" | "https") {
        return Err(invalid(
            label,
            "HTTP/2 upstream transport requires http or https",
        ));
    }
    Ok((
        url,
        Arc::from(transport_kind),
        http2,
        connect_timeout,
        request_timeout,
    ))
}

/// Resolve one upstream's outbound credential placement.
///
/// A known provider documents where its credential belongs: the authentication
/// kind, and for header credentials the header name and non-secret value
/// prefix. Those facts are the provider's, not the operator's, so supplying a
/// credential reference must not silently relocate the credential.
///
/// An `auth` block that names any placement field takes ownership of the whole
/// placement. An `auth` block that supplies only a secret overrides just the
/// protected credential reference and keeps the provider's documented
/// placement, so a preset can point a provider at an operator-chosen secret
/// without turning an `x-api-key` provider into a bearer one.
fn compile_upstream_auth(
    declaration: &UpstreamConfig,
    known: Option<&KnownProvider>,
    label: &SourceLabel,
) -> Result<Option<AuthPlan>, ConfigError> {
    // Explicit OAuth never inherits API-key authentication.
    if declaration.oauth.is_some() {
        return compile_auth(declaration.auth.as_ref(), label);
    }
    let Some(provider) = known else {
        return compile_auth(declaration.auth.as_ref(), label);
    };
    let declared = declaration.auth.as_ref();
    let documented_secret = provider
        .env
        .first()
        .map(|name| SecretRef::Env(Arc::from(name.as_str())));
    let Some(secret) = declared
        .and_then(|auth| auth.secret.clone())
        .or(documented_secret)
    else {
        // Keep the existing diagnostic for an auth block with no reachable
        // secret, and keep an undocumented provider unauthenticated.
        return compile_auth(declared, label);
    };
    let declares_placement = declared.is_some_and(|auth| {
        auth.kind.is_some() || auth.header.is_some() || auth.value_prefix.is_some()
    });
    let integration = &provider.integration;
    let resolved = if declares_placement {
        AuthConfig {
            kind: declared.and_then(|auth| auth.kind.clone()),
            secret: Some(secret),
            header: declared.and_then(|auth| auth.header.clone()),
            value_prefix: declared.and_then(|auth| auth.value_prefix.clone()),
        }
    } else {
        AuthConfig {
            kind: Some(integration.auth_kind.clone()),
            secret: Some(secret),
            header: integration.auth_header.clone(),
            value_prefix: integration.auth_value_prefix.clone(),
        }
    };
    compile_auth(Some(&resolved), label)
}

fn compile_provider_auth(
    declaration: &UpstreamConfig,
    known: Option<&KnownProvider>,
    label: &SourceLabel,
) -> Result<(Option<OAuthPlan>, Option<NativeProviderPlan>), ConfigError> {
    if declaration.oauth.is_some() && declaration.auth.is_some() {
        return Err(invalid(
            label,
            "upstream auth cannot be combined with oauth provider authentication",
        ));
    }

    let oauth = declaration
        .oauth
        .as_ref()
        .map(|value| compile_oauth(value, label))
        .transpose()?;
    let native = if let Some(native) = declaration.native.as_ref() {
        let kind = required_nonempty(native.kind.as_deref(), label, "native.kind")?;
        validate_component_id(kind, label, "native.kind")?;
        let quota_endpoint = native
            .quota_endpoint
            .as_deref()
            .map(|value| compile_secure_endpoint(value, label, "native.quota_endpoint"))
            .transpose()?;
        Some(NativeProviderPlan {
            kind: Arc::from(kind),
            quota_endpoint,
        })
    } else if declaration.oauth.is_none() {
        known
            .map(|provider| provider.integration.native_kind.trim())
            .filter(|kind| !kind.is_empty())
            .map(|kind| {
                validate_component_id(kind, label, "known_provider.native_kind")?;
                Ok(NativeProviderPlan {
                    kind: Arc::from(kind),
                    quota_endpoint: None,
                })
            })
            .transpose()?
    } else {
        None
    };
    Ok((oauth, native))
}

fn compile_oauth(declaration: &OAuthConfig, label: &SourceLabel) -> Result<OAuthPlan, ConfigError> {
    let authorization_endpoint = compile_secure_endpoint(
        required_nonempty(
            declaration.authorization_endpoint.as_deref(),
            label,
            "oauth.authorization_endpoint",
        )?,
        label,
        "oauth.authorization_endpoint",
    )?;
    let token_endpoint = compile_secure_endpoint(
        required_nonempty(
            declaration.token_endpoint.as_deref(),
            label,
            "oauth.token_endpoint",
        )?,
        label,
        "oauth.token_endpoint",
    )?;
    let revocation_endpoint = declaration
        .revocation_endpoint
        .as_deref()
        .map(|value| compile_secure_endpoint(value, label, "oauth.revocation_endpoint"))
        .transpose()?;
    let identity_endpoint = declaration
        .identity_endpoint
        .as_deref()
        .map(|value| compile_secure_endpoint(value, label, "oauth.identity_endpoint"))
        .transpose()?;
    let client_id = required_nonempty(declaration.client_id.as_deref(), label, "oauth.client_id")?;
    let callback = compile_loopback_callback(
        declaration
            .callback
            .as_deref()
            .unwrap_or(DEFAULT_OAUTH_CALLBACK),
        label,
    )?;

    if declaration.scopes.is_empty() {
        return Err(invalid(
            label,
            "oauth.scopes must contain at least one scope",
        ));
    }
    let mut scopes = Vec::with_capacity(declaration.scopes.len());
    let mut seen = BTreeSet::new();
    for scope in &declaration.scopes {
        let scope = scope.trim();
        if scope.is_empty() || !seen.insert(scope.to_owned()) {
            return Err(invalid(label, "oauth.scopes must be non-empty and unique"));
        }
        scopes.push(Arc::from(scope));
    }

    Ok(OAuthPlan {
        authorization_endpoint,
        token_endpoint,
        revocation_endpoint,
        identity_endpoint,
        client_id: Arc::from(client_id),
        scopes,
        callback,
    })
}

fn required_nonempty<'a>(
    value: Option<&'a str>,
    label: &SourceLabel,
    field: &str,
) -> Result<&'a str, ConfigError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(label, &format!("{field} is required")))
}

fn compile_secure_endpoint(
    value: &str,
    label: &SourceLabel,
    field: &str,
) -> Result<Url, ConfigError> {
    let url =
        Url::parse(value.trim()).map_err(|_| invalid(label, &format!("{field} is invalid")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            label,
            &format!("{field} must be an HTTPS URL without userinfo or fragment"),
        ));
    }
    Ok(url)
}

fn compile_loopback_callback(value: &str, label: &SourceLabel) -> Result<Url, ConfigError> {
    let url = Url::parse(value.trim())
        .map_err(|_| invalid(label, "oauth.callback must be a valid URL"))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid(label, "oauth.callback must include a loopback host"))?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false);
    if url.scheme() != "http"
        || !is_loopback
        || url.port().is_none()
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            label,
            "oauth.callback must be an HTTP loopback URL with an explicit port and no query, fragment, or userinfo",
        ));
    }
    Ok(url)
}

fn validate_component_id(value: &str, label: &SourceLabel, field: &str) -> Result<(), ConfigError> {
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    }) {
        return Err(invalid(
            label,
            &format!("{field} contains unsupported characters"),
        ));
    }
    Ok(())
}

fn compile_models(
    config: &Config,
    source: &Source,
    upstreams: &BTreeMap<Arc<str>, UpstreamPlan>,
) -> Result<BTreeMap<Arc<str>, ModelPlan>, ConfigError> {
    let mut models = BTreeMap::new();
    let mut model_labels = BTreeMap::new();
    for (ordinal, declaration) in config.models.iter().enumerate() {
        let label = model_label(source, ordinal, &declaration.id);
        validate_id("model", &declaration.id, &label)?;
        if let Some(first) = model_labels.insert(declaration.id.clone(), label.clone()) {
            return Err(ConfigError::DuplicateModel {
                id: declaration.id.clone(),
                first: Box::new(first),
                second: Box::new(label),
            });
        }
        if declaration.targets.is_empty() {
            return Err(invalid(&label, "model requires at least one static target"));
        }
        let mut targets = Vec::with_capacity(declaration.targets.len());
        for (target_ordinal, target) in declaration.targets.iter().enumerate() {
            let target_label = model_target_label(source, ordinal, target_ordinal, &declaration.id);
            let provider = target
                .provider
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid(&target_label, "model target requires provider"))?;
            if !upstreams.contains_key(provider) {
                return Err(ConfigError::MissingReference {
                    kind: "upstream",
                    name: provider.to_owned(),
                    label: target_label,
                });
            }
            let upstream_model = target
                .upstream_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid(&target_label, "model target requires upstream_model"))?;
            let capabilities = compile_capabilities(&target.capabilities, &target_label)?;
            let codecs = compile_codecs(&target.codecs, &target_label)?;
            targets.push(ModelTargetPlan {
                provider: Arc::from(provider),
                upstream_model: Arc::from(upstream_model),
                capabilities,
                codecs,
            });
        }
        models.insert(
            Arc::from(declaration.id.as_str()),
            ModelPlan {
                id: Arc::from(declaration.id.as_str()),
                targets,
                source: label,
            },
        );
    }
    Ok(models)
}

struct CatalogSourceRuntime {
    parser: CatalogParserKind,
    account: Option<Arc<str>>,
    path: Arc<str>,
    max_response_bytes: u64,
    model_facts_provider: Arc<str>,
    label: SourceLabel,
}

fn catalog_parser_kind(value: &str) -> Result<CatalogParserKind, &'static str> {
    match value {
        "openai" | "open_ai" => Ok(CatalogParserKind::OpenAi),
        "kimi" => Ok(CatalogParserKind::Kimi),
        "gemini" => Ok(CatalogParserKind::Gemini),
        "vertex" => Ok(CatalogParserKind::Vertex),
        "antigravity" => Ok(CatalogParserKind::Antigravity),
        _ => Err("known provider has an unsupported discovery parser"),
    }
}

fn compile_catalog(
    declaration: Option<&ModelCatalogConfig>,
    source: &Source,
    upstreams: &BTreeMap<Arc<str>, UpstreamPlan>,
    accounts: &BTreeMap<Arc<str>, AccountPlan>,
) -> Result<Option<ModelCatalogPlan>, ConfigError> {
    let catalog_label = source_label(source, "catalog".to_owned());
    let automatic = if declaration.is_none() {
        let mut sources = Vec::new();
        for upstream in upstreams.values() {
            let Some(provider_id) = upstream.known_provider() else {
                continue;
            };
            // Model discovery is an HTTP request. A WebSocket upstream names
            // the same provider so it authenticates the same documented way,
            // but its base URL cannot address a discovery endpoint.
            if matches!(upstream.url().scheme(), "ws" | "wss") {
                continue;
            }
            let provider = ProviderCatalog::builtin()
                .get(provider_id)
                .ok_or_else(|| invalid(&catalog_label, "known provider integration is missing"))?;
            let Some(parser) = provider
                .integration
                .discovery_parser
                .as_deref()
                .map(catalog_parser_kind)
                .transpose()
                .map_err(|message| invalid(&catalog_label, message))?
            else {
                continue;
            };
            let aliases = provider
                .integration
                .model_aliases
                .iter()
                .map(|(name, alias)| CatalogAliasConfig {
                    name: name.clone(),
                    alias: alias.clone(),
                    ..CatalogAliasConfig::default()
                })
                .collect();
            sources.push(ModelCatalogSourceConfig {
                id: format!("{}.models", upstream.id()),
                provider: upstream.id().to_owned(),
                parser: Some(parser),
                path: provider.integration.discovery_path.clone(),
                model_facts_provider: Some(provider_id.to_owned()),
                aliases,
                excluded_models: provider.integration.model_exclusions.clone(),
                ..ModelCatalogSourceConfig::default()
            });
        }
        (!sources.is_empty()).then_some(ModelCatalogConfig {
            sources,
            ..ModelCatalogConfig::default()
        })
    } else {
        None
    };
    let Some(declaration) = declaration.or(automatic.as_ref()) else {
        return Ok(None);
    };
    if declaration.sources.is_empty() {
        return Err(invalid(
            &catalog_label,
            "catalog requires at least one discovery source",
        ));
    }

    let policy = pooler_model_catalog::CatalogConfig {
        sources: declaration
            .sources
            .iter()
            .map(|source| pooler_model_catalog::CatalogSourceConfig {
                id: source.id.clone(),
                provider: source.provider.clone(),
                prefix: source.prefix.clone(),
                priority: source.priority,
                aliases: source.aliases.clone(),
                included_models: source.included_models.clone(),
                excluded_models: source.excluded_models.clone(),
            })
            .collect(),
        refresh: declaration.refresh.clone(),
        overrides: declaration.overrides.clone(),
    }
    .compile()
    .map_err(|error| invalid(&catalog_label, &error.to_string()))?;

    let mut runtime = BTreeMap::new();
    for (ordinal, source_declaration) in declaration.sources.iter().enumerate() {
        let label = source_label(source, format!("catalog.sources[{ordinal}]"));
        if !upstreams.contains_key(source_declaration.provider.as_str()) {
            return Err(ConfigError::MissingReference {
                kind: "upstream",
                name: source_declaration.provider.clone(),
                label,
            });
        }
        let account = source_declaration
            .account
            .as_deref()
            .map(str::trim)
            .filter(|account| !account.is_empty());
        if let Some(account) = account {
            let Some(account_plan) = accounts.get(account) else {
                return Err(ConfigError::MissingReference {
                    kind: "account",
                    name: account.to_owned(),
                    label,
                });
            };
            if account_plan.provider() != source_declaration.provider {
                return Err(invalid(
                    &label,
                    "catalog source account provider does not match source provider",
                ));
            }
        }
        let parser = source_declaration
            .parser
            .ok_or_else(|| invalid(&label, "catalog source requires parser"))?;
        let path = source_declaration
            .path
            .as_deref()
            .or_else(|| parser.default_path())
            .ok_or_else(|| invalid(&label, "catalog source parser requires an explicit path"))?;
        let path = path
            .parse::<PathAndQuery>()
            .ok()
            .filter(|path| path.as_str().starts_with('/') && !path.as_str().starts_with("//"))
            .ok_or_else(|| {
                invalid(
                    &label,
                    "catalog source path must be an absolute path with no authority or fragment",
                )
            })?;
        let max_response_bytes = source_declaration
            .max_response_bytes
            .unwrap_or(DEFAULT_CATALOG_MAX_RESPONSE_BYTES);
        if max_response_bytes == 0 || max_response_bytes > MAX_CATALOG_RESPONSE_BYTES {
            return Err(invalid(
                &label,
                &format!("catalog max_response_bytes must be 1..={MAX_CATALOG_RESPONSE_BYTES}"),
            ));
        }
        let model_facts_provider = source_declaration
            .model_facts_provider
            .as_deref()
            .map(str::trim)
            .filter(|provider| !provider.is_empty())
            .unwrap_or(source_declaration.provider.as_str());
        runtime.insert(
            source_declaration.id.clone(),
            CatalogSourceRuntime {
                parser,
                account: account.map(Arc::<str>::from),
                path: Arc::<str>::from(path.as_str()),
                max_response_bytes,
                model_facts_provider: Arc::<str>::from(model_facts_provider),
                label,
            },
        );
    }

    let sources = policy
        .sources()
        .iter()
        .map(|source_policy| {
            let runtime = runtime
                .remove(source_policy.id().as_str())
                .expect("compiled catalog sources retain declaration IDs");
            ModelCatalogSourcePlan {
                source: source_policy.clone(),
                parser: runtime.parser,
                account: runtime.account,
                path: runtime.path,
                max_response_bytes: runtime.max_response_bytes,
                model_facts_provider: runtime.model_facts_provider,
                source_label: runtime.label,
            }
        })
        .collect();
    Ok(Some(ModelCatalogPlan {
        limits: policy.limits(),
        sources,
        overrides: policy.overrides().clone(),
    }))
}

fn compile_capabilities(
    values: &[String],
    label: &SourceLabel,
) -> Result<CapabilitySet, ConfigError> {
    let mut capabilities = CapabilitySet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        let capability = Capability::ALL
            .into_iter()
            .find(|capability| capability.as_str() == value)
            .ok_or_else(|| invalid(label, &format!("unknown model capability `{value}`")))?;
        capabilities.insert(capability);
    }
    Ok(capabilities)
}

fn compile_codecs(values: &[String], label: &SourceLabel) -> Result<Vec<Arc<str>>, ConfigError> {
    let mut codecs = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            return Err(invalid(label, "target codec must not be empty"));
        }
        validate_component_id(value, label, "target codec")?;
        if !seen.insert(value.to_owned()) {
            return Err(invalid(label, "target codecs must be unique"));
        }
        codecs.push(Arc::from(value.to_owned()));
    }
    Ok(codecs)
}

fn compile_extensions(
    config: &Config,
    source: &Source,
) -> Result<BTreeMap<Arc<str>, ExtensionPlan>, ConfigError> {
    let mut extensions = BTreeMap::new();
    for (id, declaration) in &config.extensions {
        let label = source_label_with_key(source, "extensions", id.clone());
        validate_id("extension", id, &label)?;
        let command = declaration
            .command
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let wasm = declaration
            .wasm
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if command.is_some() == wasm.is_some() {
            return Err(invalid(
                &label,
                "extension requires exactly one of command or wasm",
            ));
        }
        if let Some(command) = command {
            if !Path::new(command).is_absolute() {
                return Err(invalid(
                    &label,
                    "extension command must be an absolute path",
                ));
            }
        }
        if let Some(wasm) = wasm {
            if !Path::new(wasm).is_absolute() {
                return Err(invalid(
                    &label,
                    "extension wasm path must be an absolute path",
                ));
            }
            if !declaration.args.is_empty() {
                return Err(invalid(&label, "WASM extensions do not accept args"));
            }
        }
        if declaration.capabilities.is_empty() {
            return Err(invalid(
                &label,
                "extension requires at least one capability",
            ));
        }
        let mut capabilities = BTreeSet::new();
        for capability in &declaration.capabilities {
            let capability = capability.trim().to_ascii_lowercase();
            if !matches!(capability.as_str(), "inspect" | "transform") {
                return Err(invalid(&label, "unknown extension capability"));
            }
            if !capabilities.insert(Arc::from(capability)) {
                return Err(invalid(&label, "duplicate extension capability"));
            }
        }
        let limits = declaration.limits.as_ref();
        let max_input_bytes = limits
            .and_then(|value| value.max_input_bytes)
            .unwrap_or(DEFAULT_EXTENSION_MAX_INPUT_BYTES);
        let max_output_bytes = limits
            .and_then(|value| value.max_output_bytes)
            .unwrap_or(DEFAULT_EXTENSION_MAX_OUTPUT_BYTES);
        let timeout = limits
            .and_then(|value| value.timeout)
            .unwrap_or(Duration::from_millis(DEFAULT_EXTENSION_TIMEOUT_MS));
        let max_memory_bytes = limits
            .and_then(|value| value.max_memory_bytes)
            .unwrap_or(DEFAULT_EXTENSION_MAX_MEMORY_BYTES);
        let max_concurrency = limits
            .and_then(|value| value.max_concurrency)
            .unwrap_or(DEFAULT_EXTENSION_MAX_CONCURRENCY);
        if max_input_bytes == 0
            || max_output_bytes == 0
            || timeout.is_zero()
            || max_memory_bytes == 0
            || max_concurrency == 0
        {
            return Err(invalid(
                &label,
                "extension limits must be greater than zero",
            ));
        }
        extensions.insert(
            Arc::from(id.as_str()),
            ExtensionPlan {
                id: Arc::from(id.as_str()),
                command: command.map(Arc::from),
                wasm: wasm.map(Arc::from),
                args: declaration
                    .args
                    .iter()
                    .map(|value| Arc::from(value.as_str()))
                    .collect(),
                capabilities,
                limits: ExtensionLimitsPlan {
                    max_input_bytes,
                    max_output_bytes,
                    timeout,
                    max_memory_bytes,
                    max_concurrency,
                },
                source: label,
            },
        );
    }
    Ok(extensions)
}

fn compile_request(
    declaration: Option<&RequestConfig>,
    label: &SourceLabel,
    extensions: &BTreeMap<Arc<str>, ExtensionPlan>,
) -> Result<(Vec<RequestTransform>, Vec<Arc<str>>), ConfigError> {
    let Some(declaration) = declaration else {
        return Ok((Vec::new(), Vec::new()));
    };
    if declaration.steps.len() > MAX_REQUEST_STEPS {
        return Err(invalid(label, "route has too many request transforms"));
    }
    let mut steps = Vec::with_capacity(declaration.steps.len());
    let mut external = Vec::new();
    let mut total_value_bytes = 0usize;
    for step in &declaration.steps {
        let kind = step.transform.trim().to_ascii_lowercase();
        if let Some(id) = kind.strip_prefix("transform.external.") {
            let extension = extensions
                .get(id)
                .ok_or_else(|| ConfigError::MissingReference {
                    kind: "extension",
                    name: id.to_owned(),
                    label: label.clone(),
                })?;
            if !extension.allows("transform") {
                return Err(invalid(
                    label,
                    "external transform capability is not granted",
                ));
            }
            external.push(Arc::from(id));
            continue;
        }
        let pointer = step
            .parameters
            .pointer
            .as_deref()
            .ok_or_else(|| invalid(label, "request transform requires pointer"))?;
        validate_json_pointer(pointer, label)?;
        let value = step.parameters.value.clone();
        let value_size = serde_json::to_vec(&value)
            .map_err(|_| invalid(label, "request transform value cannot be serialized"))?
            .len();
        if value_size > DEFAULT_JSON_PATCH_MAX_VALUE_BYTES {
            return Err(invalid(label, "request transform value exceeds size limit"));
        }
        total_value_bytes = total_value_bytes.saturating_add(value_size);
        if total_value_bytes > MAX_REQUEST_STEP_TOTAL_VALUE_BYTES {
            return Err(invalid(
                label,
                "aggregate request transform values exceed size limit",
            ));
        }
        let transform = match kind.as_str() {
            "transform.json.set" => {
                if step.parameters.prefix.is_some() {
                    return Err(invalid(
                        label,
                        "transform.json.set does not accept a prefix",
                    ));
                }
                RequestTransform::JsonSet {
                    pointer: Arc::from(pointer),
                    value,
                }
            }
            "transform.json.set_when_model_prefix" => {
                let prefix = step
                    .parameters
                    .prefix
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid(label, "model-prefix transform requires prefix"))?;
                RequestTransform::JsonSetWhenModelPrefix {
                    prefix: Arc::from(prefix),
                    pointer: Arc::from(pointer),
                    value,
                }
            }
            _ => {
                return Err(invalid(
                    label,
                    "unsupported request transform; expected transform.json.set or transform.json.set_when_model_prefix",
                ));
            }
        };
        steps.push(transform);
    }
    Ok((steps, external))
}

fn validate_external_inspectors(
    body: &BodyPlan,
    extensions: &BTreeMap<Arc<str>, ExtensionPlan>,
    label: &SourceLabel,
    field: &str,
) -> Result<(), ConfigError> {
    for inspector in body.inspectors() {
        let Some(id) = inspector
            .strip_prefix("inspect.external.")
            .or_else(|| inspector.strip_prefix("external.inspect."))
        else {
            continue;
        };
        if field == "response" {
            return Err(invalid(
                label,
                "external response inspectors are not supported; attach them to ingress",
            ));
        }
        let extension = extensions
            .get(id)
            .ok_or_else(|| ConfigError::MissingReference {
                kind: "extension",
                name: id.to_owned(),
                label: label.clone(),
            })?;
        if !extension.allows("inspect") {
            return Err(invalid(
                label,
                &format!("{field} external inspector capability is not granted"),
            ));
        }
    }
    Ok(())
}

fn has_model_inspector(body: &BodyPlan) -> bool {
    body.inspectors().iter().any(|inspector| {
        inspector.as_ref() == "inspect.openai.model"
            || inspector.starts_with("inspect.external.")
            || inspector.starts_with("external.inspect.")
    })
}

fn compile_auth(
    declaration: Option<&AuthConfig>,
    label: &SourceLabel,
) -> Result<Option<AuthPlan>, ConfigError> {
    let Some(auth) = declaration else {
        return Ok(None);
    };
    let secret = auth
        .secret
        .as_ref()
        .ok_or_else(|| invalid(label, "auth requires a secret reference"))?;
    let kind = auth
        .kind
        .as_deref()
        .unwrap_or("bearer_secret")
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_");
    if !matches!(
        kind.as_str(),
        "bearer" | "bearer_secret" | "x_api_key" | "x_goog_api_key" | "header"
    ) {
        return Err(invalid(
            label,
            "auth kind must be bearer, bearer_secret, x_api_key, x_goog_api_key, or header",
        ));
    }
    if !matches!(
        secret,
        SecretRef::Env(_) | SecretRef::File(_) | SecretRef::Keyring { .. }
    ) {
        return Err(invalid(
            label,
            "auth secrets must use an env:, file:, or keyring: reference",
        ));
    }
    let header = compile_auth_header(auth, &kind, label)?;
    Ok(Some(AuthPlan {
        kind: Arc::from(kind),
        secret: secret.clone(),
        header,
    }))
}

/// Resolve the credential header name and prefix for one auth declaration.
///
/// `header` and `value_prefix` describe where a `kind: header` credential goes,
/// so any other kind carrying them is a declaration whose intent cannot be
/// honored rather than a harmless extra field.
fn compile_auth_header(
    auth: &AuthConfig,
    kind: &str,
    label: &SourceLabel,
) -> Result<Option<CredentialHeader>, ConfigError> {
    let header = auth
        .header
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let value_prefix = auth.value_prefix.as_deref();
    if kind != "header" {
        if header.is_some() || value_prefix.is_some() {
            return Err(invalid(
                label,
                "auth header and value_prefix require kind: header",
            ));
        }
        return Ok(None);
    }
    let name = header.ok_or_else(|| invalid(label, "auth kind: header requires a header name"))?;
    if HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Err(invalid(label, "auth header must be a valid header name"));
    }
    if value_prefix.is_some_and(|prefix| HeaderValue::from_str(prefix).is_err()) {
        return Err(invalid(
            label,
            "auth value_prefix must be a valid header value",
        ));
    }
    Ok(Some(CredentialHeader {
        name: Arc::from(name),
        value_prefix: value_prefix
            .map(Arc::from)
            .filter(|prefix: &Arc<str>| !prefix.is_empty()),
    }))
}

/// Compile the static query parameters one upstream requires on every request.
fn compile_upstream_query(
    declaration: &UpstreamConfig,
    known: Option<&KnownProvider>,
    label: &SourceLabel,
) -> Result<UpstreamQuery, ConfigError> {
    let mut combined = known
        .map(|provider| provider.integration.required_query.clone())
        .unwrap_or_default();
    combined.extend(declaration.query.clone());
    let mut parameters = Vec::with_capacity(combined.len());
    for (name, value) in combined {
        let name = name.trim();
        if name.is_empty() {
            return Err(invalid(
                label,
                "upstream query parameter names must not be empty",
            ));
        }
        if name.contains(['&', '=', '#', '?']) || value.contains(['&', '#']) {
            return Err(invalid(
                label,
                "upstream query parameters must not contain query delimiters",
            ));
        }
        parameters.push((Arc::from(name), Arc::from(value)));
    }
    Ok(Arc::from(parameters))
}

fn compile_management(
    declaration: &ManagementConfig,
    source: &Source,
) -> Result<Option<ManagementPlan>, ConfigError> {
    let enabled = declaration.enabled.unwrap_or(declaration.bind.is_some());
    let label = source_label_with_key(source, "management", "management".to_owned());
    if !enabled {
        return Ok(None);
    }

    let bind = declaration
        .bind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("127.0.0.1:9090");
    validate_bind(bind, &label)?;

    let remote = declaration.remote.unwrap_or(false);
    let loopback = management_bind_is_loopback(bind);
    if !loopback && !remote {
        return Err(invalid(
            &label,
            "non-loopback management bind requires remote: true",
        ));
    }

    if remote {
        return Err(invalid(
            &label,
            "remote management requires TLS; management TLS is not configured",
        ));
    }

    let auth = compile_auth(declaration.auth.as_ref(), &label)?;
    if auth
        .as_ref()
        .is_some_and(|auth| !matches!(auth.kind(), "bearer" | "bearer_secret"))
    {
        return Err(invalid(
            &label,
            "management authentication requires a bearer auth kind",
        ));
    }
    if (remote || !loopback) && auth.is_none() {
        return Err(invalid(
            &label,
            "remote management requires bearer authentication",
        ));
    }

    Ok(Some(ManagementPlan {
        bind: Arc::from(bind),
        remote,
        auth,
        source: label,
    }))
}

fn management_bind_is_loopback(value: &str) -> bool {
    if value.starts_with('/') || value.starts_with("unix:") {
        return true;
    }
    value
        .parse::<SocketAddr>()
        .map(|address| address.ip().is_loopback())
        .unwrap_or(false)
}

fn compile_downstream_auth(
    declaration: Option<&DownstreamAuthConfig>,
    label: &SourceLabel,
) -> Result<Option<AuthPlan>, ConfigError> {
    let Some(declaration) = declaration else {
        return Ok(None);
    };
    let plan = compile_auth(Some(declaration), label)?.expect("auth declaration was present");
    if !matches!(plan.kind(), "bearer" | "bearer_secret") {
        return Err(invalid(
            label,
            "downstream authentication requires a bearer auth kind",
        ));
    }
    Ok(Some(plan))
}

fn compile_limits(
    declaration: Option<&RouteLimitsConfig>,
    label: &SourceLabel,
) -> Result<RouteLimits, ConfigError> {
    let Some(declaration) = declaration else {
        return Ok(RouteLimits::default());
    };
    let mut limits = RouteLimits::default();
    if let Some(value) = declaration.max_request_body_bytes {
        limits.max_request_body_bytes = value;
    }
    if let Some(value) = declaration.max_response_body_bytes {
        limits.max_response_body_bytes = value;
    }
    if let Some(value) = declaration.max_header_count {
        limits.max_header_count = value;
    }
    if let Some(value) = declaration.max_header_bytes {
        limits.max_header_bytes = value;
    }
    if let Some(value) = declaration.max_frame_bytes {
        limits.max_frame_bytes = value;
    }
    if let Some(value) = declaration.max_event_bytes {
        limits.max_event_bytes = value;
    }
    if let Some(value) = declaration.max_bootstrap_bytes {
        limits.max_bootstrap_bytes = value;
    }
    if let Some(value) = declaration.max_bootstrap_events {
        limits.max_bootstrap_events = value;
    }
    if let Some(value) = declaration.max_queue_bytes {
        limits.max_queue_bytes = value;
    }
    if let Some(value) = declaration.max_queue_items {
        limits.max_queue_items = value;
    }
    limits.request_timeout = declaration.request_timeout;
    limits.connect_timeout = declaration.connect_timeout;
    limits
        .validate()
        .map_err(|error| invalid(label, &format!("invalid route limits: {error}")))?;
    Ok(limits)
}

fn compile_cache(
    declaration: Option<&CacheConfig>,
    ingress_mode: BodyMode,
    label: &SourceLabel,
) -> Result<Option<CachePlan>, ConfigError> {
    let Some(declaration) = declaration else {
        return Ok(None);
    };
    let has_settings = declaration.ttl.is_some()
        || declaration.max_entries.is_some()
        || declaration.max_bytes.is_some()
        || declaration.coalesce.is_some()
        || !declaration.key_headers.is_empty();
    if !declaration.enabled {
        if has_settings {
            return Err(invalid(label, "cache settings require enabled: true"));
        }
        return Ok(None);
    }
    if ingress_mode == BodyMode::Semantic {
        return Err(invalid(
            label,
            "response cache cannot be used with semantic ingress mode",
        ));
    }
    let ttl = declaration.ttl.unwrap_or(DEFAULT_ROUTE_CACHE_TTL);
    if ttl.is_zero() || ttl > MAX_ROUTE_CACHE_TTL {
        return Err(invalid(
            label,
            "cache ttl must be greater than zero and no more than one hour",
        ));
    }
    let max_entries = declaration
        .max_entries
        .map(usize::try_from)
        .transpose()
        .map_err(|_| invalid(label, "cache max_entries is too large"))?
        .unwrap_or(DEFAULT_ROUTE_CACHE_MAX_ENTRIES);
    if max_entries == 0 || max_entries > MAX_ROUTE_CACHE_ENTRIES {
        return Err(invalid(
            label,
            "cache max_entries must be between one and 4096",
        ));
    }
    let max_bytes = declaration
        .max_bytes
        .unwrap_or(DEFAULT_ROUTE_CACHE_MAX_BYTES);
    if max_bytes == 0 || max_bytes > MAX_ROUTE_CACHE_BYTES {
        return Err(invalid(
            label,
            "cache max_bytes must be greater than zero and no more than 64 MiB",
        ));
    }
    if declaration.key_headers.len() > MAX_ROUTE_CACHE_KEY_HEADERS {
        return Err(invalid(
            label,
            "cache key_headers contains too many headers",
        ));
    }
    let mut key_headers = BTreeSet::new();
    for value in &declaration.key_headers {
        let value = value.trim().to_ascii_lowercase();
        let name = HeaderName::from_bytes(value.as_bytes())
            .map_err(|_| invalid(label, "cache key_headers contains an invalid header"))?;
        if !safe_cache_key_header(&name) {
            return Err(invalid(
                label,
                "cache key_headers cannot contain a sensitive header",
            ));
        }
        key_headers.insert(value);
    }
    Ok(Some(CachePlan {
        enabled: true,
        ttl,
        max_entries,
        max_bytes,
        coalesce: declaration.coalesce.unwrap_or(true),
        key_headers: key_headers.into_iter().map(Arc::from).collect(),
    }))
}

fn safe_cache_key_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-refresh-token"
    ) && !name.as_str().ends_with("-token")
        && !name.as_str().ends_with("-secret")
        && !name.as_str().ends_with("-credential")
}

fn compile_match(
    declaration: Option<&MatchConfig>,
    label: &SourceLabel,
) -> Result<MatchPlan, ConfigError> {
    let declaration = declaration.cloned().unwrap_or_default();
    let mut methods = declaration.methods;
    if let Some(method) = declaration.method {
        methods.push(method);
    }
    let mut method_set = BTreeSet::new();
    let mut canonical_methods = Vec::new();
    for method in methods {
        let method = method.trim().to_ascii_uppercase();
        Method::from_bytes(method.as_bytes())
            .map_err(|_| invalid(label, "invalid route method"))?;
        if method_set.insert(method.clone()) {
            canonical_methods.push(Arc::from(method));
        }
    }
    let path_count = usize::from(declaration.path.is_some())
        + usize::from(declaration.path_template.is_some())
        + usize::from(declaration.path_prefix.is_some());
    if path_count > 1 {
        return Err(invalid(label, "choose only one route path matcher"));
    }
    let path = if let Some(path) = declaration.path {
        PathPattern::Exact(valid_path(path, label)?)
    } else if let Some(path) = declaration.path_template {
        PathPattern::Template(valid_template_path(path, label)?)
    } else if let Some(path) = declaration.path_prefix {
        PathPattern::Prefix(valid_path(path, label)?)
    } else {
        PathPattern::Any
    };
    let host = declaration
        .host
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .map(Arc::from);
    let headers = compile_headers(&declaration.headers, label)?;
    let mut content_types = Vec::new();
    let mut content_set = BTreeSet::new();
    for content_type in declaration.content_types {
        let content_type = normalize_content_type(&content_type, label)?;
        if content_set.insert(content_type.clone()) {
            content_types.push(Arc::from(content_type));
        }
    }
    Ok(MatchPlan {
        methods: canonical_methods,
        host,
        path,
        headers,
        content_types,
        websocket: declaration.websocket,
    })
}

fn compile_headers(
    values: &BTreeMap<String, String>,
    label: &SourceLabel,
) -> Result<BTreeMap<Arc<str>, Arc<str>>, ConfigError> {
    let mut headers = BTreeMap::new();
    for (name, value) in values {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid(label, "invalid route header name"))?;
        if value.contains(['\r', '\n']) {
            return Err(invalid(label, "route header contains a newline"));
        }
        headers.insert(Arc::from(name.as_str()), Arc::from(value.trim().to_owned()));
    }
    Ok(headers)
}

fn compile_body(
    declaration: Option<&BodyConfig>,
    default_mode: BodyMode,
    label: &SourceLabel,
    field: &str,
) -> Result<BodyPlan, ConfigError> {
    let declaration = declaration.cloned().unwrap_or_default();
    let mode = declaration.mode.unwrap_or(default_mode);
    if declaration.framing.is_some() && field != "ingress" {
        return Err(invalid(
            label,
            &format!("{field} framing is only valid for ingress"),
        ));
    }
    if declaration.framing.is_some() && !mode.is_semantic() {
        return Err(invalid(
            label,
            &format!("{field} framing requires semantic mode"),
        ));
    }
    if mode == BodyMode::Opaque
        && (!declaration.inspectors.is_empty() || declaration.decoder.is_some())
    {
        return Err(invalid(
            label,
            &format!("{field} opaque mode cannot use inspectors or decoder"),
        ));
    }
    if mode == BodyMode::Patch {
        if declaration.decoder.is_some() || declaration.encoder.is_some() {
            return Err(invalid(
                label,
                &format!("{field} patch mode cannot use decoder or encoder"),
            ));
        }
        if declaration.inspectors.iter().any(|inspector| {
            let inspector = inspector.trim();
            inspector != "inspect.openai.model"
                && !inspector.starts_with("inspect.external.")
                && !inspector.starts_with("external.inspect.")
        }) {
            return Err(invalid(
                label,
                &format!(
                    "{field} patch mode only supports inspect.openai.model or inspect.external.<id>"
                ),
            ));
        }
    }
    Ok(BodyPlan {
        mode,
        framing: nonempty(declaration.framing),
        decoder: nonempty(declaration.decoder),
        encoder: nonempty(declaration.encoder),
        inspectors: declaration
            .inspectors
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(Arc::from)
            .collect(),
    })
}

fn compile_target(
    declaration: &RouteConfig,
    label: &SourceLabel,
    upstreams: &BTreeMap<Arc<str>, UpstreamPlan>,
    policies: &BTreeMap<Arc<str>, PolicyPlan>,
) -> Result<TargetPlan, ConfigError> {
    let target = declaration.target.as_ref();
    let (upstream, path, model_from, target_policy, capabilities, codecs, endpoint_family) =
        match target {
            Some(TargetValue::Name(name)) => (
                Some(name.as_str()),
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                None,
            ),
            Some(TargetValue::Config(config)) => (
                config.upstream.as_deref(),
                config.path.as_deref(),
                config.model_from.as_deref(),
                config.policy.as_deref(),
                config.capabilities.clone(),
                config.codecs.clone(),
                config.endpoint_family.as_deref(),
            ),
            None => (
                declaration.upstream.as_deref(),
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                None,
            ),
        };
    let upstream = upstream
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| invalid(label, "route requires target upstream/provider"))?;
    if !upstreams.contains_key(upstream) {
        return Err(ConfigError::MissingReference {
            kind: "upstream",
            name: upstream.to_owned(),
            label: label.clone(),
        });
    }
    if let Some(family) = endpoint_family {
        validate_endpoint_family(family, upstream, upstreams, label)?;
    }
    let path = path
        .map(|value| valid_path(value.to_owned(), label))
        .transpose()?;
    let capabilities = compile_capabilities(&capabilities, label)?;
    let codecs = compile_codecs(&codecs, label)?;
    let model_source = match model_from {
        None => None,
        Some("request.model") => Some(ModelSource::Request),
        Some("inspected.model") => Some(ModelSource::Inspected),
        Some(_) => {
            return Err(invalid(
                label,
                "target model_from must be request.model or inspected.model",
            ));
        }
    };
    if target_policy.is_some() && declaration.policy.is_some() {
        return Err(invalid(
            label,
            "route policy and target policy cannot both be set",
        ));
    }
    let policy = target_policy.or(declaration.policy.as_deref());
    if let Some(policy) = policy {
        let policy = policy.trim();
        if policy.is_empty() {
            return Err(invalid(label, "route policy must not be empty"));
        }
        if !policies.contains_key(policy) {
            return Err(ConfigError::MissingReference {
                kind: "policy",
                name: policy.to_owned(),
                label: label.clone(),
            });
        }
        return Ok(TargetPlan {
            upstream: Arc::from(upstream),
            path,
            model_source,
            policy: Some(Arc::from(policy)),
            capabilities,
            codecs,
        });
    }
    Ok(TargetPlan {
        upstream: Arc::from(upstream),
        path,
        model_source,
        policy: None,
        capabilities,
        codecs,
    })
}

/// Reject a route whose endpoint family the target provider does not document.
///
/// Mounting a path is not compatibility. A gateway that sends `/v1/messages` to
/// an OpenAI upstream produces a 404 at best, so an unsupported combination is
/// a configuration error rather than a runtime surprise. An upstream the
/// operator configured by URL has no documented family list, so their
/// declaration stands.
fn validate_endpoint_family(
    family: &str,
    upstream_id: &str,
    upstreams: &BTreeMap<Arc<str>, UpstreamPlan>,
    label: &SourceLabel,
) -> Result<(), ConfigError> {
    let family = family.trim();
    if family.is_empty() {
        return Err(invalid(label, "target endpoint_family must not be empty"));
    }
    let Some(provider_id) = upstreams
        .get(upstream_id)
        .and_then(UpstreamPlan::known_provider)
    else {
        return Ok(());
    };
    let provider = ProviderCatalog::builtin()
        .get(provider_id)
        .ok_or_else(|| invalid(label, "known provider integration is missing"))?;
    if provider
        .integration
        .endpoint_families
        .iter()
        .any(|documented| documented == family)
    {
        return Ok(());
    }
    Err(invalid(
        label,
        &format!("provider `{provider_id}` does not document the `{family}` endpoint family"),
    ))
}

fn detect_conflicts(routes: &[RoutePlan]) -> Result<(), ConfigError> {
    for (index, first) in routes.iter().enumerate() {
        for second in routes.iter().skip(index + 1) {
            if first.listener != second.listener
                || first.precedence().path_specificity != second.precedence().path_specificity
                || first.precedence().header_specificity != second.precedence().header_specificity
                || first.priority != second.priority
            {
                continue;
            }
            if routes_overlap(first, second) {
                return Err(ConfigError::RouteConflict {
                    first_route: first.id.to_string(),
                    first: Box::new(first.source.clone()),
                    second_route: second.id.to_string(),
                    second: Box::new(second.source.clone()),
                });
            }
        }
    }
    Ok(())
}

fn routes_overlap(first: &RoutePlan, second: &RoutePlan) -> bool {
    methods_overlap(&first.matcher.methods, &second.matcher.methods)
        && option_overlap(
            first.matcher.host.as_deref(),
            second.matcher.host.as_deref(),
        )
        && paths_overlap(&first.matcher.path, &second.matcher.path)
        && maps_overlap(&first.matcher.headers, &second.matcher.headers)
        && lists_overlap(&first.matcher.content_types, &second.matcher.content_types)
        && bools_overlap(first.matcher.websocket, second.matcher.websocket)
}

fn methods_overlap(first: &[Arc<str>], second: &[Arc<str>]) -> bool {
    first.is_empty() || second.is_empty() || first.iter().any(|method| second.contains(method))
}

fn option_overlap(first: Option<&str>, second: Option<&str>) -> bool {
    first.is_none() || second.is_none() || first == second
}

fn bools_overlap(first: Option<bool>, second: Option<bool>) -> bool {
    first.is_none() || second.is_none() || first == second
}

fn maps_overlap(
    first: &BTreeMap<Arc<str>, Arc<str>>,
    second: &BTreeMap<Arc<str>, Arc<str>>,
) -> bool {
    first
        .iter()
        .all(|(key, value)| second.get(key).is_none_or(|other| other == value))
        && second
            .iter()
            .all(|(key, value)| first.get(key).is_none_or(|other| other == value))
}

fn lists_overlap(first: &[Arc<str>], second: &[Arc<str>]) -> bool {
    first.is_empty() || second.is_empty() || first.iter().any(|value| second.contains(value))
}

fn paths_overlap(first: &PathPattern, second: &PathPattern) -> bool {
    match (first, second) {
        (PathPattern::Any, _) | (_, PathPattern::Any) => true,
        (PathPattern::Exact(a), PathPattern::Exact(b)) => a == b,
        (PathPattern::Prefix(a), PathPattern::Prefix(b)) => {
            prefix_matches(a, b) || prefix_matches(b, a)
        }
        (PathPattern::Exact(exact), PathPattern::Prefix(prefix))
        | (PathPattern::Prefix(prefix), PathPattern::Exact(exact)) => prefix_matches(prefix, exact),
        (PathPattern::Template(template), PathPattern::Prefix(prefix))
        | (PathPattern::Prefix(prefix), PathPattern::Template(template)) => {
            template_prefix_overlap(template, prefix)
        }
        (PathPattern::Exact(exact), PathPattern::Template(template))
        | (PathPattern::Template(template), PathPattern::Exact(exact)) => {
            template_matches(template, exact)
        }
        (PathPattern::Template(first), PathPattern::Template(second)) => {
            template_templates_overlap(first, second)
        }
    }
}

fn template_templates_overlap(first: &str, second: &str) -> bool {
    let first_segments: Vec<_> = first.split('/').skip(1).collect();
    let second_segments: Vec<_> = second.split('/').skip(1).collect();
    first_segments.len() == second_segments.len()
        && first_segments
            .iter()
            .zip(second_segments)
            .all(|(first, second)| {
                first == &second || is_template_segment(first) || is_template_segment(second)
            })
}

fn template_prefix_overlap(template: &str, prefix: &str) -> bool {
    let template_segments: Vec<_> = template.split('/').skip(1).collect();
    let prefix_segments: Vec<_> = prefix.split('/').skip(1).collect();
    prefix_segments.len() <= template_segments.len()
        && template_segments
            .iter()
            .zip(prefix_segments)
            .all(|(template, prefix)| is_template_segment(template) || template == &prefix)
}

fn compare_routes(first: &RoutePlan, second: &RoutePlan) -> Ordering {
    second
        .matcher
        .path
        .specificity()
        .cmp(&first.matcher.path.specificity())
        .then_with(|| {
            second
                .matcher
                .headers
                .len()
                .cmp(&first.matcher.headers.len())
        })
        .then_with(|| second.priority.cmp(&first.priority))
        .then_with(|| first.order.cmp(&second.order))
}

fn parse_duration(
    value: Option<&str>,
    label: &SourceLabel,
    field: &str,
) -> Result<Option<Duration>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    parse_duration_literal(value)
        .map(Some)
        .map_err(|message| invalid(label, &format!("{message} {field}")))
}

fn parse_duration_literal(value: &str) -> Result<Duration, &'static str> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or("duration requires a unit")?;
    if split == 0 {
        return Err("invalid duration");
    }
    let number = value[..split]
        .parse::<u64>()
        .map_err(|_| "invalid duration")?;
    match value[split..].to_ascii_lowercase().as_str() {
        "ms" => Ok(Duration::from_millis(number)),
        "s" => Ok(Duration::from_secs(number)),
        "m" => Ok(Duration::from_secs(number.saturating_mul(60))),
        "h" => Ok(Duration::from_secs(number.saturating_mul(3600))),
        _ => Err("invalid duration unit"),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ConfigDuration {
    Text(String),
    Millis(u64),
}

fn deserialize_optional_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<ConfigDuration>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(ConfigDuration::Text(value)) => parse_duration_literal(&value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(ConfigDuration::Millis(value)) => Ok(Some(Duration::from_millis(value))),
    }
}

fn default_tls_alpn() -> Vec<String> {
    vec!["http/1.1".to_owned()]
}

fn deserialize_optional_byte_size<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<ByteSize>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(ByteSize::Number(value)) => Ok(Some(value)),
        Some(ByteSize::Text(value)) => parse_byte_size_literal(&value)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ByteSize {
    Number(u64),
    Text(String),
}

fn parse_byte_size_literal(value: &str) -> Result<u64, &'static str> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or("byte size requires a unit")?;
    if split == 0 {
        return Err("invalid byte size");
    }
    let number = value[..split]
        .parse::<u64>()
        .map_err(|_| "invalid byte size")?;
    let unit = value[split..].to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "b" => 1,
        "kb" => 1_000,
        "kib" => 1 << 10,
        "mb" => 1_000_000,
        "mib" => 1 << 20,
        "gb" => 1_000_000_000,
        "gib" => 1 << 30,
        _ => return Err("invalid byte size unit"),
    };
    number
        .checked_mul(multiplier)
        .ok_or("byte size is too large")
}

fn default_request_timeout() -> Option<Duration> {
    RouteLimits::default().request_timeout
}

fn default_connect_timeout() -> Option<Duration> {
    RouteLimits::default().connect_timeout
}

fn valid_path(value: String, label: &SourceLabel) -> Result<Arc<str>, ConfigError> {
    let value = value.trim().to_owned();
    if value.is_empty() || !value.starts_with('/') || value.contains('?') {
        return Err(invalid(label, "route path must be absolute and query-free"));
    }
    Ok(Arc::from(value))
}

fn valid_template_path(value: String, label: &SourceLabel) -> Result<Arc<str>, ConfigError> {
    let path = valid_path(value, label)?;
    if path
        .split('/')
        .skip(1)
        .any(|segment| segment.contains(['{', '}']) && !is_template_segment(segment))
    {
        return Err(invalid(
            label,
            "route path template contains an invalid parameter",
        ));
    }
    Ok(path)
}

fn validate_json_pointer(pointer: &str, label: &SourceLabel) -> Result<(), ConfigError> {
    if pointer.len() > DEFAULT_JSON_PATCH_MAX_POINTER_BYTES
        || (!pointer.is_empty() && !pointer.starts_with('/'))
    {
        return Err(invalid(
            label,
            "request transform pointer is invalid or too long",
        ));
    }
    let depth = pointer.split('/').skip(1).count();
    if depth > DEFAULT_JSON_PATCH_MAX_POINTER_DEPTH {
        return Err(invalid(label, "request transform pointer is too deep"));
    }
    let mut escaped = false;
    for character in pointer.chars().skip(1) {
        if escaped {
            if character != '0' && character != '1' {
                return Err(invalid(
                    label,
                    "request transform pointer has an invalid escape",
                ));
            }
            escaped = false;
        } else if character == '~' {
            escaped = true;
        }
    }
    if escaped {
        return Err(invalid(
            label,
            "request transform pointer has an invalid escape",
        ));
    }
    Ok(())
}

fn normalize_content_type(value: &str, label: &SourceLabel) -> Result<String, ConfigError> {
    let value = value
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if value.is_empty() || value.chars().any(char::is_control) || value.contains(' ') {
        return Err(invalid(label, "content type must be a valid media type"));
    }
    Ok(value)
}

fn validate_bind(value: &str, label: &SourceLabel) -> Result<(), ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid(label, "listener bind must not be empty"));
    }
    if value.starts_with('/') || value.starts_with("unix:") {
        return Ok(());
    }
    value
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| invalid(label, "listener bind must be a socket address or Unix path"))
}

fn validate_id(kind: &str, value: &str, label: &SourceLabel) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(invalid(label, &format!("invalid {kind} ID")));
    }
    Ok(())
}

fn validate_version(config: &Config, source: &Source) -> Result<(), ConfigError> {
    if config.version != CONFIG_VERSION {
        return Err(ConfigError::UnsupportedVersion {
            version: config.version,
            label: SourceLabel::new(source, None, None, "version"),
            expected: CONFIG_VERSION,
        });
    }
    Ok(())
}

fn valid_env_name(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn nonempty(value: Option<String>) -> Option<Arc<str>> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(Arc::from)
}

fn invalid(label: &SourceLabel, message: &str) -> ConfigError {
    ConfigError::Invalid {
        label: label.clone(),
        message: message.to_owned(),
    }
}

fn parse_error(source: &Source, error: serde_yml::Error) -> ConfigError {
    let location = error.location();
    ConfigError::Parse {
        source_name: source.name.to_string(),
        line: location.as_ref().map_or(1, serde_yml::Location::line),
        column: location.as_ref().map_or(1, serde_yml::Location::column),
        message: error
            .to_string()
            .lines()
            .next()
            .unwrap_or("invalid YAML")
            .to_owned(),
    }
}

fn declaration_label(source: &Source, section: &str, id: &str, _ordinal: usize) -> SourceLabel {
    let path = format!("{section}.{id}");
    source_label(source, path)
}

fn upstream_label(source: &Source, id: &str, ordinal: usize) -> SourceLabel {
    declaration_label(source, "upstreams", id, ordinal)
}

fn account_label(source: &Source, section: &str, id: &str) -> SourceLabel {
    declaration_label(source, section, id, 0)
}

fn pool_label(source: &Source, id: &str) -> SourceLabel {
    let canonical = format!("account_pools.{id}");
    let alias = format!("pools.{id}");
    let key = if source.origins.contains_key(&canonical) {
        canonical
    } else {
        alias
    };
    source_label_with_key(source, &key, format!("account_pools.{id}"))
}

fn policy_label(source: &Source, id: &str) -> SourceLabel {
    declaration_label(source, "policies", id, 0)
}

fn model_label(source: &Source, ordinal: usize, id: &str) -> SourceLabel {
    let origin_key = format!("models.{id}");
    let display_path = format!("models[{ordinal}]");
    source_label_with_key(source, &origin_key, display_path)
}

fn model_target_label(
    source: &Source,
    model_ordinal: usize,
    target_ordinal: usize,
    model_id: &str,
) -> SourceLabel {
    source_label_with_key(
        source,
        &format!("models.{model_id}"),
        format!("models[{model_ordinal}].targets[{target_ordinal}]"),
    )
}

fn route_label(source: &Source, ordinal: usize, id: &str) -> SourceLabel {
    let origin_key = format!("routes.{id}");
    let display_path = format!("routes[{ordinal}]");
    source_label_with_key(source, &origin_key, display_path)
}

fn source_label(source: &Source, path: String) -> SourceLabel {
    source_label_with_key(source, &path, path.clone())
}

fn source_label_with_key(source: &Source, key: &str, path: String) -> SourceLabel {
    let name = source.origins.get(key).unwrap_or(&source.name);
    SourceLabel {
        source: Arc::clone(name),
        line: None,
        column: None,
        path: Arc::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
version: 1
listeners:
  local:
    bind: 127.0.0.1:8400
upstreams:
  local:
    transport:
      kind: http
      base_url: http://127.0.0.1:8319
    auth:
      kind: bearer_secret
      secret: env:POOLER_KEY
routes:
  - id: opaque
    listen: local
    match:
      methods: [POST]
      path: /v1/infer
    ingress: {mode: opaque}
    response: {mode: opaque}
    target: local
"#;

    #[test]
    fn compiles_valid_config_and_keeps_secret_as_reference() {
        let compiled = compile_yaml("config.yaml", CONFIG).expect("config");
        assert_eq!(compiled.routes()[0].ingress().mode(), BodyMode::Opaque);
        assert_eq!(compiled.routes()[0].target().upstream(), "local");
        assert_eq!(
            compiled.upstreams()["local"]
                .auth()
                .expect("auth")
                .secret()
                .kind(),
            "env"
        );
    }

    #[test]
    fn detects_equal_precedence_conflicts_with_both_labels() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: first
    listen: local
    match: {methods: [POST], path: /same}
    target: local
  - id: second
    listen: local
    match: {methods: [POST], path: /same}
    target: local
"#;
        let error = compile_yaml("conflict.yaml", text).expect_err("conflict");
        let rendered = error.to_string();
        assert!(rendered.contains("first"));
        assert!(rendered.contains("second"));
        assert!(rendered.contains("conflict.yaml"));
    }

    #[test]
    fn precedence_is_exact_then_headers_then_priority_then_order() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: prefix
    listen: local
    match: {methods: [POST], path_prefix: /v1}
    target: local
  - id: exact
    listen: local
    priority: 1
    match: {methods: [POST], path: /v1/x}
    target: local
  - id: exact-header
    listen: local
    priority: 2
    match: {methods: [POST], path: /v1/x, headers: {x-tenant: acme}}
    target: local
"#;
        let compiled = compile_yaml("order.yaml", text).expect("order");
        let ids: Vec<_> = compiled.routes().iter().map(RoutePlan::id).collect();
        assert_eq!(ids, ["exact-header", "exact", "prefix"]);
    }

    #[test]
    fn rejects_literal_secret_without_echoing_it() {
        let text = "version: 1\nupstreams:\n  x:\n    url: http://127.0.0.1:1\n    auth: {secret: literal:never-print}\n";
        let error = parse_yaml("secret.yaml", text).expect_err("literal");
        assert!(!error.to_string().contains("never-print"));
    }

    #[test]
    fn reports_missing_listener_or_upstream() {
        let text = "version: 1\nlisteners: {local: {bind: 127.0.0.1:8400}}\nroutes: [{id: x, listen: local, target: absent}]\n";
        let error = compile_yaml("missing.yaml", text).expect_err("missing upstream");
        assert!(matches!(
            error,
            ConfigError::MissingReference {
                kind: "upstream",
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_version_and_bind() {
        let version = parse_yaml("version.yaml", "version: 2\n").expect_err("version");
        assert!(version.to_string().contains("version.yaml (version)"));
        let quoted =
            parse_yaml("quoted.yaml", "{\"version\": 2, \"routes\": []}\n").expect_err("version");
        assert!(quoted.to_string().contains("quoted.yaml (version)"));
        let text = "version: 1\nlisteners: {local: {bind: invalid}}\n";
        let bind = compile_yaml("bind.yaml", text).expect_err("bind");
        assert!(bind.to_string().contains("bind.yaml"));
    }

    #[test]
    fn supports_provider_alias_and_modes() {
        let text = "version: 1\nlisteners: {l: {bind: 127.0.0.1:1}}\nproviders: {p: {url: http://127.0.0.1:2}}\nroutes: [{id: r, listen: l, ingress: {mode: semantic}, loss_policy: degrade, target: {provider: p}}]\n";
        let compiled = compile_yaml("alias.yaml", text).expect("alias");
        assert_eq!(compiled.routes()[0].ingress().mode(), BodyMode::Semantic);
        assert_eq!(compiled.routes()[0].loss_policy(), LossPolicy::Degrade);
    }

    #[test]
    fn a_known_provider_supplies_a_base_url_the_operator_did_not_write() {
        let upstream = |body: &str| {
            format!(
                "version: 1\nlisteners: {{l: {{bind: 127.0.0.1:1}}}}\nupstreams: {{u: {{{body}}}}}\n"
            )
        };

        let compiled = compile_yaml("known-provider.yaml", &upstream("known_provider: groq"))
            .expect("a known provider is addressable without a URL");
        let upstream_plan = &compiled.upstreams()["u"];
        assert_eq!(
            upstream_plan.url().as_str(),
            "https://api.groq.com/openai/v1"
        );
        assert_eq!(upstream_plan.known_provider(), Some("groq"));
        assert_eq!(
            upstream_plan
                .auth()
                .expect("catalog auth")
                .secret()
                .redacted(),
            "env:GROQ_API_KEY"
        );
        assert_eq!(
            upstream_plan.native().expect("native binding").kind(),
            "openai_compatible"
        );
        let catalog = compiled.catalog().expect("automatic model discovery");
        assert_eq!(catalog.sources().len(), 1);
        assert_eq!(catalog.sources()[0].parser(), CatalogParserKind::OpenAi);
        assert_eq!(catalog.sources()[0].path(), "/openai/v1/models");

        let anthropic = compile_yaml(
            "known-provider-anthropic.yaml",
            &upstream("known_provider: anthropic"),
        )
        .expect("Anthropic integration");
        let anthropic = &anthropic.upstreams()["u"];
        assert_eq!(
            anthropic.native().expect("native binding").kind(),
            "anthropic"
        );
        assert_eq!(
            anthropic
                .required_headers()
                .get("anthropic-version")
                .map(AsRef::as_ref),
            Some("2023-06-01")
        );

        let overridden = compile_yaml(
            "known-provider-override.yaml",
            &upstream("known_provider: groq, url: https://gateway.internal/v1"),
        )
        .expect("an explicit URL compiles");
        assert_eq!(
            overridden.upstreams()["u"].url().as_str(),
            "https://gateway.internal/v1",
            "an operator's own endpoint must win over the shipped one"
        );

        let unknown = compile_yaml(
            "known-provider-unknown.yaml",
            &upstream("known_provider: not-a-provider"),
        )
        .expect_err("an unrecognized provider must not fall through");
        assert!(
            unknown.to_string().contains(
                "known_provider `not-a-provider` is not a provider Pooler ships an endpoint for"
            ),
            "{unknown}"
        );

        let azure = compile_yaml(
            "known-provider-azure.yaml",
            &upstream("known_provider: azure"),
        )
        .expect_err("azure needs a resource name no table can supply");
        assert!(
            azure.to_string().contains("known_provider `azure`"),
            "{azure}"
        );
    }

    #[test]
    fn an_operator_can_withhold_and_reshape_discovered_models() {
        let text = "\
version: 1
listeners: {l: {bind: 127.0.0.1:1}}
upstreams: {openai: {known_provider: openai}}
catalog:
  sources:
    - id: openai.primary
      provider: openai
      parser: openai
  overrides:
    - model: gpt-4o
      disabled: true
    - model: o3
      display_name: Reasoner
      capabilities: [text, reasoning]
      dialect:
        temperature: rejected
      request:
        /reasoning_effort: high
";
        let config = compile_yaml("overrides.yaml", text).expect("overrides compile");
        let overrides = config.catalog().expect("catalog is configured").overrides();

        assert_eq!(overrides.len(), 2);
        let withheld = overrides
            .get(&pooler_core::ModelId::new("gpt-4o").expect("model id"))
            .expect("withheld model is overridden");
        assert!(withheld.disabled());

        let reshaped = overrides
            .get(&pooler_core::ModelId::new("o3").expect("model id"))
            .expect("reshaped model is overridden");
        assert!(!reshaped.disabled());
        assert_eq!(reshaped.display_name(), Some("Reasoner"));
        assert_eq!(
            reshaped.capabilities(),
            Some(
                [Capability::Text, Capability::Reasoning]
                    .into_iter()
                    .collect()
            )
        );
        assert_eq!(
            reshaped.dialect().map(|dialect| dialect.temperature),
            Some(pooler_core::ParamSupport::Rejected)
        );
        assert_eq!(
            reshaped
                .overlay()
                .fields()
                .iter()
                .map(|(pointer, value)| (pointer.as_ref(), value.to_string()))
                .collect::<Vec<_>>(),
            [("/reasoning_effort", "\"high\"".to_owned())]
        );
    }

    #[test]
    fn a_pinned_request_field_requires_a_json_pointer() {
        let text = "\
version: 1
listeners: {l: {bind: 127.0.0.1:1}}
upstreams: {openai: {known_provider: openai}}
catalog:
  sources:
    - id: openai.primary
      provider: openai
      parser: openai
  overrides:
    - model: o3
      request:
        reasoning_effort: high
";
        let error = compile_yaml("bad-pointer.yaml", text)
            .expect_err("a bare field name is not a JSON pointer");
        assert!(
            error.to_string().contains("invalid request pointer"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_override_that_declares_no_change_is_rejected() {
        let text = "\
version: 1
listeners: {l: {bind: 127.0.0.1:1}}
upstreams: {openai: {known_provider: openai}}
catalog:
  sources:
    - id: openai.primary
      provider: openai
      parser: openai
  overrides:
    - model: gpt-4o
";
        let error = compile_yaml("empty-override.yaml", text)
            .expect_err("an override that changes nothing is reported");
        assert!(
            error.to_string().contains("declares no change"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn every_shipped_provider_compiles_into_a_usable_upstream() {
        // The provider table is advertised by `pooler providers`, so an entry
        // that does not compile would be a documented endpoint that cannot be
        // used. Compiling all of them keeps the table and this resolver honest
        // about each other.
        for (id, provider) in ProviderCatalog::builtin().iter() {
            let text = format!(
                "version: 1\nlisteners: {{l: {{bind: 127.0.0.1:1}}}}\nupstreams: {{u: {{known_provider: {id}}}}}\n"
            );
            let compiled = compile_yaml("shipped-providers.yaml", &text)
                .unwrap_or_else(|error| panic!("`{id}` must compile: {error}"));
            let url = compiled.upstreams()["u"].url();
            assert_eq!(
                url.as_str().trim_end_matches('/'),
                provider.base_url,
                "`{id}` must resolve to its shipped base URL"
            );
            assert!(
                matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
                "`{id}` must resolve to an addressable URL"
            );
        }
    }

    #[test]
    fn a_credential_header_and_prefix_belong_only_to_the_header_auth_kind() {
        let upstream = |auth: &str| {
            format!(
                "version: 1\nlisteners: {{l: {{bind: 127.0.0.1:1}}}}\nupstreams: {{u: {{url: http://127.0.0.1:2, auth: {auth}}}}}\n"
            )
        };

        let compiled = compile_yaml(
            "header-auth.yaml",
            &upstream(
                "{kind: header, header: api-key, secret: 'env:AZURE_KEY', value_prefix: 'Token '}",
            ),
        )
        .expect("header auth compiles");
        let auth = compiled.upstreams()["u"].auth().expect("auth plan");
        assert_eq!(auth.kind(), "header");
        assert_eq!(auth.header(), Some("api-key"));
        assert_eq!(auth.value_prefix(), Some("Token "));

        let missing_name = compile_yaml(
            "header-auth-missing.yaml",
            &upstream("{kind: header, secret: 'env:AZURE_KEY'}"),
        )
        .expect_err("kind: header without a name is unusable");
        assert!(missing_name
            .to_string()
            .contains("auth kind: header requires a header name"));

        let stray_header = compile_yaml(
            "bearer-with-header.yaml",
            &upstream("{kind: bearer, header: api-key, secret: 'env:AZURE_KEY'}"),
        )
        .expect_err("a bearer credential cannot go in a named header");
        assert!(stray_header
            .to_string()
            .contains("auth header and value_prefix require kind: header"));

        let invalid_name = compile_yaml(
            "header-auth-invalid.yaml",
            &upstream("{kind: header, header: 'api key', secret: 'env:AZURE_KEY'}"),
        )
        .expect_err("a header name with a space is not a header name");
        assert!(invalid_name
            .to_string()
            .contains("auth header must be a valid header name"));
    }

    #[test]
    fn upstream_query_parameters_compile_in_order_and_reject_delimiters() {
        let upstream = |query: &str| {
            format!(
                "version: 1\nlisteners: {{l: {{bind: 127.0.0.1:1}}}}\nupstreams: {{u: {{url: http://127.0.0.1:2, query: {query}}}}}\n"
            )
        };

        let compiled = compile_yaml(
            "upstream-query.yaml",
            &upstream("{api-version: '2024-10-21', mode: fast}"),
        )
        .expect("upstream query compiles");
        let parameters = compiled.upstreams()["u"]
            .query()
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
            .collect::<Vec<_>>();
        assert_eq!(
            parameters,
            vec![("api-version", "2024-10-21"), ("mode", "fast")]
        );

        let smuggled = compile_yaml(
            "upstream-query-smuggled.yaml",
            &upstream("{'api-version=1&key': secret}"),
        )
        .expect_err("a delimiter in a parameter name smuggles a second parameter");
        assert!(smuggled
            .to_string()
            .contains("upstream query parameters must not contain query delimiters"));
    }

    #[test]
    fn loss_policy_defaults_by_ingress_mode_and_stays_out_of_opaque_routes() {
        let route = |mode: &str, declared: &str| {
            format!(
                "version: 1\nlisteners: {{l: {{bind: 127.0.0.1:1}}}}\nupstreams: {{p: {{url: http://127.0.0.1:2}}}}\nroutes: [{{id: r, listen: l, ingress: {{mode: {mode}}}, target: {{provider: p}}{declared}}}]\n"
            )
        };

        let patched = compile_yaml("patch-default.yaml", &route("patch", ""))
            .expect("patch ingress compiles");
        assert_eq!(
            patched.routes()[0].loss_policy(),
            LossPolicy::Degrade,
            "patch ingress shapes the caller's body for the selected target"
        );

        let semantic = compile_yaml("semantic-default.yaml", &route("semantic", ""))
            .expect("semantic ingress compiles");
        assert_eq!(semantic.routes()[0].loss_policy(), LossPolicy::Reject);

        let declared = compile_yaml(
            "patch-declared.yaml",
            &route("patch", ", loss_policy: reject"),
        )
        .expect("patch ingress accepts an explicit policy");
        assert_eq!(declared.routes()[0].loss_policy(), LossPolicy::Reject);

        let opaque = compile_yaml(
            "opaque-declared.yaml",
            &route("opaque", ", loss_policy: reject"),
        )
        .expect_err("opaque ingress has no body to shape");
        assert!(opaque
            .to_string()
            .contains("loss_policy requires semantic or patch ingress"));
    }

    #[test]
    fn validates_devin_connect_route_framing_as_ingress_schema() {
        let text = r#"
version: 1
listeners: {devin: {bind: 127.0.0.1:18473}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: devin-chat
    listen: devin
    match:
      methods: [POST]
      path: /exa.api_server_pb.ApiServerService/GetChatMessage
      content_types: [application/connect+proto]
    ingress:
      mode: semantic
      framing: decode.connect.envelope
      decoder: decode.devin.chat
    target: local
    response:
      mode: semantic
      decoder: decode.openai.chat.events
      encoder: encode.devin.connect
    loss_policy: reject
"#;
        let compiled = compile_yaml("devin.yaml", text).expect("Devin route");
        let route = &compiled.routes()[0];
        assert_eq!(route.ingress().framing(), Some("decode.connect.envelope"));
        assert_eq!(route.ingress().decoder(), Some("decode.devin.chat"));
        assert_eq!(route.response().encoder(), Some("encode.devin.connect"));
    }

    #[test]
    fn rejects_framing_outside_semantic_ingress() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: opaque
    listen: local
    ingress: {mode: opaque, framing: decode.connect.envelope}
    target: local
        "#;
        let error = compile_yaml("invalid-framing.yaml", text).expect_err("opaque framing");
        assert!(error
            .to_string()
            .contains("ingress framing requires semantic mode"));

        let response = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: response-framing
    listen: local
    ingress: {mode: semantic}
    target: local
    response: {mode: semantic, framing: decode.connect.envelope}
"#;
        let error = compile_yaml("response-framing.yaml", response).expect_err("response framing");
        assert!(error
            .to_string()
            .contains("response framing is only valid for ingress"));
    }

    #[test]
    fn rejects_unknown_body_schema_fields() {
        let text = "version: 1\nroutes: [{id: route, ingress: {mode: semantic, framng: decode.connect.envelope}}]\n";
        let error = parse_yaml("unknown-body-field.yaml", text).expect_err("unknown body field");
        let rendered = error.to_string();
        assert!(rendered.contains("unknown field"));
        assert!(rendered.contains("framng"));
    }

    #[test]
    fn cache_is_disabled_by_default_and_compiles_strict_bounds() {
        let default = compile_yaml(
            "cache-default.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\nupstreams: {local: {url: http://127.0.0.1:2}}\nroutes: [{id: route, listen: local, ingress: {mode: patch}, target: local}]\n",
        )
        .expect("default cache config");
        assert!(default.routes()[0].cache().is_none());

        let enabled = compile_yaml(
            "cache-enabled.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
routes:
  - id: route
    listen: local
    ingress: {mode: patch}
    cache:
      enabled: true
      ttl: 250ms
      max_entries: 12
      max_bytes: 128KiB
      coalesce: true
      key_headers: [accept, x-tenant]
    target: local
"#,
        )
        .expect("enabled cache config");
        let cache = enabled.routes()[0].cache().expect("cache plan");
        assert!(cache.enabled());
        assert_eq!(cache.ttl(), Duration::from_millis(250));
        assert_eq!(cache.max_entries(), 12);
        assert_eq!(cache.max_bytes(), 128 * 1024);
        assert!(cache.coalesce());
        assert_eq!(
            cache
                .key_headers()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            ["accept", "x-tenant"]
        );
    }

    #[test]
    fn cache_rejects_unbounded_or_sensitive_settings() {
        let sensitive = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
routes:
  - id: route
    listen: local
    ingress: {mode: patch}
    cache: {enabled: true, key_headers: [authorization]}
    target: local
"#;
        let error = compile_yaml("cache-sensitive.yaml", sensitive).expect_err("sensitive key");
        assert!(error.to_string().contains("sensitive header"));

        let too_large = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
routes:
  - id: route
    listen: local
    ingress: {mode: patch}
    cache: {enabled: true, max_bytes: 65MiB}
    target: local
"#;
        let error = compile_yaml("cache-large.yaml", too_large).expect_err("large cache");
        assert!(error.to_string().contains("64 MiB"));

        let opaque = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
routes:
  - id: route
    listen: local
    cache: {enabled: true}
    target: local
"#;
        let compiled = compile_yaml("cache-opaque.yaml", opaque).expect("opaque cache");
        assert!(compiled.routes()[0].cache().is_some());

        let policy = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
policies:
  pooled:
    selection: {strategy: ordered_fallback}
routes:
  - id: route
    listen: local
    ingress: {mode: patch}
    cache: {enabled: true}
    target: {upstream: local, policy: pooled}
"#;
        let error = compile_yaml("cache-policy.yaml", policy).expect_err("policy cache");
        assert!(error.to_string().contains("selection policy"));
    }

    #[test]
    fn cache_rejects_semantic_and_policy_selection_routes() {
        let semantic = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
routes:
  - id: route
    listen: local
    ingress: {mode: semantic}
    cache: {enabled: true}
    target: local
"#;
        let error = compile_yaml("cache-semantic.yaml", semantic).expect_err("semantic cache");
        assert!(error.to_string().contains("semantic ingress mode"));

        let policy = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
policies:
  default: {selection: {strategy: fill_first}}
routes:
  - id: route
    listen: local
    cache: {enabled: true}
    target: {provider: local, policy: default}
"#;
        let error = compile_yaml("cache-policy.yaml", policy).expect_err("policy cache");
        assert!(error.to_string().contains("selection policy"));
    }

    #[test]
    fn rejects_misspelled_match_method_field() {
        let text = "version: 1\nroutes:\n  - id: r\n    match: {methd: POST}\n";
        let error = parse_yaml("unknown-field.yaml", text).expect_err("unknown field");
        let rendered = error.to_string();
        assert!(rendered.contains("unknown field"));
        assert!(rendered.contains("methd"));
    }

    #[test]
    fn provider_alias_invalid_url_reports_source_and_yaml_path() {
        let text = "version: 1\nlisteners: {local: {bind: 127.0.0.1:8400}}\nproviders:\n  local:\n    url: not-a-url\nroutes: []\n";
        let error = compile_yaml("provider-alias.yaml", text).expect_err("invalid URL");
        let rendered = error.to_string();
        assert!(rendered.contains("provider-alias.yaml (upstreams.local)"));
    }

    #[test]
    fn flow_style_provider_avoids_fabricated_coordinates() {
        let text = "version: 1\nlisteners: {local: {bind: 127.0.0.1:8400}}\nproviders: {local: {url: not-a-url}}\nroutes: []\n";
        let error = compile_yaml("flow.yaml", text).expect_err("invalid URL");
        assert!(error.to_string().contains("flow.yaml (upstreams.local)"));
    }

    #[test]
    fn quoted_flow_style_provider_avoids_fabricated_coordinates() {
        let text = "version: 1\nlisteners: {local: {bind: 127.0.0.1:8400}}\nproviders: {\"local\": {url: not-a-url}}\nroutes: []\n";
        let error = compile_yaml("quoted-flow.yaml", text).expect_err("invalid URL");
        assert!(error
            .to_string()
            .contains("quoted-flow.yaml (upstreams.local)"));
    }

    #[test]
    fn quoted_provider_alias_uses_canonical_path() {
        let text = "version: 1\n\"providers\": {local: {url: not-a-url}}\nroutes: []\n";
        let error = compile_yaml("quoted-section.yaml", text).expect_err("invalid URL");
        assert!(error
            .to_string()
            .contains("quoted-section.yaml (upstreams.local)"));
    }

    #[test]
    fn later_provider_reports_its_own_yaml_path() {
        let text = "version: 1\nproviders:\n  alpha:\n    url: http://127.0.0.1:1\n  beta:\n    url: not-a-url\nroutes: []\n";
        let error = compile_yaml("multiple.yaml", text).expect_err("invalid URL");
        assert!(error.to_string().contains("multiple.yaml (upstreams.beta)"));
    }

    #[test]
    fn non_loopback_routes_require_downstream_authentication() {
        let without_auth = "version: 1\nlisteners: {remote: {bind: 0.0.0.0:8400}}\nupstreams: {local: {url: http://127.0.0.1:1}}\nroutes: [{id: r, listen: remote, target: local}]\n";
        let error = compile_yaml("remote.yaml", without_auth).expect_err("auth required");
        assert!(error
            .to_string()
            .contains("require downstream authentication"));

        let with_auth = "version: 1\nlisteners: {remote: {bind: 0.0.0.0:8400}}\nupstreams: {local: {url: http://127.0.0.1:1}}\nroutes: [{id: r, listen: remote, downstream_auth: {secret: env:POOLER_DOWNSTREAM_KEY}, target: local}]\n";
        compile_yaml("remote-auth.yaml", with_auth).expect("authenticated remote route");

        let unix_without_auth = "version: 1\nlisteners: {local: {bind: /tmp/pooler.sock}}\nupstreams: {local: {url: http://127.0.0.1:1}}\nroutes: [{id: r, listen: local, target: local}]\n";
        let error = compile_yaml("unix.yaml", unix_without_auth).expect_err("Unix auth required");
        assert!(error
            .to_string()
            .contains("require downstream authentication"));
    }

    #[test]
    fn management_is_disabled_by_default_and_compiles_loopback_plan() {
        let disabled = compile_yaml("management-disabled.yaml", "version: 1\n")
            .expect("minimal config compiles");
        assert!(disabled.management().is_none());

        let enabled = compile_yaml(
            "management-loopback.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0}\n",
        )
        .expect("loopback management compiles");
        let management = enabled.management().expect("management is enabled");
        assert_eq!(management.bind(), "127.0.0.1:0");
        assert!(!management.remote());
        assert!(management.auth().is_none());
    }

    #[test]
    fn compiles_strict_catalog_sources_without_copying_credentials_or_static_models() {
        let text = r#"
version: 1
upstreams:
  provider-a:
    url: https://provider.example/v1
    auth: {secret: env:POOLER_PROVIDER_KEY}
catalog:
  refresh:
    timeout_ms: 2500
    max_concurrency: 2
    max_merge_operations: 10000
  sources:
    - id: provider-a.primary
      provider: provider-a
      parser: open_ai
      path: /v1/models?active=true
      max_response_bytes: 4096
      prefix: team
      priority: 20
      included_models: ['gpt-*']
      excluded_models: ['*-deprecated']
      aliases:
        - {name: gpt-current, alias: latest, fork: true, force_mapping: true}
"#;
        let config = compile_yaml("catalog.yaml", text).expect("catalog compiles");
        assert!(
            config.models().is_empty(),
            "static registry stays independent"
        );
        let catalog = config.catalog().expect("catalog plan");
        assert_eq!(catalog.limits().timeout(), Duration::from_millis(2_500));
        assert_eq!(catalog.sources().len(), 1);
        let source = &catalog.sources()[0];
        assert_eq!(source.source().id().as_str(), "provider-a.primary");
        assert_eq!(source.source().provider().as_str(), "provider-a");
        assert_eq!(source.parser(), CatalogParserKind::OpenAi);
        assert_eq!(source.path(), "/v1/models?active=true");
        assert_eq!(source.max_response_bytes(), 4096);
        assert_eq!(source.source().prefix(), Some("team"));
        assert_eq!(source.source().aliases()[0].public_id().as_str(), "latest");
        assert_eq!(
            source.source().included_models().collect::<Vec<_>>(),
            vec!["gpt-*"]
        );
        assert_eq!(
            source.source().excluded_models().collect::<Vec<_>>(),
            vec!["*-deprecated"]
        );
        assert_eq!(
            config.upstreams()["provider-a"]
                .auth()
                .expect("upstream auth")
                .secret()
                .redacted(),
            "env:POOLER_PROVIDER_KEY"
        );
    }

    #[test]
    fn catalog_model_facts_provider_defaults_to_the_source_provider() {
        let text = r#"
version: 1
upstreams:
  provider-a: {url: https://provider.example/v1}
  gateway: {url: https://gateway.example/v1}
catalog:
  sources:
    - {id: provider-a.primary, provider: provider-a, parser: open_ai}
    - {id: gateway.primary, provider: gateway, parser: open_ai, model_facts_provider: openai}
"#;
        let config = compile_yaml("catalog-model-facts.yaml", text).expect("catalog compiles");
        let catalog = config.catalog().expect("catalog plan");
        let facts_provider = |id: &str| {
            catalog
                .sources()
                .iter()
                .find(|source| source.source().id().as_str() == id)
                .expect("compiled source")
                .model_facts_provider()
                .to_owned()
        };

        assert_eq!(facts_provider("provider-a.primary"), "provider-a");
        assert_eq!(facts_provider("gateway.primary"), "openai");
    }

    #[test]
    fn catalog_rejects_unknown_providers_unsafe_paths_and_unknown_fields() {
        let missing = r#"
version: 1
catalog:
  sources: [{id: missing.primary, provider: missing, parser: open_ai}]
"#;
        let error = compile_yaml("catalog-missing.yaml", missing).expect_err("missing provider");
        assert!(error.to_string().contains("missing upstream `missing`"));

        let unsafe_path = r#"
version: 1
upstreams: {local: {url: http://127.0.0.1:1}}
catalog:
  sources: [{id: local.primary, provider: local, parser: open_ai, path: //other.example/models}]
"#;
        let error =
            compile_yaml("catalog-path.yaml", unsafe_path).expect_err("authority-like path");
        assert!(error.to_string().contains("no authority or fragment"));

        let unknown = r#"
version: 1
upstreams: {local: {url: http://127.0.0.1:1}}
catalog:
  sources: [{id: local.primary, provider: local, parser: open_ai, surprise: true}]
"#;
        let error = parse_yaml("catalog-unknown.yaml", unknown).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field `surprise`"));
    }

    #[test]
    fn management_requires_explicit_remote_enablement_and_authentication() {
        let without_enablement = compile_yaml(
            "management-remote-disabled.yaml",
            "version: 1\nmanagement: {bind: 0.0.0.0:9090}\n",
        )
        .expect_err("remote bind needs explicit enablement");
        assert!(without_enablement.to_string().contains("remote: true"));

        let without_auth = compile_yaml(
            "management-remote-unauthenticated.yaml",
            "version: 1\nmanagement: {bind: 0.0.0.0:9090, remote: true}\n",
        )
        .expect_err("remote management needs TLS");
        assert!(without_auth.to_string().contains("requires TLS"));

        let authenticated = compile_yaml(
            "management-remote-authenticated.yaml",
            "version: 1\nmanagement: {bind: 0.0.0.0:9090, remote: true, auth: {secret: env:POOLER_MANAGEMENT_KEY}}\n",
        )
        .expect_err("authenticated remote management still needs TLS");
        assert!(authenticated.to_string().contains("requires TLS"));
    }

    #[test]
    fn compiles_supported_auth_sources_and_rejects_unsupported_kinds() {
        let keyring = "version: 1\nupstreams: {local: {url: http://127.0.0.1:1, auth: {secret: keyring:pooler/account}}}\n";
        let config = compile_yaml("keyring.yaml", keyring).expect("keyring source");
        assert_eq!(
            config.upstreams()["local"]
                .auth()
                .expect("auth")
                .secret()
                .kind(),
            "keyring"
        );

        let kind = "version: 1\nupstreams: {local: {url: http://127.0.0.1:1, auth: {kind: basic, secret: env:POOLER_KEY}}}\n";
        let error = compile_yaml("kind.yaml", kind).expect_err("unsupported kind");
        assert!(error.to_string().contains("x_goog_api_key"));

        for (kind, expected) in [
            ("bearer", "bearer"),
            ("x-api-key", "x_api_key"),
            ("x-goog-api-key", "x_goog_api_key"),
        ] {
            let text = format!(
                "version: 1\nupstreams: {{local: {{url: http://127.0.0.1:1, auth: {{kind: {kind}, secret: env:POOLER_KEY}}}}}}\n"
            );
            let config = compile_yaml("provider-header.yaml", &text).expect("provider auth kind");
            assert_eq!(
                config.upstreams()["local"].auth().expect("auth").kind(),
                expected
            );
        }

        let downstream = "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\nupstreams: {local: {url: http://127.0.0.1:2}}\nroutes: [{id: r, listen: local, downstream_auth: {kind: x-api-key, secret: env:POOLER_KEY}, target: {provider: local}}]\n";
        let error = compile_yaml("downstream-header.yaml", downstream)
            .expect_err("downstream auth remains bearer-only");
        assert!(error.to_string().contains("requires a bearer auth kind"));
    }

    #[test]
    fn secret_reference_debug_is_redacted() {
        let reference = SecretRef::parse("env:POOLER_KEY").expect("reference");
        assert_eq!(reference.to_string(), "env:POOLER_KEY");
        assert!(!format!("{reference:?}").contains("secret-value"));
        assert!(SecretRef::parse("literal:secret-value").is_err());
        assert!(matches!(
            SecretRef::parse("external:pooler/master"),
            Err(SecretRefError::UnknownScheme)
        ));
    }

    #[test]
    fn compiles_model_registry_and_bounded_patch_steps() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
models:
  - id: gpt-public
    targets:
      - provider: local
        upstream_model: gpt-upstream
        capabilities: [text, tools, text]
routes:
  - id: patched
    listen: local
    ingress: {mode: patch, inspectors: [inspect.openai.model]}
    request:
      steps:
        - use: transform.json.set_when_model_prefix
          with: {prefix: gpt-, pointer: /reasoning/effort, value: high}
    target: {provider: local, model_from: request.model}
    response: {mode: opaque}
"#;
        let config = compile_yaml("patch.yaml", text).expect("patch config");
        let model = &config.models()["gpt-public"];
        assert_eq!(model.targets()[0].provider(), "local");
        assert_eq!(model.targets()[0].upstream_model(), "gpt-upstream");
        assert!(model.targets()[0].capabilities().contains(Capability::Text));
        assert!(model.targets()[0]
            .capabilities()
            .contains(Capability::Tools));
        assert!(matches!(
            config.routes()[0].request_steps(),
            [RequestTransform::JsonSetWhenModelPrefix { .. }]
        ));
        assert_eq!(
            config.routes()[0].target().model_source(),
            Some(ModelSource::Request)
        );
    }

    #[test]
    fn rejects_patch_steps_on_non_patch_routes() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: invalid
    listen: local
    request:
      steps:
        - use: transform.json.set
          with: {pointer: /value, value: true}
    target: local
"#;
        let error = compile_yaml("invalid-patch.yaml", text).expect_err("patch mode required");
        assert!(error.to_string().contains("require patch ingress mode"));
    }

    #[test]
    fn preserves_pointer_and_prefix_semantics_and_accepts_null_root_value() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: exact-text
    listen: local
    ingress: {mode: patch, inspectors: [inspect.openai.model]}
    request:
      steps:
        - use: transform.json.set_when_model_prefix
          with: {prefix: "gpt- ", pointer: "/field ", value: null}
        - use: transform.json.set
          with: {pointer: "", value: null}
    target: local
    response: {mode: opaque}
"#;
        let config = compile_yaml("exact-text.yaml", text).expect("exact transform text");
        let steps = config.routes()[0].request_steps();
        assert_eq!(steps[0].pointer(), "/field ");
        assert_eq!(steps[0].model_prefix(), Some("gpt- "));
        assert_eq!(steps[1].pointer(), "");
        assert!(steps[1].value().is_null());
    }

    #[test]
    fn rejects_unknown_capability_and_unused_transform_prefix() {
        let capability = "version: 1\nupstreams: {local: {url: http://127.0.0.1:1}}\nmodels: [{id: m, targets: [{provider: local, upstream_model: m, capabilities: [tolos]}]}]\n";
        let error = compile_yaml("capability.yaml", capability).expect_err("unknown capability");
        assert!(error.to_string().contains("unknown model capability"));

        let prefix = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: r
    listen: local
    ingress: {mode: patch}
    request:
      steps:
        - use: transform.json.set
          with: {pointer: /value, value: true, prefix: gpt-}
    target: local
    response: {mode: opaque}
"#;
        let error = compile_yaml("prefix.yaml", prefix).expect_err("unused prefix");
        assert!(error.to_string().contains("does not accept a prefix"));
    }

    #[test]
    fn compiles_account_pool_policy_and_immutable_budgets() {
        let text = r#"
version: 1
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
accounts:
  primary:
    provider: local
    secret: env:POOLER_PRIMARY
    weight: 2
    max_concurrency: 4
    quota_project: billing-project-1
  backup:
    provider: local
    secret: file:/run/pooler/backup.token
account_pools:
  default: {accounts: [primary, backup]}
policies:
  default:
    account_pool: default
    selection:
      strategy: health_weighted
      session_affinity: 30m
    retry:
      maximum_attempts: 3
      maximum_credentials: 2
      before_commit_only: true
      statuses: [408, 429, 500, 503]
      base_delay: 100ms
      maximum_delay: 5s
      maximum_total_delay: 20s
    stream:
      bootstrap_events: 1
      bootstrap_bytes: 64KiB
      bootstrap_timeout: 20s
routes:
  - id: pooled
    listen: local
    target: {provider: local, policy: default}
"#;
        let config = compile_yaml("pooling.yaml", text).expect("pooling config");
        assert_eq!(config.accounts().len(), 2);
        assert_eq!(config.accounts()["primary"].weight(), 2);
        assert_eq!(
            config.accounts()["primary"].quota_project(),
            Some("billing-project-1")
        );
        assert_eq!(
            config.accounts()["primary"].source().path.as_ref(),
            "accounts.primary"
        );
        assert_eq!(config.accounts()["backup"].quota_project(), None);
        assert_eq!(config.account_pools()["default"].accounts().len(), 2);
        let policy = &config.policies()["default"];
        assert_eq!(
            policy.selection().strategy(),
            SelectionStrategy::HealthWeighted
        );
        assert_eq!(policy.selection().account_pool(), Some("default"));
        assert_eq!(
            policy.selection().affinity().expect("affinity").ttl(),
            Duration::from_secs(30 * 60)
        );
        assert!(policy.retry().before_commit_only());
        assert_eq!(policy.retry().maximum_attempts(), 3);
        assert_eq!(policy.retry().maximum_credentials(), 2);
        assert!(policy.retry().allows_status(503));
        assert!(!policy.retry().allows_status(400));
        assert_eq!(policy.stream().bootstrap_bytes(), 64 * 1024);
        assert_eq!(config.routes()[0].target().policy(), Some("default"));
    }

    #[test]
    fn rejects_unbounded_or_ambiguous_retry_configuration() {
        let missing_commit = r#"
version: 1
policies:
  default:
    retry: {maximum_attempts: 2, maximum_credentials: 2, statuses: [503]}
"#;
        let error = compile_yaml("missing-commit.yaml", missing_commit)
            .expect_err("pre-commit guard is required");
        assert!(error.to_string().contains("before_commit_only"));

        let missing_credentials = r#"
version: 1
policies:
  default:
    retry: {maximum_attempts: 2, before_commit_only: true, statuses: [503]}
"#;
        let error = compile_yaml("missing-credentials.yaml", missing_credentials)
            .expect_err("credential budget is required");
        assert!(error.to_string().contains("maximum_credentials"));

        let invalid_status = r#"
version: 1
policies:
  default:
    retry: {maximum_attempts: 2, maximum_credentials: 2, before_commit_only: true, statuses: [400]}
"#;
        let error = compile_yaml("invalid-status.yaml", invalid_status)
            .expect_err("invalid status must not retry");
        assert!(error.to_string().contains("retry statuses"));
    }

    #[test]
    fn rejects_invalid_strategy_affinity_and_budget_literals() {
        let strategy = "version: 1\npolicies: {default: {selection: {strategy: random}}}\n";
        let error = compile_yaml("strategy.yaml", strategy).expect_err("unknown strategy");
        assert!(error.to_string().contains("unknown selection strategy"));

        let affinity = r#"
version: 1
policies:
  default:
    selection:
      strategy: round_robin
      affinity: {key: "header:bad header", ttl: 0s}
"#;
        let error = compile_yaml("affinity.yaml", affinity).expect_err("invalid affinity");
        assert!(error.to_string().contains("affinity"));

        let bytes = r#"
version: 1
policies:
  default:
    stream: {bootstrap_bytes: 2XB}
"#;
        let error = parse_yaml("bytes.yaml", bytes).expect_err("invalid byte size");
        assert!(error.to_string().contains("byte size"));
    }

    #[test]
    fn account_and_policy_references_are_strict() {
        let missing_provider = r#"
version: 1
accounts: {primary: {provider: absent, secret: env:POOLER_PRIMARY}}
"#;
        let error =
            compile_yaml("provider-ref.yaml", missing_provider).expect_err("missing provider");
        assert!(error.to_string().contains("missing upstream `absent`"));

        let invalid_quota_project = r#"
version: 1
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  primary: {provider: local, secret: env:POOLER_PRIMARY, quota_project: "tenant/unsafe"}
"#;
        let error = compile_yaml("quota-project.yaml", invalid_quota_project)
            .expect_err("quota project IDs are bounded identifiers");
        assert!(error.to_string().contains("invalid quota project ID"));

        let missing_account = r#"
version: 1
account_pools: {default: {accounts: [absent]}}
"#;
        let error = compile_yaml("account-ref.yaml", missing_account).expect_err("missing account");
        assert!(error.to_string().contains("missing account `absent`"));

        let unknown = "version: 1\npolicies: {default: {rety: {maximum_attempts: 2}}}\n";
        let error = parse_yaml("policy-field.yaml", unknown).expect_err("unknown policy field");
        assert!(error.to_string().contains("rety"));
    }

    #[test]
    fn compiles_strict_oauth_provider_and_retains_no_token_material() {
        let text = r#"
version: 1
upstreams:
  codex:
    url: https://api.example.test
    oauth:
      authorization_endpoint: https://auth.example.test/authorize
      token_endpoint: https://auth.example.test/token
      revocation_endpoint: https://auth.example.test/revoke
      client_id: pooler-cli
      scopes: [openid, profile]
      callback: http://127.0.0.1:8765/oauth/callback
"#;
        let config = compile_yaml("oauth.yaml", text).expect("oauth config");
        let oauth = config.upstreams()["codex"].oauth().expect("oauth plan");
        assert_eq!(oauth.client_id(), "pooler-cli");
        assert_eq!(oauth.scopes().len(), 2);
        assert_eq!(oauth.callback().host_str(), Some("127.0.0.1"));
        assert!(format!("{oauth:?}").contains("pooler-cli"));
        assert!(!format!("{oauth:?}").contains("access_token"));
    }

    #[test]
    fn rejects_unsafe_oauth_callback_and_duplicate_scopes() {
        let public_callback = r#"
version: 1
upstreams:
  codex:
    url: https://api.example.test
    oauth:
      authorization_endpoint: https://auth.example.test/authorize
      token_endpoint: https://auth.example.test/token
      client_id: pooler-cli
      scopes: [openid]
      callback: https://example.test/callback
"#;
        let error = compile_yaml("oauth-public.yaml", public_callback)
            .expect_err("public callback must fail");
        assert!(error.to_string().contains("loopback"));

        let duplicate_scope = public_callback
            .replace("scopes: [openid]", "scopes: [openid, openid]")
            .replace(
                "callback: https://example.test/callback",
                "callback: http://127.0.0.1:8765/callback",
            );
        let error = compile_yaml("oauth-duplicate-scope.yaml", &duplicate_scope)
            .expect_err("duplicate scopes must fail");
        assert!(error.to_string().contains("non-empty and unique"));

        let fallback = r#"
version: 1
upstreams:
  codex:
    url: https://api.example.test
    oauth:
      authorization_endpoint: https://auth.example.test/authorize
      token_endpoint: https://auth.example.test/token
      client_id: pooler-cli
      scopes: [openid]
"#;
        let config = compile_yaml("oauth-fallback.yaml", fallback).expect("default callback");
        assert_eq!(
            config.upstreams()["codex"]
                .oauth()
                .expect("oauth plan")
                .callback()
                .as_str(),
            DEFAULT_OAUTH_CALLBACK
        );
    }

    #[test]
    fn compiles_native_provider_with_oauth_authentication() {
        let text = r#"
version: 1
upstreams:
  provider:
    url: https://api.example.test
    oauth:
      authorization_endpoint: https://auth.example.test/authorize
      token_endpoint: https://auth.example.test/token
      client_id: pooler-cli
      scopes: [openid]
      callback: http://127.0.0.1:8765/callback
      identity_endpoint: https://auth.example.test/me
    native: {kind: codex}
"#;
        let config = compile_yaml("oauth-native.yaml", text).expect("native OAuth provider");
        let provider = &config.upstreams()["provider"];
        assert!(provider.oauth().is_some());
        assert_eq!(
            provider
                .oauth()
                .expect("oauth plan")
                .identity_endpoint()
                .expect("identity endpoint")
                .path(),
            "/me"
        );
        assert_eq!(provider.native().expect("native plan").kind(), "codex");
    }

    #[test]
    fn native_codex_oauth_compiles_without_identity_endpoint() {
        let text = r#"
version: 1
upstreams:
  provider:
    known_provider: openai
    native: {kind: codex}
accounts:
  personal:
    provider: provider
    auth_kind: oauth
"#;
        let config = compile_yaml("oauth-native-codex.yaml", text).expect("native Codex login");
        assert!(config.upstreams()["provider"].oauth().is_none());
        assert_eq!(
            config.upstreams()["provider"].url().as_str(),
            "https://chatgpt.com/"
        );
        assert_eq!(
            config.accounts()["personal"].auth_kind(),
            AccountAuthKind::OAuth
        );

        let explicit = compile_yaml(
            "oauth-native-codex-gateway.yaml",
            r#"
version: 1
upstreams:
  provider:
    url: https://gateway.example.test/openai
    known_provider: openai
    native: {kind: codex}
"#,
        )
        .expect("explicit Codex gateway");
        assert_eq!(
            explicit.upstreams()["provider"].url().as_str(),
            "https://gateway.example.test/openai"
        );
    }

    #[test]
    fn compiles_native_provider_quota_endpoint() {
        let text = r#"
version: 1
upstreams:
  codex:
    url: https://api.example.test
    native:
      kind: codex
      quota_endpoint: https://api.example.test/quota
"#;
        let config = compile_yaml("native.yaml", text).expect("native config");
        let native = config.upstreams()["codex"].native().expect("native plan");
        assert_eq!(native.kind(), "codex");
        assert_eq!(native.quota_endpoint().expect("quota").path(), "/quota");
    }

    #[test]
    fn compiles_external_extension_component_plan() {
        let text = r#"
version: 1
extensions:
  local:
    command: /bin/cat
    capabilities: [inspect, transform]
    limits: {max_input_bytes: 2048, max_output_bytes: 4096, timeout: 250ms, max_concurrency: 2}
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
models:
  - id: selected
    targets: [{provider: local, upstream_model: selected}]
routes:
  - id: external
    listen: local
    ingress: {mode: patch, inspectors: [inspect.external.local]}
    request:
      steps:
        - use: transform.external.local
          with: {pointer: /unused, value: null}
    target: {provider: local, model_from: inspected.model}
  - id: external-inspect
    listen: local
    match: {path: /inspect}
    ingress: {mode: inspect, inspectors: [inspect.external.local]}
    target: local
"#;
        let config = compile_yaml("external.yaml", text).expect("external extension config");
        let extension = &config.extensions()["local"];
        assert_eq!(extension.command(), Some("/bin/cat"));
        assert!(extension.allows("inspect"));
        assert!(extension.allows("transform"));
        assert_eq!(extension.limits().max_input_bytes(), 2048);
        assert_eq!(
            config
                .route("external")
                .expect("external route")
                .external_transforms(),
            &[Arc::from("local")]
        );
        assert_eq!(
            config
                .route("external")
                .expect("inspect route")
                .ingress()
                .inspectors(),
            &[Arc::from("inspect.external.local")]
        );

        let wasm_config = compile_yaml(
            "wasm-extension.yaml",
            "version: 1\nextensions: {module: {wasm: /tmp/module.wasm, capabilities: [inspect]}}\n",
        )
        .expect("WASM extension declaration");
        assert_eq!(wasm_config.extensions()["module"].command(), None);
        assert_eq!(
            wasm_config.extensions()["module"].wasm(),
            Some("/tmp/module.wasm")
        );
    }

    #[test]
    fn rejects_external_extension_without_a_granted_capability() {
        let text = r#"
version: 1
extensions:
  local: {command: /bin/cat, capabilities: [inspect]}
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: external
    listen: local
    ingress: {mode: patch}
    request:
      steps:
        - use: transform.external.local
          with: {pointer: /unused, value: null}
    target: local
"#;
        let error =
            compile_yaml("external-denied.yaml", text).expect_err("missing transform grant");
        assert!(error.to_string().contains("capability is not granted"));
    }
}
