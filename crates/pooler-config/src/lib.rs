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

use http::Method;
pub use pooler_core::{BodyMode, ConfigGeneration, LossPolicy, RouteLimits};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

mod route_match;

use route_match::{prefix_matches, template_matches};
pub use route_match::{RouteMatchError, RouteRequest};

/// Current configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

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
}

impl Source {
    fn new(name: impl Into<Arc<str>>, _text: impl Into<Arc<str>>) -> Self {
        Self { name: name.into() }
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
    /// External secret-manager key.
    External(Arc<str>),
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
            "external" => Ok(Self::External(Arc::from(payload))),
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
            Self::External(key) => format!("external:{key}"),
        }
    }

    /// Reference scheme.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Env(_) => "env",
            Self::File(_) => "file",
            Self::Keyring { .. } => "keyring",
            Self::External(_) => "external",
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
    #[error("literal secret values are not allowed; use env:, file:, keyring:, or external:")]
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
    /// Routes in declaration order.
    pub routes: Vec<RouteConfig>,
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
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref).map_err(|error| ConfigError::Io {
            path: path_ref.display().to_string(),
            message: error.to_string(),
        })?;
        Self::from_yaml(path_ref.display().to_string(), &text)
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
}

/// Upstream transport declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Transport kind, normally `http` or `https`.
    pub kind: Option<String>,
    /// Base URL.
    pub base_url: Option<String>,
    /// Connection timeout such as `5s`.
    pub connect_timeout: Option<String>,
    /// Request timeout such as `30m`.
    pub request_timeout: Option<String>,
}

/// Upstream authentication declaration.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Authentication kind.
    pub kind: Option<String>,
    /// Secret reference.
    pub secret: Option<SecretRef>,
}

/// Downstream authentication declaration.
///
/// Downstream authentication currently accepts the same secret-reference
/// shape as upstream authentication, but only bearer authentication is
/// compiled into a route plan.
pub type DownstreamAuthConfig = AuthConfig;

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
    /// Ingress body handling.
    pub ingress: Option<BodyConfig>,
    /// Response body handling.
    pub response: Option<BodyConfig>,
    /// Target declaration.
    pub target: Option<TargetValue>,
    /// Upstream ID shorthand.
    pub upstream: Option<String>,
    /// Loss policy.
    pub loss_policy: Option<LossPolicy>,
    /// Explicit precedence override.
    pub priority: Option<i32>,
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
    /// Decoder component.
    pub decoder: Option<String>,
    /// Encoder component.
    pub encoder: Option<String>,
    /// Inspector components.
    pub inspectors: Vec<String>,
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
}

/// Immutable listener plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerPlan {
    id: Arc<str>,
    bind: Arc<str>,
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
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    auth: Option<AuthPlan>,
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

    /// Source declaration label.
    #[must_use]
    pub const fn source(&self) -> &SourceLabel {
        &self.source
    }
}

/// Immutable authentication plan containing only a secret reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPlan {
    kind: Arc<str>,
    secret: SecretRef,
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
    decoder: Option<Arc<str>>,
    encoder: Option<Arc<str>>,
    inspectors: Vec<Arc<str>>,
}

impl BodyPlan {
    /// Body mode.
    #[must_use]
    pub const fn mode(&self) -> BodyMode {
        self.mode
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
}

/// Immutable route plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    id: Arc<str>,
    listener: Arc<str>,
    matcher: MatchPlan,
    ingress: BodyPlan,
    response: BodyPlan,
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

    /// Response plan.
    #[must_use]
    pub const fn response(&self) -> &BodyPlan {
        &self.response
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
    routes: Vec<RoutePlan>,
}

impl CompiledConfig {
    /// Generation associated with this plan.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
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
        listeners.insert(
            Arc::from(id.as_str()),
            ListenerPlan {
                id: Arc::from(id.as_str()),
                bind: Arc::from(declaration.bind.trim()),
                source: label,
            },
        );
    }

    let mut upstreams = BTreeMap::new();
    for (id, declaration) in &config.upstreams {
        let label = upstream_label(source, id, upstreams.len());
        validate_id("upstream", id, &label)?;
        let (url, transport, connect_timeout, request_timeout) =
            compile_upstream(declaration, &label)?;
        let auth = compile_auth(declaration.auth.as_ref(), &label)?;
        upstreams.insert(
            Arc::from(id.as_str()),
            UpstreamPlan {
                id: Arc::from(id.as_str()),
                url,
                transport,
                connect_timeout,
                request_timeout,
                auth,
                source: label,
            },
        );
    }

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
        let response = compile_body(
            declaration.response.as_ref(),
            ingress.mode(),
            &label,
            "response",
        )?;
        let target = compile_target(declaration, &label, &upstreams)?;
        let downstream_auth =
            compile_downstream_auth(declaration.downstream_auth.as_ref(), &label)?;
        if listener_requires_auth(&listeners[listener]) && downstream_auth.is_none() {
            return Err(invalid(
                &label,
                "routes on non-loopback listeners require downstream authentication",
            ));
        }
        let limits = compile_limits(declaration.limits.as_ref(), &label)?;
        if declaration.loss_policy.is_some() && ingress.mode() != BodyMode::Semantic {
            return Err(invalid(&label, "loss_policy requires semantic ingress"));
        }
        routes.push(RoutePlan {
            id: Arc::from(declaration.id.as_str()),
            listener: Arc::from(listener),
            matcher,
            ingress,
            response,
            target,
            downstream_auth,
            limits,
            loss_policy: declaration.loss_policy.unwrap_or(LossPolicy::Reject),
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
        routes,
    })
}

fn listener_requires_auth(listener: &ListenerPlan) -> bool {
    listener
        .bind()
        .parse::<SocketAddr>()
        .map_or(true, |address| !address.ip().is_loopback())
}

type CompiledTransport = (Url, Arc<str>, Option<Duration>, Option<Duration>);

fn compile_upstream(
    declaration: &UpstreamConfig,
    label: &SourceLabel,
) -> Result<CompiledTransport, ConfigError> {
    let transport = declaration.transport.as_ref();
    let raw_url = transport
        .and_then(|value| value.base_url.as_deref())
        .or(declaration.base_url.as_deref())
        .or(declaration.url.as_deref())
        .ok_or_else(|| invalid(label, "upstream requires url or transport.base_url"))?;
    let url = Url::parse(raw_url).map_err(|_| invalid(label, "upstream URL is invalid"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(invalid(
            label,
            "upstream URL must use http(s) and include a host",
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
    if !matches!(transport_kind.as_str(), "http" | "https") {
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
    Ok((
        url,
        Arc::from(transport_kind),
        connect_timeout,
        request_timeout,
    ))
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
    let kind = auth.kind.as_deref().unwrap_or("bearer_secret").trim();
    if !matches!(kind, "bearer" | "bearer_secret") {
        return Err(invalid(label, "auth kind must be bearer or bearer_secret"));
    }
    if !matches!(secret, SecretRef::Env(_) | SecretRef::File(_)) {
        return Err(invalid(
            label,
            "auth secrets must use an env: or file: reference",
        ));
    }
    Ok(Some(AuthPlan {
        kind: Arc::from(kind),
        secret: secret.clone(),
    }))
}

fn compile_downstream_auth(
    declaration: Option<&DownstreamAuthConfig>,
    label: &SourceLabel,
) -> Result<Option<AuthPlan>, ConfigError> {
    let Some(declaration) = declaration else {
        return Ok(None);
    };
    let plan = compile_auth(Some(declaration), label)?.expect("auth declaration was present");
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
    if mode == BodyMode::Opaque
        && (!declaration.inspectors.is_empty() || declaration.decoder.is_some())
    {
        return Err(invalid(
            label,
            &format!("{field} opaque mode cannot use inspectors or decoder"),
        ));
    }
    Ok(BodyPlan {
        mode,
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
) -> Result<TargetPlan, ConfigError> {
    let target = declaration.target.as_ref();
    let (upstream, path) = match target {
        Some(TargetValue::Name(name)) => (Some(name.as_str()), None),
        Some(TargetValue::Config(config)) => (config.upstream.as_deref(), config.path.as_deref()),
        None => (declaration.upstream.as_deref(), None),
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
    let path = path
        .map(|value| valid_path(value.to_owned(), label))
        .transpose()?;
    Ok(TargetPlan {
        upstream: Arc::from(upstream),
        path,
    })
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
    SourceLabel::new(source, None, None, format!("{section}.{id}"))
}

fn upstream_label(source: &Source, id: &str, ordinal: usize) -> SourceLabel {
    declaration_label(source, "upstreams", id, ordinal)
}

fn route_label(source: &Source, ordinal: usize, id: &str) -> SourceLabel {
    let _ = id;
    SourceLabel::new(source, None, None, format!("routes[{ordinal}]"))
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
    fn rejects_auth_that_the_http_runtime_cannot_execute() {
        let keyring = "version: 1\nupstreams: {local: {url: http://127.0.0.1:1, auth: {secret: keyring:pooler/account}}}\n";
        let error = compile_yaml("keyring.yaml", keyring).expect_err("unsupported source");
        assert!(error.to_string().contains("env: or file:"));

        let kind = "version: 1\nupstreams: {local: {url: http://127.0.0.1:1, auth: {kind: basic, secret: env:POOLER_KEY}}}\n";
        let error = compile_yaml("kind.yaml", kind).expect_err("unsupported kind");
        assert!(error.to_string().contains("bearer or bearer_secret"));
    }

    #[test]
    fn secret_reference_debug_is_redacted() {
        let reference = SecretRef::parse("env:POOLER_KEY").expect("reference");
        assert_eq!(reference.to_string(), "env:POOLER_KEY");
        assert!(!format!("{reference:?}").contains("secret-value"));
        assert!(SecretRef::parse("literal:secret-value").is_err());
    }
}
