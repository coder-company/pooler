//! Authenticated management HTTP responses.
//!
//! The management surface is intentionally separate from inference routes.
//! It exposes immutable plans and redacted mutable state, accepts only bounded
//! body-free control operations, and never serializes credential references.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{header, HeaderMap, Method, Response, StatusCode, Uri};
use http_body::Body as _;
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use pooler_auth::{
    bearer_authorization_matches, ProviderLoginMethod, ProviderLoginRegistry, ProviderLoginSupport,
    SecretRef as RuntimeSecretRef,
};
use pooler_config::{compile_yaml, CompiledConfig, ManagementPlan};
use pooler_http::{PoolError, PoolingCoordinator};
use pooler_model_catalog::ProviderCatalog;
use pooler_store::{CredentialHealthState, CredentialHealthStatus, CredentialState};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, UnixListener},
    sync::{mpsc, Notify},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::http_runtime::RuntimeGeneration;
use crate::management_ui;
use crate::{merged_model_catalog_value, CatalogRuntime, ConfigSnapshot, ConfigStore};

const DEFAULT_DECISION_LIMIT: usize = 20;
const MAX_DECISION_LIMIT: usize = 100;
const MAX_MANAGEMENT_AUDIT_EVENTS: usize = 256;
const MAX_MANAGEMENT_RELOADS: usize = 256;
const MAX_PENDING_MANAGEMENT_RELOADS: usize = 16;
const MAX_MANAGEMENT_HEADER_BYTES: usize = 64 * 1024;
const MANAGEMENT_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MANAGEMENT_BODY_GUARD_TIMEOUT: Duration = Duration::from_millis(50);
const LOOPBACK_HOST_ERROR: &str =
    "management Host header must name localhost or a loopback address";

/// A small active-request counter shared by management and the serving
/// runtime. Counters are process-local and never persisted.
#[derive(Clone, Debug, Default)]
pub struct ActiveCounts {
    inner: Arc<ActiveCountsInner>,
}

#[derive(Debug, Default)]
struct ActiveCountsInner {
    total: AtomicUsize,
    listeners: Mutex<BTreeMap<String, usize>>,
}

impl ActiveCounts {
    /// Create empty active counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter one request for a listener. The returned guard decrements the
    /// count when the request or response stream ends.
    #[must_use]
    pub fn enter(&self, listener: impl Into<String>) -> ActiveGuard {
        let listener = listener.into();
        self.inner.total.fetch_add(1, Ordering::Relaxed);
        let mut listeners = self
            .inner
            .listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *listeners.entry(listener.clone()).or_default() += 1;
        drop(listeners);
        ActiveGuard {
            inner: Arc::clone(&self.inner),
            listener: Some(listener),
        }
    }

    /// Return the total active request count.
    #[must_use]
    pub fn total(&self) -> usize {
        self.inner.total.load(Ordering::Acquire)
    }

    /// Return deterministic active counts keyed by listener ID.
    #[must_use]
    pub fn by_listener(&self) -> BTreeMap<String, usize> {
        self.inner
            .listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// A request activity guard.
pub struct ActiveGuard {
    inner: Arc<ActiveCountsInner>,
    listener: Option<String>,
}

impl std::fmt::Debug for ActiveGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveGuard")
            .field("listener", &self.listener)
            .finish()
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let Some(listener) = self.listener.take() else {
            return;
        };
        self.inner.total.fetch_sub(1, Ordering::Release);
        let mut listeners = self
            .inner
            .listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = listeners.get_mut(&listener) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                listeners.remove(&listener);
            }
        }
    }
}

/// One body-free management response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// UTF-8 JSON response body. `HEAD` responses intentionally have an empty
    /// body while retaining the same content length as `GET`.
    pub body: Vec<u8>,
}

impl ManagementResponse {
    fn json(status: StatusCode, value: Value, head: bool) -> Self {
        let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
        Self::body(status, "application/json", encoded, head)
    }

    fn body(status: StatusCode, content_type: &'static str, encoded: Vec<u8>, head: bool) -> Self {
        let content_length = encoded.len().to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static(content_type),
        );
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_str(&content_length)
                .expect("JSON body length is a valid header value"),
        );
        security_headers(&mut headers);
        Self {
            status,
            headers,
            body: if head { Vec::new() } else { encoded },
        }
    }

    fn asset(
        status: StatusCode,
        content_type: &'static str,
        body: &'static [u8],
        head: bool,
    ) -> Self {
        Self::body(status, content_type, body.to_vec(), head)
    }
}

fn security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        header::HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        header::HeaderValue::from_static("same-origin"),
    );
}

/// Return whether a request's Host header is safe for an unauthenticated
/// loopback management listener. Browsers can be DNS-rebound onto loopback,
/// so a missing or arbitrary Host must not reach an unauthenticated API.
fn management_request_host_allowed(
    api: &ManagementApi,
    ui_asset: bool,
    headers: &HeaderMap,
) -> bool {
    if (!ui_asset && api.plan.auth().is_some()) || !management_bind_is_loopback(api.bind()) {
        return true;
    }
    let mut hosts = headers.get_all(header::HOST).iter();
    let Some(value) = hosts.next() else {
        return false;
    };
    if hosts.next().is_some() {
        return false;
    }
    value.to_str().ok().is_some_and(safe_loopback_host_value)
}

fn management_origin_allowed(headers: &HeaderMap) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    origin
        .to_str()
        .ok()
        .and_then(|value| value.parse::<Uri>().ok())
        .and_then(|uri| {
            uri.authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .is_some_and(|authority| authority.eq_ignore_ascii_case(host))
}

fn percent_decode_path(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            let hex = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            decoded.push(hex(high)?.checked_mul(16)?.checked_add(hex(low)?)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn management_query_value(query: Option<&str>, key: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(name, value)| {
            (name == key).then(|| percent_decode_path(&value.replace('+', " ")))?
        })
}

fn valid_setup_component(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_setup_model(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn setup_support_name(support: ProviderLoginSupport) -> &'static str {
    match support {
        ProviderLoginSupport::Supported => "supported",
        ProviderLoginSupport::RequiresExplicitConfiguration => "requires_explicit_configuration",
        ProviderLoginSupport::Unsupported => "unsupported",
    }
}

fn setup_client_compatible(client: &str, dialect: &str) -> bool {
    match client {
        "native" => true,
        "openai" | "codex" | "cursor" | "droid" | "factory" | "devin" => dialect == "openai",
        "anthropic" => dialect == "anthropic",
        "gemini" => dialect == "gemini",
        _ => false,
    }
}

fn setup_route_yaml(client: &str, dialect: &str, provider: &str) -> Result<String, &'static str> {
    if !setup_client_compatible(client, dialect) {
        return Err("selected client does not match the provider request dialect");
    }
    let target = format!("{{provider: {provider}, policy: setup-account}}");
    let route = match client {
        "factory" => format!(
            "  - id: setup-factory\n    listen: gateway\n    match: {{method: POST, path: /v3/ai/language-model, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: {{provider: {provider}, path: /v1/chat/completions, model_from: request.model, policy: setup-account}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: degrade\n"
        ),
        "devin" => format!(
            "  - id: setup-devin\n    listen: gateway\n    match: {{method: POST, path: /exa.api_server_pb.ApiServerService/GetChatMessage, content_types: [application/connect+proto]}}\n    ingress: {{mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}}\n    target: {{provider: {provider}, path: /v1/chat/completions, policy: setup-account}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}}\n    loss_policy: reject\n"
        ),
        _ => {
            let path_prefix = match dialect {
                "anthropic" => "/v1/",
                "gemini" => "/v1beta/",
                _ => "/v1/",
            };
            format!(
                "  - id: setup-gateway\n    listen: gateway\n    match: {{methods: [GET, POST, DELETE], path_prefix: {path_prefix}}}\n    ingress: {{mode: opaque}}\n    target: {target}\n    response: {{mode: opaque}}\n"
            )
        }
    };
    Ok(route)
}

fn generate_setup_config(
    provider_id: &str,
    auth_method: &str,
    account_id: &str,
    model_id: &str,
    client: &str,
) -> Result<String, &'static str> {
    if !valid_setup_component(provider_id, 128)
        || !valid_setup_component(account_id, 128)
        || !valid_setup_model(model_id)
    {
        return Err("setup selection contains an invalid identifier");
    }
    let catalog = ProviderCatalog::builtin();
    let provider = catalog
        .get(provider_id)
        .ok_or("selected provider is not in the built-in catalog")?;
    let login = ProviderLoginRegistry::builtin().resolve(provider_id);
    let oauth_method = match auth_method {
        "api_key" => {
            if login.is_some_and(|definition| {
                definition.support(ProviderLoginMethod::ApiKey) != ProviderLoginSupport::Supported
            }) {
                return Err("selected provider does not support API-key login in this wizard");
            }
            false
        }
        "authorization_code_pkce" => {
            let definition = login.ok_or("selected provider has no OAuth login profile")?;
            match definition.support(ProviderLoginMethod::AuthorizationCodePkce) {
                ProviderLoginSupport::Supported => {}
                ProviderLoginSupport::RequiresExplicitConfiguration => {
                    return Err(
                        "browser OAuth requires operator-owned registration details that this wizard cannot collect",
                    );
                }
                ProviderLoginSupport::Unsupported => {
                    return Err("selected provider does not support browser OAuth login");
                }
            }
            true
        }
        "device_code" => {
            let definition = login.ok_or("selected provider has no OAuth login profile")?;
            match definition.support(ProviderLoginMethod::DeviceCode) {
                ProviderLoginSupport::Supported => {}
                ProviderLoginSupport::RequiresExplicitConfiguration => {
                    return Err(
                        "device login requires operator-owned registration details that this wizard cannot collect",
                    );
                }
                ProviderLoginSupport::Unsupported => {
                    return Err("selected provider does not support device-code login");
                }
            }
            true
        }
        _ => return Err("unknown authentication method"),
    };
    let secret_environment = provider.env.first().map(String::as_str).or_else(|| {
        login.and_then(|definition| definition.api_key_environment_variables().first().copied())
    });
    if !oauth_method && secret_environment.is_none() {
        return Err("selected provider has no documented API-key environment variable");
    }
    let route = setup_route_yaml(client, &provider.integration.request_dialect, provider_id)?;
    let account = if oauth_method {
        format!("  {account_id}:\n    provider: {provider_id}\n    auth_kind: oauth\n")
    } else {
        format!(
            "  {account_id}:\n    provider: {provider_id}\n    auth_kind: api_key\n    secret: env:{}\n",
            secret_environment.expect("API-key environment checked")
        )
    };
    let discovery = match (
        provider.integration.discovery_parser.as_deref(),
        provider.integration.discovery_path.as_deref(),
    ) {
        (Some(parser), Some(path)) => format!(
            "catalog:\n  sources:\n    - id: setup-{provider_id}\n      provider: {provider_id}\n      account: {account_id}\n      parser: {parser}\n      path: {path}\n\n"
        ),
        _ => String::new(),
    };
    let quoted_model =
        serde_json::to_string(model_id).map_err(|_| "model identifier is invalid")?;
    let model_mapping = if discovery.is_empty() {
        format!(
            "models:\n  - id: {quoted_model}\n    targets:\n      - provider: {provider_id}\n        upstream_model: {quoted_model}\n\n"
        )
    } else {
        String::new()
    };
    let bind = match client {
        "factory" => "127.0.0.1:18474",
        "devin" => "127.0.0.1:18473",
        _ => "127.0.0.1:8319",
    };
    let upstream_native = if oauth_method && provider_id == "openai" {
        "    native: {kind: codex}\n"
    } else {
        ""
    };
    let config = format!(
        "version: 1\n\nlisteners:\n  gateway:\n    bind: {bind}\n\nupstreams:\n  {provider_id}:\n    known_provider: {provider_id}\n{upstream_native}\naccounts:\n{account}\naccount_pools:\n  setup:\n    accounts: [{account_id}]\n\npolicies:\n  setup-account:\n    selection:\n      strategy: ordered_fallback\n      account_pool: setup\n\n{model_mapping}{discovery}routes:\n{route}\nmanagement:\n  bind: 127.0.0.1:18477\n  auth:\n    secret: env:POOLER_MANAGEMENT_TOKEN\n"
    );
    compile_yaml("management-setup-generated.yaml", &config)
        .map_err(|_| "generated configuration did not pass Pooler validation")?;
    Ok(config)
}

fn setup_selection(
    query: Option<&str>,
) -> Result<(String, String, String, String, String), &'static str> {
    let required = |key| {
        management_query_value(query, key)
            .filter(|value| !value.is_empty())
            .ok_or("setup request is missing a required selection")
    };
    Ok((
        required("provider")?,
        required("auth")?,
        required("account")?,
        required("model")?,
        required("client")?,
    ))
}

fn management_account_action(path: &str) -> Option<(String, &str)> {
    let suffix = path.strip_prefix("/accounts/")?;
    let (account, action) = suffix.rsplit_once('/')?;
    let account = percent_decode_path(account)?;
    (!account.is_empty()
        && account.len() <= 128
        && !account.contains('/')
        && matches!(
            action,
            "enable" | "disable" | "switch" | "refresh" | "revoke"
        ))
    .then_some((account, action))
}

fn management_model_action(path: &str) -> Option<(String, &str)> {
    let suffix = path.strip_prefix("/models/")?;
    for action in ["enable", "disable"] {
        if let Some(model) = suffix.strip_suffix(&format!("/{action}")) {
            let model = model
                .split('/')
                .map(percent_decode_path)
                .collect::<Option<Vec<_>>>()?
                .join("/");
            return (!model.is_empty() && model.len() <= 256).then_some((model, action));
        }
    }
    None
}

fn is_management_mutation(method: &Method, path: &str) -> bool {
    *method == Method::POST
        && (path == "/reload"
            || path == "/models/reload"
            || management_account_action(path).is_some()
            || management_model_action(path).is_some())
}

fn mutation_body_rejection(headers: &HeaderMap) -> Option<(StatusCode, &'static str)> {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Some((
            StatusCode::BAD_REQUEST,
            "management mutations do not accept Transfer-Encoding",
        ));
    }
    let lengths = headers
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .collect::<Vec<_>>();
    if lengths.len() > 1 {
        return Some((
            StatusCode::BAD_REQUEST,
            "management mutations require a single Content-Length",
        ));
    }
    let length = lengths.first()?;
    let Ok(length) = length.to_str() else {
        return Some((
            StatusCode::BAD_REQUEST,
            "management mutation Content-Length is invalid",
        ));
    };
    let Ok(length) = length.parse::<u64>() else {
        return Some((
            StatusCode::BAD_REQUEST,
            "management mutation Content-Length is invalid",
        ));
    };
    (length != 0).then_some((
        StatusCode::PAYLOAD_TOO_LARGE,
        "management mutations do not accept request bodies",
    ))
}

fn management_bind_is_loopback(value: &str) -> bool {
    if value.starts_with('/') || value.starts_with("unix:") {
        return false;
    }
    value
        .parse::<SocketAddr>()
        .map(|address| address.ip().is_loopback())
        .unwrap_or(false)
}

fn safe_loopback_host_value(value: &str) -> bool {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_ascii_control() || character.is_whitespace())
    {
        return false;
    }

    if let Some(value) = value.strip_prefix('[') {
        let Some(close) = value.find(']') else {
            return false;
        };
        let host = &value[..close];
        let suffix = &value[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            suffix.strip_prefix(':').and_then(parse_host_port)
        };
        return host
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|address| address.is_loopback())
            && (suffix.is_empty() || port.is_some());
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, _port)) if host.contains(':') => return false,
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if let Some(port) = port {
        if parse_host_port(port).is_none() {
            return false;
        }
    }
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|address| address.is_loopback())
}

fn parse_host_port(value: &str) -> Option<u16> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

/// Immutable pair observed by one management request.
///
/// Configuration and pooling state are published together so a diagnostic
/// response cannot combine a new route plan with an old health/decision view.
#[derive(Debug)]
pub(crate) struct ManagementSnapshot {
    pub(crate) config: Arc<ConfigSnapshot<CompiledConfig>>,
    pub(crate) pooling: Arc<PoolingCoordinator>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeAccountAction {
    Refresh,
    Revoke,
}

#[derive(Debug)]
pub(crate) struct NativeAccountCommand {
    pub(crate) account: String,
    pub(crate) action: NativeAccountAction,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagementReloadKind {
    Configuration,
    Catalog,
}

impl ManagementReloadKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Catalog => "catalog",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagementReloadRequest {
    pub(crate) id: u64,
    pub(crate) kind: ManagementReloadKind,
    pub(crate) generation: u64,
}

#[derive(Debug, Default)]
struct ReloadControlState {
    pending: VecDeque<ManagementReloadRequest>,
    records: VecDeque<Value>,
}

#[derive(Debug, Default)]
struct ReloadControl {
    next_id: AtomicU64,
    state: Mutex<ReloadControlState>,
    notify: Arc<Notify>,
}

pub(crate) struct ManagementRuntimeServices {
    pub(crate) metrics: pooler_observe::MetricsRegistry,
    pub(crate) traces: pooler_observe::TraceRecorder,
    pub(crate) native_commands: mpsc::Sender<NativeAccountCommand>,
}

/// Secure management API backed by immutable plans and bounded mutable state.
#[derive(Clone)]
pub struct ManagementApi {
    plan: ManagementPlan,
    state: Arc<ArcSwap<ManagementSnapshot>>,
    runtime_dispatch: Option<Arc<ArcSwap<RuntimeGeneration>>>,
    catalog: Option<Arc<CatalogRuntime>>,
    metrics: pooler_observe::MetricsRegistry,
    traces: pooler_observe::TraceRecorder,
    audit: Arc<Mutex<VecDeque<Value>>>,
    reload: Arc<ReloadControl>,
    native_commands: Option<mpsc::Sender<NativeAccountCommand>>,
    active: ActiveCounts,
}

impl std::fmt::Debug for ManagementApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementApi")
            .field("bind", &self.plan.bind())
            .field("remote", &self.plan.remote())
            .field("authenticated", &self.plan.auth().is_some())
            .finish_non_exhaustive()
    }
}

impl ManagementApi {
    /// Construct a management API for an enabled management plan.
    #[must_use]
    pub fn new(
        plan: ManagementPlan,
        config: Arc<ConfigStore<CompiledConfig>>,
        pooling: Arc<PoolingCoordinator>,
        active: ActiveCounts,
    ) -> Self {
        Self::with_metrics(
            plan,
            config,
            pooling,
            active,
            pooler_observe::MetricsRegistry::default(),
        )
    }

    /// Construct an API with a process-shared observability registry.
    ///
    /// The registry is intentionally passed by value because it is a cheap
    /// handle to bounded process-local state. Runtime listeners can therefore
    /// publish one metrics view while this API keeps its response surface
    /// read-only.
    pub fn with_metrics(
        plan: ManagementPlan,
        config: Arc<ConfigStore<CompiledConfig>>,
        pooling: Arc<PoolingCoordinator>,
        active: ActiveCounts,
        metrics: pooler_observe::MetricsRegistry,
    ) -> Self {
        Self {
            plan,
            state: Arc::new(ArcSwap::from_pointee(ManagementSnapshot {
                config: config.snapshot(),
                pooling,
            })),
            runtime_dispatch: None,
            catalog: None,
            metrics,
            traces: pooler_observe::TraceRecorder::default(),
            audit: Arc::new(Mutex::new(VecDeque::new())),
            reload: Arc::new(ReloadControl::default()),
            native_commands: None,
            active,
        }
    }

    /// Construct an API from one compiled configuration when management is
    /// enabled. The generated store starts at the compiled plan generation.
    pub fn from_config(
        config: CompiledConfig,
        pooling: Arc<PoolingCoordinator>,
        active: ActiveCounts,
    ) -> Option<Self> {
        let plan = config.management()?.clone();
        let generation = pooler_core::ConfigGeneration::new(config.generation());
        let config = Arc::new(ConfigStore::with_generation(generation, config));
        Some(Self::new(plan, config, pooling, active))
    }

    /// Construct an API backed directly by the runtime's immutable config
    /// `Arc`, avoiding a second config clone at process startup.
    pub(crate) fn with_runtime_dispatch(
        plan: ManagementPlan,
        config: Arc<CompiledConfig>,
        pooling: Arc<PoolingCoordinator>,
        runtime_dispatch: Arc<ArcSwap<RuntimeGeneration>>,
        active: ActiveCounts,
        services: ManagementRuntimeServices,
    ) -> Self {
        let generation = pooler_core::ConfigGeneration::new(config.generation());
        Self {
            plan,
            state: Arc::new(ArcSwap::from_pointee(ManagementSnapshot {
                config: Arc::new(ConfigSnapshot::from_arc(generation, config)),
                pooling,
            })),
            runtime_dispatch: Some(runtime_dispatch),
            catalog: None,
            metrics: services.metrics,
            traces: services.traces,
            audit: Arc::new(Mutex::new(VecDeque::new())),
            reload: Arc::new(ReloadControl::default()),
            native_commands: Some(services.native_commands),
            active,
        }
    }

    pub(crate) fn record_native_result(
        &self,
        action: NativeAccountAction,
        account: &str,
        generation: u64,
        outcome: &str,
    ) {
        let action = match action {
            NativeAccountAction::Refresh => "refresh",
            NativeAccountAction::Revoke => "revoke",
        };
        self.record_audit_with_fields(
            action,
            Some(account),
            outcome,
            &[("generation", json!(generation))],
        );
    }

    /// Shared activity counters used by the serving runtime.
    #[must_use]
    pub fn active_counts(&self) -> ActiveCounts {
        self.active.clone()
    }

    /// Return the process-shared metrics registry used by this API's runtime.
    #[must_use]
    pub fn metrics(&self) -> pooler_observe::MetricsRegistry {
        self.metrics.clone()
    }

    pub(crate) fn reload_notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.reload.notify)
    }

    pub(crate) async fn next_reload_request(&self) -> ManagementReloadRequest {
        loop {
            let notified = self.reload.notify.notified();
            if let Some(request) = self
                .reload
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending
                .pop_front()
            {
                return request;
            }
            notified.await;
        }
    }

    pub(crate) fn complete_reload(
        &self,
        request_id: u64,
        outcome: &str,
        configuration_generation: u64,
        catalog_generation: Option<u64>,
    ) {
        let kind = {
            let mut state = self
                .reload
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = state
                .records
                .iter_mut()
                .find(|record| record["request_id"] == request_id)
            else {
                return;
            };
            record["status"] = Value::String(outcome.to_owned());
            record["completed_at_ms"] = json!(unix_timestamp_ms());
            record["configuration_generation"] = json!(configuration_generation);
            if let Some(generation) = catalog_generation {
                record["catalog_generation"] = json!(generation);
            }
            record["kind"]
                .as_str()
                .unwrap_or("configuration")
                .to_owned()
        };
        self.record_audit_with_fields(
            "reload",
            None,
            outcome,
            &[
                ("request_id", json!(request_id)),
                ("kind", json!(kind)),
                ("configuration_generation", json!(configuration_generation)),
            ],
        );
    }

    fn enqueue_reload(
        &self,
        kind: ManagementReloadKind,
        configuration_generation: u64,
    ) -> Option<ManagementReloadRequest> {
        let request = ManagementReloadRequest {
            id: self
                .reload
                .next_id
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
            kind,
            generation: configuration_generation,
        };
        {
            let mut state = self
                .reload
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.pending.len() >= MAX_PENDING_MANAGEMENT_RELOADS {
                return None;
            }
            state.pending.push_back(request);
            state.records.push_back(json!({
                "request_id": request.id,
                "kind": kind.as_str(),
                "status": "pending",
                "requested_at_ms": unix_timestamp_ms(),
                "accepted_configuration_generation": configuration_generation,
                "configuration_generation": configuration_generation,
            }));
            while state.records.len() > MAX_MANAGEMENT_RELOADS {
                state.records.pop_front();
            }
        }
        self.record_audit_with_fields(
            "reload",
            None,
            "accepted",
            &[
                ("request_id", json!(request.id)),
                ("kind", json!(kind.as_str())),
                ("configuration_generation", json!(configuration_generation)),
            ],
        );
        self.reload.notify.notify_one();
        Some(request)
    }

    fn reloads(&self, generation: u64) -> ManagementResponse {
        let records = self
            .reload
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({"configuration_generation": generation, "reloads": records}),
            false,
        )
    }

    fn record_audit(&self, action: &str, subject: Option<&str>, outcome: &str) {
        self.record_audit_with_fields(action, subject, outcome, &[]);
    }

    fn record_audit_with_fields(
        &self,
        action: &str,
        subject: Option<&str>,
        outcome: &str,
        fields: &[(&str, Value)],
    ) {
        let mut event = json!({
            "timestamp_ms": unix_timestamp_ms(),
            "action": action,
            "outcome": outcome,
        });
        if let Some(subject) = subject {
            event["subject"] = Value::String(subject.to_owned());
        }
        for (key, value) in fields {
            event[*key] = value.clone();
        }
        let event = pooler_observe::RedactionPolicy::strict().sanitize_json(&event);
        let mut audit = self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        audit.push_back(event);
        while audit.len() > MAX_MANAGEMENT_AUDIT_EVENTS {
            audit.pop_front();
        }
    }

    fn mutate_account(
        &self,
        path: &str,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let Some((account, action)) = management_account_action(path) else {
            return ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "management endpoint not found"}),
                false,
            );
        };
        let Some(account_plan) = snapshot.config().accounts().get(account.as_str()) else {
            self.record_audit(action, Some(&account), "not_found");
            return ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "configured account not found"}),
                false,
            );
        };
        if matches!(action, "refresh" | "revoke") {
            if account_plan.auth_kind() != pooler_config::AccountAuthKind::OAuth {
                self.record_audit(action, Some(&account), "unsupported_auth_kind");
                return ManagementResponse::json(
                    StatusCode::CONFLICT,
                    json!({"error": "account does not use OAuth credentials"}),
                    false,
                );
            }
            let Some(commands) = self.native_commands.as_ref() else {
                self.record_audit(action, Some(&account), "unavailable");
                return state_unavailable();
            };
            let command = NativeAccountCommand {
                account: account.clone(),
                action: if action == "refresh" {
                    NativeAccountAction::Refresh
                } else {
                    NativeAccountAction::Revoke
                },
                generation: snapshot.generation().value(),
            };
            return match commands.try_send(command) {
                Ok(()) => {
                    self.record_audit(action, Some(&account), "queued");
                    ManagementResponse::json(
                        StatusCode::ACCEPTED,
                        json!({
                            "generation": snapshot.generation().value(),
                            "account": account,
                            "action": action,
                            "status": "queued"
                        }),
                        false,
                    )
                }
                Err(_) => {
                    self.record_audit(action, Some(&account), "queue_unavailable");
                    state_unavailable()
                }
            };
        }
        let result = match action {
            "enable" => pooling.set_account_enabled(&account, true),
            "disable" => pooling.set_account_enabled(&account, false),
            "switch" => pooling.switch_account(&account),
            _ => unreachable!("validated account action"),
        };
        match result {
            Ok(()) => {
                self.record_audit(action, Some(&account), "succeeded");
                ManagementResponse::json(
                    StatusCode::OK,
                    json!({
                        "generation": snapshot.generation().value(),
                        "account": account,
                        "action": action,
                        "status": "ok"
                    }),
                    false,
                )
            }
            Err(PoolError::InvalidCredential) => {
                self.record_audit(action, Some(&account), "not_found");
                ManagementResponse::json(
                    StatusCode::NOT_FOUND,
                    json!({"error": "configured account not found"}),
                    false,
                )
            }
            Err(_) => {
                self.record_audit(action, Some(&account), "failed");
                state_unavailable()
            }
        }
    }

    fn mutate_model(
        &self,
        path: &str,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
        catalog: Option<&CatalogRuntime>,
    ) -> ManagementResponse {
        let Some((model, action)) = management_model_action(path) else {
            return ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "management endpoint not found"}),
                false,
            );
        };
        let known = merged_model_catalog_value(snapshot.config(), catalog)
            .get("models")
            .and_then(Value::as_array)
            .is_some_and(|models| {
                models
                    .iter()
                    .any(|entry| entry.get("id").and_then(Value::as_str) == Some(model.as_str()))
            });
        if !known {
            self.record_audit(action, Some(&model), "not_found");
            return ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "published model not found"}),
                false,
            );
        }
        let enabled = action == "enable";
        match pooling.set_model_enabled(&model, enabled) {
            Ok(()) => {
                self.record_audit(action, Some(&model), "succeeded");
                ManagementResponse::json(
                    StatusCode::OK,
                    json!({
                        "generation": snapshot.generation().value(),
                        "model": model,
                        "enabled": enabled,
                        "status": "ok"
                    }),
                    false,
                )
            }
            Err(PoolError::InvalidModel) => ManagementResponse::json(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid model identifier"}),
                false,
            ),
            Err(_) => state_unavailable(),
        }
    }

    fn traces(&self, generation: u64) -> ManagementResponse {
        let snapshot = self.traces.snapshot();
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "generation": generation,
                "traces": snapshot.records,
                "dropped": snapshot.dropped
            }),
            false,
        )
    }

    fn audit(&self, generation: u64) -> ManagementResponse {
        let audit = self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({"generation": generation, "events": audit}),
            false,
        )
    }

    fn export(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
        catalog: Option<&CatalogRuntime>,
    ) -> ManagementResponse {
        let value = json!({
            "schema_version": 1,
            "generation": snapshot.generation().value(),
            "health": response_value(self.health(snapshot, pooling)),
            "listeners": response_value(self.listeners(snapshot)),
            "routes": response_value(self.routes(snapshot)),
            "providers": response_value(self.providers(snapshot, pooling)),
            "accounts": response_value(self.accounts(snapshot, pooling)),
            "quota": response_value(self.quota(snapshot, pooling)),
            "models": response_value(self.models(snapshot, catalog, pooling)),
            "catalog": response_value(self.catalog(snapshot, catalog)),
            "metrics": self.metrics.snapshot(),
            "traces": self.traces.snapshot(),
            "audit": self.audit.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter().cloned().collect::<Vec<_>>(),
            "reloads": self.reload.state.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .records.iter().cloned().collect::<Vec<_>>(),
        });
        ManagementResponse::json(
            StatusCode::OK,
            pooler_observe::RedactionPolicy::strict().sanitize_json(&value),
            false,
        )
    }

    /// Attach an injected catalog to a standalone management API.
    #[must_use]
    pub fn with_catalog(mut self, catalog: Arc<CatalogRuntime>) -> Self {
        self.catalog = Some(catalog);
        self
    }

    /// Configured management bind address.
    #[must_use]
    pub fn bind(&self) -> &str {
        self.plan.bind()
    }

    /// Handle one body-free request.
    ///
    /// `path_and_query` may be a complete URI or just a path. A request body
    /// is deliberately not accepted by this API; callers should route only
    /// the method, URI, and headers here.
    #[must_use]
    pub fn handle(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> ManagementResponse {
        let uri = path_and_query.parse::<Uri>().ok();
        let request_path = uri.as_ref().map_or(path_and_query, Uri::path);
        let management_prefix =
            request_path == "/management" || request_path.starts_with("/management/");
        let path = uri
            .as_ref()
            .map_or(path_and_query, Uri::path)
            .strip_prefix("/management")
            .filter(|path| path.is_empty() || path.starts_with('/'))
            .unwrap_or_else(|| uri.as_ref().map_or(path_and_query, Uri::path));
        let path = if path.is_empty() { "/" } else { path };
        let head = *method == Method::HEAD;
        let mutation = is_management_mutation(method, path);
        let ui_asset = management_ui::asset(path).is_some() || (management_prefix && path == "/");
        if *method != Method::GET && !head && !mutation {
            let mut response = ManagementResponse::json(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({"error": "management method is not supported"}),
                false,
            );
            response.headers.insert(
                header::ALLOW,
                header::HeaderValue::from_static("GET, HEAD, POST"),
            );
            return response;
        }
        if !management_request_host_allowed(self, ui_asset, headers) {
            return ManagementResponse::json(
                StatusCode::FORBIDDEN,
                json!({"error": LOOPBACK_HOST_ERROR}),
                head,
            );
        }
        let local_ui_shell = ui_asset && management_bind_is_loopback(self.bind());
        if mutation {
            if let Some((status, message)) = mutation_body_rejection(headers) {
                self.record_audit(path, None, "rejected_body");
                return ManagementResponse::json(status, json!({"error": message}), false);
            }
        }
        if mutation && !management_origin_allowed(headers) {
            self.record_audit(path, None, "rejected_origin");
            return ManagementResponse::json(
                StatusCode::FORBIDDEN,
                json!({"error": "management mutation Origin does not match Host"}),
                false,
            );
        }
        if mutation && self.plan.auth().is_none() {
            self.record_audit(path, None, "authentication_not_configured");
            return ManagementResponse::json(
                StatusCode::FORBIDDEN,
                json!({"error": "management mutations require configured bearer authentication"}),
                false,
            );
        }
        if !local_ui_shell && !self.authorized(headers) {
            if mutation {
                self.record_audit(path, None, "unauthorized");
            }
            let mut response = ManagementResponse::json(
                StatusCode::UNAUTHORIZED,
                json!({"error": "management authentication required"}),
                head,
            );
            if self.plan.auth().is_some() {
                response.headers.insert(
                    header::WWW_AUTHENTICATE,
                    header::HeaderValue::from_static("Bearer"),
                );
            }
            return response;
        }

        let fallback = self.state.load_full();
        let runtime = self
            .runtime_dispatch
            .as_ref()
            .map(|dispatch| dispatch.load_full());
        let runtime_snapshot = runtime.as_ref().map(|state| {
            ConfigSnapshot::from_arc(
                pooler_core::ConfigGeneration::new(state.config.generation()),
                Arc::clone(&state.config),
            )
        });
        let (snapshot, pooling) = match (&runtime_snapshot, &runtime) {
            (Some(snapshot), Some(state)) => (snapshot, state.pooling.as_ref()),
            _ => (fallback.config.as_ref(), fallback.pooling.as_ref()),
        };
        let catalog = runtime
            .as_ref()
            .and_then(|runtime| runtime.catalog.clone())
            .or_else(|| self.catalog.clone());
        let asset = if path == "/" && management_prefix {
            management_ui::asset("/ui")
        } else {
            management_ui::asset(path)
        };
        if let Some((content_type, body)) = asset {
            return ManagementResponse::asset(StatusCode::OK, content_type, body, head);
        }
        let response = match path {
            "/health" | "/healthz" | "/" => self.health(snapshot, pooling),
            "/config" | "/config/generation" => self.config_generation(snapshot),
            "/setup/options" => self.setup_options(snapshot),
            "/setup/config" => self.setup_config(uri.as_ref().and_then(Uri::query)),
            "/setup/test" => self.setup_test(
                uri.as_ref().and_then(Uri::query),
                snapshot,
                catalog.as_deref(),
                pooling,
            ),
            "/listeners" => self.listeners(snapshot),
            "/routes" => self.routes(snapshot),
            "/models" => self.models(snapshot, catalog.as_deref(), pooling),
            "/catalog" | "/catalog/sources" => self.catalog(snapshot, catalog.as_deref()),
            "/health/providers" | "/providers/health" => self.providers(snapshot, pooling),
            "/health/credentials" | "/credentials/health" => self.credentials(snapshot, pooling),
            "/accounts" => self.accounts(snapshot, pooling),
            "/quota" => self.quota(snapshot, pooling),
            "/metrics" => self.metrics_view(snapshot),
            "/metrics/prometheus" => ManagementResponse::body(
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                self.metrics.export_prometheus().into_bytes(),
                head,
            ),
            "/active" | "/active-counts" => self.active(),
            "/decisions" | "/decisions/recent" => {
                let limit = uri.as_ref().and_then(|uri| uri.query()).map(parse_limit);
                self.decisions(limit, snapshot.generation().value(), pooling)
            }
            "/traces" => self.traces(snapshot.generation().value()),
            "/audit" => self.audit(snapshot.generation().value()),
            "/reloads" => self.reloads(snapshot.generation().value()),
            "/export" => self.export(snapshot, pooling, catalog.as_deref()),
            "/reload" | "/models/reload" if mutation => {
                let kind = if path == "/models/reload" {
                    ManagementReloadKind::Catalog
                } else {
                    ManagementReloadKind::Configuration
                };
                match self.enqueue_reload(kind, snapshot.generation().value()) {
                    Some(request) => ManagementResponse::json(
                        StatusCode::ACCEPTED,
                        json!({
                            "configuration_generation": snapshot.generation().value(),
                            "request_id": request.id,
                            "kind": request.kind.as_str(),
                            "status": "pending"
                        }),
                        false,
                    ),
                    None => {
                        self.record_audit(path, None, "queue_unavailable");
                        state_unavailable()
                    }
                }
            }
            path if management_account_action(path).is_some() && mutation => {
                self.mutate_account(path, snapshot, pooling)
            }
            path if management_model_action(path).is_some() && mutation => {
                self.mutate_model(path, snapshot, pooling, catalog.as_deref())
            }
            _ => ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "management endpoint not found"}),
                false,
            ),
        };
        if head {
            ManagementResponse {
                body: Vec::new(),
                ..response
            }
        } else {
            response
        }
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let Some(auth) = self.plan.auth() else {
            return true;
        };
        let Ok(reference) = RuntimeSecretRef::parse(&auth.secret().redacted()) else {
            return false;
        };
        let Ok(expected) = reference.resolve() else {
            return false;
        };
        let Some(value) = headers.get(header::AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };
        bearer_authorization_matches(value, &expected)
    }

    fn health(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let credentials = match pooling.credential_health_states() {
            Ok(states) => states.len(),
            Err(_) => return state_unavailable(),
        };
        let cooldowns = match pooling.cooldowns() {
            Ok(states) => states,
            Err(_) => return state_unavailable(),
        };
        let cooling_providers = cooldowns
            .iter()
            .filter(|state| matches!(state.scope.as_str(), "provider" | "provider_model"))
            .count();
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "status": "ok",
                "configuration_generation": snapshot.generation().value(),
                "management": {"mutations": self.plan.auth().is_some()},
                "active": self.active.total(),
                "credential_health_entries": credentials,
                "cooling_provider_entries": cooling_providers,
            }),
            false,
        )
    }

    fn config_generation(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "management": {"mutations": self.plan.auth().is_some()},
            }),
            false,
        )
    }

    fn setup_options(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        let registry = ProviderLoginRegistry::builtin();
        let catalog = ProviderCatalog::builtin();
        let providers = catalog
            .iter()
            .map(|(id, provider)| {
                let definition = registry.resolve(id);
                let mut authentication = definition.map_or_else(Vec::new, |definition| {
                    definition
                        .capabilities()
                        .iter()
                        .map(|capability| {
                            json!({
                                "method": capability.method().to_string(),
                                "support": setup_support_name(capability.support()),
                                "note": capability.note(),
                            })
                        })
                        .collect::<Vec<_>>()
                });
                if !provider.env.is_empty()
                    && !authentication.iter().any(|method| method["method"] == "api_key")
                {
                    authentication.push(json!({
                        "method": "api_key",
                        "support": "supported",
                        "note": "Use a provider-issued API key through a protected secret reference.",
                    }));
                }
                let configured_upstreams = snapshot
                    .config()
                    .upstreams()
                    .iter()
                    .filter(|(upstream_id, upstream)| {
                        upstream.known_provider() == Some(id)
                            || Arc::<str>::as_ref(upstream_id) == id
                    })
                    .map(|(upstream_id, _)| Arc::<str>::as_ref(upstream_id))
                    .collect::<Vec<_>>();
                let clients = [
                    "native", "openai", "anthropic", "gemini", "codex", "cursor", "droid",
                    "factory", "devin",
                ]
                .into_iter()
                .filter(|client| {
                    setup_client_compatible(client, &provider.integration.request_dialect)
                })
                .collect::<Vec<_>>();
                json!({
                    "id": id,
                    "name": provider.name,
                    "authentication": authentication,
                    "credential_environment_variables": provider.env,
                    "documentation_url": definition.map(|definition| definition.documentation_url()),
                    "request_dialect": provider.integration.request_dialect,
                    "native_kind": provider.integration.native_kind,
                    "capabilities": provider.integration.capabilities,
                    "endpoint_families": provider.integration.endpoint_families,
                    "discovery": {
                        "available": provider.integration.discovery_parser.is_some()
                            && provider.integration.discovery_path.is_some(),
                        "parser": provider.integration.discovery_parser,
                        "path": provider.integration.discovery_path,
                    },
                    "configured_upstreams": configured_upstreams,
                    "clients": clients,
                })
            })
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "schema_version": 1,
                "configuration_generation": snapshot.generation().value(),
                "providers": providers,
                "clients": [
                    {"id": "native", "name": "Provider-native API", "description": "Pass through the provider's documented request dialect."},
                    {"id": "openai", "name": "OpenAI-compatible client", "description": "Use the local /v1 API from OpenAI-compatible SDKs."},
                    {"id": "anthropic", "name": "Anthropic SDK", "description": "Use the local Anthropic Messages API."},
                    {"id": "gemini", "name": "Gemini SDK", "description": "Use the local Gemini Generate Content API."},
                    {"id": "codex", "name": "Codex", "description": "Point Codex at the local OpenAI-compatible listener."},
                    {"id": "cursor", "name": "Cursor", "description": "Point Cursor at the local OpenAI-compatible listener."},
                    {"id": "droid", "name": "Factory Droid", "description": "Point Droid's OpenAI-compatible provider at Pooler."},
                    {"id": "factory", "name": "Factory protocol", "description": "Expose Pooler's Factory v3 adapter."},
                    {"id": "devin", "name": "Devin protocol", "description": "Expose Pooler's Devin Connect adapter."},
                ],
            }),
            false,
        )
    }

    fn setup_config(&self, query: Option<&str>) -> ManagementResponse {
        let selection =
            setup_selection(query).and_then(|(provider, auth, account, model, client)| {
                generate_setup_config(&provider, &auth, &account, &model, &client)
            });
        match selection {
            Ok(config) => ManagementResponse::json(
                StatusCode::OK,
                json!({"schema_version": 1, "validated": true, "configuration": config}),
                false,
            ),
            Err(error) => {
                ManagementResponse::json(StatusCode::BAD_REQUEST, json!({"error": error}), false)
            }
        }
    }

    fn setup_test(
        &self,
        query: Option<&str>,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        catalog: Option<&CatalogRuntime>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let Ok((provider_id, auth, account_id, model_id, client)) = setup_selection(query) else {
            return ManagementResponse::json(
                StatusCode::BAD_REQUEST,
                json!({"error": "setup request is missing a required selection"}),
                false,
            );
        };
        if let Err(error) =
            generate_setup_config(&provider_id, &auth, &account_id, &model_id, &client)
        {
            return ManagementResponse::json(
                StatusCode::BAD_REQUEST,
                json!({"error": error}),
                false,
            );
        }
        let upstream_ids = snapshot
            .config()
            .upstreams()
            .iter()
            .filter(|(upstream_id, upstream)| {
                upstream.known_provider() == Some(provider_id.as_str())
                    || Arc::<str>::as_ref(upstream_id) == provider_id.as_str()
            })
            .map(|(upstream_id, _)| Arc::<str>::as_ref(upstream_id))
            .collect::<Vec<_>>();
        let provider_configured = !upstream_ids.is_empty();
        let accounts = response_value(self.accounts(snapshot, pooling));
        let account = accounts["accounts"].as_array().and_then(|accounts| {
            accounts
                .iter()
                .find(|account| account["id"].as_str() == Some(account_id.as_str()))
        });
        let account_configured = account.is_some_and(|account| {
            account["provider"]
                .as_str()
                .is_some_and(|provider| upstream_ids.contains(&provider))
        });
        let account_available = account.is_some_and(|account| {
            account["enabled"].as_bool() == Some(true)
                && matches!(
                    account["status"].as_str(),
                    Some("available" | "selected" | "unknown")
                )
        });
        let models = response_value(self.models(snapshot, catalog, pooling));
        let model = models["models"].as_array().and_then(|models| {
            models
                .iter()
                .find(|model| model["id"].as_str() == Some(model_id.as_str()))
        });
        let model_available = model.is_some_and(|model| {
            model["enabled"].as_bool() != Some(false)
                && model["targets"].as_array().is_some_and(|targets| {
                    targets.iter().any(|target| {
                        target["provider"]
                            .as_str()
                            .is_some_and(|provider| upstream_ids.contains(&provider))
                    })
                })
        });
        let catalog_view = merged_model_catalog_value(snapshot.config(), catalog);
        let discovery_verified =
            catalog_view["catalog_sources"]
                .as_array()
                .is_some_and(|sources| {
                    sources.iter().any(|source| {
                        source["provider"]
                            .as_str()
                            .is_some_and(|provider| upstream_ids.contains(&provider))
                            && source["account"].as_str() == Some(account_id.as_str())
                            && !source["state"].is_null()
                    })
                });
        let all_ready = provider_configured
            && account_configured
            && account_available
            && model_available
            && discovery_verified;
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "schema_version": 1,
                "configuration_generation": snapshot.generation().value(),
                "ready": all_ready,
                "connection": if discovery_verified {"verified"} else {"not_probed"},
                "checks": [
                    {"id": "generated_configuration", "status": "passed", "detail": "Generated YAML passed Pooler's compiler."},
                    {"id": "provider", "status": if provider_configured {"passed"} else {"pending"}, "detail": if provider_configured {"Provider is present in the active generation."} else {"Apply the generated configuration and reload Pooler."}},
                    {"id": "account", "status": if account_configured && account_available {"passed"} else {"pending"}, "detail": if account_configured && account_available {"The selected account is enabled in the active generation."} else {"Configure the account and complete its credential flow."}},
                    {"id": "model", "status": if model_available {"passed"} else {"pending"}, "detail": if model_available {"The selected model is published for this provider."} else {"Reload model discovery or apply the generated static model mapping."}},
                    {"id": "connectivity", "status": if discovery_verified {"passed"} else {"not_run"}, "detail": if discovery_verified {"A successful bounded model-discovery observation exists for this provider and account."} else {"No successful outbound catalog observation exists for this provider and account. This check does not send a billable inference request."}},
                ],
            }),
            false,
        )
    }

    fn listeners(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        let listeners = snapshot
            .config()
            .listeners()
            .values()
            .map(|listener| {
                let route_count = snapshot
                    .config()
                    .routes()
                    .iter()
                    .filter(|route| route.listener() == listener.id())
                    .count();
                json!({
                    "id": listener.id(),
                    "bind": listener.bind(),
                    "protocol": listener_protocol_name(listener.protocol()),
                    "tls": listener.tls().is_some(),
                    "route_count": route_count,
                })
            })
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "listeners": listeners,
            }),
            false,
        )
    }

    fn routes(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        let routes = snapshot
            .config()
            .routes()
            .iter()
            .map(|route| {
                json!({
                    "id": route.id(),
                    "listener": route.listener(),
                    "method_count": route.matcher().methods().len(),
                    "header_constraint_count": route.matcher().header_specificity(),
                    "path": route.matcher().path().value(),
                    "ingress": route.ingress().mode(),
                    "response": route.response().mode(),
                    "target": {
                        "upstream": route.target().upstream(),
                        "path": route.target().path(),
                        "model_source": route.target().model_source().map(|source| match source {
                            pooler_config::ModelSource::Request => "request",
                            pooler_config::ModelSource::Inspected => "inspected",
                        }),
                        "policy": route.target().policy(),
                    },
                    "loss_policy": route.loss_policy(),
                    "downstream_auth_configured": route.downstream_auth().is_some(),
                })
            })
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "routes": routes,
            }),
            false,
        )
    }

    fn models(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        catalog: Option<&CatalogRuntime>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let mut value = merged_model_catalog_value(snapshot.config(), catalog);
        if let Some(models) = value.get_mut("models").and_then(Value::as_array_mut) {
            for model in models {
                if let Some(id) = model.get("id").and_then(Value::as_str) {
                    model["enabled"] = Value::Bool(pooling.model_enabled(id).unwrap_or(false));
                }
            }
        }
        value["mutation_capable"] = json!(self.plan.auth().is_some());
        ManagementResponse::json(StatusCode::OK, value, false)
    }

    fn catalog(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        catalog: Option<&CatalogRuntime>,
    ) -> ManagementResponse {
        let view = merged_model_catalog_value(snapshot.config(), catalog);
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "catalog_generation": view["catalog_generation"],
                "catalog_refreshed_at_unix_ms": view["catalog_refreshed_at_unix_ms"],
                "sources": view["catalog_sources"],
            }),
            false,
        )
    }

    fn providers(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let cooldowns = match pooling.cooldowns() {
            Ok(cooldowns) => cooldowns,
            Err(_) => return state_unavailable(),
        };
        let providers = snapshot
            .config()
            .upstreams()
            .iter()
            .map(|(id, plan)| provider_health_value(id, plan, &cooldowns))
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({"configuration_generation": snapshot.generation().value(), "providers": providers}),
            false,
        )
    }

    fn credentials(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        self.account_view(snapshot, pooling, "credentials")
    }

    fn accounts(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        self.account_view(snapshot, pooling, "accounts")
    }

    fn account_view(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
        field: &str,
    ) -> ManagementResponse {
        let states = match pooling.credential_states() {
            Ok(states) => states,
            Err(_) => return state_unavailable(),
        };
        let health = match pooling.credential_health_states() {
            Ok(health) => health,
            Err(_) => return state_unavailable(),
        };
        let states = states
            .into_iter()
            .map(|state| (state.credential_id.clone(), state))
            .collect::<BTreeMap<_, _>>();
        let health = health
            .into_iter()
            .map(|state| (state.credential_id.clone(), state))
            .collect::<BTreeMap<_, _>>();
        let mutation_capable = self.plan.auth().is_some();
        let credentials = snapshot
            .config()
            .accounts()
            .values()
            .map(|account| {
                let enabled = states
                    .get(account.id())
                    .map_or(account.enabled(), |state| state.enabled);
                let selected = enabled
                    && !snapshot.config().accounts().values().any(|other| {
                        other.provider() == account.provider()
                            && other.id() != account.id()
                            && states
                                .get(other.id())
                                .map_or(other.enabled(), |state| state.enabled)
                    });
                let mut available_actions = Vec::new();
                if mutation_capable {
                    available_actions.push(if enabled { "disable" } else { "enable" });
                    if snapshot.config().accounts().values().any(|other| {
                        other.provider() == account.provider() && other.id() != account.id()
                    }) {
                        available_actions.push("switch");
                    }
                    if account.auth_kind() == pooler_config::AccountAuthKind::OAuth
                        && self.native_commands.is_some()
                    {
                        available_actions.extend(["refresh", "revoke"]);
                    }
                }
                credential_health_value(
                    account,
                    states.get(account.id()),
                    health.get(account.id()),
                    selected,
                    available_actions,
                )
            })
            .collect::<Vec<_>>();
        let mut value = serde_json::Map::new();
        value.insert(
            "configuration_generation".to_owned(),
            json!(snapshot.generation().value()),
        );
        value.insert("mutation_capable".to_owned(), json!(mutation_capable));
        value.insert(field.to_owned(), Value::Array(credentials));
        ManagementResponse::json(StatusCode::OK, Value::Object(value), false)
    }

    fn quota(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let entries = match pooling.cooldowns() {
            Ok(cooldowns) => cooldowns,
            Err(_) => return state_unavailable(),
        }
        .into_iter()
        .map(|cooldown| {
            json!({
                "scope": cooldown.scope,
                "key": cooldown.key,
                "until": cooldown.until,
                "reason": cooldown.reason,
            })
        })
        .collect::<Vec<_>>();
        let windows = match pooling.quota_states() {
            Ok(windows) => windows,
            Err(_) => return state_unavailable(),
        };
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "active": windows.len(),
                "windows": windows,
                "cooldowns": entries,
            }),
            false,
        )
    }

    fn metrics_view(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "metrics": self.metrics.snapshot(),
            }),
            false,
        )
    }

    fn active(&self) -> ManagementResponse {
        let by_listener = self
            .active
            .by_listener()
            .into_iter()
            .map(|(listener, count)| (listener, json!(count)))
            .collect::<serde_json::Map<_, _>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({"active": self.active.total(), "by_listener": by_listener}),
            false,
        )
    }

    fn decisions(
        &self,
        limit: Option<usize>,
        generation: u64,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let limit = limit
            .unwrap_or(DEFAULT_DECISION_LIMIT)
            .min(MAX_DECISION_LIMIT);
        match pooling.recent_decisions(limit) {
            Ok(records) => ManagementResponse::json(
                StatusCode::OK,
                json!({
                    "configuration_generation": generation,
                    "decisions": records,
                    "limit": limit,
                }),
                false,
            ),
            Err(_) => ManagementResponse::json(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "management state unavailable"}),
                false,
            ),
        }
    }
}

/// Errors raised while binding or serving a management listener.
#[derive(Debug, thiserror::Error)]
pub enum ManagementServerError {
    /// Remote management is not started because this plane has no TLS
    /// configuration and bearer authentication cannot protect raw HTTP.
    #[error("remote management listener `{listener}` requires TLS; raw bearer HTTP is disabled")]
    RemoteRequiresTls {
        /// Configured socket address or path.
        listener: String,
    },
    /// The configured management socket could not be bound.
    #[error("failed to bind management listener `{listener}`: {source}")]
    Bind {
        /// Configured socket address or path.
        listener: String,
        /// Operating-system bind error.
        #[source]
        source: io::Error,
    },
    /// The listener was already consumed by [`ManagementHttpServer::run`].
    #[error("management HTTP server is already running")]
    AlreadyRunning,
    /// A management connection task failed unexpectedly.
    #[error("management listener failed: {message}")]
    Listener {
        /// Sanitized task error.
        message: String,
    },
}

enum BoundManagementListener {
    Tcp(TcpListener),
    Unix {
        listener: UnixListener,
        path: ManagementUnixSocketPath,
    },
}

struct ManagementUnixSocketPath(PathBuf);

impl Drop for ManagementUnixSocketPath {
    fn drop(&mut self) {
        remove_unix_socket_if_safe(&self.0);
    }
}

#[cfg(unix)]
fn validate_unix_socket_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix management socket must have a parent directory",
        )
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    let mode = metadata.mode();
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || mode & 0o077 != 0
        || mode & 0o700 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix management socket parent must be an owner-private directory",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_socket_parent(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix management sockets are unavailable on this platform",
    ))
}

#[cfg(unix)]
fn unix_socket_metadata_is_safe(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode();
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || mode & 0o077 != 0
        || mode & 0o600 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix management socket must be an owner-private socket",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn unix_socket_metadata_is_safe(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix management sockets are unavailable on this platform",
    ))
}

fn validate_unix_socket_path_before_bind(path: &Path) -> io::Result<()> {
    validate_unix_socket_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            let safe_existing_socket = metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0
                && metadata.mode() & 0o600 == 0o600;
            #[cfg(not(unix))]
            let safe_existing_socket = {
                let _ = metadata;
                false
            };
            if !safe_existing_socket {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unix management socket path must be absent or an owner-private socket",
                ));
            }
            Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unix management socket path is already in use",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn harden_unix_socket(path: &Path) -> io::Result<()> {
    validate_unix_socket_parent(path)?;
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unix management socket ownership or type is unsafe",
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        unix_socket_metadata_is_safe(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix management sockets are unavailable on this platform",
        ))
    }
}

fn remove_unix_socket_if_safe(path: &Path) {
    if validate_unix_socket_parent(path).is_ok() && unix_socket_metadata_is_safe(path).is_ok() {
        let _ = fs::remove_file(path);
    }
}

struct ManagementServerState {
    listener: Mutex<Option<BoundManagementListener>>,
    cancellation: CancellationToken,
}

/// Standalone HTTP/1 management listener for a [`ManagementApi`].
///
/// The listener is separate from inference sockets and is intended to be
/// spawned by process wiring after configuration has passed the loopback and
/// remote-TLS validation boundary.
#[derive(Clone)]
pub struct ManagementHttpServer {
    api: Arc<ManagementApi>,
    state: Arc<ManagementServerState>,
    address: Arc<str>,
}

impl std::fmt::Debug for ManagementHttpServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementHttpServer")
            .field("address", &self.address)
            .field("bind", &self.api.bind())
            .finish_non_exhaustive()
    }
}

impl ManagementHttpServer {
    /// Bind the management listener described by `api`.
    pub async fn bind(api: Arc<ManagementApi>) -> Result<Self, ManagementServerError> {
        if api.plan.remote() {
            return Err(ManagementServerError::RemoteRequiresTls {
                listener: api.bind().to_owned(),
            });
        }
        let bind = api.bind();
        let (listener, address) = if bind.starts_with('/') || bind.starts_with("unix:") {
            let path = bind.strip_prefix("unix:").unwrap_or(bind);
            let path = Path::new(path);
            validate_unix_socket_path_before_bind(path).map_err(|source| {
                ManagementServerError::Bind {
                    listener: bind.to_owned(),
                    source,
                }
            })?;
            let listener =
                UnixListener::bind(path).map_err(|source| ManagementServerError::Bind {
                    listener: bind.to_owned(),
                    source,
                })?;
            if let Err(source) = harden_unix_socket(path) {
                drop(listener);
                remove_unix_socket_if_safe(path);
                return Err(ManagementServerError::Bind {
                    listener: bind.to_owned(),
                    source,
                });
            }
            (
                BoundManagementListener::Unix {
                    listener,
                    path: ManagementUnixSocketPath(path.to_owned()),
                },
                path.display().to_string(),
            )
        } else {
            let listener =
                TcpListener::bind(bind)
                    .await
                    .map_err(|source| ManagementServerError::Bind {
                        listener: bind.to_owned(),
                        source,
                    })?;
            let address = listener
                .local_addr()
                .map_err(|source| ManagementServerError::Bind {
                    listener: bind.to_owned(),
                    source,
                })?;
            (BoundManagementListener::Tcp(listener), address.to_string())
        };
        Ok(Self {
            api,
            state: Arc::new(ManagementServerState {
                listener: Mutex::new(Some(listener)),
                cancellation: CancellationToken::new(),
            }),
            address: Arc::from(address),
        })
    }

    /// Concrete address assigned while binding.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Begin graceful management listener shutdown.
    pub fn begin_shutdown(&self) {
        self.state.cancellation.cancel();
    }

    /// Cancellation token used by process lifecycle integration.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.state.cancellation.clone()
    }

    /// Serve management requests until cancellation.
    pub async fn run(&self) -> Result<(), ManagementServerError> {
        let listener = self
            .state
            .listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(ManagementServerError::AlreadyRunning)?;
        let mut tasks = JoinSet::new();
        match listener {
            BoundManagementListener::Tcp(listener) => loop {
                tokio::select! {
                    _ = self.state.cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, _) = result.map_err(|source| ManagementServerError::Listener { message: source.to_string() })?;
                        let api = Arc::clone(&self.api);
                        let cancellation = self.state.cancellation.clone();
                        tasks.spawn(async move {
                            serve_management_connection(stream, api, cancellation).await
                        });
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = result {
                            return Err(ManagementServerError::Listener { message: error.to_string() });
                        }
                    }
                }
            },
            BoundManagementListener::Unix {
                listener,
                path: _path,
            } => loop {
                tokio::select! {
                    _ = self.state.cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, _) = result.map_err(|source| ManagementServerError::Listener { message: source.to_string() })?;
                        let api = Arc::clone(&self.api);
                        let cancellation = self.state.cancellation.clone();
                        tasks.spawn(async move {
                            serve_management_connection(stream, api, cancellation).await
                        });
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = result {
                            return Err(ManagementServerError::Listener { message: error.to_string() });
                        }
                    }
                }
            },
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                return Err(ManagementServerError::Listener {
                    message: error.to_string(),
                });
            }
        }
        Ok(())
    }
}

struct PrefixedIo<I> {
    prefix: Vec<u8>,
    offset: usize,
    inner: I,
}

impl<I> PrefixedIo<I> {
    fn new(prefix: Vec<u8>, inner: I) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for PrefixedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.offset < this.prefix.len() {
            let available = &this.prefix[this.offset..];
            let amount = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..amount]);
            this.offset += amount;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn read_management_header_prefix<I: AsyncRead + Unpin>(
    io: &mut I,
) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = Vec::with_capacity(1024);
    loop {
        if prefix.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(Some(prefix));
        }
        if prefix.len() >= MAX_MANAGEMENT_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "management request headers exceed the configured bound",
            ));
        }
        let mut chunk = [0_u8; 1024];
        let remaining = MAX_MANAGEMENT_HEADER_BYTES - prefix.len();
        let chunk_len = remaining.min(chunk.len());
        let read = io.read(&mut chunk[..chunk_len]).await?;
        if read == 0 {
            return Ok(None);
        }
        prefix.extend_from_slice(&chunk[..read]);
    }
}

fn raw_management_path(request_target: &str) -> Option<String> {
    let request_path = if request_target.starts_with('/') {
        request_target
            .split('?')
            .next()
            .unwrap_or(request_target)
            .to_owned()
    } else {
        let uri = request_target.parse::<http::Uri>().ok()?;
        if uri.scheme().is_none() || uri.authority().is_none() {
            return None;
        }
        uri.path().to_owned()
    };
    let management_path = request_path
        .strip_prefix("/management")
        .filter(|path| path.is_empty() || path.starts_with('/'))
        .unwrap_or(&request_path);
    Some(management_path.to_owned())
}

fn raw_is_management_mutation(prefix: &[u8]) -> bool {
    let Some(header_end) = prefix.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&prefix[..header_end]) else {
        return false;
    };
    let Some(request_line) = headers.lines().next() else {
        return false;
    };
    let mut request = request_line.split_whitespace();
    if request.next() != Some("POST") {
        return false;
    }
    let Some(request_target) = request.next() else {
        return false;
    };
    let Some(management_path) = raw_management_path(request_target) else {
        return false;
    };
    is_management_mutation(&Method::POST, &management_path)
}

fn raw_mutation_body_rejection(prefix: &[u8]) -> Option<(StatusCode, &'static str)> {
    let header_end = prefix.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&prefix[..header_end]).ok()?;
    let mut lines = headers.split("\r\n");
    let mut request = lines.next()?.split_whitespace();
    if request.next()? != "POST" {
        return None;
    }
    let request_target = request.next()?;
    let management_path = raw_management_path(request_target)?;
    if !is_management_mutation(&Method::POST, &management_path) {
        return None;
    }

    let mut content_lengths = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Some((
                StatusCode::BAD_REQUEST,
                "management mutations do not accept Transfer-Encoding",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_lengths.push(value.trim());
        }
    }
    if content_lengths.len() > 1 {
        return Some((
            StatusCode::BAD_REQUEST,
            "management mutations require a single Content-Length",
        ));
    }
    if prefix.len() > header_end.saturating_add(4) {
        return Some((
            StatusCode::PAYLOAD_TOO_LARGE,
            "management mutations do not accept request bodies",
        ));
    }
    let length = content_lengths.first()?;
    let Ok(length) = length.parse::<u64>() else {
        return Some((
            StatusCode::BAD_REQUEST,
            "management mutation Content-Length is invalid",
        ));
    };
    (length != 0).then_some((
        StatusCode::PAYLOAD_TOO_LARGE,
        "management mutations do not accept request bodies",
    ))
}

async fn serve_management_connection<I>(
    mut io: I,
    api: Arc<ManagementApi>,
    cancellation: CancellationToken,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut prefix = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            MANAGEMENT_HEADER_TIMEOUT,
            read_management_header_prefix(&mut io),
        ) => match result {
            Ok(Ok(Some(prefix))) => prefix,
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return,
        },
    };
    if raw_mutation_body_rejection(&prefix).is_none() && raw_is_management_mutation(&prefix) {
        let mut probe = [0_u8; 1024];
        let probe_result = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = tokio::time::timeout(
                MANAGEMENT_BODY_GUARD_TIMEOUT,
                io.read(&mut probe),
            ) => result,
        };
        match probe_result {
            Ok(Ok(0)) | Err(_) => {}
            Ok(Ok(read)) => prefix.extend_from_slice(&probe[..read]),
            Ok(Err(_)) => return,
        }
    }
    if let Some((status, message)) = raw_mutation_body_rejection(&prefix) {
        api.record_audit("http_boundary", None, "rejected_body");
        let response = management_http_response(ManagementResponse::json(
            status,
            json!({"error": message}),
            false,
        ));
        let service = service_fn(move |_request: Request<Incoming>| {
            let response = response.clone();
            async move { Ok::<_, std::convert::Infallible>(response) }
        });
        let connection = hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(PrefixedIo::new(prefix, io)), service);
        tokio::pin!(connection);
        tokio::select! {
            _ = cancellation.cancelled() => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
            _ = &mut connection => {}
        }
        return;
    }
    let io = TokioIo::new(PrefixedIo::new(prefix, io));
    let service = service_fn(move |request: Request<Incoming>| {
        let api = Arc::clone(&api);
        async move {
            let request_path = request.uri().path();
            let management_path = request_path
                .strip_prefix("/management")
                .filter(|path| path.is_empty() || path.starts_with('/'))
                .unwrap_or(request_path);
            let ui_asset = management_ui::asset(management_path).is_some()
                || (request_path.starts_with("/management") && management_path == "/");
            let response = if !management_request_host_allowed(&api, ui_asset, request.headers()) {
                ManagementResponse::json(
                    StatusCode::FORBIDDEN,
                    json!({"error": LOOPBACK_HOST_ERROR}),
                    false,
                )
            } else if is_management_mutation(request.method(), management_path) {
                if let Some((status, message)) = mutation_body_rejection(request.headers()) {
                    api.record_audit(management_path, None, "rejected_body");
                    ManagementResponse::json(status, json!({"error": message}), false)
                } else if !request.body().is_end_stream() {
                    api.record_audit(management_path, None, "rejected_body");
                    ManagementResponse::json(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "management mutations require an empty HTTP body"}),
                        false,
                    )
                } else {
                    api.handle(
                        request.method(),
                        request.uri().to_string().as_str(),
                        request.headers(),
                    )
                }
            } else {
                api.handle(
                    request.method(),
                    request.uri().to_string().as_str(),
                    request.headers(),
                )
            };
            Ok::<_, std::convert::Infallible>(management_http_response(response))
        }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        _ = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
        _ = &mut connection => {}
    }
}

fn management_http_response(response: ManagementResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    builder = builder.header(header::CONNECTION, "close");
    builder
        .body(Full::new(Bytes::from(response.body)))
        .expect("management response headers are valid")
}

// Keep URI query handling intentionally small and bounded. Unknown values use
// the default rather than producing a verbose parser error to an untrusted
// caller.
fn parse_limit(query: &str) -> usize {
    query
        .split('&')
        .find_map(|part| {
            part.strip_prefix("limit=")
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(DEFAULT_DECISION_LIMIT)
}

fn listener_protocol_name(protocol: pooler_config::ListenerProtocol) -> &'static str {
    match protocol {
        pooler_config::ListenerProtocol::Http1 => "http1",
        pooler_config::ListenerProtocol::Auto => "auto",
        pooler_config::ListenerProtocol::H2c => "h2c",
    }
}

fn response_value(response: ManagementResponse) -> Value {
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|_| json!({"error": "management view serialization failed"}))
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn state_unavailable() -> ManagementResponse {
    ManagementResponse::json(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error": "management state unavailable"}),
        false,
    )
}

fn availability_status(state: Option<&CredentialHealthState>) -> &'static str {
    match state.map(|state| state.status) {
        Some(CredentialHealthStatus::CoolingDown) => "cooling_down",
        Some(CredentialHealthStatus::Disabled) => "disabled",
        Some(CredentialHealthStatus::Healthy) | None => "available",
    }
}

fn credential_health_value(
    account: &pooler_config::AccountPlan,
    state: Option<&CredentialState>,
    health: Option<&CredentialHealthState>,
    selected: bool,
    available_actions: Vec<&'static str>,
) -> Value {
    json!({
        "id": account.id(),
        "provider": account.provider(),
        "auth_kind": account.auth_kind().as_str(),
        "enabled": state.map_or(account.enabled(), |state| state.enabled),
        "selected": selected,
        "available_actions": available_actions,
        "status": availability_status(health),
        "failure_count": health.map_or(0, |health| health.failure_count),
        "cooldown_until": health.and_then(|health| health.cooldown_until),
    })
}

fn provider_health_value(
    id: &str,
    plan: &pooler_config::UpstreamPlan,
    cooldowns: &[pooler_store::CooldownState],
) -> Value {
    let cooling = cooldowns.iter().any(|cooldown| {
        matches!(cooldown.scope.as_str(), "provider" | "provider_model") && cooldown.key == id
            || cooldown.scope == "provider_model" && cooldown.key.starts_with(&format!("{id}:"))
    });
    json!({
        "id": id,
        "transport": plan.transport(),
        "auth_configured": plan.auth().is_some() || plan.oauth().is_some() || plan.native().is_some(),
        "native": plan.native().map(|native| native.kind()),
        "status": if cooling { "cooling_down" } else { "not_cooling" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pooler_core::ConfigGeneration;
    use pooler_store::{
        CooldownState, CredentialHealthState, CredentialState, DecisionRecord, MemoryStore,
        PruneReport, RetentionPolicy, SessionAffinity, Store, StoreError, StoreResult, Timestamp,
    };
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct FailingDiagnosticsStore {
        inner: MemoryStore,
        fail_reads: AtomicBool,
    }

    impl FailingDiagnosticsStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                fail_reads: AtomicBool::new(false),
            }
        }

        fn fail_reads(&self) {
            self.fail_reads.store(true, Ordering::Release);
        }

        fn unavailable<T>(&self) -> StoreResult<T> {
            Err(StoreError::Io("diagnostics unavailable".to_owned()))
        }

        fn should_fail(&self) -> bool {
            self.fail_reads.load(Ordering::Acquire)
        }
    }

    impl Store for FailingDiagnosticsStore {
        fn retention(&self) -> RetentionPolicy {
            self.inner.retention()
        }

        fn upsert_credential_state(&self, state: CredentialState) -> StoreResult<CredentialState> {
            self.inner.upsert_credential_state(state)
        }

        fn credential_state(&self, credential_id: &str) -> StoreResult<Option<CredentialState>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.credential_state(credential_id)
            }
        }

        fn credential_states(&self) -> StoreResult<Vec<CredentialState>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.credential_states()
            }
        }

        fn set_credential_enabled(
            &self,
            credential_id: &str,
            enabled: bool,
            updated_at: Timestamp,
        ) -> StoreResult<CredentialState> {
            self.inner
                .set_credential_enabled(credential_id, enabled, updated_at)
        }

        fn switch_credential(
            &self,
            selected: &str,
            siblings: &[String],
            updated_at: Timestamp,
        ) -> StoreResult<Vec<CredentialState>> {
            self.inner.switch_credential(selected, siblings, updated_at)
        }

        fn remove_credential_state(&self, credential_id: &str) -> StoreResult<bool> {
            self.inner.remove_credential_state(credential_id)
        }

        fn upsert_credential_health(
            &self,
            state: CredentialHealthState,
        ) -> StoreResult<CredentialHealthState> {
            self.inner.upsert_credential_health(state)
        }

        fn credential_health(
            &self,
            credential_id: &str,
        ) -> StoreResult<Option<CredentialHealthState>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.credential_health(credential_id)
            }
        }

        fn credential_health_states(&self) -> StoreResult<Vec<CredentialHealthState>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.credential_health_states()
            }
        }

        fn upsert_cooldown(&self, state: CooldownState) -> StoreResult<CooldownState> {
            self.inner.upsert_cooldown(state)
        }

        fn cooldown(
            &self,
            scope: &str,
            key: &str,
            now: Timestamp,
        ) -> StoreResult<Option<CooldownState>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.cooldown(scope, key, now)
            }
        }

        fn cooldowns(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.cooldowns(now)
            }
        }

        fn remove_cooldown(&self, scope: &str, key: &str) -> StoreResult<bool> {
            self.inner.remove_cooldown(scope, key)
        }

        fn upsert_session_affinity(
            &self,
            affinity: SessionAffinity,
        ) -> StoreResult<SessionAffinity> {
            self.inner.upsert_session_affinity(affinity)
        }

        fn session_affinity(
            &self,
            key: &str,
            now: Timestamp,
        ) -> StoreResult<Option<SessionAffinity>> {
            self.inner.session_affinity(key, now)
        }

        fn session_affinities(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>> {
            self.inner.session_affinities(now)
        }

        fn remove_session_affinity(&self, key: &str) -> StoreResult<bool> {
            self.inner.remove_session_affinity(key)
        }

        fn append_decision(&self, record: DecisionRecord) -> StoreResult<DecisionRecord> {
            self.inner.append_decision(record)
        }

        fn decisions(&self) -> StoreResult<Vec<DecisionRecord>> {
            self.inner.decisions()
        }

        fn recent_decisions(&self, limit: usize) -> StoreResult<Vec<DecisionRecord>> {
            self.inner.recent_decisions(limit)
        }

        fn prune(&self, now: Timestamp) -> StoreResult<PruneReport> {
            self.inner.prune(now)
        }
    }

    fn api() -> ManagementApi {
        let config = pooler_config::compile_yaml(
            "management-test.yaml",
            r#"
version: 1
management: {bind: 127.0.0.1:0}
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {provider-a: {url: http://127.0.0.1:1}}
models:
  - id: public-model
    targets: [{provider: provider-a, upstream_model: provider-model, capabilities: [text, streaming]}]
routes:
  - id: route-a
    listen: local
    match: {path: /v1/chat}
    target: {provider: provider-a, model_from: request.model}
    ingress: {mode: patch}
"#,
        )
        .expect("management config compiles");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling coordinator"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        ManagementApi::new(plan, store, pooling, ActiveCounts::new())
    }

    fn authenticated_api(secret_env: &str) -> ManagementApi {
        let config = pooler_config::compile_yaml(
            "authenticated-management-test.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:{secret_env}}}}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{provider-a: {{url: http://127.0.0.1:1}}}}\nmodels: [{{id: public-model, targets: [{{provider: provider-a, upstream_model: provider-model}}]}}]\nroutes: [{{id: route-a, listen: local, match: {{path: /v1/chat}}, target: {{provider: provider-a, model_from: request.model}}, ingress: {{mode: patch}}}}]\n"
            ),
        )
        .expect("authenticated management config compiles");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling coordinator"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        ManagementApi::new(plan, store, pooling, ActiveCounts::new())
    }

    fn loopback_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_static("localhost"));
        headers
    }

    #[test]
    fn unauthenticated_loopback_host_validation_allows_only_local_names() {
        let api = api();
        let mut headers = HeaderMap::new();
        assert!(!management_request_host_allowed(&api, false, &headers));
        let direct = api.handle(&Method::GET, "/health", &headers);
        assert_eq!(direct.status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&direct.body).contains(LOOPBACK_HOST_ERROR));

        for host in [
            "localhost",
            "LOCALHOST:9090",
            "127.0.0.1",
            "127.0.0.1:9090",
            "[::1]",
            "[::1]:9090",
        ] {
            headers.insert(header::HOST, header::HeaderValue::from_static(host));
            assert!(
                management_request_host_allowed(&api, false, &headers),
                "expected safe Host {host}"
            );
        }

        for host in [
            "example.test",
            "0.0.0.0",
            "localhost:0",
            "[::2]",
            "::1",
            "localhost:bad",
        ] {
            headers.insert(header::HOST, header::HeaderValue::from_static(host));
            assert!(
                !management_request_host_allowed(&api, false, &headers),
                "expected unsafe Host {host}"
            );
        }

        headers.append(header::HOST, header::HeaderValue::from_static("localhost"));
        assert!(!management_request_host_allowed(&api, false, &headers));
    }

    #[test]
    fn read_only_endpoints_expose_generation_and_redacted_plan_views() {
        let api = api();
        let headers = loopback_headers();
        let health = api.handle(&Method::GET, "/health", &headers);
        assert_eq!(health.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&health.body).contains("configuration_generation"));

        let routes = api.handle(&Method::GET, "/routes", &headers);
        let body = String::from_utf8_lossy(&routes.body);
        assert!(body.contains("route-a"));
        assert!(!body.contains("Authorization"));
        assert!(!body.contains("secret"));

        let models = api.handle(&Method::GET, "/models", &headers);
        assert!(String::from_utf8_lossy(&models.body).contains("public-model"));
        let providers = api.handle(&Method::GET, "/health/providers", &headers);
        let providers: Value = serde_json::from_slice(&providers.body).expect("providers json");
        assert_eq!(providers["providers"][0]["id"], "provider-a");
        assert_eq!(providers["providers"][0]["status"], "not_cooling");

        let config = api.handle(&Method::GET, "/config", &headers);
        let config: Value = serde_json::from_slice(&config.body).expect("config json");
        assert_eq!(config["management"]["mutations"], false);
    }

    #[test]
    fn management_ui_assets_are_authenticated_and_hardened() {
        let api = api();
        let headers = loopback_headers();
        let html = api.handle(&Method::GET, "/management/ui", &headers);
        assert_eq!(html.status, StatusCode::OK);
        assert_eq!(
            html.headers.get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/html; charset=utf-8"
            ))
        );
        let html_body = String::from_utf8_lossy(&html.body);
        assert!(html_body.contains("Pooler"));
        assert!(html_body.contains("Coder Company"));
        assert!(html_body.contains("/management/ui.js"));
        assert!(html_body.contains("/management/ui.css"));
        assert!(html_body.contains("/management/ui/icons.js"));
        assert!(html_body.contains("/management/ui/providers.js"));
        assert!(html_body.contains("/management/ui/assets/mark-charcoal-64.png"));
        assert!(!html_body.contains("type=\"submit\""));
        for endpoint in [
            "listeners",
            "health/providers",
            "routes",
            "models",
            "accounts",
            "quota",
            "metrics",
            "export",
            "traces",
            "audit",
        ] {
            assert!(!html_body.contains(&format!("href=\"/management/{endpoint}")));
        }
        assert_eq!(
            html.headers.get(header::CONTENT_SECURITY_POLICY),
            Some(&header::HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            ))
        );
        assert_eq!(
            html.headers.get(header::X_CONTENT_TYPE_OPTIONS),
            Some(&header::HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            html.headers.get(header::X_FRAME_OPTIONS),
            Some(&header::HeaderValue::from_static("DENY"))
        );
        let management_root = api.handle(&Method::GET, "/management", &headers);
        assert_eq!(management_root.status, StatusCode::OK);
        assert_eq!(management_root.body, html.body);

        let css = api.handle(&Method::GET, "/management/ui.css", &headers);
        assert_eq!(css.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&css.body).contains("--surface"));
        let icons = api.handle(&Method::GET, "/management/ui/icons.js", &headers);
        assert_eq!(icons.status, StatusCode::OK);
        let providers = api.handle(&Method::GET, "/management/ui/providers.js", &headers);
        assert_eq!(providers.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&providers.body).contains("resolveProviderSlug"));
        let mark = api.handle(
            &Method::GET,
            "/management/ui/assets/mark-charcoal-64.png",
            &headers,
        );
        assert_eq!(mark.status, StatusCode::OK);
        assert_eq!(
            mark.headers.get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("image/png"))
        );
        let font = api.handle(
            &Method::GET,
            "/management/ui/fonts/geist-latin.woff2",
            &headers,
        );
        assert_eq!(font.status, StatusCode::OK);
        assert_eq!(
            font.headers.get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("font/woff2"))
        );
        let js = api.handle(&Method::GET, "/management/ui.js", &headers);
        assert_eq!(js.status, StatusCode::OK);
        let js_body = String::from_utf8_lossy(&js.body);
        assert!(js_body.contains("\"/metrics\""));
        assert!(js_body.contains("cache: \"no-store\""));
        assert!(js_body.contains("method: \"POST\""));
        assert!(js_body.contains("Authorization"));
        assert!(js_body.contains("downloadExport"));
        assert!(js_body.contains("`${BASE}/export`"));
        assert!(!js_body.contains("localStorage"));
        assert!(!js_body.contains("sessionStorage"));
        assert!(!js_body.contains("?token="));
    }

    #[test]
    fn management_ui_data_endpoints_cover_runtime_overview_without_secrets() {
        let api = api();
        let headers = loopback_headers();
        for path in [
            "/listeners",
            "/routes",
            "/models",
            "/health/providers",
            "/accounts",
            "/quota",
            "/metrics",
            "/metrics/prometheus",
        ] {
            let response = api.handle(&Method::GET, path, &headers);
            assert_eq!(response.status, StatusCode::OK, "{path}");
            assert!(!response.body.is_empty(), "{path} returned an empty body");
            let body = String::from_utf8_lossy(&response.body);
            assert!(
                !body.contains("Authorization"),
                "{path} leaked auth material"
            );
            assert!(
                !body.contains("management-secret"),
                "{path} leaked a secret"
            );
        }
        let listeners = api.handle(&Method::GET, "/listeners", &headers);
        let listeners = String::from_utf8_lossy(&listeners.body);
        assert!(listeners.contains("local"));
        assert!(listeners.contains("route_count"));
        let metrics = api.handle(&Method::GET, "/metrics", &headers);
        assert!(String::from_utf8_lossy(&metrics.body).contains("dropped_series"));
    }

    #[test]
    fn management_state_failures_return_typed_service_unavailable() {
        let config = pooler_config::compile_yaml(
            "management-failing-store.yaml",
            r#"
version: 1
management: {bind: 127.0.0.1:0}
upstreams: {provider-a: {url: http://127.0.0.1:1}}
accounts: {account-a: {provider: provider-a, secret: env:POOLER_ACCOUNT_KEY}}
"#,
        )
        .expect("failing-store config compiles");
        let plan = config.management().cloned().expect("management plan");
        let store = Arc::new(FailingDiagnosticsStore::new());
        let pooling = Arc::new(
            PoolingCoordinator::with_store(&config, store.clone()).expect("pooling coordinator"),
        );
        store.fail_reads();
        let config_store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        let api = ManagementApi::new(plan, config_store, pooling, ActiveCounts::new());
        let headers = loopback_headers();
        for path in ["/health", "/health/providers", "/accounts", "/quota"] {
            let response = api.handle(&Method::GET, path, &headers);
            assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
            assert_eq!(
                String::from_utf8_lossy(&response.body),
                r#"{"error":"management state unavailable"}"#,
                "{path} must not report an empty healthy view"
            );
        }
    }

    #[test]
    fn remaining_high_regression_root_health_surfaces_store_failure() {
        let config = pooler_config::compile_yaml(
            "management-root-health-failing-store.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0}\nupstreams: {provider-a: {url: http://127.0.0.1:1}}\n",
        )
        .expect("config compiles");
        let plan = config.management().cloned().expect("management plan");
        let store = Arc::new(FailingDiagnosticsStore::new());
        let pooling = Arc::new(
            PoolingCoordinator::with_store(&config, store.clone()).expect("pooling coordinator"),
        );
        store.fail_reads();
        let api = ManagementApi::new(
            plan,
            Arc::new(ConfigStore::with_generation(
                ConfigGeneration::new(config.generation()),
                config,
            )),
            pooling,
            ActiveCounts::new(),
        );
        let response = api.handle(&Method::GET, "/health", &loopback_headers());
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            r#"{"error":"management state unavailable"}"#
        );
    }

    #[test]
    fn mutation_requests_are_rejected_and_active_counts_are_bounded() {
        let api = api();
        let headers = loopback_headers();
        let response = api.handle(&Method::POST, "/routes", &headers);
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(String::from_utf8_lossy(&response.body).contains("not supported"));
        let reload = api.handle(&Method::POST, "/reload", &headers);
        assert_eq!(reload.status, StatusCode::FORBIDDEN);

        let guard = api.active_counts().enter("local");
        let active = api.handle(&Method::GET, "/active", &headers);
        assert!(String::from_utf8_lossy(&active.body).contains("\"active\":1"));
        drop(guard);
        let active = api.handle(&Method::GET, "/active", &headers);
        assert!(String::from_utf8_lossy(&active.body).contains("\"active\":0"));
    }

    #[tokio::test]
    async fn authenticated_account_controls_reload_audit_and_export_are_live_and_redacted() {
        std::env::set_var("POOLER_MANAGEMENT_MUTATION_KEY", "mutation-secret");
        let first_secret = tempfile::NamedTempFile::new().expect("first secret");
        let second_secret = tempfile::NamedTempFile::new().expect("second secret");
        std::fs::write(first_secret.path(), "first-account-secret").expect("write first");
        std::fs::write(second_secret.path(), "second-account-secret").expect("write second");
        #[cfg(unix)]
        for path in [first_secret.path(), second_secret.path()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("secret permissions");
        }
        let config = pooler_config::compile_yaml(
            "management-mutation-test.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:POOLER_MANAGEMENT_MUTATION_KEY}}}}\nupstreams: {{provider: {{url: http://127.0.0.1:1}}}}\naccounts:\n  alpha: {{provider: provider, secret: 'file:{}'}}\n  beta: {{provider: provider, secret: 'file:{}'}}\naccount_pools: {{accounts: {{accounts: [alpha, beta]}}}}\npolicies: {{accounts: {{selection: {{strategy: ordered_fallback, account_pool: accounts}}}}}}\nmodels: [{{id: public, targets: [{{provider: provider, upstream_model: public}}]}}]\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nroutes: [{{id: route, listen: local, ingress: {{mode: patch}}, target: {{provider: provider, model_from: request.model, policy: accounts}}}}]\n",
                first_secret.path().display(),
                second_secret.path().display(),
            ),
        )
        .expect("management mutation config");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        let api = ManagementApi::new(plan, store, pooling, ActiveCounts::new());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer mutation-secret"),
        );

        let mut cross_origin = headers.clone();
        cross_origin.insert(
            header::HOST,
            header::HeaderValue::from_static("127.0.0.1:1"),
        );
        cross_origin.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://attacker.example"),
        );
        assert_eq!(
            api.handle(&Method::POST, "/accounts/alpha/disable", &cross_origin)
                .status,
            StatusCode::FORBIDDEN
        );
        let mut body_headers = headers.clone();
        body_headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("1"),
        );
        assert_eq!(
            api.handle(&Method::POST, "/accounts/alpha/disable", &body_headers)
                .status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let mut transfer_headers = headers.clone();
        transfer_headers.insert(
            header::TRANSFER_ENCODING,
            header::HeaderValue::from_static("chunked"),
        );
        assert_eq!(
            api.handle(&Method::POST, "/accounts/alpha/disable", &transfer_headers,)
                .status,
            StatusCode::BAD_REQUEST
        );
        let mut malformed_length = headers.clone();
        malformed_length.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("invalid"),
        );
        assert_eq!(
            api.handle(&Method::POST, "/accounts/alpha/disable", &malformed_length,)
                .status,
            StatusCode::BAD_REQUEST
        );
        let mut multiple_lengths = headers.clone();
        multiple_lengths.append(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("0"),
        );
        multiple_lengths.append(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("0"),
        );
        assert_eq!(
            api.handle(&Method::POST, "/accounts/alpha/disable", &multiple_lengths,)
                .status,
            StatusCode::BAD_REQUEST
        );

        let disabled = api.handle(&Method::POST, "/accounts/alpha/disable", &headers);
        assert_eq!(disabled.status, StatusCode::OK);
        let accounts = api.handle(&Method::GET, "/accounts", &headers);
        let accounts: Value = serde_json::from_slice(&accounts.body).expect("accounts json");
        let alpha = accounts["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .find(|account| account["id"] == "alpha")
            .expect("alpha");
        assert_eq!(accounts["mutation_capable"], true);
        assert_eq!(alpha["enabled"], false);
        assert_eq!(alpha["auth_kind"], "api_key");
        assert_eq!(alpha["status"], "disabled");
        assert_eq!(alpha["selected"], false);
        let beta = accounts["accounts"]
            .as_array()
            .expect("accounts")
            .iter()
            .find(|account| account["id"] == "beta")
            .expect("beta");
        assert_eq!(beta["status"], "available");
        assert_eq!(beta["selected"], true);
        assert!(alpha["available_actions"]
            .as_array()
            .expect("available actions")
            .iter()
            .any(|action| action == "enable"));

        let model = api.handle(&Method::POST, "/models/public/disable", &headers);
        assert_eq!(model.status, StatusCode::OK);
        let models = api.handle(&Method::GET, "/models", &headers);
        let models: Value = serde_json::from_slice(&models.body).expect("models json");
        assert_eq!(models["mutation_capable"], true);
        assert_eq!(models["models"][0]["enabled"], false);

        let notifier = api.reload_notifier();
        let reload = api.handle(&Method::POST, "/reload", &headers);
        assert_eq!(reload.status, StatusCode::ACCEPTED);
        let reload: Value = serde_json::from_slice(&reload.body).expect("reload json");
        assert_eq!(reload["kind"], "configuration");
        assert_eq!(reload["status"], "pending");
        let request_id = reload["request_id"].as_u64().expect("reload request id");
        tokio::time::timeout(std::time::Duration::from_secs(1), notifier.notified())
            .await
            .expect("reload notification");
        let request = api.next_reload_request().await;
        assert_eq!(request.id, request_id);
        assert_eq!(request.kind, ManagementReloadKind::Configuration);
        assert_eq!(request.generation, 1);
        api.complete_reload(request.id, "succeeded", 2, None);
        let reloads = api.handle(&Method::GET, "/reloads", &headers);
        let reloads: Value = serde_json::from_slice(&reloads.body).expect("reloads json");
        assert_eq!(reloads["reloads"][0]["status"], "succeeded");

        let catalog_reload = api.handle(&Method::POST, "/models/reload", &headers);
        let catalog_reload: Value =
            serde_json::from_slice(&catalog_reload.body).expect("catalog reload json");
        assert_eq!(catalog_reload["kind"], "catalog");
        let catalog_request = api.next_reload_request().await;
        assert_eq!(catalog_request.kind, ManagementReloadKind::Catalog);
        api.complete_reload(catalog_request.id, "unchanged", 2, Some(1));
        api.traces.record(
            pooler_observe::TraceRecord::new(pooler_observe::TraceStage::Attempt)
                .route("route")
                .provider("provider")
                .attribute("authorization", "Bearer trace-secret"),
        );
        let traces = api.handle(&Method::GET, "/traces", &headers);
        assert_eq!(traces.status, StatusCode::OK);
        assert!(!String::from_utf8_lossy(&traces.body).contains("trace-secret"));

        let audit = api.handle(&Method::GET, "/audit", &headers);
        let audit: Value = serde_json::from_slice(&audit.body).expect("audit json");
        let events = audit["events"].as_array().expect("events");
        assert!(events
            .iter()
            .any(|event| { event["request_id"] == request_id && event["outcome"] == "accepted" }));
        assert!(events
            .iter()
            .any(|event| { event["request_id"] == request_id && event["outcome"] == "succeeded" }));
        let export = api.handle(&Method::GET, "/export", &headers);
        let export = String::from_utf8(export.body).expect("export utf8");
        for secret in [
            "mutation-secret",
            "first-account-secret",
            "second-account-secret",
        ] {
            assert!(!export.contains(secret));
        }
        std::env::remove_var("POOLER_MANAGEMENT_MUTATION_KEY");
    }

    #[test]
    fn management_alias_and_head_keep_the_response_shape() {
        let api = api();
        let headers = loopback_headers();
        let get = api.handle(&Method::GET, "/management/health?ignored=true", &headers);
        let head = api.handle(&Method::HEAD, "/management/health", &headers);
        assert_eq!(get.status, StatusCode::OK);
        assert_eq!(head.status, StatusCode::OK);
        assert!(head.body.is_empty());
        assert_eq!(
            head.headers.get(header::CONTENT_LENGTH),
            get.headers.get(header::CONTENT_LENGTH)
        );
    }

    #[test]
    fn configured_management_auth_is_constant_time_and_never_echoed() {
        let config = pooler_config::compile_yaml(
            "management-auth-test.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_MANAGEMENT_TEST_KEY}}\n",
        )
        .expect("management auth config compiles");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling coordinator"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        let api = ManagementApi::new(plan, store, pooling, ActiveCounts::new());

        std::env::set_var("POOLER_MANAGEMENT_TEST_KEY", "management-secret");
        let mut wrong = HeaderMap::new();
        wrong.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer wrong"),
        );
        let rejected = api.handle(&Method::GET, "/health", &wrong);
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert!(!String::from_utf8_lossy(&rejected.body).contains("management-secret"));
        let rejected_ui = api.handle(&Method::GET, "/management/routes", &wrong);
        assert_eq!(rejected_ui.status, StatusCode::UNAUTHORIZED);
        assert!(!String::from_utf8_lossy(&rejected_ui.body).contains("management-secret"));

        let no_bearer_data = api.handle(&Method::GET, "/management/routes", &loopback_headers());
        assert_eq!(no_bearer_data.status, StatusCode::UNAUTHORIZED);

        let shell = api.handle(&Method::GET, "/management/ui", &loopback_headers());
        assert_eq!(shell.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&shell.body).contains("Coder Company"));

        let mut correct = HeaderMap::new();
        correct.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer management-secret"),
        );
        let accepted = api.handle(&Method::GET, "/health", &correct);
        assert_eq!(accepted.status, StatusCode::OK);
        std::env::remove_var("POOLER_MANAGEMENT_TEST_KEY");
    }

    #[test]
    fn remote_management_is_rejected_without_tls() {
        let error = pooler_config::compile_yaml(
            "management-remote-no-tls.yaml",
            "version: 1\nmanagement: {bind: 0.0.0.0:0, remote: true, auth: {secret: env:POOLER_MANAGEMENT_TEST_KEY}}\n",
        )
        .expect_err("remote management must be rejected without TLS");
        assert!(error.to_string().contains("requires TLS"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_management_socket_requires_private_parent_and_socket_mode() {
        let parent = tempfile::tempdir().expect("Unix management parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("set private Unix management parent mode");
        let path = parent.path().join("management.sock");
        let config = pooler_config::compile_yaml(
            "management-unix.yaml",
            &format!("version: 1\nmanagement: {{bind: {}}}\n", path.display()),
        )
        .expect("Unix management config compiles");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling coordinator"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        let server = ManagementHttpServer::bind(Arc::new(ManagementApi::new(
            plan,
            store,
            pooling,
            ActiveCounts::new(),
        )))
        .await
        .expect("private Unix management socket binds");
        let metadata = fs::symlink_metadata(&path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o077, 0);
        drop(server);
        assert!(
            !path.exists(),
            "management socket cleanup removed only its socket"
        );

        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755))
            .expect("relax Unix management parent mode");
        let config = pooler_config::compile_yaml(
            "management-unix-insecure-parent.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: {}}}\n",
                parent.path().join("insecure.sock").display()
            ),
        )
        .expect("insecure-parent config compiles");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling coordinator"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        let error = ManagementHttpServer::bind(Arc::new(ManagementApi::new(
            plan,
            store,
            pooling,
            ActiveCounts::new(),
        )))
        .await
        .expect_err("insecure Unix parent must be rejected");
        assert!(error.to_string().contains("owner-private"));
    }

    #[tokio::test]
    async fn management_listener_rejects_mutation_framing_at_http_boundary() {
        let server = ManagementHttpServer::bind(Arc::new(api()))
            .await
            .expect("management listener binds");
        let address: SocketAddr = server
            .address()
            .parse()
            .expect("ephemeral management address");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        for (label, request, expected) in [
            (
                "transfer encoding",
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n".as_slice(),
                "400 Bad Request",
            ),
            (
                "malformed content length",
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: invalid\r\nConnection: close\r\n\r\n".as_slice(),
                "400 Bad Request",
            ),
            (
                "multiple content lengths",
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
                "400 Bad Request",
            ),
            (
                "unframed payload bytes",
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\nx".as_slice(),
                "413 Payload Too Large",
            ),
            (
                "nonzero content length",
                b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".as_slice(),
                "413 Payload Too Large",
            ),
        ] {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("management connects");
            stream
                .write_all(request)
                .await
                .expect("management request writes");
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read_to_end(&mut response),
            )
            .await
            .expect("management rejection arrives")
            .expect("management rejection reads");
            assert!(
                String::from_utf8_lossy(&response).contains(expected),
                "{label} response was {}",
                String::from_utf8_lossy(&response)
            );
        }

        let mut delayed = TcpStream::connect(address)
            .await
            .expect("delayed management connection");
        delayed
            .write_all(
                b"POST http://localhost/reload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("delayed management headers write");
        tokio::time::sleep(Duration::from_millis(10)).await;
        delayed
            .write_all(b"x")
            .await
            .expect("delayed payload writes");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), delayed.read_to_end(&mut response))
            .await
            .expect("delayed body rejection arrives")
            .expect("delayed body rejection reads");
        assert!(
            String::from_utf8_lossy(&response).contains("413 Payload Too Large"),
            "delayed unframed payload response was {}",
            String::from_utf8_lossy(&response)
        );

        server.begin_shutdown();
        runner
            .await
            .expect("management task does not panic")
            .expect("management task shuts down");
    }

    #[tokio::test]
    async fn standalone_management_listener_serves_json_and_shuts_down() {
        let server = ManagementHttpServer::bind(Arc::new(api()))
            .await
            .expect("management listener binds");
        let address: SocketAddr = server
            .address()
            .parse()
            .expect("ephemeral management address");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let mut rebinding = TcpStream::connect(address)
            .await
            .expect("management connects for Host validation");
        rebinding
            .write_all(b"GET /health HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("Host validation request writes");
        let mut rejected = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rebinding.read_to_end(&mut rejected),
        )
        .await
        .expect("Host validation response arrives")
        .expect("Host validation response reads");
        let rejected = String::from_utf8_lossy(&rejected);
        assert!(rejected.contains("403 Forbidden"));
        assert!(rejected.contains(LOOPBACK_HOST_ERROR));

        let mut stream = TcpStream::connect(address)
            .await
            .expect("management connects");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("management request writes");
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("management response arrives")
        .expect("management response reads");
        assert!(String::from_utf8_lossy(&response).contains("\"status\":\"ok\""));

        server.begin_shutdown();
        runner
            .await
            .expect("management task does not panic")
            .expect("management task shuts down");
    }

    #[test]
    fn setup_options_are_catalog_derived_and_do_not_expose_secrets() {
        let response = api().handle(&Method::GET, "/setup/options", &loopback_headers());
        assert_eq!(response.status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&response.body).expect("setup options json");
        let openai = value["providers"]
            .as_array()
            .and_then(|providers| providers.iter().find(|provider| provider["id"] == "openai"))
            .expect("built-in OpenAI provider");
        assert_eq!(openai["request_dialect"], "openai");
        assert!(openai["authentication"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method["method"] == "api_key")));
        let moonshot = value["providers"]
            .as_array()
            .and_then(|providers| {
                providers
                    .iter()
                    .find(|provider| provider["id"] == "moonshotai")
            })
            .expect("Moonshot catalog provider");
        assert!(moonshot["authentication"]
            .as_array()
            .is_some_and(|methods| {
                methods.iter().any(|method| {
                    method["method"] == "device_code"
                        && method["support"] == "requires_explicit_configuration"
                })
            }));
        let body = String::from_utf8(response.body).expect("UTF-8 setup options");
        assert!(!body.contains("sk-"));
        assert!(!body.contains("client_secret"));
    }

    #[test]
    fn setup_configuration_is_secret_free_and_compiler_validated() {
        let response = api().handle(
            &Method::GET,
            "/setup/config?provider=openai&auth=api_key&account=primary&model=gpt-5&client=openai",
            &loopback_headers(),
        );
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let value: Value = serde_json::from_slice(&response.body).expect("setup config json");
        assert_eq!(value["validated"], true);
        let config = value["configuration"].as_str().expect("generated YAML");
        assert!(config.contains("secret: env:OPENAI_API_KEY"));
        assert!(!config.contains("Bearer "));
        compile_yaml("setup-roundtrip.yaml", config).expect("generated YAML compiles again");
        for (provider, model, client) in [
            ("anthropic", "claude-3-7-sonnet", "anthropic"),
            ("google", "gemini-2.5-pro", "gemini"),
            ("openai", "gpt-5", "factory"),
            ("openai", "org/model@revision", "native"),
            ("openai", "gpt-5", "devin"),
        ] {
            let generated = generate_setup_config(provider, "api_key", "primary", model, client)
                .unwrap_or_else(|error| panic!("{provider}/{client} generation failed: {error}"));
            compile_yaml(format!("setup-{provider}-{client}.yaml"), &generated)
                .unwrap_or_else(|error| panic!("{provider}/{client} did not compile: {error}"));
        }
        let oauth = generate_setup_config("openai", "device_code", "personal", "gpt-5", "codex")
            .expect("supported device-code setup compiles");
        assert!(oauth.contains("auth_kind: oauth"));
        assert!(!oauth.contains("OPENAI_API_KEY"));
        assert_eq!(
            generate_setup_config(
                "moonshotai",
                "device_code",
                "primary",
                "kimi-k2",
                "openai",
            )
            .expect_err("explicitly configured device flow is not wizard-safe"),
            "device login requires operator-owned registration details that this wizard cannot collect"
        );

        let incompatible = api().handle(
            &Method::GET,
            "/setup/config?provider=anthropic&auth=api_key&account=primary&model=claude&client=gemini",
            &loopback_headers(),
        );
        assert_eq!(incompatible.status, StatusCode::BAD_REQUEST);
        let injected = api().handle(
            &Method::GET,
            "/setup/config?provider=openai&auth=api_key&account=primary%0Aadmin&model=gpt-5&client=openai",
            &loopback_headers(),
        );
        assert_eq!(injected.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn setup_connection_test_does_not_claim_unmeasured_health() {
        let response = api().handle(
            &Method::GET,
            "/setup/test?provider=openai&auth=api_key&account=primary&model=gpt-5&client=openai",
            &loopback_headers(),
        );
        assert_eq!(response.status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&response.body).expect("setup test json");
        assert_eq!(value["ready"], false);
        assert_eq!(value["connection"], "not_probed");
        assert_eq!(value["checks"][4]["status"], "not_run");
    }

    #[tokio::test]
    async fn management_listener_accepts_body_free_authenticated_mutations() {
        const SECRET_ENV: &str = "POOLER_MANAGEMENT_BODY_FREE_TEST_KEY";
        std::env::set_var(SECRET_ENV, "body-free-secret");
        let server = ManagementHttpServer::bind(Arc::new(authenticated_api(SECRET_ENV)))
            .await
            .expect("management listener binds");
        let address: SocketAddr = server
            .address()
            .parse()
            .expect("ephemeral management address");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        for request in [
            b"POST /management/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer body-free-secret\r\nConnection: close\r\n\r\n".as_slice(),
            b"POST /management/models/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer body-free-secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        ] {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("management connects");
            stream
                .write_all(request)
                .await
                .expect("management request writes");
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read_to_end(&mut response),
            )
            .await
            .expect("management response arrives")
            .expect("management response reads");
            assert!(
                String::from_utf8_lossy(&response).contains("202 Accepted"),
                "body-free mutation response was {}",
                String::from_utf8_lossy(&response)
            );
        }

        server.begin_shutdown();
        runner
            .await
            .expect("management task does not panic")
            .expect("management task shuts down");
        std::env::remove_var(SECRET_ENV);
    }

    #[tokio::test]
    async fn management_reload_queue_is_bounded_and_recovers_capacity() {
        const SECRET_ENV: &str = "POOLER_MANAGEMENT_RELOAD_QUEUE_TEST_KEY";
        std::env::set_var(SECRET_ENV, "reload-queue-secret");
        let api = authenticated_api(SECRET_ENV);
        let mut headers = loopback_headers();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer reload-queue-secret"),
        );

        for _ in 0..MAX_PENDING_MANAGEMENT_RELOADS {
            assert_eq!(
                api.handle(&Method::POST, "/reload", &headers).status,
                StatusCode::ACCEPTED
            );
        }
        assert_eq!(
            api.handle(&Method::POST, "/reload", &headers).status,
            StatusCode::SERVICE_UNAVAILABLE
        );

        let consumed = api.next_reload_request().await;
        assert_eq!(consumed.generation, 1);
        assert_eq!(
            api.handle(&Method::POST, "/models/reload", &headers).status,
            StatusCode::ACCEPTED
        );
        let reloads = api.handle(&Method::GET, "/reloads", &headers);
        let reloads: Value = serde_json::from_slice(&reloads.body).expect("reload history json");
        assert_eq!(
            reloads["reloads"].as_array().expect("reload history").len(),
            MAX_PENDING_MANAGEMENT_RELOADS + 1
        );
        std::env::remove_var(SECRET_ENV);
    }
}
