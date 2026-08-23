//! Authenticated management HTTP responses.
//!
//! The management surface is intentionally separate from inference routes.
//! It exposes immutable plans and redacted mutable state, accepts only bounded
//! typed configuration operations and body-free controls, and never serializes
//! credential references.

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
use http_body_util::{BodyExt as _, Full, Limited};
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
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, UnixListener},
    sync::{mpsc, Notify},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::config_management::{
    ConfigManagement, ConfigManagementError, PreparedCommit, TypedConfigPatch,
};
use crate::http_runtime::RuntimeGeneration;
use crate::management_ui;
use crate::usage_management::{usage_aggregate, usage_list, usage_otlp_json, usage_prometheus};
use crate::{merged_model_catalog_value, CatalogRuntime, ConfigSnapshot, ConfigStore};

const DEFAULT_DECISION_LIMIT: usize = 20;
const MAX_DECISION_LIMIT: usize = 100;
const DEFAULT_REQUEST_LIMIT: usize = 20;
const MAX_REQUEST_LIMIT: usize = 100;
const MAX_REQUEST_EXPORT: usize = 4_096;
const MAX_MANAGEMENT_AUDIT_EVENTS: usize = 256;
const MAX_MANAGEMENT_RELOADS: usize = 256;
const MAX_PENDING_MANAGEMENT_RELOADS: usize = 16;
const MAX_OAUTH_DEVICE_RECORDS: usize = 32;
const MAX_MANAGEMENT_HEADER_BYTES: usize = 64 * 1024;
const MAX_CONFIG_MUTATION_BODY_BYTES: usize = 256 * 1024;
const MANAGEMENT_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MANAGEMENT_BODY_GUARD_TIMEOUT: Duration = Duration::from_millis(50);
const MANAGEMENT_CONFIG_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const LOOPBACK_HOST_ERROR: &str =
    "management Host header must name localhost or a loopback address";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountDraftRequest {
    id: String,
    provider: String,
    auth_kind: AccountDraftAuthKind,
    secret: Option<AccountSecretReference>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AccountDraftAuthKind {
    ApiKey,
    OAuth,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AccountSecretReference {
    Env { name: String },
    File { path: String },
    Keyring { service: String, account: String },
}

impl AccountSecretReference {
    fn render(self) -> Result<String, ConfigManagementError> {
        let value = match self {
            Self::Env { name } if valid_secret_component(&name, 128) => format!("env:{name}"),
            Self::File { path }
                if valid_secret_component(&path, 1024) && Path::new(&path).is_absolute() =>
            {
                format!("file:{path}")
            }
            Self::Keyring { service, account }
                if valid_secret_component(&service, 128)
                    && valid_secret_component(&account, 128) =>
            {
                format!("keyring:{service}/{account}")
            }
            _ => return Err(ConfigManagementError::UnsupportedPatch),
        };
        Ok(value)
    }
}

fn valid_secret_component(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(|character| character.is_control())
}

fn create_account_draft(
    manager: &ConfigManagement,
    active: &CompiledConfig,
    generation: u64,
    body: &[u8],
) -> Result<Value, ConfigManagementError> {
    let request = serde_json::from_slice::<AccountDraftRequest>(body)
        .map_err(|_| ConfigManagementError::UnsupportedPatch)?;
    if !active.upstreams().contains_key(request.provider.as_str()) {
        return Err(ConfigManagementError::UnsupportedPatch);
    }
    let mut value = json!({
        "provider": request.provider,
        "auth_kind": match request.auth_kind {
            AccountDraftAuthKind::ApiKey => "api_key",
            AccountDraftAuthKind::OAuth => "oauth",
        }
    });
    match (request.auth_kind, request.secret) {
        (AccountDraftAuthKind::ApiKey, Some(secret)) => {
            value
                .as_object_mut()
                .expect("account draft is an object")
                .insert("secret".to_owned(), Value::String(secret.render()?));
        }
        (AccountDraftAuthKind::OAuth, None) => {}
        _ => return Err(ConfigManagementError::UnsupportedPatch),
    }

    let created = manager.create(generation)?;
    let id = created
        .get("draft_id")
        .and_then(Value::as_u64)
        .ok_or(ConfigManagementError::Persistence)?;
    let etag = created
        .get("etag")
        .and_then(Value::as_str)
        .ok_or(ConfigManagementError::Persistence)?;
    let applied = manager.apply(
        id,
        etag,
        TypedConfigPatch::Upsert {
            section: "accounts".to_owned(),
            id: request.id,
            value,
        },
    )?;
    let etag = applied
        .get("etag")
        .and_then(Value::as_str)
        .ok_or(ConfigManagementError::Persistence)?;
    manager.validate(id, etag)
}

#[derive(Clone, Copy)]
enum UsageRepresentation {
    List,
    Aggregate,
    Export,
    Prometheus,
    OtlpJson,
}

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

fn setup_discovery_is_fresh(
    source: &Value,
    upstream_ids: &[&str],
    account_id: &str,
    reload_requested_at: u64,
) -> bool {
    source["provider"]
        .as_str()
        .is_some_and(|provider| upstream_ids.contains(&provider))
        && source["account"].as_str() == Some(account_id)
        && source["state"]["observed_at_unix_ms"]
            .as_u64()
            .is_some_and(|observed_at| observed_at > reload_requested_at)
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
            if provider_id == "google" {
                return Err(
                    "browser OAuth requires operator-owned registration details that this wizard cannot collect",
                );
            }
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
            "enable" | "disable" | "switch" | "refresh" | "revoke" | "oauth-device"
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

fn is_config_request(path: &str) -> bool {
    path == "/config/drafts"
        || path == "/config/accounts/draft"
        || path == "/config/rollback"
        || path.starts_with("/config/drafts/")
}

fn is_config_mutation(method: &Method, path: &str) -> bool {
    is_config_request(path) && (*method == Method::POST || *method == Method::PATCH)
}

fn config_draft_action(path: &str) -> Option<(u64, Option<&str>)> {
    let suffix = path.strip_prefix("/config/drafts/")?;
    let (id, action) = suffix
        .split_once('/')
        .map_or((suffix, None), |(id, action)| (id, Some(action)));
    let id = id.parse::<u64>().ok()?;
    (id > 0 && action.is_none_or(|action| matches!(action, "validate" | "diff" | "commit")))
        .then_some((id, action))
}

fn is_management_mutation(method: &Method, path: &str) -> bool {
    is_config_mutation(method, path)
        || (*method == Method::POST
            && (path == "/reload"
                || path == "/models/reload"
                || management_account_action(path).is_some()
                || management_model_action(path).is_some()))
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
    DeviceLogin { request_id: u64 },
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagementReloadRequest {
    pub(crate) id: u64,
    pub(crate) kind: ManagementReloadKind,
    pub(crate) generation: u64,
    pub(crate) source: Option<PathBuf>,
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

#[derive(Debug, Default)]
struct OAuthDeviceControl {
    next_id: AtomicU64,
    records: Mutex<VecDeque<Value>>,
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
    oauth_device: Arc<OAuthDeviceControl>,
    native_commands: Option<mpsc::Sender<NativeAccountCommand>>,
    config_management: Arc<Mutex<Option<Arc<ConfigManagement>>>>,
    configuration_reload_serial: Arc<Mutex<()>>,
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
            oauth_device: Arc::new(OAuthDeviceControl::default()),
            native_commands: None,
            config_management: Arc::new(Mutex::new(None)),
            configuration_reload_serial: Arc::new(Mutex::new(())),
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
            oauth_device: Arc::new(OAuthDeviceControl::default()),
            native_commands: Some(services.native_commands),
            config_management: Arc::new(Mutex::new(None)),
            configuration_reload_serial: Arc::new(Mutex::new(())),
            active,
        }
    }

    /// Enable bounded typed configuration drafts for this process source.
    pub fn enable_config_management(&self, source: impl AsRef<Path>) -> io::Result<()> {
        let manager = ConfigManagement::new(source).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed configuration source was rejected",
            )
        })?;
        *self
            .config_management
            .lock()
            .expect("configuration management lock poisoned") = Some(Arc::new(manager));
        Ok(())
    }

    pub(crate) fn try_begin_unmanaged_configuration_reload(&self) -> bool {
        self.config_management
            .lock()
            .expect("configuration management lock poisoned")
            .as_ref()
            .is_none_or(|manager| manager.try_begin_unmanaged_reload())
    }

    pub(crate) fn finish_unmanaged_configuration_reload(&self) {
        if let Some(manager) = self
            .config_management
            .lock()
            .expect("configuration management lock poisoned")
            .as_ref()
        {
            manager.finish_unmanaged_reload();
        }
    }

    fn managed_configuration_reload_pending(&self) -> bool {
        if !self.try_begin_unmanaged_configuration_reload() {
            return true;
        }
        self.finish_unmanaged_configuration_reload();
        false
    }

    fn has_pending_configuration_reload(&self) -> bool {
        self.reload
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .iter()
            .any(|record| {
                record["kind"] == ManagementReloadKind::Configuration.as_str()
                    && record["status"] == "pending"
            })
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
            NativeAccountAction::DeviceLogin { .. } => "oauth_device",
        };
        self.record_audit_with_fields(
            action,
            Some(account),
            outcome,
            &[("generation", json!(generation))],
        );
    }

    pub(crate) fn record_oauth_device_prompt(
        &self,
        request_id: u64,
        verification_uri: &str,
        verification_uri_complete: Option<&str>,
        user_code: &str,
        expires_in_seconds: u64,
    ) {
        let mut records = self
            .oauth_device
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = records
            .iter_mut()
            .find(|record| record["request_id"].as_u64() == Some(request_id))
        {
            record["status"] = json!("authorization_required");
            record["verification_uri"] = json!(verification_uri);
            record["verification_uri_complete"] =
                verification_uri_complete.map_or(Value::Null, |value| json!(value));
            record["user_code"] = json!(user_code);
            record["expires_in_seconds"] = json!(expires_in_seconds);
        }
    }

    pub(crate) fn record_oauth_device_result(&self, request_id: u64, outcome: &str) {
        let mut records = self
            .oauth_device
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = records
            .iter_mut()
            .find(|record| record["request_id"].as_u64() == Some(request_id))
        {
            record["status"] = json!(outcome);
            record["completed_at_ms"] = json!(unix_timestamp_ms());
            if outcome == "succeeded" {
                record
                    .as_object_mut()
                    .expect("device record object")
                    .remove("user_code");
                record
                    .as_object_mut()
                    .expect("device record object")
                    .remove("verification_uri_complete");
            }
        }
    }

    fn oauth_device_status(&self, path: &str) -> ManagementResponse {
        let Some(request_id) = path
            .strip_prefix("/oauth/device/")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "OAuth device request not found"}),
                false,
            );
        };
        let records = self
            .oauth_device
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        records
            .iter()
            .find(|record| record["request_id"].as_u64() == Some(request_id))
            .cloned()
            .map_or_else(
                || {
                    ManagementResponse::json(
                        StatusCode::NOT_FOUND,
                        json!({"error": "OAuth device request not found"}),
                        false,
                    )
                },
                |record| ManagementResponse::json(StatusCode::OK, record, false),
            )
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
        let restoration_failed = self
            .config_management
            .lock()
            .expect("configuration management lock poisoned")
            .as_ref()
            .is_some_and(|manager| {
                manager
                    .complete_commit(request_id, matches!(outcome, "succeeded" | "unchanged"))
                    .is_err()
            });
        let outcome = if restoration_failed {
            "restoration_failed"
        } else {
            outcome
        };
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

    fn new_reload_request(
        &self,
        kind: ManagementReloadKind,
        configuration_generation: u64,
        source: Option<PathBuf>,
    ) -> ManagementReloadRequest {
        ManagementReloadRequest {
            id: self
                .reload
                .next_id
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
            kind,
            generation: configuration_generation,
            source,
        }
    }

    fn enqueue_reload_request(&self, request: ManagementReloadRequest) -> bool {
        let kind = request.kind;
        let configuration_generation = request.generation;
        {
            let mut state = self
                .reload
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.pending.len() >= MAX_PENDING_MANAGEMENT_RELOADS {
                return false;
            }
            state.pending.push_back(request.clone());
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
        true
    }

    fn enqueue_reload(
        &self,
        kind: ManagementReloadKind,
        configuration_generation: u64,
        source: Option<PathBuf>,
    ) -> Option<ManagementReloadRequest> {
        let request = self.new_reload_request(kind, configuration_generation, source);
        self.enqueue_reload_request(request.clone())
            .then_some(request)
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
        if matches!(action, "refresh" | "revoke" | "oauth-device") {
            if account_plan.auth_kind() != pooler_config::AccountAuthKind::OAuth {
                self.record_audit(action, Some(&account), "unsupported_auth_kind");
                return ManagementResponse::json(
                    StatusCode::CONFLICT,
                    json!({"error": "account does not use OAuth credentials"}),
                    false,
                );
            }
            if action == "oauth-device" {
                let supports_device_login = snapshot
                    .config()
                    .upstreams()
                    .get(account_plan.provider())
                    .is_some_and(|upstream| {
                        upstream
                            .native()
                            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
                    });
                if !supports_device_login {
                    self.record_audit(action, Some(&account), "unsupported_provider");
                    return ManagementResponse::json(
                        StatusCode::CONFLICT,
                        json!({"error": "account provider has no documented brokered device flow"}),
                        false,
                    );
                }
            }
            let Some(commands) = self.native_commands.as_ref() else {
                self.record_audit(action, Some(&account), "unavailable");
                return state_unavailable();
            };
            let request_id = if action == "oauth-device" {
                let mut records = self
                    .oauth_device
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if records.iter().any(|record| {
                    matches!(
                        record["status"].as_str(),
                        Some("starting" | "authorization_required")
                    )
                }) {
                    self.record_audit(action, Some(&account), "already_active");
                    return ManagementResponse::json(
                        StatusCode::CONFLICT,
                        json!({"error": "a brokered OAuth device authorization is already active"}),
                        false,
                    );
                }
                let request_id = self
                    .oauth_device
                    .next_id
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                records.push_back(json!({
                    "schema_version": 1,
                    "request_id": request_id,
                    "account": account,
                    "generation": snapshot.generation().value(),
                    "status": "starting",
                    "created_at_ms": unix_timestamp_ms(),
                }));
                while records.len() > MAX_OAUTH_DEVICE_RECORDS {
                    records.pop_front();
                }
                Some(request_id)
            } else {
                None
            };
            let command = NativeAccountCommand {
                account: account.clone(),
                action: match action {
                    "refresh" => NativeAccountAction::Refresh,
                    "revoke" => NativeAccountAction::Revoke,
                    "oauth-device" => NativeAccountAction::DeviceLogin {
                        request_id: request_id.expect("device request ID"),
                    },
                    _ => unreachable!("validated native account action"),
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
                            "request_id": request_id,
                            "status": "queued"
                        }),
                        false,
                    )
                }
                Err(_) => {
                    if let Some(request_id) = request_id {
                        self.record_oauth_device_result(request_id, "failed");
                    }
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

    fn config_manager(&self) -> Option<Arc<ConfigManagement>> {
        self.config_management
            .lock()
            .expect("configuration management lock poisoned")
            .clone()
    }

    fn config_error(error: ConfigManagementError) -> ManagementResponse {
        let (status, message) = match error {
            ConfigManagementError::NotFound => {
                (StatusCode::NOT_FOUND, "configuration draft was not found")
            }
            ConfigManagementError::Expired => (StatusCode::GONE, "configuration draft has expired"),
            ConfigManagementError::Precondition => (
                StatusCode::PRECONDITION_FAILED,
                "configuration precondition failed",
            ),
            ConfigManagementError::UnsupportedPatch => (
                StatusCode::BAD_REQUEST,
                "configuration patch is not supported",
            ),
            ConfigManagementError::PatchLimit => (
                StatusCode::TOO_MANY_REQUESTS,
                "configuration patch limit reached",
            ),
            ConfigManagementError::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "configuration document is too large",
            ),
            ConfigManagementError::Invalid(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "configuration candidate is invalid",
            ),
            ConfigManagementError::Confirmation => (
                StatusCode::CONFLICT,
                "configuration confirmation is invalid",
            ),
            ConfigManagementError::Persistence => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration persistence failed",
            ),
            ConfigManagementError::RecoveryRequired => (
                StatusCode::SERVICE_UNAVAILABLE,
                "configuration persistence requires operator recovery",
            ),
        };
        ManagementResponse::json(status, json!({"error": message}), false)
    }

    fn queue_config_commit(
        &self,
        manager: &Arc<ConfigManagement>,
        commit: PreparedCommit,
        action: &str,
    ) -> ManagementResponse {
        let generation = commit.base_generation;
        let source = commit.managed_path.clone();
        let request = self.new_reload_request(
            ManagementReloadKind::Configuration,
            generation,
            Some(source),
        );
        manager.register_commit(request.id, commit);
        if !self.enqueue_reload_request(request.clone()) {
            let outcome = if manager.complete_commit(request.id, false).is_ok() {
                "queue_unavailable"
            } else {
                "restoration_failed"
            };
            self.record_audit(action, None, outcome);
            return state_unavailable();
        }
        self.record_audit_with_fields(
            action,
            None,
            "accepted",
            &[
                ("request_id", json!(request.id)),
                ("base_generation", json!(generation)),
            ],
        );
        ManagementResponse::json(
            StatusCode::ACCEPTED,
            json!({
                "request_id": request.id,
                "base_generation": generation,
                "status": "pending"
            }),
            false,
        )
    }

    fn handle_config_request(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
        active: &CompiledConfig,
        active_generation: u64,
    ) -> ManagementResponse {
        let Some(manager) = self.config_manager() else {
            return ManagementResponse::json(
                StatusCode::CONFLICT,
                json!({"error": "managed configuration is not enabled"}),
                false,
            );
        };
        let if_match = || {
            headers
                .get(header::IF_MATCH)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    ManagementResponse::json(
                        StatusCode::PRECONDITION_REQUIRED,
                        json!({"error": "If-Match is required"}),
                        false,
                    )
                })
        };
        let result = match (method, path, config_draft_action(path)) {
            (&Method::POST, "/config/drafts", _) if body.is_empty() => {
                manager.create(active_generation)
            }
            (&Method::POST, "/config/accounts/draft", _) => {
                create_account_draft(&manager, active, active_generation, body)
            }
            (&Method::GET, _, Some((id, None))) if body.is_empty() => manager.view(id),
            (&Method::GET, _, Some((id, Some("diff")))) if body.is_empty() => manager.diff(id),
            (&Method::PATCH, _, Some((id, None))) => {
                let etag = match if_match() {
                    Ok(etag) => etag,
                    Err(response) => return response,
                };
                let patch = match serde_json::from_slice::<TypedConfigPatch>(body) {
                    Ok(patch) => patch,
                    Err(_) => {
                        return ManagementResponse::json(
                            StatusCode::BAD_REQUEST,
                            json!({"error": "typed configuration patch is invalid"}),
                            false,
                        );
                    }
                };
                manager.apply(id, etag, patch)
            }
            (&Method::POST, _, Some((id, Some("validate")))) if body.is_empty() => {
                let etag = match if_match() {
                    Ok(etag) => etag,
                    Err(response) => return response,
                };
                manager.validate(id, etag)
            }
            (&Method::POST, _, Some((id, Some("commit")))) => {
                let etag = match if_match() {
                    Ok(etag) => etag,
                    Err(response) => return response,
                };
                let token = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("confirmation_token")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    });
                let Some(token) = token else {
                    return ManagementResponse::json(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "confirmation_token is required"}),
                        false,
                    );
                };
                let _serial = self
                    .configuration_reload_serial
                    .lock()
                    .expect("configuration reload serialization lock poisoned");
                if self.has_pending_configuration_reload() {
                    return Self::config_error(ConfigManagementError::Precondition);
                }
                return match manager.commit(id, etag, active_generation, &token) {
                    Ok(commit) => self.queue_config_commit(&manager, commit, "config_commit"),
                    Err(error) => Self::config_error(error),
                };
            }
            (&Method::POST, "/config/rollback", _) => {
                let expected = format!("generation-{active_generation}");
                let matched = if_match().is_ok_and(|value| value.trim_matches('"') == expected);
                let confirmed = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("confirm")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .is_some_and(|value| value == "rollback");
                if !matched || !confirmed {
                    return ManagementResponse::json(
                        StatusCode::PRECONDITION_FAILED,
                        json!({"error": "rollback generation and confirmation are required"}),
                        false,
                    );
                }
                let _serial = self
                    .configuration_reload_serial
                    .lock()
                    .expect("configuration reload serialization lock poisoned");
                if self.has_pending_configuration_reload() {
                    return Self::config_error(ConfigManagementError::Precondition);
                }
                return match manager.rollback(active_generation) {
                    Ok(commit) => self.queue_config_commit(&manager, commit, "config_rollback"),
                    Err(error) => Self::config_error(error),
                };
            }
            _ => {
                return ManagementResponse::json(
                    StatusCode::METHOD_NOT_ALLOWED,
                    json!({"error": "configuration operation is not supported"}),
                    false,
                );
            }
        };
        match result {
            Ok(value) => {
                let status = if *method == Method::POST
                    && matches!(path, "/config/drafts" | "/config/accounts/draft")
                {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                };
                self.record_audit(path, None, "succeeded");
                let etag = value.get("etag").and_then(Value::as_str).map(str::to_owned);
                let mut response = ManagementResponse::json(status, value, false);
                if let Some(etag) =
                    etag.and_then(|etag| header::HeaderValue::from_str(&format!("\"{etag}\"")).ok())
                {
                    response.headers.insert(header::ETAG, etag);
                }
                response
            }
            Err(error) => {
                self.record_audit(path, None, "failed");
                Self::config_error(error)
            }
        }
    }

    /// Handle one body-free management request.
    #[must_use]
    pub fn handle(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
    ) -> ManagementResponse {
        self.handle_with_body(method, path_and_query, headers, &[])
    }

    fn handle_with_body(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
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
                header::HeaderValue::from_static("GET, HEAD, POST, PATCH"),
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
        if mutation && !is_config_mutation(method, path) {
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
            "/health" | "/healthz" | "/ready" | "/readiness" | "/" => {
                self.health(snapshot, pooling)
            }
            path if is_config_request(path) => self.handle_config_request(
                method,
                path,
                headers,
                body,
                snapshot.config(),
                snapshot.generation().value(),
            ),
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
            path if path.starts_with("/oauth/device/") => self.oauth_device_status(path),
            "/quota" => self.quota(snapshot, pooling),
            "/metrics" => self.metrics_view(snapshot),
            "/metrics/prometheus" => ManagementResponse::body(
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                format_persistence_prometheus(
                    self.metrics.export_prometheus(),
                    &pooling.persistence_status().json(),
                )
                .into_bytes(),
                head,
            ),
            "/active" | "/active-counts" => self.active(),
            "/decisions" | "/decisions/recent" => {
                let limit = uri.as_ref().and_then(|uri| uri.query()).map(parse_limit);
                self.decisions(limit, snapshot.generation().value(), pooling)
            }
            "/requests" => self.requests(uri.as_ref().and_then(Uri::query), pooling, false),
            "/requests/export" => self.requests(uri.as_ref().and_then(Uri::query), pooling, true),
            path if path.starts_with("/requests/") => self.request_detail(path, pooling),
            "/usage" => self.usage(
                uri.as_ref().and_then(Uri::query),
                pooling,
                UsageRepresentation::List,
            ),
            "/usage/aggregate" => self.usage(
                uri.as_ref().and_then(Uri::query),
                pooling,
                UsageRepresentation::Aggregate,
            ),
            "/usage/export" => self.usage(
                uri.as_ref().and_then(Uri::query),
                pooling,
                UsageRepresentation::Export,
            ),
            "/usage/prometheus" => self.usage(
                uri.as_ref().and_then(Uri::query),
                pooling,
                UsageRepresentation::Prometheus,
            ),
            "/usage/otlp" => self.usage(
                uri.as_ref().and_then(Uri::query),
                pooling,
                UsageRepresentation::OtlpJson,
            ),
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
                let request = if kind == ManagementReloadKind::Configuration {
                    let _serial = self
                        .configuration_reload_serial
                        .lock()
                        .expect("configuration reload serialization lock poisoned");
                    if self.managed_configuration_reload_pending() {
                        return ManagementResponse::json(
                            StatusCode::CONFLICT,
                            json!({"error": "a managed configuration reload is pending"}),
                            false,
                        );
                    }
                    self.enqueue_reload(kind, snapshot.generation().value(), None)
                } else {
                    self.enqueue_reload(kind, snapshot.generation().value(), None)
                };
                match request {
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

    fn config_mutation_authorization_rejection(
        &self,
        path: &str,
        headers: &HeaderMap,
    ) -> Option<ManagementResponse> {
        if !management_origin_allowed(headers) {
            self.record_audit(path, None, "rejected_origin");
            return Some(ManagementResponse::json(
                StatusCode::FORBIDDEN,
                json!({"error": "management mutation Origin does not match Host"}),
                false,
            ));
        }
        if self.plan.auth().is_none() {
            self.record_audit(path, None, "authentication_not_configured");
            return Some(ManagementResponse::json(
                StatusCode::FORBIDDEN,
                json!({"error": "management mutations require configured bearer authentication"}),
                false,
            ));
        }
        if !self.authorized(headers) {
            self.record_audit(path, None, "unauthorized");
            let mut response = ManagementResponse::json(
                StatusCode::UNAUTHORIZED,
                json!({"error": "management authentication required"}),
                false,
            );
            response.headers.insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
            return Some(response);
        }
        None
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
        let persistence = pooling.persistence_status().json();
        let ready = persistence["complete"].as_bool().unwrap_or(false);
        ManagementResponse::json(
            if ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            json!({
                "status": if ready { "ok" } else { "degraded" },
                "ready": ready,
                "configuration_generation": snapshot.generation().value(),
                "management": {"mutations": self.plan.auth().is_some()},
                "active": self.active.total(),
                "credential_health_entries": credentials,
                "cooling_provider_entries": cooling_providers,
                "persistence": persistence,
            }),
            false,
        )
    }

    fn config_generation(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        let generation = snapshot.generation().value();
        let etag = format!("generation-{generation}");
        let mut response = ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": generation,
                "etag": etag,
                "management": {
                    "mutations": self.plan.auth().is_some(),
                    "typed_drafts": self.config_management
                        .lock()
                        .expect("configuration management lock poisoned")
                        .is_some(),
                },
            }),
            false,
        );
        response.headers.insert(
            header::ETAG,
            header::HeaderValue::from_str(&format!("\"generation-{generation}\""))
                .expect("generation ETag is a valid header"),
        );
        response
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
                            let method = capability.method().to_string();
                            let registration_required =
                                id == "google" && method == "authorization_code_pkce";
                            json!({
                                "method": method,
                                "support": if registration_required {
                                    "requires_explicit_configuration"
                                } else {
                                    setup_support_name(capability.support())
                                },
                                "note": if registration_required {
                                    "Google browser OAuth requires operator-owned upstream registration details that this wizard cannot collect."
                                } else {
                                    capability.note()
                                },
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
        let Some(reload_request_id) = management_query_value(query, "reload_request_id")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return ManagementResponse::json(
                StatusCode::BAD_REQUEST,
                json!({"error": "setup verification requires a correlated catalog reload request"}),
                false,
            );
        };
        let (reload_record, latest_catalog_reload_id) = {
            let reload = self
                .reload
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = reload
                .records
                .iter()
                .find(|record| record["request_id"].as_u64() == Some(reload_request_id))
                .cloned();
            let latest = reload
                .records
                .iter()
                .rev()
                .find(|record| record["kind"].as_str() == Some("catalog"))
                .and_then(|record| record["request_id"].as_u64());
            (record, latest)
        };
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
        let catalog_generation = catalog_view["catalog_generation"].as_u64().unwrap_or(0);
        let reload_requested_at = reload_record
            .as_ref()
            .and_then(|record| record["requested_at_ms"].as_u64())
            .unwrap_or(u64::MAX);
        let reload_verified = reload_record.as_ref().is_some_and(|record| {
            latest_catalog_reload_id == Some(reload_request_id)
                && record["kind"].as_str() == Some("catalog")
                && record["status"].as_str() == Some("succeeded")
                && record["accepted_configuration_generation"].as_u64()
                    == Some(snapshot.generation().value())
                && record["configuration_generation"].as_u64()
                    == Some(snapshot.generation().value())
                && record["catalog_generation"].as_u64() == Some(catalog_generation)
        });
        let discovery_verified = reload_verified
            && catalog_view["catalog_sources"]
                .as_array()
                .is_some_and(|sources| {
                    sources.iter().any(|source| {
                        setup_discovery_is_fresh(
                            source,
                            &upstream_ids,
                            &account_id,
                            reload_requested_at,
                        )
                    })
                });
        let persistence = pooling.persistence_status().json();
        let persistence_complete = persistence["complete"].as_bool().unwrap_or(false);
        let all_ready = provider_configured
            && account_configured
            && account_available
            && model_available
            && discovery_verified
            && persistence_complete;
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "schema_version": 1,
                "configuration_generation": snapshot.generation().value(),
                "ready": all_ready,
                "connection": if discovery_verified {"verified"} else {"not_probed"},
                "persistence": persistence,
                "checks": [
                    {"id": "generated_configuration", "status": "passed", "detail": "Generated YAML passed Pooler's compiler."},
                    {"id": "provider", "status": if provider_configured {"passed"} else {"pending"}, "detail": if provider_configured {"Provider is present in the active generation."} else {"Apply the generated configuration and reload Pooler."}},
                    {"id": "account", "status": if account_configured && account_available {"passed"} else {"pending"}, "detail": if account_configured && account_available {"The selected account is enabled in the active generation."} else {"Configure the account and complete its credential flow."}},
                    {"id": "model", "status": if model_available {"passed"} else {"pending"}, "detail": if model_available {"The selected model is published for this provider."} else {"Reload model discovery or apply the generated static model mapping."}},
                    {"id": "catalog_reload", "status": if reload_verified {"passed"} else {"failed"}, "detail": if reload_verified {"The correlated catalog reload succeeded for the active configuration and catalog generations."} else {"The correlated catalog reload did not succeed for the active configuration and catalog generations."}},
                    {"id": "connectivity", "status": if discovery_verified {"passed"} else {"not_run"}, "detail": if discovery_verified {"A matching model-discovery observation was recorded after the correlated reload request."} else {"No fresh matching discovery observation followed the correlated reload request; retained last-good state is not accepted. This check does not send a billable inference request."}},
                    {"id": "persistence", "status": if persistence_complete {"passed"} else {"failed"}, "detail": if persistence_complete {"Historical request and usage writes are complete."} else {"Historical request or usage persistence is incomplete; readiness is withheld until the lost-write condition is investigated."}},
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
                        "transport_upstream": route.target().transport_upstream(),
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
                        if snapshot
                            .config()
                            .upstreams()
                            .get(account.provider())
                            .and_then(|upstream| upstream.native())
                            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
                        {
                            available_actions.push("oauth_device");
                        }
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

    fn requests(
        &self,
        query: Option<&str>,
        pooling: &PoolingCoordinator,
        export: bool,
    ) -> ManagementResponse {
        let query = parse_request_query(query);
        let events = match pooling.request_events() {
            Ok(events) => events,
            Err(_) => return state_unavailable(),
        };
        let mut summaries = summarize_request_events(&events);
        summaries.retain(|summary| request_summary_matches(summary, &query));
        if let Some(cursor) = query.cursor {
            summaries.retain(|summary| {
                summary["last_event_id"]
                    .as_u64()
                    .is_some_and(|id| id < cursor)
            });
        }
        let limit = if export {
            query
                .limit
                .unwrap_or(MAX_REQUEST_EXPORT)
                .min(MAX_REQUEST_EXPORT)
        } else {
            query
                .limit
                .unwrap_or(DEFAULT_REQUEST_LIMIT)
                .min(MAX_REQUEST_LIMIT)
        };
        let has_more = summaries.len() > limit;
        summaries.truncate(limit);
        let next_cursor = has_more
            .then(|| summaries.last())
            .flatten()
            .and_then(|summary| summary["last_event_id"].as_u64());
        let value = json!({
            "schema_version": 1,
            "requests": summaries,
            "limit": limit,
            "next_cursor": next_cursor,
            "persistence": pooling.persistence_status().json(),
            "retention": {
                "max_events": pooling.store().retention().max_request_events,
                "max_events_per_request": pooler_store::MAX_REQUEST_EVENTS_PER_REQUEST,
                "ttl_ms": pooling.store().retention().request_history_ttl_ms,
            },
        });
        ManagementResponse::json(
            StatusCode::OK,
            pooler_observe::RedactionPolicy::strict().sanitize_json(&value),
            false,
        )
    }

    fn usage(
        &self,
        query: Option<&str>,
        pooling: &PoolingCoordinator,
        representation: UsageRepresentation,
    ) -> ManagementResponse {
        let records = match pooling.usage_records() {
            Ok(records) => records,
            Err(_) => return state_unavailable(),
        };
        let policy = pooler_observe::RedactionPolicy::strict();
        let persistence = pooling.persistence_status().json();
        match representation {
            UsageRepresentation::List => {
                let value = with_persistence(
                    usage_list(records, query, pooling.store().retention(), false),
                    persistence,
                );
                ManagementResponse::json(StatusCode::OK, policy.sanitize_json(&value), false)
            }
            UsageRepresentation::Export => {
                let value = with_persistence(
                    usage_list(records, query, pooling.store().retention(), true),
                    persistence,
                );
                ManagementResponse::json(StatusCode::OK, policy.sanitize_json(&value), false)
            }
            UsageRepresentation::Aggregate => {
                let value = with_persistence(usage_aggregate(records, query), persistence);
                ManagementResponse::json(StatusCode::OK, policy.sanitize_json(&value), false)
            }
            UsageRepresentation::Prometheus => ManagementResponse::body(
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                policy
                    .sanitize_text(&format_persistence_prometheus(
                        usage_prometheus(records, query),
                        &persistence,
                    ))
                    .into_bytes(),
                false,
            ),
            UsageRepresentation::OtlpJson => ManagementResponse::json(
                StatusCode::OK,
                policy.sanitize_json(&usage_otlp_json(records, query)),
                false,
            ),
        }
    }

    fn request_detail(&self, path: &str, pooling: &PoolingCoordinator) -> ManagementResponse {
        let suffix = path.strip_prefix("/requests/").unwrap_or_default();
        let (request_id, timeline) = suffix
            .strip_suffix("/timeline")
            .map_or((suffix, false), |request_id| (request_id, true));
        if request_id.is_empty()
            || request_id.len() > 128
            || !request_id
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
        {
            return ManagementResponse::json(
                StatusCode::BAD_REQUEST,
                json!({"error": "request identifier is invalid"}),
                false,
            );
        }
        let events = match pooling.request_events_for(request_id) {
            Ok(events) => events,
            Err(_) => return state_unavailable(),
        };
        let persistence = pooling.persistence_status().json();
        if events.is_empty() {
            if !persistence["request_events"]["complete"]
                .as_bool()
                .unwrap_or(false)
            {
                return ManagementResponse::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({
                        "error": "request history is incomplete",
                        "persistence": persistence,
                    }),
                    false,
                );
            }
            return ManagementResponse::json(
                StatusCode::NOT_FOUND,
                json!({"error": "request history was not found"}),
                false,
            );
        }
        let value = if timeline {
            json!({
                "schema_version": 1,
                "request_id": request_id,
                "timeline": events,
                "persistence": persistence,
            })
        } else {
            let summary = summarize_request_events(&events)
                .into_iter()
                .next()
                .expect("non-empty request events produce a summary");
            json!({
                "schema_version": 1,
                "request": summary,
                "persistence": persistence,
            })
        };
        ManagementResponse::json(
            StatusCode::OK,
            pooler_observe::RedactionPolicy::strict().sanitize_json(&value),
            false,
        )
    }
}

fn with_persistence(mut value: Value, persistence: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("persistence".to_owned(), persistence);
    }
    value
}

fn format_persistence_prometheus(mut output: String, persistence: &Value) -> String {
    let enabled = persistence["enabled"].as_bool().unwrap_or(false);
    let complete = persistence["complete"].as_bool().unwrap_or(false);
    output.push_str(
        "# HELP pooler_persistence_enabled Whether historical persistence is enabled.\n# TYPE pooler_persistence_enabled gauge\npooler_persistence_enabled ",
    );
    output.push_str(if enabled { "1\n" } else { "0\n" });
    output.push_str(
        "# HELP pooler_persistence_complete Whether no historical writes have been lost.\n# TYPE pooler_persistence_complete gauge\npooler_persistence_complete ",
    );
    output.push_str(if complete { "1\n" } else { "0\n" });
    output.push_str(
        "# HELP pooler_persistence_complete_stream Whether a historical stream has no lost writes.\n# TYPE pooler_persistence_complete_stream gauge\n",
    );
    output.push_str(
        "# HELP pooler_persistence_lost_writes Historical records that could not be persisted.\n# TYPE pooler_persistence_lost_writes gauge\n",
    );
    output.push_str(
        "# HELP pooler_persistence_successful_writes Historical records persisted successfully.\n# TYPE pooler_persistence_successful_writes gauge\n",
    );
    for stream in ["request_events", "usage_records"] {
        let value = &persistence[stream];
        output.push_str(&format!(
            "pooler_persistence_complete_stream{{stream=\"{stream}\"}} {}\n",
            value["complete"].as_bool().unwrap_or(false) as u8
        ));
        output.push_str(&format!(
            "pooler_persistence_lost_writes{{stream=\"{stream}\"}} {}\n",
            value["lost_writes"].as_u64().unwrap_or_default()
        ));
        output.push_str(&format!(
            "pooler_persistence_successful_writes{{stream=\"{stream}\"}} {}\n",
            value["successful_writes"].as_u64().unwrap_or_default()
        ));
    }
    output
}

#[derive(Default)]
struct RequestQuery {
    cursor: Option<u64>,
    limit: Option<usize>,
    route: Option<String>,
    listener: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    status: Option<String>,
    since: Option<u64>,
    until: Option<u64>,
}

fn parse_request_query(query: Option<&str>) -> RequestQuery {
    let mut parsed = RequestQuery::default();
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "cursor" => parsed.cursor = value.parse().ok(),
            "limit" => parsed.limit = value.parse().ok(),
            "route" if value.len() <= 128 => parsed.route = Some(value),
            "listener" if value.len() <= 128 => parsed.listener = Some(value),
            "provider" if value.len() <= 128 => parsed.provider = Some(value),
            "model" if value.len() <= 256 => parsed.model = Some(value),
            "status" if value.len() <= 64 => parsed.status = Some(value),
            "since" => parsed.since = value.parse().ok(),
            "until" => parsed.until = value.parse().ok(),
            _ => {}
        }
    }
    parsed
}

fn summarize_request_events(events: &[pooler_store::RequestEvent]) -> Vec<Value> {
    let mut grouped = BTreeMap::<String, Vec<&pooler_store::RequestEvent>>::new();
    for event in events {
        grouped
            .entry(event.request_id.clone())
            .or_default()
            .push(event);
    }
    let mut summaries = grouped
        .into_values()
        .filter_map(|mut events| {
            events.sort_by_key(|event| (event.event_index, event.id));
            let first = *events.first()?;
            let last = *events.last()?;
            let latest_string = |select: fn(&pooler_store::RequestEvent) -> Option<&String>| {
                events.iter().rev().find_map(|event| select(event).cloned())
            };
            let attempts = events.iter().filter_map(|event| event.attempt).max();
            let status = events.iter().rev().find_map(|event| event.status);
            let ttft_ms = events.iter().rev().find_map(|event| event.ttft_ms);
            let latency_ms = events.iter().rev().find_map(|event| event.latency_ms);
            let committed = events
                .iter()
                .any(|event| event.kind == pooler_store::RequestEventKind::Commitment);
            let mut semantic_losses = events
                .iter()
                .flat_map(|event| event.semantic_losses.iter().cloned())
                .collect::<Vec<_>>();
            semantic_losses.sort();
            semantic_losses.dedup();
            Some(json!({
                "request_id": first.request_id,
                "first_event_id": first.id,
                "last_event_id": last.id,
                "started_at": first.recorded_at,
                "updated_at": last.recorded_at,
                "listener": first.listener,
                "route": first.route_id,
                "public_model": latest_string(|event| event.public_model.as_ref()),
                "upstream_model": latest_string(|event| event.upstream_model.as_ref()),
                "provider": latest_string(|event| event.provider.as_ref()),
                "account_pseudonym": latest_string(|event| event.account_pseudonym.as_ref()),
                "attempts": attempts,
                "committed": committed,
                "ttft_ms": ttft_ms,
                "latency_ms": latency_ms,
                "status": status,
                "error_class": latest_string(|event| event.error_class.as_ref()),
                "quota_effect": latest_string(|event| event.quota_effect.as_ref()),
                "cooldown_effect": latest_string(|event| event.cooldown_effect.as_ref()),
                "semantic_losses": semantic_losses,
                "configuration_generation": last.configuration_generation,
                "catalog_generation": last.catalog_generation,
                "body_hashes_present": events.iter().any(|event| {
                    event.request_body_sha256.is_some() || event.response_body_sha256.is_some()
                }),
            }))
        })
        .collect::<Vec<_>>();
    summaries.sort_by_key(|summary| std::cmp::Reverse(summary["last_event_id"].as_u64()));
    summaries
}

fn request_summary_matches(summary: &Value, query: &RequestQuery) -> bool {
    let matches_string = |field: &str, expected: &Option<String>| {
        expected.as_ref().is_none_or(|expected| {
            summary[field]
                .as_str()
                .is_some_and(|actual| actual == expected)
        })
    };
    matches_string("route", &query.route)
        && matches_string("listener", &query.listener)
        && matches_string("provider", &query.provider)
        && query.model.as_ref().is_none_or(|expected| {
            summary["public_model"].as_str() == Some(expected)
                || summary["upstream_model"].as_str() == Some(expected)
        })
        && query.status.as_ref().is_none_or(|expected| {
            summary["status"]
                .as_u64()
                .is_some_and(|status| status.to_string() == *expected)
                || summary["error_class"].as_str() == Some(expected)
        })
        && query.since.is_none_or(|since| {
            summary["updated_at"]
                .as_u64()
                .is_some_and(|updated| updated >= since)
        })
        && query.until.is_none_or(|until| {
            summary["started_at"]
                .as_u64()
                .is_some_and(|started| started <= until)
        })
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

fn raw_config_mutation_headers(prefix: &[u8]) -> Result<Option<(String, HeaderMap)>, ()> {
    let header_end = prefix
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(())?;
    let headers = std::str::from_utf8(&prefix[..header_end]).map_err(|_| ())?;
    let mut lines = headers.split("\r\n");
    let mut request = lines.next().ok_or(())?.split_whitespace();
    let method = match request.next().ok_or(())? {
        "POST" => Method::POST,
        "PATCH" => Method::PATCH,
        _ => return Ok(None),
    };
    let request_target = request.next().ok_or(())?;
    let management_path = raw_management_path(request_target).ok_or(())?;
    if !is_config_mutation(&method, &management_path) {
        return Ok(None);
    }

    let mut parsed = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        let name = header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        let value = header::HeaderValue::from_str(value.trim()).map_err(|_| ())?;
        parsed.append(name, value);
    }
    Ok(Some((management_path, parsed)))
}

fn raw_is_body_free_management_mutation(prefix: &[u8]) -> bool {
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
    let method = match request.next() {
        Some("POST") => Method::POST,
        Some("PATCH") => Method::PATCH,
        _ => return false,
    };
    let Some(request_target) = request.next() else {
        return false;
    };
    let Some(management_path) = raw_management_path(request_target) else {
        return false;
    };
    is_management_mutation(&method, &management_path)
        && !is_config_mutation(&method, &management_path)
}

fn raw_mutation_body_rejection(prefix: &[u8]) -> Option<(StatusCode, &'static str)> {
    let header_end = prefix.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&prefix[..header_end]).ok()?;
    let mut lines = headers.split("\r\n");
    let mut request = lines.next()?.split_whitespace();
    let method = match request.next()? {
        "POST" => Method::POST,
        "PATCH" => Method::PATCH,
        _ => return None,
    };
    let request_target = request.next()?;
    let management_path = raw_management_path(request_target)?;
    if !is_management_mutation(&method, &management_path)
        || is_config_mutation(&method, &management_path)
    {
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
    let header_end = prefix
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header reader returned a complete prefix")
        + 4;
    let overflow = prefix.split_off(header_end);
    let mut boundary_response = match raw_config_mutation_headers(&prefix) {
        Ok(Some((path, headers))) => {
            if !management_request_host_allowed(&api, false, &headers) {
                api.record_audit(&path, None, "rejected_host");
                Some(ManagementResponse::json(
                    StatusCode::FORBIDDEN,
                    json!({"error": LOOPBACK_HOST_ERROR}),
                    false,
                ))
            } else {
                api.config_mutation_authorization_rejection(&path, &headers)
            }
        }
        Ok(None) => None,
        Err(()) => Some(ManagementResponse::json(
            StatusCode::BAD_REQUEST,
            json!({"error": "management request headers are invalid"}),
            false,
        )),
    };

    if boundary_response.is_none() {
        prefix.extend_from_slice(&overflow);
        if raw_mutation_body_rejection(&prefix).is_none()
            && raw_is_body_free_management_mutation(&prefix)
        {
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
            boundary_response = Some(ManagementResponse::json(
                status,
                json!({"error": message}),
                false,
            ));
        }
    }

    if let Some(response) = boundary_response {
        let response = management_http_response(response);
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
            } else if is_config_mutation(request.method(), management_path) {
                if let Some(response) =
                    api.config_mutation_authorization_rejection(management_path, request.headers())
                {
                    response
                } else if request.headers().contains_key(header::TRANSFER_ENCODING) {
                    ManagementResponse::json(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "typed configuration mutations require Content-Length"}),
                        false,
                    )
                } else if request
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok())
                    .is_some_and(|length| length > MAX_CONFIG_MUTATION_BODY_BYTES)
                {
                    ManagementResponse::json(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        json!({"error": "typed configuration mutation is too large"}),
                        false,
                    )
                } else {
                    let (parts, incoming) = request.into_parts();
                    match tokio::time::timeout(
                        MANAGEMENT_CONFIG_BODY_TIMEOUT,
                        Limited::new(incoming, MAX_CONFIG_MUTATION_BODY_BYTES).collect(),
                    )
                    .await
                    {
                        Ok(Ok(collected)) => api.handle_with_body(
                            &parts.method,
                            parts.uri.to_string().as_str(),
                            &parts.headers,
                            &collected.to_bytes(),
                        ),
                        Ok(Err(_)) => ManagementResponse::json(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            json!({"error": "typed configuration mutation is too large"}),
                            false,
                        ),
                        Err(_) => {
                            api.record_audit(parts.uri.path(), None, "body_timeout");
                            ManagementResponse::json(
                                StatusCode::REQUEST_TIMEOUT,
                                json!({"error": "typed configuration mutation body timed out"}),
                                false,
                            )
                        }
                    }
                }
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
        PruneReport, RequestEvent, RetentionPolicy, SessionAffinity, Store, StoreError,
        StoreResult, Timestamp, UsageRecord,
    };
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn private_configuration_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary configuration directory");
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private configuration directory");
        directory
    }

    fn make_configuration_private(path: &Path) {
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private configuration source");
    }

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

        fn append_request_event(&self, event: RequestEvent) -> StoreResult<RequestEvent> {
            self.inner.append_request_event(event)
        }

        fn request_events(&self) -> StoreResult<Vec<RequestEvent>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.request_events()
            }
        }

        fn request_events_for(&self, request_id: &str) -> StoreResult<Vec<RequestEvent>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.request_events_for(request_id)
            }
        }

        fn append_usage_record(&self, record: UsageRecord) -> StoreResult<UsageRecord> {
            self.inner.append_usage_record(record)
        }

        fn usage_records(&self) -> StoreResult<Vec<UsageRecord>> {
            if self.should_fail() {
                self.unavailable()
            } else {
                self.inner.usage_records()
            }
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
        assert!(html_body.contains("data-route=\"configuration\""));
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
        assert!(js_body.contains("\"PATCH\""));
        assert!(js_body.contains("If-Match"));
        assert!(js_body.contains("/config/drafts"));
        assert!(js_body.contains("confirmation_token"));
        assert!(js_body.contains("Authorization"));
        assert!(js_body.contains("downloadExport"));
        assert!(js_body.contains("`${BASE}${path}`"));
        assert!(js_body.contains("/requests/export?"));
        assert!(js_body.contains("persistenceWarning"));
        assert!(js_body.contains("lost_writes"));
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
        let google = value["providers"]
            .as_array()
            .and_then(|providers| providers.iter().find(|provider| provider["id"] == "google"))
            .expect("built-in Google provider");
        assert!(google["authentication"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| {
                method["method"] == "authorization_code_pkce"
                    && method["support"] == "requires_explicit_configuration"
            })));
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
        assert!(!body.contains("\"client_secret\":"));
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
        assert_eq!(
            generate_setup_config(
                "google",
                "authorization_code_pkce",
                "primary",
                "gemini-2.5-pro",
                "gemini",
            )
            .expect_err("Google PKCE requires explicit upstream OAuth registration"),
            "browser OAuth requires operator-owned registration details that this wizard cannot collect"
        );
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
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let value: Value = serde_json::from_slice(&response.body).expect("setup test json");
        assert_eq!(
            value["error"],
            "setup verification requires a correlated catalog reload request"
        );
    }

    #[test]
    fn setup_discovery_must_be_newer_than_verification_reload() {
        let stale = json!({
            "provider": "openai",
            "account": "primary",
            "state": {"observed_at_unix_ms": 100},
        });
        let fresh = json!({
            "provider": "openai",
            "account": "primary",
            "state": {"observed_at_unix_ms": 101},
        });
        assert!(!setup_discovery_is_fresh(
            &stale,
            &["openai"],
            "primary",
            100
        ));
        assert!(setup_discovery_is_fresh(
            &fresh,
            &["openai"],
            "primary",
            100
        ));
    }

    #[test]
    fn setup_verification_requires_latest_successful_generation_matched_reload() {
        let api = api();
        let generation = api.state.load().config.generation().value();
        let first = api
            .enqueue_reload(ManagementReloadKind::Catalog, generation, None)
            .expect("first catalog reload queued");
        api.complete_reload(first.id, "succeeded", generation, Some(0));
        let path = format!(
            "/setup/test?provider=openai&auth=api_key&account=primary&model=gpt-5&client=openai&reload_request_id={}",
            first.id
        );
        let response = api.handle(&Method::GET, &path, &loopback_headers());
        assert_eq!(response.status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&response.body).expect("setup test JSON");
        assert_eq!(value["checks"][4]["status"], "passed");
        assert_eq!(
            value["ready"], false,
            "reload success alone is not discovery"
        );

        let second = api
            .enqueue_reload(ManagementReloadKind::Catalog, generation, None)
            .expect("second catalog reload queued");
        api.complete_reload(second.id, "failed", generation, Some(0));
        let stale = api.handle(&Method::GET, &path, &loopback_headers());
        let stale: Value = serde_json::from_slice(&stale.body).expect("stale setup JSON");
        assert_eq!(
            stale["checks"][4]["status"], "failed",
            "an older successful reload must not bypass a newer failed reload"
        );
    }

    #[test]
    fn request_explorer_is_paginated_filterable_redacted_and_timeline_consistent() {
        let api = api();
        let pooling = api.state.load_full().pooling.clone();
        let store = pooling.store();
        for (index, kind) in [
            pooler_store::RequestEventKind::Admission,
            pooler_store::RequestEventKind::Selection,
            pooler_store::RequestEventKind::Attempt,
            pooler_store::RequestEventKind::Retry,
            pooler_store::RequestEventKind::Commitment,
            pooler_store::RequestEventKind::Completion,
        ]
        .into_iter()
        .enumerate()
        {
            let mut event = pooler_store::RequestEvent::new(
                "pool-request-1",
                u32::try_from(index).expect("event index"),
                kind,
                "local",
                "route-a",
                100 + u64::try_from(index).expect("timestamp"),
            );
            event.public_model = Some("public-model".to_owned());
            event.provider = Some("provider-a".to_owned());
            event.attempt = Some(1);
            if kind == pooler_store::RequestEventKind::Retry {
                event.retry_reason = Some("Authorization: Bearer raw-secret-sentinel".to_owned());
                event.cooldown_effect = Some("credential".to_owned());
            }
            if kind == pooler_store::RequestEventKind::Commitment {
                event.commitment = Some("response_headers".to_owned());
                event.status = Some(200);
            }
            if kind == pooler_store::RequestEventKind::Completion {
                event.status = Some(200);
                event.error_class = Some("success".to_owned());
                event.ttft_ms = Some(12);
                event.latency_ms = Some(30);
            }
            store.append_request_event(event).expect("request event");
        }
        store
            .append_request_event(pooler_store::RequestEvent::new(
                "pool-request-2",
                0,
                pooler_store::RequestEventKind::Admission,
                "local",
                "other-route",
                200,
            ))
            .expect("second request");

        let headers = loopback_headers();
        let listed = api.handle(
            &Method::GET,
            "/requests?limit=1&route=route-a&provider=provider-a&status=200",
            &headers,
        );
        assert_eq!(listed.status, StatusCode::OK);
        let listed_text = String::from_utf8(listed.body.clone()).expect("request list text");
        assert!(!listed_text.contains("raw-secret-sentinel"));
        let listed = response_value(listed);
        assert_eq!(listed["requests"].as_array().expect("requests").len(), 1);
        assert_eq!(listed["requests"][0]["request_id"], "pool-request-1");
        assert_eq!(listed["requests"][0]["attempts"], 1);
        assert_eq!(listed["requests"][0]["committed"], true);
        assert_eq!(listed["requests"][0]["ttft_ms"], 12);

        let detail = response_value(api.handle(&Method::GET, "/requests/pool-request-1", &headers));
        assert_eq!(detail["request"]["route"], "route-a");
        let timeline =
            response_value(api.handle(&Method::GET, "/requests/pool-request-1/timeline", &headers));
        let timeline = timeline["timeline"].as_array().expect("timeline");
        assert_eq!(timeline.len(), 6);
        assert!(timeline
            .iter()
            .all(|event| event["request_id"] == "pool-request-1"));

        let exported = api.handle(&Method::GET, "/requests/export", &headers);
        assert_eq!(exported.status, StatusCode::OK);
        assert!(!String::from_utf8(exported.body)
            .expect("request export text")
            .contains("raw-secret-sentinel"));
        assert_eq!(
            api.handle(&Method::GET, "/requests/missing", &headers)
                .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            api.handle(&Method::GET, "/requests/bad%2Fid", &headers)
                .status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn historical_write_loss_is_explicit_in_requests_usage_and_missing_details() {
        let api = api();
        let pooling = api.state.load_full().pooling.clone();
        let status = pooling.persistence_status();
        status.record_failure(
            pooler_http::PersistenceStream::RequestEvents,
            &StoreError::Sqlite("operator-secret-path".to_owned()),
        );
        status.record_failure(
            pooler_http::PersistenceStream::UsageRecords,
            &StoreError::Io("operator-secret-path".to_owned()),
        );

        let headers = loopback_headers();
        let requests = api.handle(&Method::GET, "/requests", &headers);
        assert_eq!(requests.status, StatusCode::OK);
        let requests = response_value(requests);
        assert_eq!(requests["persistence"]["request_events"]["complete"], false);
        assert_eq!(requests["persistence"]["request_events"]["lost_writes"], 1);
        assert_eq!(
            requests["persistence"]["request_events"]["last_failure_class"],
            "database"
        );
        assert!(!requests.to_string().contains("operator-secret-path"));

        let usage = api.handle(&Method::GET, "/usage/aggregate", &headers);
        assert_eq!(usage.status, StatusCode::OK);
        let usage = response_value(usage);
        assert_eq!(usage["persistence"]["usage_records"]["complete"], false);
        assert_eq!(usage["persistence"]["usage_records"]["lost_writes"], 1);
        assert_eq!(
            usage["persistence"]["usage_records"]["last_failure_class"],
            "io"
        );
        let prometheus = api.handle(&Method::GET, "/usage/prometheus", &headers);
        assert_eq!(prometheus.status, StatusCode::OK);
        let prometheus = String::from_utf8(prometheus.body).expect("Prometheus text");
        assert!(prometheus.contains("pooler_persistence_complete 0"));
        assert!(prometheus.contains("pooler_persistence_lost_writes{stream=\"usage_records\"} 1"));

        let prometheus = api.handle(&Method::GET, "/metrics/prometheus", &headers);
        assert_eq!(prometheus.status, StatusCode::OK);
        let prometheus = String::from_utf8(prometheus.body).expect("Prometheus text");
        assert!(prometheus.contains("pooler_persistence_complete 0"));
        assert!(prometheus.contains("pooler_persistence_lost_writes{stream=\"request_events\"} 1"));
        assert!(prometheus.contains("pooler_persistence_lost_writes{stream=\"usage_records\"} 1"));

        let health = api.handle(&Method::GET, "/health", &headers);
        assert_eq!(health.status, StatusCode::SERVICE_UNAVAILABLE);
        let health = response_value(health);
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["ready"], false);
        assert_eq!(health["persistence"]["complete"], false);
        let readiness = api.handle(&Method::GET, "/readiness", &headers);
        assert_eq!(readiness.status, StatusCode::SERVICE_UNAVAILABLE);

        let detail = api.handle(&Method::GET, "/requests/missing", &headers);
        assert_eq!(detail.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_value(detail)["error"],
            "request history is incomplete"
        );
    }

    #[test]
    fn usage_ledger_filters_aggregates_and_exports_redacted_formats() {
        let api = api();
        let store = api.state.load_full().pooling.store();
        let mut first = UsageRecord::new(100, "usage-1", "route-a", "success");
        first.provider = Some("provider-a".to_owned());
        first.public_model = Some("public-model".to_owned());
        first.upstream_model = Some("provider-model".to_owned());
        first.account_pseudonym = Some("account-pseudo".to_owned());
        first.input_tokens = Some(11);
        first.output_tokens = Some(7);
        first.reasoning_tokens = Some(3);
        first.cache_tokens = Some(2);
        first.latency_ms = 30;
        first.ttft_ms = Some(12);
        first.service_tier = Some("Authorization: Bearer raw-usage-secret".to_owned());
        first.cost_in_usd_ticks = Some(42);
        first.cost_provenance = pooler_store::CostProvenance::ProviderReported;
        first.configuration_generation = 1;
        store.append_usage_record(first).expect("first usage");
        store
            .append_usage_record(UsageRecord::new(
                200,
                "usage-2",
                "other-route",
                "upstream_error",
            ))
            .expect("second usage");

        let headers = loopback_headers();
        let listed = api.handle(
            &Method::GET,
            "/usage?route=route-a&provider=provider-a&limit=1",
            &headers,
        );
        assert_eq!(listed.status, StatusCode::OK);
        let listed_text = String::from_utf8(listed.body.clone()).expect("usage list text");
        assert!(!listed_text.contains("raw-usage-secret"));
        let listed = response_value(listed);
        assert_eq!(listed["records"].as_array().expect("records").len(), 1);
        assert_eq!(listed["records"][0]["input_tokens"], 11);

        let aggregate = response_value(api.handle(
            &Method::GET,
            "/usage/aggregate?route=route-a&group_by=route,provider",
            &headers,
        ));
        assert_eq!(aggregate["series"][0]["totals"]["input_tokens"], 11);
        assert_eq!(
            aggregate["series"][0]["totals"]["provider_reported_cost_records"],
            1
        );

        let prometheus = api.handle(
            &Method::GET,
            "/usage/prometheus?route=route-a&group_by=service_tier",
            &headers,
        );
        assert_eq!(prometheus.status, StatusCode::OK);
        let prometheus = String::from_utf8(prometheus.body).expect("Prometheus text");
        assert!(prometheus.contains("pooler_usage_input_tokens"));
        assert!(!prometheus.contains("raw-usage-secret"));

        let otlp = response_value(api.handle(
            &Method::GET,
            "/usage/otlp?route=route-a&group_by=service_tier",
            &headers,
        ));
        assert_eq!(
            otlp["resourceMetrics"][0]["scopeMetrics"][0]["scope"]["name"],
            "pooler.usage"
        );
        assert!(otlp.get("persistence").is_none());
        assert!(!otlp.to_string().contains("raw-usage-secret"));
        let export = api.handle(&Method::GET, "/usage/export", &headers);
        assert!(!String::from_utf8(export.body)
            .expect("usage export text")
            .contains("raw-usage-secret"));
    }

    #[test]
    fn brokered_device_oauth_exposes_only_operator_prompt_and_keeps_result_server_side() {
        const MANAGEMENT_ENV: &str = "POOLER_DEVICE_OAUTH_MANAGEMENT_KEY";
        std::env::set_var(MANAGEMENT_ENV, "device-oauth-management-secret");
        let config = pooler_config::compile_yaml(
            "device-oauth-management.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:{MANAGEMENT_ENV}}}}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{openai: {{known_provider: openai, native: {{kind: codex}}}}}}\naccounts: {{personal: {{provider: openai, auth_kind: oauth}}}}\nmodels: [{{id: public-model, targets: [{{provider: openai, upstream_model: provider-model}}]}}]\nroutes: [{{id: route-a, listen: local, match: {{path: /v1/chat}}, target: {{provider: openai, model_from: request.model}}, ingress: {{mode: patch}}}}]\n"
            ),
        )
        .expect("device OAuth configuration");
        let plan = config.management().cloned().expect("management plan");
        let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling coordinator"));
        let store = Arc::new(ConfigStore::with_generation(
            ConfigGeneration::new(config.generation()),
            config,
        ));
        let (commands, mut receiver) = mpsc::channel(2);
        let mut api = ManagementApi::new(plan, store, pooling, ActiveCounts::new());
        api.native_commands = Some(commands);
        let mut headers = loopback_headers();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer device-oauth-management-secret"),
        );
        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("http://localhost"),
        );
        let queued = api.handle(&Method::POST, "/accounts/personal/oauth-device", &headers);
        assert_eq!(queued.status, StatusCode::ACCEPTED);
        let queued = response_value(queued);
        let request_id = queued["request_id"].as_u64().expect("request ID");
        let duplicate = api.handle(&Method::POST, "/accounts/personal/oauth-device", &headers);
        assert_eq!(duplicate.status, StatusCode::CONFLICT);
        let command = receiver.try_recv().expect("device command");
        assert_eq!(command.account, "personal");
        assert_eq!(
            command.action,
            NativeAccountAction::DeviceLogin { request_id }
        );
        api.record_oauth_device_prompt(
            request_id,
            "https://provider.example/device",
            Some("https://provider.example/device?code=safe-user-code"),
            "SAFE-CODE",
            600,
        );
        let status = api.handle(
            &Method::GET,
            &format!("/oauth/device/{request_id}"),
            &headers,
        );
        assert_eq!(status.status, StatusCode::OK);
        let text = String::from_utf8(status.body.clone()).expect("device status text");
        assert!(text.contains("SAFE-CODE"));
        assert!(!text.contains("access_token"));
        assert!(!text.contains("refresh_token"));
        assert!(!text.contains("device_code"));
        let status = response_value(status);
        assert_eq!(status["status"], "authorization_required");
        api.record_oauth_device_result(request_id, "succeeded");
        let completed = response_value(api.handle(
            &Method::GET,
            &format!("/oauth/device/{request_id}"),
            &headers,
        ));
        assert_eq!(completed["status"], "succeeded");
        assert!(completed.get("user_code").is_none());
        assert!(completed.get("verification_uri_complete").is_none());
        std::env::remove_var(MANAGEMENT_ENV);
    }

    #[test]
    fn typed_account_draft_supports_env_file_and_keyring_without_echoing_references() {
        const MANAGEMENT_ENV: &str = "POOLER_ACCOUNT_DRAFT_MANAGEMENT_KEY";
        std::env::set_var(MANAGEMENT_ENV, "account-draft-management-secret");
        let directory = private_configuration_tempdir();
        let source = directory.path().join("gateway.yaml");
        std::fs::write(
            &source,
            format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:{MANAGEMENT_ENV}}}}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{provider-a: {{url: http://127.0.0.1:1}}}}\nmodels: [{{id: public-model, targets: [{{provider: provider-a, upstream_model: provider-model}}]}}]\nroutes: [{{id: route-a, listen: local, match: {{path: /v1/chat}}, target: {{provider: provider-a, model_from: request.model}}, ingress: {{mode: patch}}}}]\n"
            ),
        )
        .expect("source configuration");
        make_configuration_private(&source);
        let api = authenticated_api(MANAGEMENT_ENV);
        api.enable_config_management(&source)
            .expect("typed management enabled");
        let mut headers = loopback_headers();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer account-draft-management-secret"),
        );
        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("http://localhost"),
        );
        for (kind, fields) in [
            ("env", json!({"name": "POOLER_PROVIDER_KEY"})),
            ("file", json!({"path": "/run/secrets/provider-key"})),
            (
                "keyring",
                json!({"service": "pooler", "account": "provider-a"}),
            ),
        ] {
            let mut secret = fields.as_object().expect("secret fields").clone();
            secret.insert("kind".to_owned(), json!(kind));
            let body = serde_json::to_vec(&json!({
                "id": format!("account-{kind}"),
                "provider": "provider-a",
                "auth_kind": "api_key",
                "secret": secret,
            }))
            .expect("account draft JSON");
            let response =
                api.handle_with_body(&Method::POST, "/config/accounts/draft", &headers, &body);
            assert_eq!(response.status, StatusCode::CREATED);
            let text = String::from_utf8(response.body.clone()).expect("response text");
            assert!(!text.contains("POOLER_PROVIDER_KEY"));
            assert!(!text.contains("/run/secrets"));
            assert!(!text.contains("env:"));
            assert!(!text.contains("file:"));
            assert!(!text.contains("keyring:"));
            let value = response_value(response);
            assert_eq!(value["valid"], true);
            assert_eq!(value["semantic_diff"][0]["section"], "accounts");
            assert!(value["semantic_diff"][0].get("value").is_none());
        }
        let relative_file = serde_json::to_vec(&json!({
            "id": "relative-file-account",
            "provider": "provider-a",
            "auth_kind": "api_key",
            "secret": {"kind": "file", "path": "relative/provider.key"},
        }))
        .expect("relative file JSON");
        let rejected_relative = api.handle_with_body(
            &Method::POST,
            "/config/accounts/draft",
            &headers,
            &relative_file,
        );
        assert_eq!(rejected_relative.status, StatusCode::BAD_REQUEST);

        let literal = serde_json::to_vec(&json!({
            "id": "literal-account",
            "provider": "provider-a",
            "auth_kind": "api_key",
            "secret": {"kind": "literal", "value": "forbidden"},
        }))
        .expect("literal JSON");
        let rejected =
            api.handle_with_body(&Method::POST, "/config/accounts/draft", &headers, &literal);
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
        assert!(!String::from_utf8(rejected.body)
            .expect("error text")
            .contains("forbidden"));
        std::env::remove_var(MANAGEMENT_ENV);
    }

    #[tokio::test]
    async fn typed_configuration_api_requires_etags_and_activates_only_after_reload() {
        const SECRET_ENV: &str = "POOLER_MANAGEMENT_CONFIG_TEST_KEY";
        std::env::set_var(SECRET_ENV, "managed-config-secret");
        let directory = private_configuration_tempdir();
        let source = directory.path().join("gateway.yaml");
        std::fs::write(
            &source,
            format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:{SECRET_ENV}}}}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{provider-a: {{url: http://127.0.0.1:1}}}}\nmodels: [{{id: public-model, targets: [{{provider: provider-a, upstream_model: provider-model}}]}}]\nroutes: [{{id: route-a, listen: local, match: {{path: /v1/chat}}, target: {{provider: provider-a, model_from: request.model}}, ingress: {{mode: patch}}}}]\n"
            ),
        )
        .expect("source configuration written");
        make_configuration_private(&source);
        let api = authenticated_api(SECRET_ENV);
        api.enable_config_management(&source)
            .expect("typed management enabled");
        let mut headers = loopback_headers();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer managed-config-secret"),
        );
        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("http://localhost"),
        );

        let created = api.handle_with_body(&Method::POST, "/config/drafts", &headers, &[]);
        assert_eq!(created.status, StatusCode::CREATED);
        let created = response_value(created);
        let draft = created["draft_id"].as_u64().expect("draft id");
        let etag = created["etag"].as_str().expect("draft etag");
        let patch_path = format!("/config/drafts/{draft}");
        let missing_etag = api.handle_with_body(
            &Method::PATCH,
            &patch_path,
            &headers,
            br#"{"op":"remove","section":"models","id":"public-model"}"#,
        );
        assert_eq!(missing_etag.status, StatusCode::PRECONDITION_REQUIRED);

        headers.insert(
            header::IF_MATCH,
            header::HeaderValue::from_str(etag).expect("ETag header"),
        );
        let patch = json!({
            "op": "upsert",
            "section": "models",
            "id": "public-model",
            "value": {
                "id": "public-model",
                "targets": [{
                    "provider": "provider-a",
                    "upstream_model": "provider-model-2"
                }]
            }
        });
        let patched = api.handle_with_body(
            &Method::PATCH,
            &patch_path,
            &headers,
            &serde_json::to_vec(&patch).expect("patch JSON"),
        );
        assert_eq!(patched.status, StatusCode::OK);
        let patched = response_value(patched);
        let etag = patched["etag"].as_str().expect("patched etag");
        headers.insert(
            header::IF_MATCH,
            header::HeaderValue::from_str(etag).expect("updated ETag header"),
        );
        let validated = api.handle_with_body(
            &Method::POST,
            &format!("{patch_path}/validate"),
            &headers,
            &[],
        );
        assert_eq!(validated.status, StatusCode::OK);
        let validated = response_value(validated);
        assert_eq!(validated["valid"], true);
        assert_eq!(validated["semantic_diff"][0]["section"], "models");
        assert!(validated["semantic_diff"][0].get("value").is_none());
        let confirmation = validated["confirmation_token"]
            .as_str()
            .expect("confirmation token");
        let committed = api.handle_with_body(
            &Method::POST,
            &format!("{patch_path}/commit"),
            &headers,
            &serde_json::to_vec(&json!({"confirmation_token": confirmation})).expect("commit JSON"),
        );
        assert_eq!(committed.status, StatusCode::ACCEPTED);
        let committed_body = String::from_utf8(committed.body).expect("commit response text");
        assert!(!committed_body.contains(SECRET_ENV));
        assert!(!committed_body.contains("managed-config-secret"));
        assert!(!committed_body.contains("provider-model-2"));

        assert!(api.managed_configuration_reload_pending());
        let overlapping = api.handle(&Method::POST, "/reload", &headers);
        assert_eq!(overlapping.status, StatusCode::CONFLICT);

        let request = api.next_reload_request().await;
        let managed = directory.path().join("gateway.managed.yaml");
        assert!(managed.is_file());
        let canonical_managed = managed.canonicalize().expect("canonical managed sidecar");
        assert_eq!(request.source.as_deref(), Some(canonical_managed.as_path()));
        let generated = std::fs::read_to_string(&managed).expect("managed sidecar readable");
        assert!(generated.starts_with("# Generated and exclusively managed by Pooler."));
        assert!(generated.contains("provider-model-2"));
        assert_eq!(
            std::fs::read_to_string(&source).expect("operator source readable"),
            format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:{SECRET_ENV}}}}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{provider-a: {{url: http://127.0.0.1:1}}}}\nmodels: [{{id: public-model, targets: [{{provider: provider-a, upstream_model: provider-model}}]}}]\nroutes: [{{id: route-a, listen: local, match: {{path: /v1/chat}}, target: {{provider: provider-a, model_from: request.model}}, ingress: {{mode: patch}}}}]\n"
            )
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&managed)
                .expect("managed metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );

        api.complete_reload(request.id, "failed", request.generation, None);
        assert!(
            !managed.exists(),
            "a failed publication restores the pre-commit filesystem state"
        );
        std::env::remove_var(SECRET_ENV);
    }

    #[tokio::test]
    async fn management_listener_collects_only_bounded_typed_configuration_json() {
        const SECRET_ENV: &str = "POOLER_MANAGEMENT_TYPED_BODY_TEST_KEY";
        assert!(!raw_is_body_free_management_mutation(
            b"PATCH /management/config/drafts/1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ));
        assert!(raw_is_body_free_management_mutation(
            b"POST /management/reload HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ));

        std::env::set_var(SECRET_ENV, "typed-body-secret");
        let directory = private_configuration_tempdir();
        let source = directory.path().join("gateway.yaml");
        std::fs::write(
            &source,
            format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0, auth: {{secret: env:{SECRET_ENV}}}}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{provider-a: {{url: http://127.0.0.1:1}}}}\nmodels: [{{id: public-model, targets: [{{provider: provider-a, upstream_model: provider-model}}]}}]\nroutes: [{{id: route-a, listen: local, match: {{path: /v1/chat}}, target: {{provider: provider-a, model_from: request.model}}, ingress: {{mode: patch}}}}]\n"
            ),
        )
        .expect("source configuration written");
        make_configuration_private(&source);
        let api = Arc::new(authenticated_api(SECRET_ENV));
        api.enable_config_management(&source)
            .expect("typed management enabled");
        let server = ManagementHttpServer::bind(Arc::clone(&api))
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

        let send = |request: Vec<u8>| async move {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("management connects");
            stream
                .write_all(&request)
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
            response
        };
        let created = send(
            b"POST /management/config/drafts HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nAuthorization: Bearer typed-body-secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .await;
        assert!(String::from_utf8_lossy(&created).contains("201 Created"));
        let created_body = created
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| &created[position + 4..])
            .expect("HTTP response body");
        let created: Value = serde_json::from_slice(created_body).expect("created draft JSON");
        let draft = created["draft_id"].as_u64().expect("draft id");
        let etag = created["etag"].as_str().expect("draft ETag");
        let patch = serde_json::to_vec(&json!({
            "op": "remove",
            "section": "models",
            "id": "public-model"
        }))
        .expect("patch JSON");
        let request = format!(
            "PATCH /management/config/drafts/{draft} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nAuthorization: Bearer typed-body-secret\r\nIf-Match: {etag}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            patch.len()
        );
        let mut request = request.into_bytes();
        request.extend_from_slice(&patch);
        let patched = send(request).await;
        assert!(
            String::from_utf8_lossy(&patched).contains("200 OK"),
            "typed mutation response was {}",
            String::from_utf8_lossy(&patched)
        );

        let oversized = send(
            b"PATCH /management/config/drafts/1 HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nAuthorization: Bearer typed-body-secret\r\nIf-Match: ignored\r\nContent-Type: application/json\r\nContent-Length: 300000\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .await;
        assert!(String::from_utf8_lossy(&oversized).contains("413 Payload Too Large"));

        let unauthenticated = send(
            b"PATCH /management/config/drafts/1 HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"
                .to_vec(),
        )
        .await;
        assert!(String::from_utf8_lossy(&unauthenticated).contains("401 Unauthorized"));

        let mut slow = TcpStream::connect(address)
            .await
            .expect("slow management client connects");
        slow.write_all(
            b"PATCH /management/config/drafts/1 HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nAuthorization: Bearer typed-body-secret\r\nIf-Match: ignored\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("slow management headers write");
        let mut timed_out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(6),
            slow.read_to_end(&mut timed_out),
        )
        .await
        .expect("bounded body deadline elapses")
        .expect("body timeout response reads");
        assert!(String::from_utf8_lossy(&timed_out).contains("408 Request Timeout"));

        server.begin_shutdown();
        runner
            .await
            .expect("management task does not panic")
            .expect("management task shuts down");
        std::env::remove_var(SECRET_ENV);
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
