//! Read-only management HTTP responses.
//!
//! The management surface is intentionally separate from inference routes.
//! It accepts no request body, exposes only immutable plans and redacted
//! mutable state, and never resolves or serializes credential references.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{header, HeaderMap, Method, Response, StatusCode, Uri};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use pooler_auth::{bearer_authorization_matches, SecretRef as RuntimeSecretRef};
use pooler_config::{CompiledConfig, ManagementPlan};
use pooler_http::PoolingCoordinator;
use pooler_store::{CredentialHealthState, CredentialHealthStatus, CredentialState};
use serde_json::{json, Value};
use tokio::{
    net::{TcpListener, UnixListener},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::http_runtime::RuntimeGeneration;
use crate::management_ui;
use crate::{merged_model_catalog_value, CatalogRuntime, ConfigSnapshot, ConfigStore};

const DEFAULT_DECISION_LIMIT: usize = 20;
const MAX_DECISION_LIMIT: usize = 100;
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
        body: &'static str,
        head: bool,
    ) -> Self {
        Self::body(status, content_type, body.as_bytes().to_vec(), head)
    }
}

fn security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
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

/// Read-only management API backed by an immutable configuration store.
#[derive(Clone)]
pub struct ManagementApi {
    plan: ManagementPlan,
    state: Arc<ArcSwap<ManagementSnapshot>>,
    runtime_dispatch: Option<Arc<ArcSwap<RuntimeGeneration>>>,
    catalog: Option<Arc<CatalogRuntime>>,
    metrics: pooler_observe::MetricsRegistry,
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
        metrics: pooler_observe::MetricsRegistry,
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
            metrics,
            active,
        }
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
        let ui_asset = management_ui::asset(path).is_some() || (management_prefix && path == "/");
        if *method != Method::GET && !head {
            let mut response = ManagementResponse::json(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({"error": "management endpoint is read-only"}),
                false,
            );
            response
                .headers
                .insert(header::ALLOW, header::HeaderValue::from_static("GET, HEAD"));
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
        if !local_ui_shell && !self.authorized(headers) {
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
        let response = match path {
            "/" if management_prefix => {
                let (content_type, body) = management_ui::asset("/ui").expect("UI asset");
                ManagementResponse::asset(StatusCode::OK, content_type, body, head)
            }
            path if management_ui::asset(path).is_some() => {
                let (content_type, body) = management_ui::asset(path).expect("asset exists");
                ManagementResponse::asset(StatusCode::OK, content_type, body, head)
            }
            "/health" | "/healthz" | "/" => self.health(snapshot, pooling),
            "/config" | "/config/generation" => self.config_generation(snapshot),
            "/listeners" => self.listeners(snapshot),
            "/routes" => self.routes(snapshot),
            "/models" => self.models(snapshot, catalog.as_deref()),
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
            json!({"configuration_generation": snapshot.generation().value()}),
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
    ) -> ManagementResponse {
        ManagementResponse::json(
            StatusCode::OK,
            merged_model_catalog_value(snapshot.config(), catalog),
            false,
        )
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
        let credentials = snapshot
            .config()
            .accounts()
            .values()
            .map(|account| {
                credential_health_value(account, states.get(account.id()), health.get(account.id()))
            })
            .collect::<Vec<_>>();
        let mut value = serde_json::Map::new();
        value.insert(
            "configuration_generation".to_owned(),
            json!(snapshot.generation().value()),
        );
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
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "active": entries.len(),
                "entries": entries,
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
                        tasks.spawn(async move { serve_management_connection(TokioIo::new(stream), api, cancellation).await });
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
                        tasks.spawn(async move { serve_management_connection(TokioIo::new(stream), api, cancellation).await });
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

async fn serve_management_connection<I>(
    io: TokioIo<I>,
    api: Arc<ManagementApi>,
    cancellation: CancellationToken,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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

fn state_unavailable() -> ManagementResponse {
    ManagementResponse::json(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error": "management state unavailable"}),
        false,
    )
}

fn health_status(state: Option<&CredentialHealthState>) -> &'static str {
    match state.map(|state| state.status) {
        Some(CredentialHealthStatus::CoolingDown) => "cooling_down",
        Some(CredentialHealthStatus::Disabled) => "disabled",
        Some(CredentialHealthStatus::Healthy) | None => "healthy",
    }
}

fn credential_health_value(
    account: &pooler_config::AccountPlan,
    state: Option<&CredentialState>,
    health: Option<&CredentialHealthState>,
) -> Value {
    json!({
        "id": account.id(),
        "provider": account.provider(),
        "enabled": state.map_or(account.enabled(), |state| state.enabled),
        "status": health_status(health),
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
        "status": if cooling { "cooling_down" } else { "healthy" },
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
        assert!(String::from_utf8_lossy(&providers.body).contains("provider-a"));
    }

    #[test]
    fn management_ui_assets_are_read_only_and_hardened() {
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
        assert!(html_body.contains("Pooler Control"));
        assert!(html_body.contains("/management/ui.js"));
        assert!(html_body.contains("Listeners"));
        assert!(html_body.contains("Quota &amp; cooldowns"));
        assert!(!html_body.contains("type=\"submit\""));
        assert_eq!(
            html.headers.get(header::CONTENT_SECURITY_POLICY),
            Some(&header::HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
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
        let js = api.handle(&Method::GET, "/management/ui.js", &headers);
        assert_eq!(js.status, StatusCode::OK);
        let js_body = String::from_utf8_lossy(&js.body);
        assert!(js_body.contains("/management/metrics"));
        assert!(js_body.contains("cache: \"no-store\""));
        assert!(!js_body.contains("method: \"POST\""));
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
        assert!(String::from_utf8_lossy(&response.body).contains("read-only"));

        let guard = api.active_counts().enter("local");
        let active = api.handle(&Method::GET, "/active", &headers);
        assert!(String::from_utf8_lossy(&active.body).contains("\"active\":1"));
        drop(guard);
        let active = api.handle(&Method::GET, "/active", &headers);
        assert!(String::from_utf8_lossy(&active.body).contains("\"active\":0"));
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
        assert!(String::from_utf8_lossy(&shell.body).contains("Pooler Control"));

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
}
