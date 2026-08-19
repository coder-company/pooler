//! Read-only management HTTP responses.
//!
//! The management surface is intentionally separate from inference routes.
//! It accepts no request body, exposes only immutable plans and redacted
//! mutable state, and never resolves or serializes credential references.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

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
use crate::{ConfigSnapshot, ConfigStore};

const DEFAULT_DECISION_LIMIT: usize = 20;
const MAX_DECISION_LIMIT: usize = 100;

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
        let content_length = encoded.len().to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
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
        Self {
            status,
            headers,
            body: if head { Vec::new() } else { encoded },
        }
    }
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
        let path = uri
            .as_ref()
            .map_or(path_and_query, Uri::path)
            .strip_prefix("/management")
            .filter(|path| path.is_empty() || path.starts_with('/'))
            .unwrap_or_else(|| uri.as_ref().map_or(path_and_query, Uri::path));
        let path = if path.is_empty() { "/" } else { path };
        let head = *method == Method::HEAD;
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
        if !self.authorized(headers) {
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
        let response = match path {
            "/health" | "/healthz" | "/" => self.health(snapshot, pooling),
            "/config" | "/config/generation" => self.config_generation(snapshot),
            "/routes" => self.routes(snapshot),
            "/models" => self.models(snapshot),
            "/health/providers" | "/providers/health" => self.providers(snapshot, pooling),
            "/health/credentials" | "/credentials/health" => self.credentials(snapshot, pooling),
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
        let credentials = pooling
            .credential_health_states()
            .ok()
            .map_or(0, |states| states.len());
        let cooling_providers = pooling.cooldowns().ok().map_or(0, |states| {
            states
                .iter()
                .filter(|state| matches!(state.scope.as_str(), "provider" | "provider_model"))
                .count()
        });
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

    fn models(&self, snapshot: &ConfigSnapshot<CompiledConfig>) -> ManagementResponse {
        let models = snapshot
            .config()
            .models()
            .values()
            .map(|model| {
                let targets = model
                    .targets()
                    .iter()
                    .map(|target| {
                        json!({
                            "provider": target.provider(),
                            "upstream_model": target.upstream_model(),
                            "capabilities": target
                                .capabilities()
                                .iter()
                                .map(|capability| capability.as_str())
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect::<Vec<_>>();
                json!({"id": model.id(), "targets": targets})
            })
            .collect::<Vec<_>>();
        ManagementResponse::json(
            StatusCode::OK,
            json!({
                "configuration_generation": snapshot.generation().value(),
                "models": models,
            }),
            false,
        )
    }

    fn providers(
        &self,
        snapshot: &ConfigSnapshot<CompiledConfig>,
        pooling: &PoolingCoordinator,
    ) -> ManagementResponse {
        let cooldowns = pooling.cooldowns().unwrap_or_default();
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
        let states = pooling.credential_states().unwrap_or_default();
        let health = pooling.credential_health_states().unwrap_or_default();
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
        ManagementResponse::json(
            StatusCode::OK,
            json!({"configuration_generation": snapshot.generation().value(), "credentials": credentials}),
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
        let _ = std::fs::remove_file(&self.0);
    }
}

struct ManagementServerState {
    listener: Mutex<Option<BoundManagementListener>>,
    cancellation: CancellationToken,
}

/// Standalone HTTP/1 management listener for a [`ManagementApi`].
///
/// The listener is separate from inference sockets and is intended to be
/// spawned by process wiring after configuration has passed the loopback /
/// remote-auth validation boundary.
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
        let bind = api.bind();
        let (listener, address) = if bind.starts_with('/') || bind.starts_with("unix:") {
            let path = bind.strip_prefix("unix:").unwrap_or(bind);
            let listener =
                UnixListener::bind(path).map_err(|source| ManagementServerError::Bind {
                    listener: bind.to_owned(),
                    source,
                })?;
            (
                BoundManagementListener::Unix {
                    listener,
                    path: ManagementUnixSocketPath(PathBuf::from(path)),
                },
                path.to_owned(),
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
            let response = api.handle(
                request.method(),
                request.uri().to_string().as_str(),
                request.headers(),
            );
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
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

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

    #[test]
    fn read_only_endpoints_expose_generation_and_redacted_plan_views() {
        let api = api();
        let headers = HeaderMap::new();
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
    fn mutation_requests_are_rejected_and_active_counts_are_bounded() {
        let api = api();
        let headers = HeaderMap::new();
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
        let headers = HeaderMap::new();
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

        let mut correct = HeaderMap::new();
        correct.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer management-secret"),
        );
        let accepted = api.handle(&Method::GET, "/health", &correct);
        assert_eq!(accepted.status, StatusCode::OK);
        std::env::remove_var("POOLER_MANAGEMENT_TEST_KEY");
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
