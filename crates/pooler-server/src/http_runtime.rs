//! Concrete Hyper listener runtime for the opaque HTTP proxy.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::Duration,
};

use adapter_anthropic::AnthropicSemanticAdapter;
use adapter_devin::DevinSemanticAdapter;
use adapter_droid::DroidOpenAiSemanticAdapter;
use adapter_factory::FactorySemanticAdapter;
use adapter_fx::FxSemanticAdapter;
use adapter_gemini::GeminiSemanticAdapter;
use adapter_xai::XaiSemanticAdapter;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::{body::Incoming, http, http::Request, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use pooler_config::{CompiledConfig, ListenerProtocol};
use pooler_extension::{
    ExtensionCapabilities, ExtensionLimits, ExtensionRegistry, ExtensionSpec, WasmExtension,
};
use pooler_http::{
    BoxError, DrainError, HttpProxy, MediaSemanticAdapter, NativeRuntime, PoolingCoordinator,
    ProxyBody, ProxyError, RuntimeResourceGuard, RuntimeResourceSnapshot, RuntimeResources,
    SelectionContext, SemanticAdapter, SemanticRequestBody, SemanticResponseBody,
    SemanticResponseHint, SemanticWebSocketTransport,
};
use pooler_observe::MetricsRegistry;
use thiserror::Error;
use tokio::{
    net::{TcpListener, UnixListener},
    sync::{mpsc, Mutex as AsyncMutex},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::management::{
    ManagementReloadKind, ManagementRuntimeServices, NativeAccountAction, NativeAccountCommand,
};
use crate::tls::{PreparedTls, TlsError};
use crate::{
    ActiveCounts, ActiveGuard, CatalogRuntime, CatalogRuntimeError, ManagementApi,
    ManagementHttpServer, ManagementServerError,
};

const FORCE_CANCEL_GRACE: Duration = Duration::from_secs(1);

type RuntimeProxy = HttpProxy<RuntimeSemanticAdapter>;

/// Semantic adapters mounted by the concrete HTTP runtime.
///
/// The route plan chooses the adapter by its component identifiers. Keeping
/// this dispatch at the runtime boundary lets Factory and Devin routes share a
/// listener without making either adapter aware of the other protocol.
#[derive(Clone, Copy, Debug, Default)]
struct RuntimeSemanticAdapter;

impl SemanticAdapter for RuntimeSemanticAdapter {
    fn supports(&self, route: &pooler_config::RoutePlan) -> bool {
        DroidOpenAiSemanticAdapter.supports(route)
            || XaiSemanticAdapter.supports(route)
            || MediaSemanticAdapter::default().supports(route)
            || AnthropicSemanticAdapter.supports(route)
            || GeminiSemanticAdapter.supports(route)
            || FxSemanticAdapter.supports(route)
            || FactorySemanticAdapter.supports(route)
            || DevinSemanticAdapter.supports(route)
    }

    fn encode_request(
        &self,
        route: &pooler_config::RoutePlan,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        if DroidOpenAiSemanticAdapter.supports(route) {
            DroidOpenAiSemanticAdapter.encode_request(route, headers, body)
        } else if XaiSemanticAdapter.supports(route) {
            XaiSemanticAdapter.encode_request(route, headers, body)
        } else if MediaSemanticAdapter::default().supports(route) {
            MediaSemanticAdapter::default().encode_request(route, headers, body)
        } else if AnthropicSemanticAdapter.supports(route) {
            AnthropicSemanticAdapter.encode_request(route, headers, body)
        } else if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.encode_request(route, headers, body)
        } else if FxSemanticAdapter.supports(route) {
            FxSemanticAdapter.encode_request(route, headers, body)
        } else if FactorySemanticAdapter.supports(route) {
            FactorySemanticAdapter.encode_request(route, headers, body)
        } else if DevinSemanticAdapter.supports(route) {
            DevinSemanticAdapter.encode_request(route, headers, body)
        } else {
            Err(unsupported_semantic_route(route))
        }
    }

    fn encode_request_with_uri(
        &self,
        route: &pooler_config::RoutePlan,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.encode_request_with_uri(route, uri, headers, body)
        } else {
            self.encode_request(route, headers, body)
        }
    }

    fn selection_context(
        &self,
        route: &pooler_config::RoutePlan,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        if DroidOpenAiSemanticAdapter.supports(route) {
            DroidOpenAiSemanticAdapter.selection_context(route, headers, body)
        } else if XaiSemanticAdapter.supports(route) {
            XaiSemanticAdapter.selection_context(route, headers, body)
        } else if MediaSemanticAdapter::default().supports(route) {
            MediaSemanticAdapter::default().selection_context(route, headers, body)
        } else if AnthropicSemanticAdapter.supports(route) {
            AnthropicSemanticAdapter.selection_context(route, headers, body)
        } else if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.selection_context(route, headers, body)
        } else if FxSemanticAdapter.supports(route) {
            FxSemanticAdapter.selection_context(route, headers, body)
        } else if FactorySemanticAdapter.supports(route) {
            FactorySemanticAdapter.selection_context(route, headers, body)
        } else if DevinSemanticAdapter.supports(route) {
            DevinSemanticAdapter.selection_context(route, headers, body)
        } else {
            Err(unsupported_semantic_route(route))
        }
    }

    fn selection_context_with_uri(
        &self,
        route: &pooler_config::RoutePlan,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.selection_context_with_uri(route, uri, headers, body)
        } else {
            self.selection_context(route, headers, body)
        }
    }

    fn model_in_request_body(&self, route: &pooler_config::RoutePlan) -> bool {
        if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.model_in_request_body(route)
        } else {
            true
        }
    }

    fn websocket_transport(
        &self,
        route: &pooler_config::RoutePlan,
    ) -> Option<SemanticWebSocketTransport> {
        if DroidOpenAiSemanticAdapter.supports(route) {
            DroidOpenAiSemanticAdapter.websocket_transport(route)
        } else if XaiSemanticAdapter.supports(route) {
            XaiSemanticAdapter.websocket_transport(route)
        } else {
            None
        }
    }

    fn rewrite_upstream_uri(
        &self,
        route: &pooler_config::RoutePlan,
        downstream_uri: &http::Uri,
        upstream_model: Option<&str>,
        upstream_uri: http::Uri,
    ) -> Result<http::Uri, BoxError> {
        if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.rewrite_upstream_uri(
                route,
                downstream_uri,
                upstream_model,
                upstream_uri,
            )
        } else {
            Ok(upstream_uri)
        }
    }

    fn sanitize_request_headers(&self, headers: &mut http::HeaderMap) {
        DroidOpenAiSemanticAdapter.sanitize_request_headers(headers);
        XaiSemanticAdapter.sanitize_request_headers(headers);
        MediaSemanticAdapter::default().sanitize_request_headers(headers);
        AnthropicSemanticAdapter.sanitize_request_headers(headers);
        GeminiSemanticAdapter.sanitize_request_headers(headers);
        FxSemanticAdapter.sanitize_request_headers(headers);
        FactorySemanticAdapter.sanitize_request_headers(headers);
        DevinSemanticAdapter.sanitize_request_headers(headers);
    }

    fn decode_response(
        &self,
        route: &pooler_config::RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        if DroidOpenAiSemanticAdapter.supports(route) {
            DroidOpenAiSemanticAdapter.decode_response(route, body, cancellation)
        } else if XaiSemanticAdapter.supports(route) {
            XaiSemanticAdapter.decode_response(route, body, cancellation)
        } else if AnthropicSemanticAdapter.supports(route) {
            AnthropicSemanticAdapter.decode_response(route, body, cancellation)
        } else if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.decode_response(route, body, cancellation)
        } else if FxSemanticAdapter.supports(route) {
            FxSemanticAdapter.decode_response(route, body, cancellation)
        } else if FactorySemanticAdapter.supports(route) {
            FactorySemanticAdapter.decode_response(route, body, cancellation)
        } else if DevinSemanticAdapter.supports(route) {
            DevinSemanticAdapter.decode_response(route, body, cancellation)
        } else {
            Err(unsupported_semantic_route(route))
        }
    }

    fn decode_response_with_request_headers(
        &self,
        route: &pooler_config::RoutePlan,
        body: ProxyBody,
        request_headers: &http::HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        if DroidOpenAiSemanticAdapter.supports(route) {
            DroidOpenAiSemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else if XaiSemanticAdapter.supports(route) {
            XaiSemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else if AnthropicSemanticAdapter.supports(route) {
            AnthropicSemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else if FxSemanticAdapter.supports(route) {
            FxSemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else if FactorySemanticAdapter.supports(route) {
            FactorySemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else if DevinSemanticAdapter.supports(route) {
            DevinSemanticAdapter.decode_response_with_request_headers(
                route,
                body,
                request_headers,
                cancellation,
            )
        } else {
            Err(unsupported_semantic_route(route))
        }
    }

    fn decode_response_with_hint(
        &self,
        route: &pooler_config::RoutePlan,
        body: ProxyBody,
        request_headers: &http::HeaderMap,
        hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        if DroidOpenAiSemanticAdapter.supports(route) {
            DroidOpenAiSemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else if XaiSemanticAdapter.supports(route) {
            XaiSemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else if AnthropicSemanticAdapter.supports(route) {
            AnthropicSemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else if GeminiSemanticAdapter.supports(route) {
            GeminiSemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else if FxSemanticAdapter.supports(route) {
            FxSemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else if FactorySemanticAdapter.supports(route) {
            FactorySemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else if DevinSemanticAdapter.supports(route) {
            DevinSemanticAdapter.decode_response_with_hint(
                route,
                body,
                request_headers,
                hint,
                cancellation,
            )
        } else {
            Err(unsupported_semantic_route(route))
        }
    }
}

fn unsupported_semantic_route(route: &pooler_config::RoutePlan) -> BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("no semantic adapter supports route `{}`", route.id()),
    ))
}

/// A listener's concrete address after binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerAddress {
    id: Arc<str>,
    address: Arc<str>,
}

impl ListenerAddress {
    /// Stable listener ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Display form of the assigned TCP address or Unix path.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Errors raised while binding or running concrete HTTP listeners.
#[derive(Debug, Error)]
pub enum HttpProxyServerError {
    /// A configured listener failed to bind.
    #[error("failed to bind listener `{listener}`: {source}")]
    Bind {
        listener: String,
        #[source]
        source: io::Error,
    },
    /// Proxy transport setup failed.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    /// A configured TLS listener could not be prepared.
    #[error("failed to prepare TLS listener `{listener}`: {message}")]
    Tls { listener: String, message: String },
    /// Graceful drain exceeded its bound.
    #[error(transparent)]
    Drain(#[from] DrainError),
    /// A listener task failed unexpectedly.
    #[error("listener `{listener}` failed: {message}")]
    Listener { listener: String, message: String },
    /// `run` already consumed the bound sockets.
    #[error("HTTP proxy server is already running")]
    AlreadyRunning,
    /// Reload tried to change sockets that were already bound.
    #[error("configuration reload cannot change the bound listener set; restart is required")]
    ListenerSetChanged,
    /// The configured management listener could not be started.
    #[error(transparent)]
    Management(#[from] ManagementServerError),
    /// Configured model discovery could not be constructed.
    #[error(transparent)]
    CatalogRuntime(#[from] CatalogRuntimeError),
    /// Configured model discovery could not publish a complete refresh.
    #[error(transparent)]
    CatalogRefresh(#[from] pooler_model_catalog::CatalogError),
    /// No remote model catalog exists in the active generation.
    #[error("model catalog refresh is unavailable because no catalog is configured")]
    CatalogUnavailable,
    /// A queued management operation no longer matches the active generation.
    #[error("management operation generation changed from {expected} to {actual}")]
    StaleManagementGeneration { expected: u64, actual: u64 },
}

/// Result of applying a compiled HTTP runtime candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReloadOutcome {
    /// The candidate was equivalent and no generation changed.
    Unchanged { generation: u64 },
    /// The candidate was atomically published for new requests.
    Reloaded { generation: u64 },
}

impl HttpReloadOutcome {
    /// Runtime generation visible after the reload attempt.
    #[must_use]
    pub const fn generation(self) -> u64 {
        match self {
            Self::Unchanged { generation } | Self::Reloaded { generation } => generation,
        }
    }

    /// Whether a new generation was published.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Reloaded { .. })
    }
}

enum BoundListener {
    Tcp {
        id: Arc<str>,
        listener: TcpListener,
        dispatch: Arc<ArcSwap<RuntimeGeneration>>,
    },
    Unix {
        id: Arc<str>,
        listener: UnixListener,
        path: UnixSocketPath,
        dispatch: Arc<ArcSwap<RuntimeGeneration>>,
    },
}

struct UnixSocketPath {
    path: PathBuf,
    _resource: RuntimeResourceGuard,
}

impl Drop for UnixSocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct RuntimeState {
    listeners: Mutex<Option<Vec<BoundListener>>>,
    dispatch: Arc<ArcSwap<RuntimeGeneration>>,
    reload_lock: Arc<AsyncMutex<()>>,
    native: Arc<NativeRuntime>,
    retired: Mutex<Vec<Vec<Arc<RuntimeProxy>>>>,
    metrics: MetricsRegistry,
    traces: pooler_observe::TraceRecorder,
    active: ActiveCounts,
    management: Option<ManagementHttpServer>,
    management_api: Option<Arc<ManagementApi>>,
    cancellation: CancellationToken,
    resources: RuntimeResources,
}

/// Immutable runtime dispatch table for one configuration generation.
///
/// Accept loops hold the swap independently from each bound socket. A request
/// loads one table before dispatch, so every request sees one coherent plan;
/// an in-flight request retains its selected proxy and therefore its old
/// generation until the response body ends.
pub(crate) struct RuntimeGeneration {
    pub(crate) config: Arc<CompiledConfig>,
    proxies: BTreeMap<Arc<str>, Arc<RuntimeProxy>>,
    tls: BTreeMap<Arc<str>, Option<Arc<PreparedTls>>>,
    pub(crate) pooling: Arc<PoolingCoordinator>,
    pub(crate) catalog: Option<Arc<CatalogRuntime>>,
}

/// A concrete HTTP/1 listener set serving every compiled listener.
#[derive(Clone)]
pub struct HttpProxyServer {
    state: Arc<RuntimeState>,
    addresses: Arc<Vec<ListenerAddress>>,
}

impl std::fmt::Debug for HttpProxyServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProxyServer")
            .field("listeners", &self.addresses)
            .field("active", &self.active())
            .field("draining", &self.is_draining())
            .finish()
    }
}

impl HttpProxyServer {
    /// Bind all listeners before accepting any downstream connection.
    pub async fn bind(config: CompiledConfig) -> Result<Self, HttpProxyServerError> {
        Self::bind_with_native_runtime(config, Arc::new(NativeRuntime::disabled())).await
    }

    /// Bind listeners with a caller-owned pooling coordinator.
    ///
    /// The coordinator may be backed by an encrypted SQLite store. It is
    /// retained by every configuration generation published by this server.
    pub async fn bind_with_pooling(
        config: CompiledConfig,
        pooling: Arc<PoolingCoordinator>,
    ) -> Result<Self, HttpProxyServerError> {
        Self::bind_with_native_runtime_and_pooling(
            config,
            Arc::new(NativeRuntime::disabled()),
            pooling,
        )
        .await
    }

    /// Bind listeners with injected native and account-pooling runtimes.
    ///
    /// Both runtimes are shared by all listeners. The pooling coordinator is
    /// also reused, through its backing store, when configuration reloads.
    pub async fn bind_with_native_runtime_and_pooling(
        config: CompiledConfig,
        native: Arc<NativeRuntime>,
        pooling: Arc<PoolingCoordinator>,
    ) -> Result<Self, HttpProxyServerError> {
        Self::bind_inner(config, native, pooling).await
    }

    /// Bind listeners with an injected native provider runtime. This keeps
    /// credential stores and refresh policy outside immutable configuration
    /// while allowing native routes to share one refresh coordinator.
    pub async fn bind_with_native_runtime(
        config: CompiledConfig,
        native: Arc<NativeRuntime>,
    ) -> Result<Self, HttpProxyServerError> {
        let pooling =
            Arc::new(PoolingCoordinator::new(&config).map_err(|error| {
                HttpProxyServerError::Proxy(ProxyError::Pool(error.to_string()))
            })?);
        Self::bind_inner(config, native, pooling).await
    }

    async fn bind_inner(
        config: CompiledConfig,
        native: Arc<NativeRuntime>,
        pooling: Arc<PoolingCoordinator>,
    ) -> Result<Self, HttpProxyServerError> {
        let catalog = prepare_catalog(&config, Arc::clone(&native)).await?;
        let pooling = Arc::new(
            pooling
                .as_ref()
                .clone()
                .with_optional_catalog(catalog.as_ref().map(|catalog| catalog.service())),
        );
        let config = Arc::new(config);
        let resources = RuntimeResources::new();
        let dispatch = Arc::new(ArcSwap::from_pointee(RuntimeGeneration {
            config: Arc::clone(&config),
            proxies: BTreeMap::new(),
            tls: BTreeMap::new(),
            pooling: Arc::clone(&pooling),
            catalog: catalog.clone(),
        }));
        let metrics = MetricsRegistry::default();
        let traces = pooler_observe::TraceRecorder::default();
        let active = ActiveCounts::new();
        let cancellation = CancellationToken::new();
        let (native_commands, native_command_receiver) = mpsc::channel(16);
        let reload_lock = Arc::new(AsyncMutex::new(()));
        let management_api = config.management().map(|plan| {
            Arc::new(ManagementApi::with_runtime_dispatch(
                plan.clone(),
                Arc::clone(&config),
                Arc::clone(&pooling),
                Arc::clone(&dispatch),
                active.clone(),
                ManagementRuntimeServices {
                    metrics: metrics.clone(),
                    traces: traces.clone(),
                    native_commands,
                },
            ))
        });
        if let Some(api) = management_api.as_ref() {
            tokio::spawn(run_native_account_commands(
                native_command_receiver,
                Arc::clone(&native),
                Arc::clone(&dispatch),
                Arc::clone(&reload_lock),
                Arc::downgrade(api),
                cancellation.clone(),
            ));
        }
        let management = match management_api.as_ref() {
            Some(api) => Some(ManagementHttpServer::bind(Arc::clone(api)).await?),
            None => None,
        };
        let mut listeners = Vec::with_capacity(config.listeners().len());
        let mut proxies = BTreeMap::new();
        let mut tls_by_listener = BTreeMap::new();
        let mut addresses = Vec::with_capacity(config.listeners().len());
        let extensions = extension_registry(&config)?;

        for plan in config.listeners().values() {
            let id: Arc<str> = Arc::from(plan.id());
            let proxy = Arc::new(
                HttpProxy::with_semantic_adapter_and_pooling_and_native(
                    // Native provider handling is selected per upstream at the
                    // attempt boundary; all listeners share this runtime.
                    Arc::clone(&config),
                    Arc::clone(&id),
                    RuntimeSemanticAdapter,
                    Arc::clone(&pooling),
                    Arc::clone(&native),
                )?
                .with_extensions(Arc::clone(&extensions))
                .with_observability(metrics.clone())
                .with_trace_recorder(traces.clone())
                .with_runtime_resources(resources.clone()),
            );
            let bind = plan.bind();
            let prepared_tls = plan
                .tls()
                .map(PreparedTls::load)
                .transpose()
                .map_err(|error: TlsError| HttpProxyServerError::Tls {
                    listener: id.to_string(),
                    message: error.to_string(),
                })?
                .map(Arc::new);
            tls_by_listener.insert(Arc::clone(&id), prepared_tls);
            if bind.starts_with('/') || bind.starts_with("unix:") {
                if plan.tls().is_some() {
                    return Err(HttpProxyServerError::Tls {
                        listener: id.to_string(),
                        message: "TLS is supported only on TCP listeners".to_owned(),
                    });
                }
                let path = bind.strip_prefix("unix:").unwrap_or(bind);
                let listener =
                    UnixListener::bind(path).map_err(|source| HttpProxyServerError::Bind {
                        listener: bind.to_owned(),
                        source,
                    })?;
                listeners.push(BoundListener::Unix {
                    id: Arc::clone(&id),
                    listener,
                    path: UnixSocketPath {
                        path: PathBuf::from(path),
                        _resource: resources.temporary_file(),
                    },
                    dispatch: Arc::clone(&dispatch),
                });
                addresses.push(ListenerAddress {
                    id: Arc::clone(&id),
                    address: Arc::from(path),
                });
            } else {
                let listener =
                    TcpListener::bind(bind)
                        .await
                        .map_err(|source| HttpProxyServerError::Bind {
                            listener: bind.to_owned(),
                            source,
                        })?;
                let address =
                    listener
                        .local_addr()
                        .map_err(|source| HttpProxyServerError::Bind {
                            listener: bind.to_owned(),
                            source,
                        })?;
                listeners.push(BoundListener::Tcp {
                    id: Arc::clone(&id),
                    listener,
                    dispatch: Arc::clone(&dispatch),
                });
                addresses.push(ListenerAddress {
                    id: Arc::clone(&id),
                    address: Arc::from(address.to_string()),
                });
            }
            proxies.insert(id, proxy);
        }

        dispatch.store(Arc::new(RuntimeGeneration {
            config: Arc::clone(&config),
            proxies,
            tls: tls_by_listener,
            pooling: Arc::clone(&pooling),
            catalog,
        }));

        Ok(Self {
            state: Arc::new(RuntimeState {
                listeners: Mutex::new(Some(listeners)),
                dispatch,
                reload_lock,
                native,
                retired: Mutex::new(Vec::new()),
                metrics,
                traces,
                active,
                management,
                management_api,
                cancellation,
                resources,
            }),
            addresses: Arc::new(addresses),
        })
    }

    /// Addresses assigned while binding, in compiled listener order.
    #[must_use]
    pub fn listener_addresses(&self) -> &[ListenerAddress] {
        self.addresses.as_slice()
    }

    /// Concrete management address assigned while binding, when management
    /// is enabled in the immutable configuration.
    #[must_use]
    pub fn management_address(&self) -> Option<&str> {
        self.state
            .management
            .as_ref()
            .map(ManagementHttpServer::address)
    }

    /// Return the live authenticated management API, when enabled.
    #[must_use]
    pub fn management_api(&self) -> Option<Arc<ManagementApi>> {
        self.state.management_api.clone()
    }

    /// Notification used by compatibility callers observing management reload requests.
    #[must_use]
    pub fn management_reload_notifier(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.state
            .management_api
            .as_ref()
            .map(|api| api.reload_notifier())
    }

    /// Wait for the next bounded management reload request.
    ///
    /// The boolean is true only for a catalog-only refresh; the final value is
    /// the accepting configuration generation. A server without management
    /// enabled waits forever rather than causing caller spin.
    pub async fn next_management_reload_request(&self) -> (u64, bool, u64) {
        let Some(api) = self.state.management_api.as_ref() else {
            return std::future::pending().await;
        };
        loop {
            let request = api.next_reload_request().await;
            let generation = self.state.dispatch.load_full();
            if generation.config.generation() == request.generation {
                return (
                    request.id,
                    request.kind == ManagementReloadKind::Catalog,
                    request.generation,
                );
            }
            let catalog_generation = generation
                .catalog
                .as_ref()
                .map(|catalog| catalog.snapshot().generation());
            api.complete_reload(
                request.id,
                "failed",
                generation.config.generation(),
                catalog_generation,
            );
        }
    }

    /// Record a correlated management reload completion in bounded API state.
    /// `changed` is `None` for failure, `Some(false)` for unchanged, and
    /// `Some(true)` for success with newly published state.
    pub fn complete_management_reload(&self, request_id: u64, changed: Option<bool>) {
        let generation = self.state.dispatch.load_full();
        let outcome = match changed {
            Some(true) => "succeeded",
            Some(false) => "unchanged",
            None => "failed",
        };
        let catalog_generation = generation
            .catalog
            .as_ref()
            .map(|catalog| catalog.snapshot().generation());
        if let Some(api) = self.state.management_api.as_ref() {
            api.complete_reload(
                request_id,
                outcome,
                generation.config.generation(),
                catalog_generation,
            );
        }
    }

    /// Refresh only the active remote model catalog without recompiling or
    /// publishing a configuration generation.
    pub async fn refresh_catalog(
        &self,
        expected_generation: u64,
    ) -> Result<bool, HttpProxyServerError> {
        let _guard = self.state.reload_lock.lock().await;
        let generation = self.state.dispatch.load_full();
        let actual_generation = generation.config.generation();
        if actual_generation != expected_generation {
            return Err(HttpProxyServerError::StaleManagementGeneration {
                expected: expected_generation,
                actual: actual_generation,
            });
        }
        let Some(catalog) = generation.catalog.as_ref() else {
            return Err(HttpProxyServerError::CatalogUnavailable);
        };
        let before = catalog.snapshot().generation();
        catalog.refresh().await?;
        Ok(catalog.snapshot().generation() != before)
    }

    /// Return the process-shared bounded metrics registry.
    #[must_use]
    pub fn observability(&self) -> MetricsRegistry {
        self.state.metrics.clone()
    }

    /// Number of active requests across listeners.
    #[must_use]
    pub fn active(&self) -> usize {
        self.state.active.total()
    }

    /// Return live and peak counts from production runtime ownership guards.
    #[must_use]
    pub fn resource_snapshot(&self) -> RuntimeResourceSnapshot {
        self.state
            .resources
            .snapshot()
            .merge(self.state.native.resource_snapshot())
    }

    /// Whether shutdown has begun on any listener.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.all_proxies()
            .iter()
            .any(|proxy| proxy.drain_controller().is_draining())
    }

    /// Configuration generation used for newly admitted requests.
    #[must_use]
    pub fn config_generation(&self) -> u64 {
        self.state.dispatch.load().config.generation()
    }

    /// Current immutable compiled plan for diagnostics and management views.
    #[must_use]
    pub fn config(&self) -> Arc<CompiledConfig> {
        let snapshot = self.state.dispatch.load_full();
        snapshot.config.clone()
    }

    /// Return the mutable pooling coordinator for the active generation.
    #[must_use]
    pub fn pooling(&self) -> Arc<PoolingCoordinator> {
        let snapshot = self.state.dispatch.load_full();
        snapshot.pooling.clone()
    }

    /// Current remote model-catalog runtime, when discovery is configured.
    #[must_use]
    pub fn catalog(&self) -> Option<Arc<CatalogRuntime>> {
        self.state.dispatch.load_full().catalog.clone()
    }

    /// Atomically publish a compiled route plan for new requests.
    ///
    /// Candidate proxies are fully constructed before the swap. Existing
    /// requests retain their old proxy `Arc`, while new requests load the new
    /// immutable generation from the dispatch table. A changed socket set is
    /// rejected because replacing bound sockets requires a process-level
    /// listener handoff; the current service remains untouched.
    pub async fn reload(
        &self,
        candidate: CompiledConfig,
    ) -> Result<HttpReloadOutcome, HttpProxyServerError> {
        self.reload_inner(candidate, None).await
    }

    /// Apply a management-requested candidate only if its accepting generation
    /// is still active when the reload lock is acquired.
    pub async fn reload_for_generation(
        &self,
        candidate: CompiledConfig,
        expected_generation: u64,
    ) -> Result<HttpReloadOutcome, HttpProxyServerError> {
        self.reload_inner(candidate, Some(expected_generation))
            .await
    }

    async fn reload_inner(
        &self,
        candidate: CompiledConfig,
        expected_generation: Option<u64>,
    ) -> Result<HttpReloadOutcome, HttpProxyServerError> {
        let _guard = self.state.reload_lock.lock().await;
        let current = self.state.dispatch.load_full();
        if let Some(expected) = expected_generation {
            let actual = current.config.generation();
            if expected != actual {
                return Err(HttpProxyServerError::StaleManagementGeneration { expected, actual });
            }
        }
        if !same_listener_bindings(&current.config, &candidate) {
            return Err(HttpProxyServerError::ListenerSetChanged);
        }
        if current.config.management() != candidate.management() {
            return Err(HttpProxyServerError::ListenerSetChanged);
        }
        let tls = prepare_tls_map(&candidate)?;
        if current.config.equivalent(&candidate) && same_tls_map(&current.tls, &tls) {
            return Ok(HttpReloadOutcome::Unchanged {
                generation: current.config.generation(),
            });
        }
        let catalog = prepare_catalog(&candidate, Arc::clone(&self.state.native)).await?;

        let generation = current.config.generation().saturating_add(1);
        let config = Arc::new(candidate.with_generation(generation));
        let pooling = Arc::new(
            current
                .pooling
                .reconfigure(&config)
                .map_err(|error| HttpProxyServerError::Proxy(ProxyError::Pool(error.to_string())))?
                .with_optional_catalog(catalog.as_ref().map(|catalog| catalog.service())),
        );
        let mut proxies = BTreeMap::new();
        let extensions = extension_registry(&config)?;
        for plan in config.listeners().values() {
            let id: Arc<str> = Arc::from(plan.id());
            let proxy = Arc::new(
                HttpProxy::with_semantic_adapter_and_pooling_and_native(
                    Arc::clone(&config),
                    Arc::clone(&id),
                    RuntimeSemanticAdapter,
                    Arc::clone(&pooling),
                    Arc::clone(&self.state.native),
                )?
                .with_extensions(Arc::clone(&extensions))
                .with_observability(self.state.metrics.clone())
                .with_trace_recorder(self.state.traces.clone())
                .with_runtime_resources(self.state.resources.clone()),
            );
            proxies.insert(id, proxy);
        }

        self.state
            .retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(current.proxies.values().cloned().collect());
        self.state.dispatch.store(Arc::new(RuntimeGeneration {
            config: Arc::clone(&config),
            proxies,
            tls,
            pooling: Arc::clone(&pooling),
            catalog,
        }));
        Ok(HttpReloadOutcome::Reloaded { generation })
    }

    /// Run all accept loops until graceful drain is requested.
    pub async fn run(&self) -> Result<(), HttpProxyServerError> {
        self.run_with_drain_timeout(Duration::from_secs(30)).await
    }

    async fn run_with_drain_timeout(
        &self,
        drain_timeout: Duration,
    ) -> Result<(), HttpProxyServerError> {
        let listeners = self
            .state
            .listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(HttpProxyServerError::AlreadyRunning)?;
        let mut tasks = JoinSet::new();
        let active = self.state.active.clone();
        for listener in listeners {
            let cancellation = self.state.cancellation.clone();
            let active = active.clone();
            let task = self.state.resources.task();
            let resources = self.state.resources.clone();
            tasks.spawn(async move {
                let _task = task;
                accept_loop(listener, cancellation, active, resources).await
            });
        }
        if let Some(management) = self.state.management.clone() {
            let task = self.state.resources.task();
            tasks.spawn(async move {
                let _task = task;
                management
                    .run()
                    .await
                    .map_err(|error| HttpProxyServerError::Listener {
                        listener: "management".to_owned(),
                        message: error.to_string(),
                    })
            });
        }

        loop {
            tokio::select! {
                _ = self.state.cancellation.cancelled() => break,
                result = tasks.join_next() => {
                    match result {
                        Some(Ok(Ok(()))) => {}
                        Some(Ok(Err(error))) => {
                            self.begin_drain();
                            return Err(error);
                        }
                        Some(Err(error)) => {
                            self.begin_drain();
                            return Err(HttpProxyServerError::Listener {
                                listener: "unknown".to_owned(),
                                message: error.to_string(),
                            });
                        }
                        None => break,
                    }
                }
            }
        }

        self.begin_drain();
        let drain_result = self.drain(drain_timeout).await;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => {
                    return Err(HttpProxyServerError::Listener {
                        listener: "unknown".to_owned(),
                        message: error.to_string(),
                    });
                }
            }
        }
        drain_result
    }

    /// Begin graceful drain and wait for all listener requests to finish.
    pub async fn drain(&self, timeout: Duration) -> Result<(), HttpProxyServerError> {
        self.begin_drain();
        let deadline = tokio::time::Instant::now() + timeout;
        for proxy in self.all_proxies() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Err(error) = proxy.drain(remaining).await {
                for proxy in self.all_proxies() {
                    proxy.cancel_active();
                }
                let cleanup_deadline = tokio::time::Instant::now() + FORCE_CANCEL_GRACE;
                for proxy in self.all_proxies() {
                    let remaining =
                        cleanup_deadline.saturating_duration_since(tokio::time::Instant::now());
                    proxy.drain(remaining).await?;
                }
                return Err(error.into());
            }
        }
        Ok(())
    }

    /// Signal all listeners to stop accepting connections.
    pub fn begin_drain(&self) {
        for proxy in self.all_proxies() {
            proxy.begin_drain();
        }
        if let Some(management) = &self.state.management {
            management.begin_shutdown();
        }
        self.state.cancellation.cancel();
    }

    /// Cancellation token used by process lifecycle integration.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.state.cancellation.clone()
    }

    fn current_proxies(&self) -> Vec<Arc<RuntimeProxy>> {
        self.state
            .dispatch
            .load_full()
            .proxies
            .values()
            .cloned()
            .collect()
    }

    fn all_proxies(&self) -> Vec<Arc<RuntimeProxy>> {
        let mut proxies = self.current_proxies();
        let mut retired = self
            .state
            .retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retired.retain(|group| {
            let active = group
                .iter()
                .map(|proxy| proxy.drain_controller().active())
                .sum::<usize>();
            if active > 0 {
                proxies.extend(group.iter().cloned());
                true
            } else {
                false
            }
        });
        proxies
    }
}

async fn run_native_account_commands(
    mut commands: mpsc::Receiver<NativeAccountCommand>,
    native: Arc<NativeRuntime>,
    dispatch: Arc<ArcSwap<RuntimeGeneration>>,
    reload_lock: Arc<AsyncMutex<()>>,
    management: Weak<ManagementApi>,
    cancellation: CancellationToken,
) {
    loop {
        let command = tokio::select! {
            () = cancellation.cancelled() => break,
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        let _reload_guard = reload_lock.lock().await;
        let generation = dispatch.load_full();
        let outcome = if generation.config.generation() != command.generation {
            "stale_generation"
        } else {
            let succeeded = match command.action {
                NativeAccountAction::Refresh => native
                    .refresh_account(
                        generation.config.as_ref(),
                        &command.account,
                        cancellation.child_token(),
                    )
                    .await
                    .is_ok(),
                NativeAccountAction::Revoke => {
                    let revoked = native
                        .revoke_account(generation.config.as_ref(), &command.account)
                        .await
                        .is_ok();
                    revoked
                        && generation
                            .pooling
                            .set_account_enabled(&command.account, false)
                            .is_ok()
                }
            };
            if succeeded {
                "succeeded"
            } else {
                "failed"
            }
        };
        if let Some(management) = management.upgrade() {
            management.record_native_result(
                command.action,
                &command.account,
                command.generation,
                outcome,
            );
        }
    }
}

async fn prepare_catalog(
    config: &CompiledConfig,
    native: Arc<NativeRuntime>,
) -> Result<Option<Arc<CatalogRuntime>>, HttpProxyServerError> {
    let catalog = CatalogRuntime::from_config(config, native)?;
    if let Some(catalog) = &catalog {
        catalog.refresh().await?;
    }
    Ok(catalog)
}

fn same_listener_bindings(current: &CompiledConfig, candidate: &CompiledConfig) -> bool {
    current.listeners().len() == candidate.listeners().len()
        && current.listeners().iter().all(|(id, plan)| {
            candidate.listeners().get(id).is_some_and(|other| {
                other.bind() == plan.bind() && other.protocol() == plan.protocol()
            })
        })
}

fn prepare_tls_map(
    config: &CompiledConfig,
) -> Result<BTreeMap<Arc<str>, Option<Arc<PreparedTls>>>, HttpProxyServerError> {
    config
        .listeners()
        .values()
        .map(|plan| {
            let id: Arc<str> = Arc::from(plan.id());
            let tls = plan
                .tls()
                .map(PreparedTls::load)
                .transpose()
                .map_err(|error: TlsError| HttpProxyServerError::Tls {
                    listener: id.to_string(),
                    message: error.to_string(),
                })?
                .map(Arc::new);
            Ok((id, tls))
        })
        .collect()
}

fn same_tls_map(
    current: &BTreeMap<Arc<str>, Option<Arc<PreparedTls>>>,
    candidate: &BTreeMap<Arc<str>, Option<Arc<PreparedTls>>>,
) -> bool {
    current.len() == candidate.len()
        && current.iter().all(|(id, current_tls)| {
            candidate
                .get(id)
                .is_some_and(|candidate_tls| same_prepared_tls(current_tls, candidate_tls))
        })
}

fn same_prepared_tls(
    current: &Option<Arc<PreparedTls>>,
    candidate: &Option<Arc<PreparedTls>>,
) -> bool {
    match (current, candidate) {
        (None, None) => true,
        (Some(current), Some(candidate)) => current.fingerprint() == candidate.fingerprint(),
        _ => false,
    }
}

fn extension_registry(
    config: &CompiledConfig,
) -> Result<Arc<ExtensionRegistry>, HttpProxyServerError> {
    let mut specs = Vec::with_capacity(config.extensions().len());
    let mut wasm_extensions = Vec::new();
    for plan in config.extensions().values() {
        let capabilities =
            ExtensionCapabilities::from_names(plan.capabilities().iter().map(AsRef::as_ref))
                .map_err(|error| HttpProxyServerError::Proxy(ProxyError::Extension(error)))?;
        let limits = plan.limits();
        let limits = ExtensionLimits {
            max_input_bytes: bounded_extension_usize(limits.max_input_bytes()),
            max_output_bytes: bounded_extension_usize(limits.max_output_bytes()),
            timeout: limits.timeout(),
            max_memory_bytes: limits.max_memory_bytes(),
            max_concurrency: limits.max_concurrency() as usize,
        };
        if let Some(command) = plan.command() {
            let args = plan
                .args()
                .iter()
                .map(|value| std::ffi::OsString::from(value.as_ref()));
            let spec = ExtensionSpec::new(plan.id(), command, args, capabilities, limits).map_err(
                |error| HttpProxyServerError::Proxy(ProxyError::Extension(error.to_string())),
            )?;
            specs.push(spec);
        } else if let Some(path) = plan.wasm() {
            let module = std::fs::read(path).map_err(|error| {
                HttpProxyServerError::Proxy(ProxyError::Extension(format!(
                    "failed to read WASM extension `{path}`: {error}"
                )))
            })?;
            let extension =
                WasmExtension::new(plan.id(), &module, capabilities, limits).map_err(|error| {
                    HttpProxyServerError::Proxy(ProxyError::Extension(error.to_string()))
                })?;
            wasm_extensions.push(extension);
        }
    }
    let mut registry = ExtensionRegistry::from_wasm_extensions(wasm_extensions)
        .map_err(|error| HttpProxyServerError::Proxy(ProxyError::Extension(error.to_string())))?;
    let process = ExtensionRegistry::from_specs(specs)
        .map_err(|error| HttpProxyServerError::Proxy(ProxyError::Extension(error.to_string())))?;
    registry
        .merge(process)
        .map_err(|error| HttpProxyServerError::Proxy(ProxyError::Extension(error.to_string())))?;
    Ok(Arc::new(registry))
}

fn bounded_extension_usize(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

/// Holds a management activity guard until the downstream response stream
/// ends or is dropped. Counting only until headers would make the read-only
/// management view miss long-running inference streams.
struct ActiveBody {
    inner: Pin<Box<ProxyBody>>,
    guard: Option<ActiveGuard>,
}

impl ActiveBody {
    fn new(inner: ProxyBody, guard: ActiveGuard) -> Self {
        Self {
            inner: Box::pin(inner),
            guard: Some(guard),
        }
    }
}

impl Body for ActiveBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.inner.as_mut().poll_frame(context);
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.guard.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

async fn accept_loop(
    listener: BoundListener,
    cancellation: CancellationToken,
    active: ActiveCounts,
    resources: RuntimeResources,
) -> Result<(), HttpProxyServerError> {
    match listener {
        BoundListener::Tcp {
            id,
            listener,
            dispatch,
        } => {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, peer) = result.map_err(|source| HttpProxyServerError::Listener {
                            listener: id.to_string(),
                            message: source.to_string(),
                        })?;
                        let generation = dispatch.load_full();
                        let dispatch = Arc::clone(&dispatch);
                        let connection_id = Arc::clone(&id);
                        let protocol = generation
                            .config
                            .listeners()
                            .get(id.as_ref())
                            .map_or(ListenerProtocol::Http1, |listener| listener.protocol());
                        let tls = generation.tls.get(id.as_ref()).cloned().flatten();
                        let cancellation = cancellation.clone();
                        let active = active.clone();
                        let task = resources.task();
                        connections.spawn(async move {
                            let _task = task;
                            serve_tcp_connection(
                                stream,
                                connection_id,
                                protocol,
                                tls,
                                dispatch,
                                cancellation,
                                active,
                            )
                            .await;
                        });
                        debug!(listener = %id, ?peer, "accepted HTTP connection");
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = result {
                            debug!(listener = %id, %error, "HTTP connection task failed");
                        }
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    debug!(listener = %id, %error, "HTTP connection task failed during drain");
                }
            }
        }
        BoundListener::Unix {
            id,
            listener,
            path: _path,
            dispatch,
        } => {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, _) = result.map_err(|source| HttpProxyServerError::Listener {
                            listener: id.to_string(),
                            message: source.to_string(),
                        })?;
                        let dispatch = Arc::clone(&dispatch);
                        let id = Arc::clone(&id);
                        let protocol = dispatch
                            .load()
                            .config
                            .listeners()
                            .get(id.as_ref())
                            .map_or(ListenerProtocol::Http1, |listener| listener.protocol());
                        let cancellation = cancellation.clone();
                        let active = active.clone();
                        let task = resources.task();
                        connections.spawn(async move {
                            let _task = task;
                            serve_connection(
                                TokioIo::new(stream),
                                id,
                                protocol,
                                dispatch,
                                cancellation,
                                active,
                            )
                            .await;
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = result {
                            debug!(listener = %id, %error, "HTTP connection task failed");
                        }
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    debug!(listener = %id, %error, "HTTP connection task failed during drain");
                }
            }
        }
    }
    Ok(())
}

async fn serve_connection<I>(
    io: TokioIo<I>,
    listener_id: Arc<str>,
    protocol: ListenerProtocol,
    dispatch: Arc<ArcSwap<RuntimeGeneration>>,
    cancellation: CancellationToken,
    active: ActiveCounts,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let request_listener_id = Arc::clone(&listener_id);
    let service = service_fn(move |request: Request<Incoming>| {
        let generation = dispatch.load_full();
        let proxy = generation
            .proxies
            .get(request_listener_id.as_ref())
            .cloned()
            .expect("bound listener must have a proxy in every generation");
        let active = active.clone();
        let listener = Arc::clone(&request_listener_id);
        async move {
            let guard = active.enter(listener.as_ref());
            let response = proxy.handle(request).await;
            let response = response.map(|body| ActiveBody::new(body, guard).boxed());
            Ok::<_, Infallible>(response)
        }
    });
    // HTTP/1 remains the default.  Cleartext HTTP/2 is only selected by an
    // explicit listener protocol, while `auto` is available for deployments
    // that intentionally accept either wire preface.  The auto builder keeps
    // one service implementation for both protocols and runs HTTP/2 streams
    // concurrently on the same connection.
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().keep_alive(true).max_headers(100);
    {
        let mut http2 = builder.http2();
        http2
            .max_concurrent_streams(Some(128))
            .max_frame_size(Some(16 * 1024))
            .max_header_list_size(64 * 1024)
            .max_pending_accept_reset_streams(Some(20))
            .max_local_error_reset_streams(Some(1024));
    }
    let builder = match protocol {
        ListenerProtocol::Http1 => builder.http1_only(),
        ListenerProtocol::Auto => builder,
        ListenerProtocol::H2c => builder.http2_only(),
    };
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);

    tokio::select! {
        result = &mut connection => {
            if let Err(error) = result {
                debug!(listener = %listener_id, %error, "HTTP connection closed with an error");
            }
        }
        _ = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();
            if let Err(error) = connection.await {
                debug!(listener = %listener_id, %error, "HTTP connection drained with an error");
            }
        }
    }
}

async fn serve_tcp_connection(
    stream: tokio::net::TcpStream,
    listener_id: Arc<str>,
    protocol: ListenerProtocol,
    tls: Option<Arc<PreparedTls>>,
    dispatch: Arc<ArcSwap<RuntimeGeneration>>,
    cancellation: CancellationToken,
    active: ActiveCounts,
) {
    if let Some(tls) = tls {
        match tls.accept(stream, &cancellation).await {
            Ok(Some(stream)) => {
                let negotiated = stream.get_ref().1.alpn_protocol();
                let protocol = match (protocol, negotiated) {
                    (ListenerProtocol::Http1, Some(b"h2")) => {
                        debug!(listener = %listener_id, "rejecting h2 negotiated on h1-only listener");
                        return;
                    }
                    (ListenerProtocol::Auto, Some(b"h2")) => ListenerProtocol::H2c,
                    (ListenerProtocol::Auto, Some(b"http/1.1")) => ListenerProtocol::Http1,
                    (ListenerProtocol::Http1, Some(b"http/1.1")) => ListenerProtocol::Http1,
                    (_, Some(_)) => {
                        debug!(listener = %listener_id, "rejecting TLS connection with unsupported ALPN protocol");
                        return;
                    }
                    (ListenerProtocol::Auto, None) => {
                        debug!(listener = %listener_id, "rejecting TLS connection without a configured ALPN protocol");
                        return;
                    }
                    (configured, None) => configured,
                };
                serve_connection(
                    TokioIo::new(stream),
                    listener_id,
                    protocol,
                    dispatch,
                    cancellation,
                    active,
                )
                .await;
            }
            Ok(None) => {}
            Err(TlsError::Cancelled) => {}
            Err(error) => {
                debug!(listener = %listener_id, %error, "TLS handshake failed");
            }
        }
    } else {
        serve_connection(
            TokioIo::new(stream),
            listener_id,
            protocol,
            dispatch,
            cancellation,
            active,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        },
    };

    use http::Response;
    use http_body_util::{BodyExt as _, Full};
    use pooler_auth::{
        OAuthCredentialProfile, OAuthFuture, OAuthRefresher, OAuthTokenStore, OAuthTokens,
        SecretValue,
    };
    use pooler_store::{CredentialState, MasterKey, SqliteOAuthTokenStore, SqliteStore, Store};
    use pooler_testkit::{normalize_json_value, Fixture, ScriptedChunk, ScriptedResult};
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Barrier, Notify},
        time::{sleep, Duration},
    };

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn management_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HOST,
            http::HeaderValue::from_static("localhost"),
        );
        headers
    }

    struct TestSecret {
        path: PathBuf,
    }

    impl TestSecret {
        fn new(value: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "pooler-http-runtime-secret-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, value).expect("test secret writes");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("test secret permissions");
            }
            Self { path }
        }

        fn reference(&self) -> String {
            format!("file:{}", self.path.display())
        }
    }

    impl Drop for TestSecret {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn spawn_one_shot_upstream(
        body: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let address = listener.local_addr().expect("upstream address available");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("upstream accepts");
            let request = read_request(&mut stream)
                .await
                .expect("upstream request bytes");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .await
                .expect("upstream response headers");
            stream
                .write_all(body)
                .await
                .expect("upstream response body");
            request
        });
        (address, task)
    }

    async fn send_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        stream
            .write_all(request)
            .await
            .expect("downstream request bytes");
        tokio::time::timeout(TEST_TIMEOUT, read_response(&mut stream))
            .await
            .expect("downstream response arrives before timeout")
            .expect("downstream response bytes")
    }

    async fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before HTTP headers",
                ));
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(bytes);
            }
        }
    }

    async fn read_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = read_headers(stream).await?;
        let header_length = header_end(&bytes).map_or(bytes.len(), |index| index + 4);
        let body_length = content_length(&bytes[..header_length]).unwrap_or_default();
        let request_length = header_length + body_length;
        while bytes.len() < request_length {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before request body",
                ));
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        bytes.truncate(request_length);
        Ok(bytes)
    }

    async fn read_response(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = header_end(&bytes) else {
                continue;
            };
            let Some(content_length) = content_length(&bytes[..header_end]) else {
                continue;
            };
            let response_end = header_end + 4 + content_length;
            if bytes.len() >= response_end {
                bytes.truncate(response_end);
                return Ok(bytes);
            }
        }
    }

    async fn read_response_until(stream: &mut TcpStream, marker: &[u8]) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(marker.len()).any(|window| window == marker) {
                return Ok(bytes);
            }
        }
    }

    async fn send_request_until(address: SocketAddr, request: &[u8], marker: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        stream
            .write_all(request)
            .await
            .expect("downstream request bytes");
        tokio::time::timeout(TEST_TIMEOUT, read_response_until(&mut stream, marker))
            .await
            .expect("downstream response arrives before timeout")
            .expect("downstream response bytes")
    }

    async fn send_request_until_idle(
        address: SocketAddr,
        request: &[u8],
        idle_timeout: Duration,
    ) -> Vec<u8> {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        stream
            .write_all(request)
            .await
            .expect("downstream request bytes");
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            match tokio::time::timeout(idle_timeout, stream.read(&mut buffer)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return bytes,
                Ok(Ok(read)) => bytes.extend_from_slice(&buffer[..read]),
            }
        }
    }

    fn header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &[u8]) -> Option<usize> {
        String::from_utf8_lossy(headers).lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
    }

    fn status(response: &[u8]) -> u16 {
        String::from_utf8_lossy(response)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap_or_default()
    }

    fn response_body(response: &[u8]) -> &[u8] {
        let Some(header_end) = header_end(response) else {
            return &[];
        };
        &response[header_end + 4..]
    }

    fn decode_chunked_body(body: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        let mut offset = 0;
        while offset < body.len() {
            let Some(line_end) = body[offset..]
                .windows(2)
                .position(|window| window == b"\r\n")
            else {
                break;
            };
            let line_end = offset + line_end;
            let Ok(size_text) = std::str::from_utf8(&body[offset..line_end]) else {
                break;
            };
            let Ok(size) = usize::from_str_radix(size_text.trim(), 16) else {
                break;
            };
            offset = line_end + 2;
            if size == 0 || offset.saturating_add(size) > body.len() {
                break;
            }
            decoded.extend_from_slice(&body[offset..offset + size]);
            offset += size;
            if body.get(offset..offset + 2) != Some(b"\r\n") {
                break;
            }
            offset += 2;
        }
        decoded
    }

    fn has_header(request: &[u8], expected: &str) -> bool {
        String::from_utf8_lossy(request).lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case(expected))
        })
    }

    fn request_header<'a>(request: &'a [u8], expected: &str) -> Option<&'a str> {
        let header_end = header_end(request)?;
        std::str::from_utf8(&request[..header_end])
            .ok()?
            .lines()
            .skip(1)
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(expected).then_some(value.trim())
            })
    }

    fn listener_address(server: &HttpProxyServer, id: &str) -> SocketAddr {
        server
            .listener_addresses()
            .iter()
            .find(|listener| listener.id() == id)
            .unwrap_or_else(|| panic!("listener `{id}` is not bound"))
            .address()
            .parse()
            .expect("ephemeral listener address")
    }

    async fn wait_for_active(server: &HttpProxyServer, expected: usize) {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if server.active() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("proxy reaches expected active count");
    }

    async fn stop_server(
        server: &HttpProxyServer,
        runner: tokio::task::JoinHandle<Result<(), HttpProxyServerError>>,
    ) {
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        assert_eq!(server.active(), 0);
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
    }

    #[tokio::test]
    async fn h2c_accepts_concurrent_streams_and_preserves_http1_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let barrier = Arc::new(Barrier::new(2));
        let upstream = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            async move {
                let mut tasks = Vec::new();
                for _ in 0..2 {
                    let (mut stream, _) = upstream_listener
                        .accept()
                        .await
                        .expect("upstream accepts both requests");
                    let barrier = Arc::clone(&barrier);
                    tasks.push(tokio::spawn(async move {
                        read_request(&mut stream).await.expect("upstream request");
                        barrier.wait().await;
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            )
                            .await
                            .expect("upstream response");
                    }));
                }
                for task in tasks {
                    task.await.expect("upstream request task");
                }
            }
        });

        let config = pooler_config::compile_yaml(
            "h2c.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0, protocol: h2c}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: h2c\n    listen: local\n    match: {{method: GET, path: /h2c}}\n    target: local\n"
            ),
        )
        .expect("h2c config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let stream = TcpStream::connect(address).await.expect("h2c connects");
        let (sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .expect("h2c handshake");
        let connection_task = tokio::spawn(connection);
        let request = || {
            Request::builder()
                .method("GET")
                .uri("http://localhost/h2c")
                .version(http::Version::HTTP_2)
                .header("host", "localhost")
                .body(Full::new(Bytes::new()))
                .expect("h2 request")
        };
        let first = sender.clone().send_request(request());
        let second = sender.clone().send_request(request());
        let (first, second) =
            tokio::time::timeout(TEST_TIMEOUT, async { tokio::join!(first, second) })
                .await
                .expect("concurrent h2 streams complete");
        let first = first.expect("first h2 response");
        let second = second.expect("second h2 response");
        assert_eq!(first.status(), http::StatusCode::OK);
        assert_eq!(second.status(), http::StatusCode::OK);
        assert_eq!(
            first
                .into_body()
                .collect()
                .await
                .expect("first body")
                .to_bytes()
                .as_ref(),
            b"ok"
        );
        assert_eq!(
            second
                .into_body()
                .collect()
                .await
                .expect("second body")
                .to_bytes()
                .as_ref(),
            b"ok"
        );

        drop(sender);
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        connection_task
            .await
            .expect("h2 connection task does not panic")
            .expect("h2 connection closes cleanly");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        drop(server);
        upstream.await.expect("upstream task");
    }

    #[tokio::test]
    async fn h2_route_header_limit_is_enforced_per_stream() {
        let config = pooler_config::compile_yaml(
            "h2-header-limit.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:0, protocol: h2c}}\nupstreams: {local: {url: http://127.0.0.1:1}}\nroutes:\n  - id: h2-header-limit\n    listen: local\n    match: {method: GET, path: /h2-header-limit}\n    limits: {max_header_bytes: 16}\n    target: local\n",
        )
        .expect("h2 header-limit config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let stream = TcpStream::connect(address).await.expect("h2c connects");
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .expect("h2c handshake");
        let connection_task = tokio::spawn(connection);
        let request = Request::builder()
            .method("GET")
            .uri("http://localhost/h2-header-limit")
            .version(http::Version::HTTP_2)
            .header("host", "localhost")
            .header("x-large", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            .body(Full::new(Bytes::new()))
            .expect("h2 request");
        let response = sender
            .send_request(request)
            .await
            .expect("h2 header-limit response");
        assert_eq!(
            response.status(),
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        drop(response);
        drop(sender);
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        connection_task
            .await
            .expect("h2 connection task does not panic")
            .expect("h2 connection closes cleanly");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        drop(server);
    }

    #[tokio::test]
    async fn h2_drain_sends_goaway_and_rejects_new_streams() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"goaway").await;
        let config = pooler_config::compile_yaml(
            "h2-goaway.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0, protocol: h2c}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: h2-goaway\n    listen: local\n    match: {{method: GET, path: /h2-goaway}}\n    target: local\n"
            ),
        )
        .expect("h2 GOAWAY config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let stream = TcpStream::connect(address).await.expect("h2c connects");
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .expect("h2c handshake");
        let connection_task = tokio::spawn(connection);
        let request = || {
            Request::builder()
                .method("GET")
                .uri("http://localhost/h2-goaway")
                .version(http::Version::HTTP_2)
                .header("host", "localhost")
                .body(Full::new(Bytes::new()))
                .expect("h2 request")
        };
        let response = sender
            .send_request(request())
            .await
            .expect("initial h2 response");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("initial body")
                .to_bytes()
                .as_ref(),
            b"goaway"
        );
        server.begin_drain();
        let second = tokio::time::timeout(TEST_TIMEOUT, sender.send_request(request()))
            .await
            .expect("GOAWAY response arrives");
        assert!(
            second.is_err()
                || second.expect("response exists").status()
                    == http::StatusCode::SERVICE_UNAVAILABLE
        );
        drop(sender);
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        connection_task
            .await
            .expect("h2 connection task does not panic")
            .expect("h2 connection closes cleanly");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        drop(server);
        upstream.await.expect("upstream task");
    }

    #[tokio::test]
    async fn explicit_auto_listener_accepts_http1_and_http2() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
                tasks.push(tokio::spawn(async move {
                    read_request(&mut stream).await.expect("upstream request");
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nauto",
                        )
                        .await
                        .expect("upstream response");
                }));
            }
            for task in tasks {
                task.await.expect("upstream task");
            }
        });
        let config = pooler_config::compile_yaml(
            "auto.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0, protocol: auto}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: auto-h2\n    listen: local\n    match: {{method: GET, path: /auto-h2}}\n    target: local\n  - id: auto-h1\n    listen: local\n    match: {{method: GET, path: /auto-h1}}\n    target: local\n"
            ),
        )
        .expect("auto config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let h2_stream = TcpStream::connect(address).await.expect("h2 connects");
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(h2_stream),
        )
        .await
        .expect("h2 handshake");
        let connection_task = tokio::spawn(connection);
        let h2_request = Request::builder()
            .method("GET")
            .uri("http://localhost/auto-h2")
            .version(http::Version::HTTP_2)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .expect("h2 request");
        let h2_response = sender.send_request(h2_request).await.expect("h2 response");
        assert_eq!(h2_response.status(), http::StatusCode::OK);
        assert_eq!(
            h2_response
                .into_body()
                .collect()
                .await
                .expect("h2 body")
                .to_bytes()
                .as_ref(),
            b"auto"
        );
        let h1_response = send_request(
            address,
            b"GET /auto-h1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&h1_response), 200);
        assert_eq!(response_body(&h1_response), b"auto");
        drop(sender);
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        connection_task
            .await
            .expect("h2 connection task does not panic")
            .expect("h2 connection closes cleanly");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        drop(server);
        upstream.await.expect("upstream task");
    }

    #[tokio::test]
    async fn h2_stream_reset_drops_the_active_proxy_body() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let headers_sent = Arc::new(Notify::new());
        let release_body = Arc::new(Notify::new());
        let upstream = tokio::spawn({
            let headers_sent = Arc::clone(&headers_sent);
            let release_body = Arc::clone(&release_body);
            async move {
                let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
                read_request(&mut stream).await.expect("upstream request");
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
                    .await
                    .expect("upstream response headers");
                headers_sent.notify_one();
                release_body.notified().await;
                let _ = stream.write_all(b"hello").await;
            }
        });

        let config = pooler_config::compile_yaml(
            "h2-reset.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0, protocol: h2c}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: h2-reset\n    listen: local\n    match: {{method: GET, path: /h2-reset}}\n    target: local\n"
            ),
        )
        .expect("h2 reset config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let stream = TcpStream::connect(address).await.expect("h2c connects");
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .expect("h2c handshake");
        let connection_task = tokio::spawn(connection);
        let request = Request::builder()
            .method("GET")
            .uri("http://localhost/h2-reset")
            .version(http::Version::HTTP_2)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .expect("h2 request");
        let response = sender
            .send_request(request)
            .await
            .expect("h2 response headers");
        headers_sent.notified().await;
        drop(response);
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if server.active() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reset releases the active proxy body");
        release_body.notify_one();
        drop(sender);
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        connection_task
            .await
            .expect("h2 connection task does not panic")
            .expect("h2 connection closes cleanly");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        drop(server);
        upstream.await.expect("upstream task");
    }

    #[tokio::test]
    async fn explicit_upstream_http2_uses_h2c_prior_knowledge() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let saw_http2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let upstream = tokio::spawn({
            let saw_http2 = Arc::clone(&saw_http2);
            async move {
                let (stream, _) = upstream_listener.accept().await.expect("upstream accepts");
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let saw_http2 = Arc::clone(&saw_http2);
                    async move {
                        saw_http2.store(
                            request.version() == http::Version::HTTP_2,
                            Ordering::Relaxed,
                        );
                        let response = Response::builder()
                            .status(http::StatusCode::OK)
                            .header("content-length", "8")
                            .body(Full::new(Bytes::from_static(b"upstream")))
                            .expect("h2 response");
                        Ok::<_, Infallible>(response)
                    }
                });
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .expect("upstream h2 connection");
            }
        });

        let config = pooler_config::compile_yaml(
            "upstream-h2c.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  local:\n    transport: {{kind: http, base_url: http://{upstream_address}, http2: true}}\nroutes:\n  - id: upstream-h2c\n    listen: local\n    match: {{method: GET, path: /upstream-h2c}}\n    target: local\n"
            ),
        )
        .expect("upstream h2c config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let response = send_request(
            address,
            b"GET /upstream-h2c HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"upstream");
        assert!(saw_http2.load(Ordering::Relaxed));
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        drop(server);
        upstream.await.expect("upstream task");
    }

    #[tokio::test]
    async fn forwards_opaque_bytes_across_ephemeral_listeners() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.expect("request bytes");
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Upstream: yes\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .expect("response bytes");
            request
        });

        let config = pooler_config::compile_yaml(
            "e2e.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: opaque\n    listen: local\n    match: {{method: GET, path: /proxy}}\n    target: local\n"
            ),
        )
        .expect("proxy config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let downstream_address: SocketAddr = server.listener_addresses()[0]
            .address()
            .parse()
            .expect("ephemeral listener address");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        // Give the accept loop a scheduling turn before connecting. TCP would
        // also queue the connection, but this keeps the test deterministic on
        // slower CI workers.
        sleep(Duration::from_millis(1)).await;
        let mut downstream = TcpStream::connect(downstream_address)
            .await
            .expect("downstream connects");
        downstream
            .write_all(
                b"GET /proxy?opaque=true HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("request bytes");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !response.ends_with(b"hello") {
            let read = tokio::time::timeout(Duration::from_secs(5), downstream.read(&mut buffer))
                .await
                .expect("response arrives before timeout")
                .expect("response bytes");
            assert_ne!(
                read,
                0,
                "response closed early: {}",
                String::from_utf8_lossy(&response)
            );
            response.extend_from_slice(&buffer[..read]);
        }
        drop(downstream);

        server
            .drain(Duration::from_secs(5))
            .await
            .expect("proxy drains");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        let upstream_request = upstream.await.expect("upstream task does not panic");

        assert!(upstream_request.starts_with(b"GET /proxy?opaque=true HTTP/1.1\r\n"));
        assert!(!upstream_request
            .windows(b"connection:".len())
            .any(|window| window.eq_ignore_ascii_case(b"connection:")));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"hello"));
        assert!(response
            .windows(b"x-upstream: yes".len())
            .any(|window| { window.eq_ignore_ascii_case(b"x-upstream: yes") }));
    }

    #[tokio::test]
    async fn dispatches_mixed_routes_on_one_listener() {
        let (first_address, first_upstream) = spawn_one_shot_upstream(b"first").await;
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"second").await;
        let config = pooler_config::compile_yaml(
            "mixed.yaml",
            &format!(
                "version: 1\nlisteners: {{shared: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: first\n    listen: shared\n    match: {{path: /first}}\n    target: first\n  - id: second\n    listen: shared\n    match: {{path: /second}}\n    target: second\n"
            ),
        )
        .expect("mixed config compiles");
        let server = match HttpProxyServer::bind(config).await {
            Ok(server) => server,
            Err(HttpProxyServerError::Proxy(ProxyError::Extension(error)))
                if error.contains("sandbox") =>
            {
                return
            }
            Err(error) => panic!("proxy binds: {error}"),
        };
        let address = listener_address(&server, "shared");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let first = send_request(address, b"GET /first HTTP/1.1\r\nHost: test\r\n\r\n").await;
        let second = send_request(address, b"GET /second HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&first), b"first");
        assert_eq!(response_body(&second), b"second");
        assert!(first_upstream
            .await
            .expect("first upstream")
            .starts_with(b"GET /first "));
        assert!(second_upstream
            .await
            .expect("second upstream")
            .starts_with(b"GET /second "));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn serves_same_path_on_two_independent_listeners() {
        let (first_address, first_upstream) = spawn_one_shot_upstream(b"listener-a").await;
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"listener-b").await;
        let config = pooler_config::compile_yaml(
            "listeners.yaml",
            &format!(
                "version: 1\nlisteners:\n  a: {{bind: 127.0.0.1:0}}\n  b: {{bind: 127.0.0.1:0}}\nupstreams:\n  a: {{url: http://{first_address}}}\n  b: {{url: http://{second_address}}}\nroutes:\n  - {{id: a, listen: a, match: {{path: /same}}, target: a}}\n  - {{id: b, listen: b, match: {{path: /same}}, target: b}}\n"
            ),
        )
        .expect("multi-listener config");
        let server = HttpProxyServer::bind(config).await.expect("listeners bind");
        let first_listener = listener_address(&server, "a");
        let second_listener = listener_address(&server, "b");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let first = send_request(first_listener, b"GET /same HTTP/1.1\r\nHost: test\r\n\r\n").await;
        let second =
            send_request(second_listener, b"GET /same HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&first), b"listener-a");
        assert_eq!(response_body(&second), b"listener-b");
        assert!(first_upstream
            .await
            .expect("first upstream")
            .starts_with(b"GET /same "));
        assert!(second_upstream
            .await
            .expect("second upstream")
            .starts_with(b"GET /same "));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn bearer_auth_rejects_before_upstream_and_is_not_forwarded() {
        let secret = TestSecret::new("correct-token\n");
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"accepted").await;
        let config = pooler_config::compile_yaml(
            "auth.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: protected\n    listen: local\n    match: {{path: /protected}}\n    downstream_auth: {{secret: {}}}\n    target: local\n",
                secret.reference()
            ),
        )
        .expect("auth config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let rejected = send_request(
            address,
            b"GET /protected HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer wrong\r\n\r\n",
        )
        .await;
        assert_eq!(status(&rejected), 401);
        let accepted = send_request(
            address,
            b"GET /protected HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer correct-token\r\n\r\n",
        )
        .await;
        assert_eq!(status(&accepted), 200);
        let upstream_request = upstream.await.expect("upstream task");
        assert!(!has_header(&upstream_request, "authorization"));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn rejects_declared_oversized_body_before_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let config = pooler_config::compile_yaml(
            "limit.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: limited\n    listen: local\n    match: {{method: POST, path: /limited}}\n    limits: {{max_request_body_bytes: 3}}\n    target: local\n  - id: expanded\n    listen: local\n    match: {{method: POST, path: /expanded}}\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /x, value: \"1234567890123456789012345678901234567890\"}}\n    limits: {{max_request_body_bytes: 16}}\n    target: local\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("limit config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(
            address,
            b"POST /limited HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nhello",
        )
        .await;
        assert_eq!(status(&response), 413);
        let encoded = send_request(
            address,
            b"POST /limited HTTP/1.1\r\nHost: test\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx",
        )
        .await;
        assert_eq!(status(&encoded), 415);
        let repeated_encoding = send_request(
            address,
            b"POST /limited HTTP/1.1\r\nHost: test\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx",
        )
        .await;
        assert_eq!(status(&repeated_encoding), 415);
        let expanded = send_request(
            address,
            b"POST /expanded HTTP/1.1\r\nHost: test\r\nContent-Length: 7\r\n\r\n{\"x\":0}",
        )
        .await;
        assert_eq!(status(&expanded), 413);
        let metrics = server.observability().snapshot();
        assert!(metrics
            .completions
            .iter()
            .any(|metric| metric.route == "limited" && metric.class == "invalid_request"));
        assert!(!metrics
            .completions
            .iter()
            .any(|metric| metric.route == "limited" && metric.class == "cancelled"));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn crashed_external_transform_returns_error_without_crashing_pooler() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let directory = tempfile::tempdir().expect("WASM fixture directory");
        let module_path = directory.path().join("trap.wasm");
        let module = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "handle") (param i32 i32) (result i64)
                unreachable))"#,
        )
        .expect("trap WAT");
        std::fs::write(&module_path, module).expect("trap module");
        let config = pooler_config::compile_yaml(
            "extension-crash.yaml",
            &format!(
                "version: 1\nextensions:\n  broken:\n    wasm: {}\n    capabilities: [transform]\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: external\n    listen: local\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.external.broken\n          with: {{pointer: /unused, value: null}}\n    response: {{mode: opaque}}\n    target: local\n",
                module_path.display(),
            ),
        )
        .expect("extension crash config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(
            address,
            b"POST / HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"x\":0}",
        )
        .await;
        assert_eq!(status(&response), 502);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn external_inspector_metadata_selects_and_rewrites_a_model() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"ok").await;
        let config = pooler_config::compile_yaml(
            "extension-inspect.yaml",
            &format!(
                "version: 1\nextensions:\n  selector:\n    command: /bin/sh\n    args: [-c, 'read line; printf \\\"%s\\\\n\\\" \\\"{{\\\\\"metadata\\\\\":{{\\\\\"model\\\\\":\\\\\"provider\\\\\"}}}}\\\"']\n    capabilities: [inspect]\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nmodels:\n  - id: provider\n    targets: [{{provider: local, upstream_model: upstream-provider}}]\nroutes:\n  - id: external-inspect\n    listen: local\n    ingress: {{mode: patch, inspectors: [inspect.external.selector]}}\n    response: {{mode: opaque}}\n    target: {{provider: local, model_from: inspected.model}}\n"
            ),
        )
        .expect("external inspector config compiles");
        let server = match HttpProxyServer::bind(config).await {
            Ok(server) => server,
            Err(HttpProxyServerError::Proxy(ProxyError::Extension(error)))
                if error.contains("sandbox") =>
            {
                return
            }
            Err(error) => panic!("proxy binds: {error}"),
        };
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(
            address,
            b"POST / HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert_eq!(status(&response), 200);
        let upstream_request = upstream.await.expect("upstream request");
        assert!(
            String::from_utf8_lossy(&upstream_request).contains("\"model\":\"upstream-provider\"")
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn wasm_inspector_selects_and_wasm_transform_changes_the_request() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"ok").await;
        let directory = tempfile::tempdir().expect("WASM fixture directory");
        let selector_path = directory.path().join("selector.wasm");
        let transformer_path = directory.path().join("transformer.wasm");
        let selector = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (data (i32.const 0) "{\"metadata\":{\"model\":\"provider\"}}")
              (func (export "handle") (param i32 i32) (result i64)
                i64.const 141733920768)
            )"#,
        )
        .expect("selector WAT");
        let transformer = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (data (i32.const 0) "{\"body\":[123,34,109,111,100,101,108,34,58,34,112,114,111,118,105,100,101,114,34,44,34,99,104,97,110,103,101,100,34,58,116,114,117,101,125],\"metadata\":{}}")
              (func (export "handle") (param i32 i32) (result i64)
                i64.const 657129996288)
            )"#,
        )
        .expect("transformer WAT");
        std::fs::write(&selector_path, selector).expect("selector module");
        std::fs::write(&transformer_path, transformer).expect("transformer module");
        let config = pooler_config::compile_yaml(
            "wasm-extension.yaml",
            &format!(
                "version: 1\nextensions:\n  selector:\n    wasm: {}\n    capabilities: [inspect]\n  transformer:\n    wasm: {}\n    capabilities: [transform]\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nmodels:\n  - id: provider\n    targets: [{{provider: local, upstream_model: upstream-provider}}]\nroutes:\n  - id: wasm\n    listen: local\n    ingress: {{mode: patch, inspectors: [inspect.external.selector]}}\n    request:\n      steps:\n        - use: transform.external.transformer\n          with: {{pointer: /unused, value: null}}\n    response: {{mode: opaque}}\n    target: {{provider: local, model_from: inspected.model}}\n",
                selector_path.display(),
                transformer_path.display(),
            ),
        )
        .expect("WASM extension config compiles");
        let server = HttpProxyServer::bind(config)
            .await
            .expect("WASM extension does not require bwrap");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(
            address,
            b"POST / HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert_eq!(status(&response), 200);
        let upstream_request = upstream.await.expect("upstream request");
        let upstream_request = String::from_utf8_lossy(&upstream_request);
        assert!(upstream_request.contains("\"model\":\"upstream-provider\""));
        assert!(upstream_request.contains("\"changed\":true"));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn terminates_oversized_upstream_response() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"hello").await;
        let config = pooler_config::compile_yaml(
            "response-limit.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: limited\n    listen: local\n    limits: {{max_response_body_bytes: 3}}\n    target: local\n"
            ),
        )
        .expect("response limit config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(address, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(status(&response), 502);
        assert_ne!(response_body(&response), b"hello");
        upstream.await.expect("upstream task");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn downstream_disconnect_releases_active_request() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            read_headers(&mut stream).await.expect("upstream request");
            let mut byte = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
                .await
                .expect("upstream is canceled")
                .expect("upstream read")
        });
        let config = pooler_config::compile_yaml(
            "cancel.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes: [{{id: cancel, listen: local, target: local}}]\n"
            ),
        )
        .expect("cancel config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let mut downstream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        downstream
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .expect("request writes");
        wait_for_active(&server, 1).await;
        drop(downstream);

        assert_eq!(upstream.await.expect("upstream task"), 0);
        tokio::time::timeout(TEST_TIMEOUT, async {
            while server.active() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("active request releases");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn management_active_counts_track_inference_until_stream_end() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let body_started = Arc::new(Notify::new());
        let release_body = Arc::new(Notify::new());
        let body_started_upstream = Arc::clone(&body_started);
        let release_body_upstream = Arc::clone(&release_body);
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            read_request(&mut stream).await.expect("upstream request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhel")
                .await
                .expect("upstream response prefix");
            body_started_upstream.notify_waiters();
            release_body_upstream.notified().await;
            stream
                .write_all(b"lo")
                .await
                .expect("upstream response suffix");
        });
        let config = pooler_config::compile_yaml(
            "management-active.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes: [{{id: active, listen: local, target: local}}]\n"
            ),
        )
        .expect("management active config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let api = server.management_api().expect("management API");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let mut downstream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        downstream
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("downstream request");

        wait_for_active(&server, 1).await;
        let active = api.handle(&http::Method::GET, "/active", &management_headers());
        assert_eq!(active.status, http::StatusCode::OK);
        assert!(String::from_utf8_lossy(&active.body).contains("\"active\":1"));

        tokio::time::timeout(TEST_TIMEOUT, body_started.notified())
            .await
            .expect("upstream starts response body");
        let prefix = tokio::time::timeout(
            TEST_TIMEOUT,
            read_response_until(&mut downstream, b"\r\n\r\nhel"),
        )
        .await
        .expect("response prefix arrives")
        .expect("response prefix reads");
        assert!(prefix.ends_with(b"hel"));
        assert_eq!(server.active(), 1);
        let active_during_stream = api.handle(&http::Method::GET, "/active", &management_headers());
        assert!(String::from_utf8_lossy(&active_during_stream.body).contains("\"active\":1"));

        release_body.notify_one();
        let suffix = tokio::time::timeout(TEST_TIMEOUT, read_response(&mut downstream))
            .await
            .expect("response suffix arrives")
            .expect("response suffix reads");
        assert!(suffix.ends_with(b"lo"));
        tokio::time::timeout(TEST_TIMEOUT, async {
            while server.active() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("active stream releases");
        let inactive = api.handle(&http::Method::GET, "/active", &management_headers());
        assert!(String::from_utf8_lossy(&inactive.body).contains("\"active\":0"));

        upstream.await.expect("upstream task");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn lifecycle_cancellation_force_drains_pending_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            read_headers(&mut stream).await.expect("upstream request");
            let mut byte = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
                .await
                .expect("upstream canceled")
                .expect("upstream read")
        });
        let config = pooler_config::compile_yaml(
            "lifecycle.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes: [{{id: pending, listen: local, target: local}}]\n"
            ),
        )
        .expect("lifecycle config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .run_with_drain_timeout(Duration::from_millis(20))
                    .await
            })
        };
        let client = tokio::spawn(async move {
            send_request(address, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").await
        });
        wait_for_active(&server, 1).await;
        server.cancellation_token().cancel();

        let result = tokio::time::timeout(TEST_TIMEOUT, runner)
            .await
            .expect("runner finishes after forced drain")
            .expect("runner task");
        assert!(matches!(result, Err(HttpProxyServerError::Drain(_))));
        assert_eq!(server.active(), 0);
        client.await.expect("client task");
        assert_eq!(upstream.await.expect("upstream task"), 0);
    }

    #[tokio::test]
    async fn patch_route_changes_reasoning_and_preserves_unknown_json() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"patched").await;
        let config = pooler_config::compile_yaml(
            "patch.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: patch\n    listen: local\n    match: {{method: POST, path: /patch}}\n    ingress: {{mode: patch, inspectors: [inspect.openai.model]}}\n    request:\n      steps:\n        - use: transform.json.set_when_model_prefix\n          with: {{prefix: gpt-, pointer: /reasoning/effort, value: high}}\n    target: local\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("patch route compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body =
            br#"{"model":"gpt-5.6-sol","reasoning":{"effort":"low"},"unknown":{"keep":[1,2]}}"#;
        let request = format!(
            "POST /patch HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(status(&response), 200);
        let upstream_request = upstream.await.expect("upstream task");
        let patched: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("patched JSON body");
        assert_eq!(patched["reasoning"]["effort"], "high");
        assert_eq!(patched["unknown"]["keep"], serde_json::json!([1, 2]));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn request_model_selects_provider_and_rewrites_upstream_model() {
        let fallback_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fallback binds");
        let fallback_address = fallback_listener.local_addr().expect("fallback address");
        let (selected_address, selected_upstream) = spawn_one_shot_upstream(b"selected").await;
        let selected_secret = TestSecret::new("selected-token\n");
        let config = pooler_config::compile_yaml(
            "model-route.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  fallback: {{url: http://{fallback_address}}}\n  selected:\n    url: http://{selected_address}\n    auth: {{secret: {}}}\nmodels:\n  - id: public-model\n    targets:\n      - {{provider: selected, upstream_model: provider-model, capabilities: [text]}}\nroutes:\n  - id: model-route\n    listen: local\n    match: {{method: POST, path: /model}}\n    ingress: {{mode: patch, inspectors: [inspect.openai.model]}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /model, value: mutated-model}}\n    target: {{provider: fallback, model_from: inspected.model}}\n    response: {{mode: opaque}}\n",
                selected_secret.reference()
            ),
        )
        .expect("model route compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"public-model","unknown":true}"#;
        let request = format!(
            "POST /model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(response_body(&response), b"selected");
        let upstream_request = selected_upstream.await.expect("selected upstream");
        assert!(String::from_utf8_lossy(&upstream_request)
            .to_ascii_lowercase()
            .contains("authorization: bearer selected-token"));
        let forwarded: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("forwarded JSON");
        assert_eq!(forwarded["model"], "provider-model");
        assert_eq!(forwarded["unknown"], true);
        for invalid_body in [br#"{"model":"unknown"}"#.as_slice(), br#"{}"#.as_slice()] {
            let invalid_request = format!(
                "POST /model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                invalid_body.len(),
                String::from_utf8_lossy(invalid_body)
            );
            let rejected = send_request(address, invalid_request.as_bytes()).await;
            assert_eq!(status(&rejected), 400);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fallback_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_model_selection_filters_targets_and_sticks_to_body_session() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("semantic pooling upstream binds");
        let upstream_address = listener
            .local_addr()
            .expect("semantic pooling upstream address");
        let upstream = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..3 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("semantic pooling upstream accepts");
                let request = read_request(&mut stream)
                    .await
                    .expect("semantic pooling request bytes");
                let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
                let first = request_text.contains("authorization: bearer first-token");
                let (status, reason, body, extra_headers) = if index == 0 && first {
                    (
                        429,
                        "Too Many Requests",
                        b"quota".as_slice(),
                        "x-error-code: insufficient_quota\r\nRetry-After: 1\r\n",
                    )
                } else {
                    (
                        200,
                        "OK",
                        b"data: {\"id\":\"chat-1\",\"model\":\"rebound-model\",\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chat-1\",\"model\":\"rebound-model\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\ndata: [DONE]\n\n".as_slice(),
                        "",
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("semantic pooling response headers");
                stream
                    .write_all(body)
                    .await
                    .expect("semantic pooling response body");
                requests.push(request);
            }
            requests
        });

        let first_secret = TestSecret::new("first-token");
        let blocked_secret = TestSecret::new("blocked-token");
        let rebound_secret = TestSecret::new("rebound-token");
        let config = pooler_config::compile_yaml(
            "semantic-model-selection.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{upstream_address}}}\n  blocked: {{url: http://{upstream_address}}}\n  rebound: {{url: http://{upstream_address}}}\naccounts:\n  first: {{provider: first, secret: {}}}\n  blocked: {{provider: blocked, secret: {}}}\n  rebound: {{provider: rebound, secret: {}}}\naccount_pools: {{pool: {{accounts: [first, blocked, rebound]}}}}\nmodels:\n  - id: public-model\n    targets:\n      - {{provider: first, upstream_model: first-model, capabilities: [text, streaming], codecs: [decode.factory.language_model]}}\n      - {{provider: blocked, upstream_model: blocked-model, capabilities: [streaming], codecs: [decode.other]}}\n      - {{provider: rebound, upstream_model: rebound-model, capabilities: [text, streaming], codecs: [decode.factory.language_model]}}\npolicies:\n  pooled:\n    selection: {{strategy: ordered_fallback, account_pool: pool, affinity: {{key: request.session_id, ttl: 10m, rebind: true}}}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}}\nroutes:\n  - id: factory-pooled\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: {{provider: first, model_from: request.model, policy: pooled}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: reject\n",
                first_secret.reference(),
                blocked_secret.reference(),
                rebound_secret.reference(),
            ),
        )
        .expect("semantic model-selection config compiles");
        let server = HttpProxyServer::bind(config)
            .await
            .expect("semantic model-selection server binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"sessionId":"body-session","prompt":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}"#;
        let request = |idempotency: &str| {
            format!(
                "POST /v3/ai/language-model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nAI-Language-Model-Id: public-model\r\nAI-Language-Model-Specification-Version: 3\r\nAI-Language-Model-Streaming: true\r\nIdempotency-Key: {idempotency}\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body),
            )
        };

        let first_response = send_request_until(
            address,
            request("semantic-session-1").as_bytes(),
            b"data: [DONE]\n\n",
        )
        .await;
        assert_eq!(status(&first_response), 200);
        assert!(String::from_utf8_lossy(&first_response).contains("ok"));
        let second_response = send_request_until(
            address,
            request("semantic-session-2").as_bytes(),
            b"data: [DONE]\n\n",
        )
        .await;
        assert_eq!(status(&second_response), 200);

        let requests = tokio::time::timeout(TEST_TIMEOUT, upstream)
            .await
            .expect("semantic pooling upstream completes")
            .expect("semantic pooling upstream task");
        assert_eq!(requests.len(), 3);
        let request_texts = requests
            .iter()
            .map(|request| String::from_utf8_lossy(request).to_ascii_lowercase())
            .collect::<Vec<_>>();
        assert!(request_texts[0].contains("authorization: bearer first-token"));
        assert!(
            request_texts[1].contains("authorization: bearer rebound-token"),
            "requests: {request_texts:?}"
        );
        assert!(
            request_texts[2].contains("authorization: bearer rebound-token"),
            "requests: {request_texts:?}"
        );
        for request in requests.iter().skip(1) {
            let body = response_body(request);
            let body: serde_json::Value = serde_json::from_slice(body).expect("OpenAI request");
            assert_eq!(body["model"], "rebound-model");
        }
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn pooled_patch_request_fails_over_after_credential_quota() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("pooling upstream binds");
        let upstream_address = listener.local_addr().expect("pooling upstream address");
        let upstream = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("pooling upstream accepts");
                let request = read_request(&mut stream)
                    .await
                    .expect("pooling request bytes");
                let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
                let quota = request_text.contains("bearer first-token") || index == 2;
                let (status, body) = if quota {
                    (429, b"quota".as_slice())
                } else {
                    (200, b"ok".as_slice())
                };
                let reason = if quota { "Too Many Requests" } else { "OK" };
                let code = if quota {
                    "x-error-code: insufficient_quota\r\nRetry-After: 1\r\n"
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n{code}Connection: close\r\n\r\n",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("pooling response headers");
                stream.write_all(body).await.expect("pooling response body");
                requests.push(request);
            }
            requests
        });
        let first_secret = TestSecret::new("first-token");
        let second_secret = TestSecret::new("second-token");
        let config = pooler_config::compile_yaml(
            "pooling.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\naccounts:\n  a-backup: {{provider: local, secret: {}}}\n  z-primary: {{provider: local, secret: {}}}\naccount_pools:\n  pool: {{accounts: [z-primary, a-backup]}}\npolicies:\n  pooled:\n    selection: {{strategy: ordered_fallback, account_pool: pool}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}}\nroutes:\n  - id: pooled\n    listen: local\n    match: {{method: POST, path: /pooled}}\n    ingress: {{mode: patch}}\n    target: {{provider: local, policy: pooled}}\n    response: {{mode: opaque}}\n",
                second_secret.reference(),
                first_secret.reference()
            ),
        )
        .expect("pooling config compiles");
        let server = HttpProxyServer::bind(config)
            .await
            .expect("pooling proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"public","value":true}"#;
        let request = format!(
            "POST /pooled HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nIdempotency-Key: pooling-test-1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"ok");
        let exhausted_request = request.replace("pooling-test-1", "pooling-test-2");
        let exhausted_response = send_request(address, exhausted_request.as_bytes()).await;
        assert_eq!(status(&exhausted_response), 429);
        assert_eq!(response_body(&exhausted_response), b"quota");
        let requests = tokio::time::timeout(TEST_TIMEOUT, upstream)
            .await
            .expect("pooling upstream completes")
            .expect("pooling upstream task");
        assert_eq!(requests.len(), 3);
        assert!(String::from_utf8_lossy(&requests[0]).contains("authorization: Bearer first-token"));
        assert!(
            String::from_utf8_lossy(&requests[1]).contains("authorization: Bearer second-token")
        );
        assert!(
            String::from_utf8_lossy(&requests[2]).contains("authorization: Bearer second-token")
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn sqlite_pooling_state_survives_server_restart() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("pooling upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("pooling upstream address");
        let upstream = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = upstream_listener
                    .accept()
                    .await
                    .expect("pooling upstream accepts");
                let request = read_request(&mut stream)
                    .await
                    .expect("pooling request bytes");
                let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
                let first = request_text.contains("bearer first-token");
                let (status, reason, body, headers) = if first {
                    (
                        429,
                        "Too Many Requests",
                        b"quota".as_slice(),
                        "x-error-code: insufficient_quota\r\nRetry-After: 60\r\n",
                    )
                } else {
                    (200, "OK", b"ok".as_slice(), "")
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("pooling response headers");
                stream.write_all(body).await.expect("pooling response body");
                requests.push(request);
            }
            requests
        });

        let first_secret = TestSecret::new("first-token");
        let second_secret = TestSecret::new("second-token");
        let config = pooler_config::compile_yaml(
            "pooling-restart.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\naccounts:\n  first: {{provider: local, secret: {}}}\n  second: {{provider: local, secret: {}}}\naccount_pools:\n  pool: {{accounts: [first, second]}}\npolicies:\n  pooled:\n    selection:\n      strategy: ordered_fallback\n      account_pool: pool\n      affinity: {{key: header:x-session, ttl: 10m, rebind: true}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1s, maximum_total_delay: 2s}}\nroutes:\n  - id: pooled\n    listen: local\n    match: {{method: POST, path: /pooled}}\n    ingress: {{mode: patch}}\n    target: {{provider: local, policy: pooled}}\n    response: {{mode: opaque}}\n",
                first_secret.reference(),
                second_secret.reference()
            ),
        )
        .expect("pooling restart config");

        let directory = tempdir().expect("pooling store directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("pooling store directory permissions");
        }
        let store_path = directory.path().join("credentials.sqlite3");
        let master_key = MasterKey::from_bytes(b"pooling-restart-test-key").expect("master key");
        let store = SqliteStore::open_encrypted(&store_path, master_key.clone()).expect("store");
        let pooling = Arc::new(
            PoolingCoordinator::with_store(&config, Arc::new(store.clone()))
                .expect("pooling coordinator"),
        );
        let server = HttpProxyServer::bind_with_pooling(config.clone(), pooling)
            .await
            .expect("pooling server binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"public","value":true}"#;
        let request = format!(
            "POST /pooled HTTP/1.1\r\nHost: test\r\nX-Session: restart-session\r\nContent-Type: application/json\r\nIdempotency-Key: pooling-restart-1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"ok");
        upstream.await.expect("pooling upstream task");

        stop_server(&server, runner).await;
        drop(server);

        let persisted_states = store.credential_states().expect("credential states");
        assert!(persisted_states
            .iter()
            .any(|state| state.credential_id == "first" && state.enabled));
        assert!(store
            .cooldowns(0)
            .expect("cooldowns")
            .iter()
            .any(|cooldown| cooldown.scope == "credential" && cooldown.key == "first"));
        assert!(!store.session_affinities(0).expect("affinities").is_empty());
        assert!(store.decisions().expect("decisions").len() >= 2);

        let restart_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("restart upstream binds");
        let restart_address = restart_listener
            .local_addr()
            .expect("restart upstream address");
        let restart_upstream = tokio::spawn(async move {
            let (mut stream, _) = restart_listener
                .accept()
                .await
                .expect("restart upstream accepts");
            let request = read_request(&mut stream)
                .await
                .expect("restart request bytes");
            let body = b"restarted";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("restart response headers");
            stream.write_all(body).await.expect("restart response body");
            request
        });
        let restart_yaml = format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{restart_address}}}}}\naccounts:\n  first: {{provider: local, secret: {}}}\n  second: {{provider: local, secret: {}}}\naccount_pools:\n  pool: {{accounts: [first, second]}}\npolicies:\n  pooled:\n    selection: {{strategy: ordered_fallback, account_pool: pool, affinity: {{key: header:x-session, ttl: 10m, rebind: true}}}}\nroutes:\n  - id: pooled\n    listen: local\n    match: {{method: POST, path: /pooled}}\n    ingress: {{mode: patch}}\n    target: {{provider: local, policy: pooled}}\n    response: {{mode: opaque}}\n",
            first_secret.reference(),
            second_secret.reference()
        );
        let restarted_config = pooler_config::compile_yaml("pooling-restart.yaml", &restart_yaml)
            .expect("restart config");
        let restarted_store =
            SqliteStore::open_encrypted(&store_path, master_key).expect("reopen store");
        let restarted_pooling = Arc::new(
            PoolingCoordinator::with_store(&restarted_config, Arc::new(restarted_store.clone()))
                .expect("restarted pooling coordinator"),
        );
        let restarted_server =
            HttpProxyServer::bind_with_pooling(restarted_config, restarted_pooling)
                .await
                .expect("restarted server binds");
        let restarted_runner = {
            let server = restarted_server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let restarted_request = format!(
            "POST /pooled HTTP/1.1\r\nHost: test\r\nX-Session: restart-session\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let restarted_response = send_request(
            listener_address(&restarted_server, "local"),
            restarted_request.as_bytes(),
        )
        .await;
        assert_eq!(status(&restarted_response), 200);
        assert_eq!(response_body(&restarted_response), b"restarted");
        let restarted_request = restart_upstream.await.expect("restart upstream task");
        assert!(String::from_utf8_lossy(&restarted_request)
            .to_ascii_lowercase()
            .contains("authorization: bearer second-token"));
        assert!(
            restarted_store
                .decisions()
                .expect("restarted decisions")
                .len()
                >= 3
        );
        stop_server(&restarted_server, restarted_runner).await;
    }

    #[tokio::test]
    async fn patch_model_validation_only_runs_for_the_selected_source() {
        let (plain_address, plain_upstream) = spawn_one_shot_upstream(b"plain").await;
        let (selected_address, selected_upstream) = spawn_one_shot_upstream(b"selected").await;
        let config = pooler_config::compile_yaml(
            "model-source.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  plain: {{url: http://{plain_address}}}\n  selected: {{url: http://{selected_address}}}\nmodels:\n  - id: public\n    targets: [{{provider: selected, upstream_model: private}}]\nroutes:\n  - id: plain\n    listen: local\n    match: {{method: POST, path: /plain}}\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /value, value: true}}\n    target: plain\n    response: {{mode: opaque}}\n  - id: request-model\n    listen: local\n    match: {{method: POST, path: /request-model}}\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /model, value: public}}\n    target: {{provider: plain, model_from: request.model}}\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("model source config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        for path in ["/plain", "/request-model"] {
            let body = br#"{"model":null,"value":false}"#;
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            );
            let response = send_request(address, request.as_bytes()).await;
            assert_eq!(status(&response), 200);
        }
        let plain_request = plain_upstream.await.expect("plain upstream");
        let plain: serde_json::Value =
            serde_json::from_slice(response_body(&plain_request)).expect("plain patch body");
        assert!(plain["model"].is_null());
        assert_eq!(plain["value"], true);
        let selected_request = selected_upstream.await.expect("selected upstream");
        let selected: serde_json::Value =
            serde_json::from_slice(response_body(&selected_request)).expect("selected patch body");
        assert_eq!(selected["model"], "private");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn cursor_preset_expands_and_patches_a_live_request() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"cursor").await;
        let upstream_secret = TestSecret::new("cursor-token\n");
        let config_file = TestSecret::new(&format!(
            "imports:\n  - preset: cursor\n    as: cursor-test\n    with:\n      bind: 127.0.0.1:0\n      reasoning_effort: high\n      model_prefix: gpt-\n      upstream_url: http://{upstream_address}\n      secret: {}\nversion: 1\n",
            upstream_secret.reference()
        ));
        let config = pooler_config::Config::from_path(&config_file.path)
            .expect("cursor preset loads")
            .compile()
            .expect("cursor preset compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "cursor-test");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"gpt-test","unknown":{"keep":true}}"#;
        let request = format!(
            "POST /cursor HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(response_body(&response), b"cursor");
        let upstream_request = upstream.await.expect("upstream task");
        let forwarded: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("cursor JSON");
        assert_eq!(forwarded["reasoning_effort"], "high");
        assert_eq!(forwarded["unknown"]["keep"], true);
        assert!(String::from_utf8_lossy(&upstream_request)
            .to_ascii_lowercase()
            .contains("authorization: bearer cursor-token"));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn cursor_current_fixture_replays_through_http_runtime() {
        const MANIFEST_FIXTURE: &str =
            include_str!("../../../fixtures/cursor/cursor-agent-local-2026.08.04.json");
        let fixture: Fixture =
            serde_json::from_str(MANIFEST_FIXTURE).expect("Cursor current-client fixture parses");
        assert_eq!(fixture.metadata.id, "cursor-agent-local.2026.08.04.pooler");
        let downstream = fixture
            .downstream_request
            .as_ref()
            .expect("Cursor fixture downstream request");
        let expected_upstream = fixture
            .expected_upstream_request
            .as_ref()
            .expect("Cursor fixture expected upstream request");
        let scripted_response = match fixture
            .upstream_script
            .first()
            .expect("Cursor fixture upstream script")
        {
            ScriptedResult::Response(response) => response.clone(),
            other => panic!("expected Cursor response script, got {other:?}"),
        };

        let sse_body = |chunks: &[ScriptedChunk]| {
            let mut body = Vec::new();
            for chunk in chunks {
                let ScriptedChunk::Sse { event, data } = chunk else {
                    panic!("Cursor fixture must contain only SSE chunks")
                };
                if let Some(event) = event {
                    body.extend_from_slice(b"event: ");
                    body.extend_from_slice(event.as_bytes());
                    body.extend_from_slice(b"\n");
                }
                for line in data.split('\n') {
                    body.extend_from_slice(b"data: ");
                    body.extend_from_slice(line.as_bytes());
                    body.extend_from_slice(b"\n");
                }
                body.extend_from_slice(b"\n");
            }
            body
        };
        let upstream_body = sse_body(&scripted_response.chunks);
        let expected_downstream_body = sse_body(&fixture.expected_downstream_chunks);

        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Cursor fixture upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("Cursor fixture upstream address");
        let upstream_content_type = scripted_response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map_or("text/event-stream", |(_, value)| value.as_str())
            .to_owned();
        let upstream_status = scripted_response.status;
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener
                .accept()
                .await
                .expect("Cursor fixture upstream accepts");
            let request = read_request(&mut stream)
                .await
                .expect("Cursor fixture upstream request");
            let response = format!(
                "HTTP/1.1 {upstream_status} OK\r\nContent-Type: {upstream_content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                upstream_body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("Cursor fixture upstream response headers");
            stream
                .write_all(&upstream_body)
                .await
                .expect("Cursor fixture upstream response body");
            request
        });

        let upstream_secret = TestSecret::new("cursor-fixture-token");
        let config_file = TestSecret::new(&format!(
            "imports:\n  - preset: cursor\n    as: cursor-fixture\n    with:\n      bind: 127.0.0.1:0\n      reasoning_effort: high\n      model_prefix: gpt-\n      upstream_url: http://{upstream_address}\n      secret: {}\nversion: 1\n",
            upstream_secret.reference()
        ));
        let config = pooler_config::Config::from_path(&config_file.path)
            .expect("Cursor fixture config loads")
            .compile()
            .expect("Cursor fixture config compiles");
        let server = HttpProxyServer::bind(config)
            .await
            .expect("Cursor fixture server binds");
        let address = listener_address(&server, "cursor-fixture");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let mut request = format!(
            "{} {} HTTP/1.1\r\nHost: cursor-fixture\r\n",
            downstream.method, downstream.uri
        )
        .into_bytes();
        for (name, value) in &downstream.headers {
            request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        request.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                downstream.body.len()
            )
            .as_bytes(),
        );
        request.extend_from_slice(&downstream.body);

        let response = send_request_until(address, &request, b"data: [DONE]\n\n").await;
        assert_eq!(status(&response), 200);
        let response_headers = String::from_utf8_lossy(
            &response[..header_end(&response).expect("Cursor response headers")],
        )
        .to_ascii_lowercase();
        let actual_downstream_body = if response_headers.contains("transfer-encoding: chunked") {
            decode_chunked_body(response_body(&response))
        } else {
            response_body(&response).to_vec()
        };
        assert_eq!(actual_downstream_body, expected_downstream_body);

        let upstream_request = upstream.await.expect("Cursor fixture upstream task");
        let upstream_request_text = String::from_utf8_lossy(&upstream_request);
        let mut request_line = upstream_request_text.lines();
        let mut request_parts = request_line
            .next()
            .expect("upstream request line")
            .split_whitespace();
        assert_eq!(
            request_parts.next(),
            Some(expected_upstream.method.as_str())
        );
        assert_eq!(request_parts.next(), Some(expected_upstream.uri.as_str()));
        assert!(has_header(&upstream_request, "content-type"));
        let actual_upstream_body: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request))
                .expect("Cursor upstream JSON body");
        let expected_upstream_body: serde_json::Value =
            serde_json::from_slice(&expected_upstream.body)
                .expect("Cursor expected upstream JSON body");
        assert_eq!(
            normalize_json_value(actual_upstream_body.clone()),
            normalize_json_value(expected_upstream_body)
        );
        assert_eq!(
            actual_upstream_body["model"],
            serde_json::Value::String(fixture.extracted_fields["model"].clone())
        );
        assert_eq!(actual_upstream_body["reasoning_effort"], "high");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn streams_factory_semantics_from_fragmented_openai_sse() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished_for_task = Arc::clone(&upstream_finished);
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            let request = read_request(&mut stream).await.expect("upstream request");
            let request_body = response_body(&request);
            let request_json: serde_json::Value =
                serde_json::from_slice(request_body).expect("OpenAI request JSON");
            assert_eq!(request_json["model"], "gpt-test");
            assert_eq!(request_json["stream"], true);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("upstream response headers");
            stream
                .write_all(
                    b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n",
                )
                .await
                .expect("first SSE fragment");
            stream.write_all(b"\n").await.expect("first SSE delimiter");
            tokio::time::sleep(Duration::from_millis(100)).await;
            stream
                .write_all(
                    b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
                )
                .await
                .expect("text SSE event");
            stream
                .write_all(
                    b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n",
                )
                .await
                .expect("finish SSE event");
            stream
                .write_all(b"data: [DONE]\n\n")
                .await
                .expect("SSE done event");
            finished_for_task.store(true, Ordering::Release);
            request
        });

        let config = pooler_config::compile_yaml(
            "factory-runtime.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: factory\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model, content_types: [application/json]}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: {{provider: local, path: /v1/chat/completions}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: reject\n"
            ),
        )
        .expect("Factory semantic route compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let body = br#"{"prompt":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}"#;
        let mut downstream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        let request = format!(
            "POST /v3/ai/language-model HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Type: application/json\r\nAI-Language-Model-Id: gpt-test\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        downstream
            .write_all(request.as_bytes())
            .await
            .expect("Factory request bytes");
        let mut response = read_headers(&mut downstream)
            .await
            .expect("downstream response headers");
        assert_eq!(status(&response), 200);
        assert!(String::from_utf8_lossy(&response)
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream"));
        let body_start = header_end(&response).expect("response header delimiter") + 4;
        let mut first_event = response.split_off(body_start);
        tokio::time::timeout(TEST_TIMEOUT, async {
            while !first_event
                .windows(b"response-metadata".len())
                .any(|window| window == b"response-metadata")
            {
                let mut chunk = [0_u8; 1024];
                let read = downstream
                    .read(&mut chunk)
                    .await
                    .expect("first event bytes");
                assert_ne!(read, 0, "semantic stream closed before first event");
                first_event.extend_from_slice(&chunk[..read]);
            }
        })
        .await
        .expect("first Factory event arrives");
        assert!(!upstream_finished.load(Ordering::Acquire));

        let rest = if first_event
            .windows(b"data: [DONE]\n\n".len())
            .any(|window| window == b"data: [DONE]\n\n")
        {
            Vec::new()
        } else {
            read_response_until(&mut downstream, b"data: [DONE]\n\n")
                .await
                .expect("remaining semantic stream")
        };
        first_event.extend_from_slice(&rest);
        assert!(first_event
            .windows(b"text-delta".len())
            .any(|window| window == b"text-delta"));
        assert!(first_event
            .windows(b"\"type\":\"finish\"".len())
            .any(|window| window == b"\"type\":\"finish\""));
        drop(downstream);
        let upstream_request = upstream.await.expect("upstream task");
        let upstream_request_text = String::from_utf8_lossy(&upstream_request).to_ascii_lowercase();
        assert!(upstream_request_text.contains("/v1/chat/completions"));
        for header in [
            "ai-language-model-id:",
            "ai-language-model-specification-version:",
            "ai-language-model-streaming:",
        ] {
            assert!(!upstream_request_text.contains(header));
        }
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_factory_route_streams_fragmented_openai_sse() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            let request = read_request(&mut stream).await.expect("upstream request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n")
                .await
                .expect("upstream headers");
            for fragment in [
                b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{" as &[u8],
                b"\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
                b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
                b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n",
                b"data: [DONE]\n\n",
            ] {
                stream
                    .write_all(fragment)
                    .await
                    .expect("upstream SSE fragment");
                tokio::task::yield_now().await;
            }
            request
        });

        let config = pooler_config::compile_yaml(
            "semantic-factory.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: factory\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: local\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: reject\n"
            ),
        )
        .expect("semantic route config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"prompt":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}"#;
        let mut request = format!(
            "POST /v3/ai/language-model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nAccept-Encoding: gzip, br\r\nai-language-model-id: gpt-test\r\nai-language-model-specification-version: 3\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let response = send_request_until(address, &request, b"data: [DONE]\n\n").await;
        assert_eq!(status(&response), 200);
        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.contains("\"type\":\"response-metadata\""));
        assert!(response_text.contains("\"type\":\"text-delta\""));
        assert!(response_text.contains("hello"));
        assert!(response_text.contains("data: [DONE]\n\n"));
        let response_headers = response_text.to_ascii_lowercase();
        assert!(!response_headers.contains("content-length:"));
        assert!(!response_headers.contains("content-encoding:"));
        let upstream_request = upstream.await.expect("upstream task");
        assert!(String::from_utf8_lossy(&upstream_request)
            .to_ascii_lowercase()
            .contains("accept-encoding: identity\r\n"));
        let upstream_body: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("OpenAI JSON");
        assert_eq!(upstream_body["model"], "gpt-test");
        assert_eq!(upstream_body["stream"], true);
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_devin_route_accepts_compressed_connect_and_streams_fragmented_sse() {
        use adapter_devin::{encode_connect_frame, proto, ConnectDecoder, ConnectLimits};
        use prost::Message;

        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            let request = read_request(&mut stream).await.expect("upstream request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                .await
                .expect("upstream headers");
            for fragment in [
                b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{" as &[u8],
                b"\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
                b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
                b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n",
                b"data: [DONE]\n\n",
            ] {
                for fragment in fragment.chunks(3) {
                    stream
                        .write_all(fragment)
                        .await
                        .expect("upstream SSE fragment");
                    tokio::task::yield_now().await;
                }
            }
            request
        });

        let config = pooler_config::compile_yaml(
            "semantic-devin.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: devin\n    listen: local\n    match: {{method: POST, path: /exa.api_server_pb.ApiServerService/GetChatMessage, content_types: [application/connect+proto]}}\n    ingress: {{mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}}\n    target: {{provider: local, upstream_path: /v1/chat/completions}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}}\n    loss_policy: reject\n"
            ),
        )
        .expect("semantic route config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let request_message = proto::GetChatMessageRequest {
            metadata: Some(proto::Metadata {
                api_key: "devin-session-token$test".to_owned(),
                user_jwt: "jwt".to_owned(),
                ..Default::default()
            }),
            prompt: "system".to_owned(),
            chat_message_prompts: vec![proto::ChatMessagePrompt {
                message_id: "message-1".to_owned(),
                source: proto::ChatMessageSource::User as i32,
                prompt: "hello".to_owned(),
                ..Default::default()
            }],
            chat_model_uid: "gpt-test".to_owned(),
            request_type: proto::ChatMessageRequestType::Cascade as i32,
            cascade_id: "cascade-1".to_owned(),
            execution_id: "execution-1".to_owned(),
            ..Default::default()
        };
        let body = encode_connect_frame(&request_message.encode_to_vec(), true, false)
            .expect("compressed Devin request frame");
        let mut request = format!(
            "POST /exa.api_server_pb.ApiServerService/GetChatMessage HTTP/1.1\r\nHost: test\r\nContent-Type: application/connect+proto\r\nConnect-Protocol-Version: 1\r\nConnect-Content-Encoding: gzip\r\nConnect-Accept-Encoding: gzip\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        let response = send_request_until_idle(address, &request, Duration::from_millis(100)).await;
        assert_eq!(status(&response), 200);
        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text
            .to_ascii_lowercase()
            .contains("content-type: application/connect+proto"));
        let decoded_body = decode_chunked_body(response_body(&response));
        let mut decoder = ConnectDecoder::with_gzip(ConnectLimits::default());
        let frames = decoder
            .push(&decoded_body)
            .expect("Connect response frames");
        decoder.finish().expect("complete Connect response");
        assert!(frames.iter().any(|frame| frame.is_end_stream()));
        let mut text = String::new();
        let mut saw_usage = false;
        for frame in frames.into_iter().filter(|frame| !frame.is_end_stream()) {
            let message = proto::GetChatMessageResponse::decode(frame.payload.as_slice())
                .expect("Devin response protobuf");
            text.push_str(&message.delta_text);
            saw_usage |= message.usage.is_some();
        }
        assert_eq!(text, "hello");
        assert!(saw_usage);

        let upstream_request = upstream.await.expect("upstream task");
        assert!(String::from_utf8_lossy(&upstream_request)
            .to_ascii_lowercase()
            .contains("post /v1/chat/completions"));
        assert!(has_header(&upstream_request, "content-type"));
        assert!(!has_header(&upstream_request, "connect-content-encoding"));
        let upstream_body: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("OpenAI JSON");
        assert_eq!(upstream_body["model"], "gpt-test");
        assert_eq!(upstream_body["stream"], true);
        assert_eq!(upstream_body["messages"][1]["content"], "hello");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_devin_route_cancels_a_pending_upstream_when_client_disconnects() {
        use adapter_devin::{encode_connect_frame, proto};
        use prost::Message;

        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            let _request = read_request(&mut stream).await.expect("upstream request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                .await
                .expect("upstream headers");
            let mut buffer = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut buffer))
                .await
                .expect("upstream observes downstream cancellation")
                .expect("upstream read");
        });
        let config = pooler_config::compile_yaml(
            "semantic-devin-cancel.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: devin\n    listen: local\n    match: {{method: POST, path: /exa.api_server_pb.ApiServerService/GetChatMessage, content_types: [application/connect+proto]}}\n    ingress: {{mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}}\n    target: {{provider: local, upstream_path: /v1/chat/completions}}\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}}\n    loss_policy: reject\n"
            ),
        )
        .expect("semantic route config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let request_message = proto::GetChatMessageRequest {
            metadata: Some(proto::Metadata::default()),
            chat_message_prompts: vec![proto::ChatMessagePrompt {
                source: proto::ChatMessageSource::User as i32,
                prompt: "cancel me".to_owned(),
                ..Default::default()
            }],
            chat_model_uid: "gpt-test".to_owned(),
            request_type: proto::ChatMessageRequestType::Cascade as i32,
            ..Default::default()
        };
        let body = encode_connect_frame(&request_message.encode_to_vec(), true, false)
            .expect("compressed Devin request frame");
        let mut downstream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        let request = format!(
            "POST /exa.api_server_pb.ApiServerService/GetChatMessage HTTP/1.1\r\nHost: test\r\nContent-Type: application/connect+proto\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        downstream
            .write_all(request.as_bytes())
            .await
            .expect("request headers");
        downstream.write_all(&body).await.expect("request body");
        let _headers = read_headers(&mut downstream)
            .await
            .expect("response headers");
        drop(downstream);
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if server.active() == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("semantic request permit released");
        upstream.await.expect("upstream cancellation task");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_loss_rejection_happens_before_upstream_connect() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let config = pooler_config::compile_yaml(
            "semantic-reject.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: factory\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: local\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: reject\n"
            ),
        )
        .expect("semantic route config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"prompt":[{"role":"user","content":[{"type":"file","data":{"type":"url","url":"https://example.test/input.txt"}}]}]}"#;
        let mut request = format!(
            "POST /v3/ai/language-model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nai-language-model-id: gpt-test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let response = send_request_until(address, &request, b"invalid request").await;
        assert_eq!(status(&response), 400);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_converted_request_respects_request_body_limit() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let config = pooler_config::compile_yaml(
            "semantic-request-limit.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: factory\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model}}\n    limits: {{max_request_body_bytes: 100}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: local\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: reject\n"
            ),
        )
        .expect("semantic route config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"prompt":[{"role":"user","content":[{"type":"text","text":"x"}]}]}"#;
        let mut request = format!(
            "POST /v3/ai/language-model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nai-language-model-id: gpt-test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let response = send_request(address, &request).await;
        assert_eq!(status(&response), 413);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn semantic_raw_request_frame_limit_rejects_before_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let config = pooler_config::compile_yaml(
            "semantic-frame-limit.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: factory\n    listen: local\n    match: {{method: POST, path: /v3/ai/language-model}}\n    limits: {{max_frame_bytes: 8, max_request_body_bytes: 4096}}\n    ingress: {{mode: semantic, decoder: decode.factory.language_model}}\n    target: local\n    response: {{mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}}\n    loss_policy: reject\n"
            ),
        )
        .expect("semantic route config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body =
            br#"{"prompt":[{"role":"user","content":[{"type":"text","text":"raw frame"}]}]}"#;
        let mut request = format!(
            "POST /v3/ai/language-model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nai-language-model-id: gpt-test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let response = send_request(address, &request).await;
        assert_eq!(status(&response), 413);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    struct MockCodexRefresher {
        calls: AtomicUsize,
    }

    impl OAuthRefresher for MockCodexRefresher {
        fn refresh<'a>(
            &'a self,
            _refresh_token: &'a SecretValue,
            _cancellation: CancellationToken,
        ) -> OAuthFuture<'a, OAuthTokens> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(OAuthTokens::bearer("new-access", Some("new-refresh"), None)) })
        }
    }

    #[tokio::test]
    async fn native_codex_materializes_headers_refreshes_once_and_replays_before_commit() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..2 {
                let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
                let request = read_request(&mut stream).await.expect("request bytes");
                let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
                if index == 0 {
                    assert!(request_text.contains("authorization: bearer old-access"));
                    assert!(request_text.contains("chatgpt-account-id: chatgpt-account-a"));
                    stream
                        .write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("401 response");
                } else {
                    assert!(request_text.contains("authorization: bearer new-access"));
                    assert!(request_text.contains("chatgpt-account-id: chatgpt-account-a"));
                    let body = b"ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("200 headers");
                    stream.write_all(body).await.expect("200 body");
                }
                requests.push(request);
            }
            requests
        });

        let config = pooler_config::compile_yaml(
            "native-codex-e2e.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  codex:\n    url: http://{upstream_address}\n    native: {{kind: codex}}\n    oauth:\n      authorization_endpoint: https://oauth.example/authorize\n      token_endpoint: https://oauth.example/token\n      identity_endpoint: https://oauth.example/me\n      client_id: pooler-test\n      scopes: [openid]\naccounts:\n  account-a:\n    provider: codex\n    secret: env:CODEX_TEST_SECRET\npolicies:\n  codex:\n    selection: {{strategy: fill_first, accounts: [account-a]}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 1, statuses: [429], before_commit_only: true}}\nroutes:\n  - id: codex\n    listen: local\n    match: {{method: POST, path: /responses, content_types: [application/json]}}\n    ingress: {{mode: patch}}\n    target: {{provider: codex, policy: codex}}\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("native route config");
        let token_store = Arc::new(pooler_auth::MemoryOAuthTokenStore::new());
        let credential = pooler_auth::CredentialId::new("account-a").expect("credential");
        token_store.insert(
            credential,
            OAuthTokens::bearer("old-access", Some("old-refresh"), None),
        );
        let refresher = Arc::new(MockCodexRefresher {
            calls: AtomicUsize::new(0),
        });
        let native = Arc::new(
            NativeRuntime::with_codex_provider(token_store.clone(), "codex", refresher.clone())
                .with_account_id("account-a", "chatgpt-account-a"),
        );
        let server = HttpProxyServer::bind_with_native_runtime(config, native)
            .await
            .expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"gpt-test","input":"hello"}"#;
        let mut request = format!(
            "POST /responses HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let response = send_request(address, &request).await;
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"ok");
        assert_eq!(refresher.calls.load(Ordering::Relaxed), 1);
        let rotated = token_store
            .load(&pooler_auth::CredentialId::new("account-a").expect("credential"))
            .await
            .expect("token store load")
            .expect("rotated snapshot");
        assert_eq!(rotated.generation(), 1);
        assert_eq!(
            rotated.tokens().access_token().expose_secret(),
            "new-access"
        );
        upstream.await.expect("upstream task");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn mixed_api_key_and_imported_subscription_failover_isolates_attempt_auth() {
        let subscription_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("subscription upstream binds");
        let subscription_address = subscription_listener
            .local_addr()
            .expect("subscription upstream address");
        let subscription_upstream = tokio::spawn(async move {
            let (mut stream, _) = subscription_listener
                .accept()
                .await
                .expect("subscription upstream accepts");
            let request = read_request(&mut stream)
                .await
                .expect("subscription request bytes");
            let body = br#"{"error":{"type":"account_quota_exhausted","code":"account_quota_exhausted","message":"subscription quota"}}"#;
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("subscription response headers");
            stream
                .write_all(body)
                .await
                .expect("subscription response body");
            request
        });

        let api_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("API-key upstream binds");
        let api_address = api_listener.local_addr().expect("API-key upstream address");
        let api_upstream = tokio::spawn(async move {
            let (mut stream, _) = api_listener
                .accept()
                .await
                .expect("API-key upstream accepts");
            let request = read_request(&mut stream)
                .await
                .expect("API-key request bytes");
            let body = b"api-key-fallback-ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("API-key response headers");
            stream.write_all(body).await.expect("API-key response body");
            request
        });

        let api_secret = TestSecret::new("static-api-secret");
        let config = pooler_config::compile_yaml(
            "mixed-openai-auth-e2e.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  subscription:\n    url: http://{subscription_address}\n    native: {{kind: codex}}\n    oauth:\n      authorization_endpoint: https://oauth.example/authorize\n      token_endpoint: https://oauth.example/token\n      identity_endpoint: https://oauth.example/me\n      client_id: pooler-test\n      scopes: [openid]\n  api:\n    url: http://{api_address}\naccounts:\n  a-subscription-account:\n    provider: subscription\n    auth_kind: oauth\n  b-api-account:\n    provider: api\n    auth_kind: api_key\n    secret: {}\naccount_pools:\n  mixed: {{accounts: [a-subscription-account, b-api-account]}}\nmodels:\n  - id: gpt-test\n    targets:\n      - {{provider: subscription, upstream_model: gpt-test}}\n      - {{provider: api, upstream_model: gpt-test}}\npolicies:\n  mixed:\n    selection: {{strategy: ordered_fallback, account_pool: mixed}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, maximum_providers: 2, statuses: [429], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1s}}\nroutes:\n  - id: mixed\n    listen: local\n    match: {{method: POST, path: /responses, content_types: [application/json]}}\n    ingress: {{mode: patch}}\n    target: {{provider: subscription, model_from: request.model, policy: mixed}}\n    response: {{mode: opaque}}\n",
                api_secret.reference()
            ),
        )
        .expect("mixed-auth route config");

        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"mixed-openai-auth-test-key").expect("master key"),
        )
        .expect("encrypted credential store");
        let state = store
            .upsert_credential_state(CredentialState::new(
                "a-subscription-account",
                "subscription",
                true,
                1,
            ))
            .expect("subscription credential metadata");
        let token_store = Arc::new(SqliteOAuthTokenStore::new(store));
        let credential = pooler_auth::CredentialId::new("a-subscription-account")
            .expect("subscription credential ID");
        let profile = OAuthCredentialProfile::new(
            "openai",
            OAuthTokens::bearer(
                "subscription-access-token",
                Some("subscription-refresh-token"),
                None,
            ),
        )
        .with_account_id("chatgpt-subscription-account");
        token_store
            .compare_and_swap_profile(&credential, state.revision, &profile)
            .expect("imported subscription profile persists");
        let native = Arc::new(
            NativeRuntime::new_with_sqlite(&config, token_store)
                .expect("native runtime loads imported profile"),
        );

        let server = HttpProxyServer::bind_with_native_runtime(config, native)
            .await
            .expect("mixed-auth proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"gpt-test","input":"hello"}"#;
        let request = format!(
            "POST /responses HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nIdempotency-Key: mixed-auth-e2e\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(
            status(&response),
            200,
            "response={}, decisions={:?}",
            String::from_utf8_lossy(&response),
            server.pooling().recent_decisions(8)
        );
        assert_eq!(response_body(&response), b"api-key-fallback-ok");

        let subscription_request = subscription_upstream
            .await
            .expect("subscription upstream task");
        assert_eq!(
            request_header(&subscription_request, "authorization"),
            Some("Bearer subscription-access-token")
        );
        assert_eq!(
            request_header(&subscription_request, "chatgpt-account-id"),
            Some("chatgpt-subscription-account")
        );
        assert!(!String::from_utf8_lossy(&subscription_request).contains("static-api-secret"));

        let api_request = api_upstream.await.expect("API-key upstream task");
        assert_eq!(
            request_header(&api_request, "authorization"),
            Some("Bearer static-api-secret")
        );
        assert_eq!(request_header(&api_request, "chatgpt-account-id"), None);
        assert_eq!(request_header(&api_request, "originator"), None);
        assert!(!String::from_utf8_lossy(&api_request).contains("subscription-access-token"));
        assert!(!String::from_utf8_lossy(&response).contains("subscription-access-token"));
        assert!(!String::from_utf8_lossy(&response).contains("static-api-secret"));
        assert!(!String::from_utf8_lossy(&response).contains("chatgpt-subscription-account"));

        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn reload_swaps_dispatch_atomically_and_keeps_noop_generation_stable() {
        let (first_address, first_upstream) = spawn_one_shot_upstream(b"first-generation").await;
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"second-generation").await;
        let config = pooler_config::compile_yaml(
            "reload.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /reload}}\n    target: first\n"
            ),
        )
        .expect("initial config");
        let server = HttpProxyServer::bind(config.clone())
            .await
            .expect("proxy binds");
        let address = listener_address(&server, "local");
        assert_eq!(server.config_generation(), 1);
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let unchanged = server.reload(config).await.expect("same config is a no-op");
        assert_eq!(unchanged, HttpReloadOutcome::Unchanged { generation: 1 });
        assert_eq!(server.config_generation(), 1);
        let first = send_request(address, b"GET /reload HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&first), b"first-generation");

        let replacement = pooler_config::compile_yaml(
            "reload.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /reload}}\n    target: second\n"
            ),
        )
        .expect("replacement config");
        let changed = server.reload(replacement).await.expect("reload succeeds");
        assert_eq!(changed, HttpReloadOutcome::Reloaded { generation: 2 });
        let second = send_request(address, b"GET /reload HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&second), b"second-generation");

        first_upstream.await.expect("first upstream");
        second_upstream.await.expect("second upstream");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn management_listener_tracks_live_generation_and_decisions_after_reload() {
        let (first_address, first_upstream) = spawn_one_shot_upstream(b"management-first").await;
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"management-second").await;
        let config = pooler_config::compile_yaml(
            "management-runtime.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /management-runtime}}\n    target: first\n"
            ),
        )
        .expect("management runtime config");
        let server = HttpProxyServer::bind(config.clone())
            .await
            .expect("proxy and management listeners bind");
        let proxy_address = listener_address(&server, "local");
        let management_address: SocketAddr = server
            .management_address()
            .expect("management address")
            .parse()
            .expect("management socket address");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let health_before = send_request(
            management_address,
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&health_before), 200);
        assert!(String::from_utf8_lossy(response_body(&health_before))
            .contains("\"configuration_generation\":1"));
        let decisions_before = send_request(
            management_address,
            b"GET /decisions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&decisions_before), 200);
        assert!(String::from_utf8_lossy(response_body(&decisions_before))
            .contains("\"configuration_generation\":1"));

        let first = send_request(
            proxy_address,
            b"GET /management-runtime HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(response_body(&first), b"management-first");
        let traces_before = send_request(
            management_address,
            b"GET /traces HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&traces_before), 200);
        let traces_before: serde_json::Value =
            serde_json::from_slice(response_body(&traces_before)).expect("trace json");
        let trace_count_before = traces_before["traces"]
            .as_array()
            .expect("trace array")
            .len();
        assert!(trace_count_before > 0);

        let replacement = pooler_config::compile_yaml(
            "management-runtime.yaml",
            &format!(
                "version: 1\nmanagement: {{bind: 127.0.0.1:0}}\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /management-runtime}}\n    target: second\n"
            ),
        )
        .expect("replacement management runtime config");
        let outcome = server.reload(replacement).await.expect("runtime reload");
        assert_eq!(outcome, HttpReloadOutcome::Reloaded { generation: 2 });

        let health_after = send_request(
            management_address,
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&health_after), 200);
        assert!(String::from_utf8_lossy(response_body(&health_after))
            .contains("\"configuration_generation\":2"));
        let decisions_after = send_request(
            management_address,
            b"GET /decisions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&decisions_after), 200);
        assert!(String::from_utf8_lossy(response_body(&decisions_after))
            .contains("\"configuration_generation\":2"));

        let second = send_request(
            proxy_address,
            b"GET /management-runtime HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(response_body(&second), b"management-second");
        let traces_after = send_request(
            management_address,
            b"GET /traces HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let traces_after: serde_json::Value =
            serde_json::from_slice(response_body(&traces_after)).expect("trace json");
        assert!(
            traces_after["traces"]
                .as_array()
                .expect("trace array")
                .len()
                > trace_count_before
        );

        first_upstream.await.expect("first upstream");
        second_upstream.await.expect("second upstream");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn stale_management_reload_is_failed_instead_of_applied() {
        const SECRET_ENV: &str = "POOLER_MANAGEMENT_STALE_RELOAD_TEST_KEY";
        std::env::set_var(SECRET_ENV, "stale-reload-secret");
        let config = pooler_config::compile_yaml(
            "management-stale-reload.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_MANAGEMENT_STALE_RELOAD_TEST_KEY}}\nupstreams: {provider: {url: http://127.0.0.1:1}}\n",
        )
        .expect("initial management config");
        let server = HttpProxyServer::bind(config).await.expect("bind server");
        let api = server.management_api().expect("management api");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer stale-reload-secret"),
        );
        let accepted = api.handle(&http::Method::POST, "/reload", &headers);
        assert_eq!(accepted.status, http::StatusCode::ACCEPTED);
        let accepted: serde_json::Value =
            serde_json::from_slice(&accepted.body).expect("accepted reload json");
        let request_id = accepted["request_id"].as_u64().expect("request id");

        let replacement = pooler_config::compile_yaml(
            "management-stale-reload.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_MANAGEMENT_STALE_RELOAD_TEST_KEY}}\nupstreams: {provider: {url: http://127.0.0.1:2}}\n",
        )
        .expect("replacement management config");
        assert_eq!(
            server.reload(replacement).await.expect("runtime reload"),
            HttpReloadOutcome::Reloaded { generation: 2 }
        );

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                server.next_management_reload_request(),
            )
            .await
            .is_err(),
            "stale request should be consumed and the waiter should remain pending"
        );
        let reloads = api.handle(&http::Method::GET, "/reloads", &headers);
        let reloads: serde_json::Value =
            serde_json::from_slice(&reloads.body).expect("reload history json");
        let record = reloads["reloads"]
            .as_array()
            .expect("reload records")
            .iter()
            .find(|record| record["request_id"] == request_id)
            .expect("correlated reload record");
        assert_eq!(record["status"], "failed");
        assert_eq!(record["accepted_configuration_generation"], 1);
        assert_eq!(record["configuration_generation"], 2);

        let accepted = api.handle(&http::Method::POST, "/reload", &headers);
        assert_eq!(accepted.status, http::StatusCode::ACCEPTED);
        let (second_request_id, catalog_only, accepted_generation) =
            server.next_management_reload_request().await;
        assert!(!catalog_only);
        assert_eq!(accepted_generation, 2);
        let third = pooler_config::compile_yaml(
            "management-stale-reload.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_MANAGEMENT_STALE_RELOAD_TEST_KEY}}\nupstreams: {provider: {url: http://127.0.0.1:3}}\n",
        )
        .expect("third management config");
        assert_eq!(
            server
                .reload(third)
                .await
                .expect("concurrent runtime reload"),
            HttpReloadOutcome::Reloaded { generation: 3 }
        );
        let obsolete = pooler_config::compile_yaml(
            "management-stale-reload.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_MANAGEMENT_STALE_RELOAD_TEST_KEY}}\nupstreams: {provider: {url: http://127.0.0.1:4}}\n",
        )
        .expect("obsolete management candidate");
        assert!(matches!(
            server
                .reload_for_generation(obsolete, accepted_generation)
                .await,
            Err(HttpProxyServerError::StaleManagementGeneration {
                expected: 2,
                actual: 3
            })
        ));
        server.complete_management_reload(second_request_id, None);
        server.begin_drain();
        std::env::remove_var(SECRET_ENV);
    }

    #[tokio::test]
    async fn management_native_account_commands_are_bounded_and_audited() {
        std::env::set_var("POOLER_MANAGEMENT_NATIVE_TEST_KEY", "native-command-secret");
        let config = pooler_config::compile_yaml(
            "management-native-command.yaml",
            "version: 1\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_MANAGEMENT_NATIVE_TEST_KEY}}\nupstreams:\n  codex:\n    url: http://127.0.0.1:1\n    native: {kind: codex}\n    oauth:\n      authorization_endpoint: https://oauth.example/authorize\n      token_endpoint: https://oauth.example/token\n      client_id: test\n      scopes: [openid]\naccounts:\n  account-a: {provider: codex, auth_kind: oauth}\n",
        )
        .expect("management native command config");
        let server = HttpProxyServer::bind(config).await.expect("bind server");
        let api = server.management_api().expect("management api");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer native-command-secret"),
        );
        let response = api.handle(&http::Method::POST, "/accounts/account-a/refresh", &headers);
        assert_eq!(response.status, http::StatusCode::ACCEPTED);

        let audit = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let response = api.handle(&http::Method::GET, "/audit", &headers);
                let value: serde_json::Value =
                    serde_json::from_slice(&response.body).expect("audit json");
                let events = value["events"].as_array().expect("audit events");
                if events
                    .iter()
                    .any(|event| event["action"] == "refresh" && event["outcome"] == "failed")
                {
                    break value;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("native command completion audit");
        assert!(audit["events"]
            .as_array()
            .expect("audit events")
            .iter()
            .any(|event| event["outcome"] == "queued"));

        let (sender, receiver) = mpsc::channel(1);
        let stale_worker = tokio::spawn(run_native_account_commands(
            receiver,
            Arc::clone(&server.state.native),
            Arc::clone(&server.state.dispatch),
            Arc::clone(&server.state.reload_lock),
            Arc::downgrade(&api),
            server.cancellation_token(),
        ));
        sender
            .send(NativeAccountCommand {
                account: "account-a".to_owned(),
                action: NativeAccountAction::Revoke,
                generation: 0,
            })
            .await
            .expect("stale command queues");
        drop(sender);
        stale_worker.await.expect("stale command worker");
        let audit = api.handle(&http::Method::GET, "/audit", &headers);
        let audit: serde_json::Value =
            serde_json::from_slice(&audit.body).expect("stale audit json");
        assert!(audit["events"]
            .as_array()
            .expect("audit events")
            .iter()
            .any(|event| {
                event["action"] == "revoke"
                    && event["generation"] == 0
                    && event["outcome"] == "stale_generation"
            }));
        server.begin_drain();
        std::env::remove_var("POOLER_MANAGEMENT_NATIVE_TEST_KEY");
    }

    #[tokio::test]
    async fn reload_keeps_an_inflight_request_on_its_old_generation() {
        let first_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("first upstream binds");
        let first_address = first_listener.local_addr().expect("first upstream address");
        let release = Arc::new(Notify::new());
        let release_first = Arc::clone(&release);
        let first_upstream = tokio::spawn(async move {
            let (mut stream, _) = first_listener.accept().await.expect("first accepts");
            let _request = read_request(&mut stream).await.expect("first request");
            release_first.notified().await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nold")
                .await
                .expect("old response");
        });
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"new").await;
        let config = pooler_config::compile_yaml(
            "reload-inflight.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /reload}}\n    target: first\n"
            ),
        )
        .expect("initial config");
        let server = HttpProxyServer::bind(config.clone())
            .await
            .expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let old_request = tokio::spawn(async move {
            send_request(address, b"GET /reload HTTP/1.1\r\nHost: test\r\n\r\n").await
        });
        wait_for_active(&server, 1).await;

        let replacement = pooler_config::compile_yaml(
            "reload-inflight.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /reload}}\n    target: second\n"
            ),
        )
        .expect("replacement config");
        let outcome = server.reload(replacement).await.expect("reload succeeds");
        assert_eq!(outcome, HttpReloadOutcome::Reloaded { generation: 2 });
        let new_request =
            send_request(address, b"GET /reload HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&new_request), b"new");
        release.notify_one();
        let old_response = old_request.await.expect("old request task");
        assert_eq!(response_body(&old_response), b"old");
        first_upstream.await.expect("first upstream");
        second_upstream.await.expect("second upstream");
        stop_server(&server, runner).await;
    }
}
