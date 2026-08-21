//! HTTP forwarding for opaque and bounded JSON-patch routes.
//!
//! Opaque bodies remain Hyper streams. Patch routes buffer within their route
//! limit, apply the compiled transforms, and keep responses opaque.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant as StdInstant},
};

use adapter_providers::{AuthPlacement, ProviderKind, ProviderResponseClassifier};
use base64::Engine;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use pooler_auth::{constant_time_eq, SecretRef as AuthSecretRef, SecretValue};
use pooler_config::{
    CompiledConfig, ModelSource, RequestTransform, RouteMatchError, RoutePlan, RouteRequest,
    SecretRef, UpstreamPlan,
};
use pooler_core::{BodyMode, ErrorClass, RouteLimits};
use pooler_extension::{ExtensionInput, ExtensionRegistry};
use pooler_observe::{
    AttemptRecord, AttemptResult, CompletionClass, CooldownRecord, DecisionRecord, MetricsRegistry,
    QuotaRecord, RequestObservation, RetryRecord, TraceRecord, TraceRecorder, TraceStage,
    Usage as ObservedUsage,
};
use pooler_policy::{CommitmentState, QuotaObservation, ReplayCheck, SelectionLease};
use pooler_protocol::{JsonPatchLimits, PreservedJson};
use ring::rand::SecureRandom;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::{self, Instant, Sleep},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::openai_websocket::{
    materialized_authorization_generation, materialized_generation, ConnectionIdentity,
    CredentialGeneration, OpenAiResponsesWebSocketAttempt, OpenAiResponsesWebSocketError,
    OpenAiResponsesWebSocketPool, ResponsesWebSocketFlavor, SemanticWebSocketResponse,
    RESPONSES_WEBSOCKET_BETA,
};
use crate::{
    extract_bearer_token, replayable_response_headers, retry_after_delay, safe_method_for_cache,
    safe_request_for_cache, safe_response_for_cache, strip_hop_by_hop_headers, CacheKey,
    CacheKeyInput, CacheLeader, CacheLookup, CachePolicy, CachedResponse, DrainController,
    DrainGuard, DrainedBody, FrameLimitedBody, LimitedBody, NativeAuthorization,
    NativeAuthorizationRequest, NativeRuntime, NativeRuntimeError, PoolError, PoolSelection,
    PoolingCoordinator, ResponseCache, RuntimeResources, SelectionContext, SelectionTiming,
};

/// The erased body type used by responses returned from [`HttpProxy`].
pub type ProxyBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// A boxed body error. Hyper and body-limit errors are both preserved as the
/// source error behind this boundary.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// A semantic adapter's encoded upstream request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticRequestBody {
    /// Serialized request bytes for the selected upstream protocol.
    pub body: Vec<u8>,
    /// Content type to send with `body`.
    pub content_type: HeaderValue,
    /// Request-local response representation selected while decoding the body.
    /// This value is never forwarded as an HTTP header.
    pub response_hint: SemanticResponseHint,
}

/// Request-local information needed while encoding the downstream response.
/// It is retained in memory only and is never forwarded to an upstream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SemanticResponseHint {
    /// Response representation selected from the decoded request.
    pub mode: SemanticResponseMode,
    /// Model resolved from the downstream request before upstream translation.
    pub requested_model: Option<String>,
}

/// Request-local response representation selected by a semantic adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SemanticResponseMode {
    /// Let the adapter use its route-defined response behavior.
    #[default]
    AdapterDefault,
    /// Decode and return one bounded JSON response document.
    Json,
    /// Decode and return a server-sent event stream.
    ServerSentEvents,
}

/// Semantic protocol carried over an upstream WebSocket connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticWebSocketTransport {
    /// OpenAI Responses `response.create` client messages and JSON server events.
    OpenAiResponses,
    /// xAI Responses-compatible realtime client messages and JSON server events.
    XaiResponses,
}

/// A semantic adapter's transformed downstream response body.
#[derive(Debug)]
pub struct SemanticResponseBody {
    /// Stream body that emits the downstream protocol.
    pub body: ProxyBody,
    /// Content type for the transformed body.
    pub content_type: HeaderValue,
}

/// Narrow seam between HTTP transport and one semantic route adapter.
pub trait SemanticAdapter: Clone + Send + Sync + 'static {
    /// Whether this adapter owns the configured semantic route.
    fn supports(&self, route: &RoutePlan) -> bool;

    /// Decode and convert a bounded downstream request before connecting
    /// upstream. Errors are returned before any upstream request is made.
    fn encode_request(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError>;

    /// Decode a request with access to the actual matched URI.
    ///
    /// The default preserves adapters whose wire contract depends only on the
    /// compiled route, headers, and body.
    fn encode_request_with_uri(
        &self,
        route: &RoutePlan,
        _uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        self.encode_request(route, headers, body)
    }

    /// Decode request-local policy inputs before upstream translation.
    ///
    /// Adapters may expose non-header session identifiers and the exact codec
    /// needed by a route. The default keeps custom adapters compatible with
    /// header-only policy selection.
    fn selection_context(
        &self,
        _route: &RoutePlan,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        Ok(SelectionContext::default())
    }

    /// Decode policy inputs with access to the actual matched URI.
    fn selection_context_with_uri(
        &self,
        route: &RoutePlan,
        _uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        self.selection_context(route, headers, body)
    }

    /// Whether model selection rewrites the conventional JSON `/model` field.
    /// Provider protocols that carry the model in the URL return `false`.
    fn model_in_request_body(&self, _route: &RoutePlan) -> bool {
        true
    }

    /// Select an upstream semantic WebSocket transport for this route.
    ///
    /// The proxy additionally requires a `ws` or `wss` upstream. Returning
    /// `None` preserves the ordinary HTTP semantic path.
    fn websocket_transport(&self, _route: &RoutePlan) -> Option<SemanticWebSocketTransport> {
        None
    }

    /// Apply provider-specific path or query rewriting after model selection.
    fn rewrite_upstream_uri(
        &self,
        _route: &RoutePlan,
        _downstream_uri: &Uri,
        _upstream_model: Option<&str>,
        upstream_uri: Uri,
    ) -> Result<Uri, BoxError> {
        Ok(upstream_uri)
    }

    /// Removes downstream-only headers before the translated request is sent
    /// to an upstream protocol.
    fn sanitize_request_headers(&self, _headers: &mut HeaderMap) {}

    /// Transform an upstream response stream into downstream semantic bytes.
    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError>;

    /// Transform an upstream response using request headers that remain
    /// meaningful to the downstream protocol.
    ///
    /// Most semantic adapters do not need request-local response negotiation,
    /// so their existing [`Self::decode_response`] implementation remains the
    /// source of truth.  Protocols such as Connect use this hook for explicit
    /// per-request compression negotiation.
    fn decode_response_with_request_headers(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        self.decode_response(route, body, cancellation)
    }

    /// Transform an upstream response using the representation selected while
    /// decoding this request. The default preserves existing adapter behavior.
    fn decode_response_with_hint(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        request_headers: &HeaderMap,
        _hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        self.decode_response_with_request_headers(route, body, request_headers, cancellation)
    }
}

/// Adapter used by callers that only need opaque and patch routes.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSemanticAdapter;

impl SemanticAdapter for NoSemanticAdapter {
    fn supports(&self, _route: &RoutePlan) -> bool {
        false
    }

    fn encode_request(
        &self,
        _route: &RoutePlan,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        Err(box_error(ProxyError::UnsupportedBodyMode {
            route: "semantic".to_owned(),
        }))
    }

    fn selection_context(
        &self,
        _route: &RoutePlan,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        Ok(SelectionContext::default())
    }

    fn sanitize_request_headers(&self, _headers: &mut HeaderMap) {}

    fn decode_response(
        &self,
        _route: &RoutePlan,
        _body: ProxyBody,
        _cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        Err(box_error(ProxyError::UnsupportedBodyMode {
            route: "semantic".to_owned(),
        }))
    }

    fn decode_response_with_request_headers(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        self.decode_response(route, body, cancellation)
    }
}

type UpstreamClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, ProxyBody>;

struct DeadlineBody<B> {
    inner: Pin<Box<B>>,
    timeout: Pin<Box<Sleep>>,
    timed_out: bool,
}

impl<B> DeadlineBody<B> {
    fn new(inner: B, deadline: Instant) -> Self {
        Self {
            inner: Box::pin(inner),
            timeout: Box::pin(time::sleep_until(deadline)),
            timed_out: false,
        }
    }
}

impl<B> Body for DeadlineBody<B>
where
    B: Body<Data = Bytes, Error = BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if !self.timed_out && self.timeout.as_mut().poll(context).is_ready() {
            self.timed_out = true;
            return Poll::Ready(Some(Err(Box::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream response exceeded its request timeout",
            )))));
        }
        self.inner.as_mut().poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.timed_out || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DEFAULT_ERROR_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

fn external_inspector_id(component: &str) -> Option<&str> {
    component
        .strip_prefix("inspect.external.")
        .or_else(|| component.strip_prefix("external.inspect."))
}

fn extension_metadata(route: &RoutePlan) -> BTreeMap<String, String> {
    BTreeMap::from([(String::from("route"), route.id().to_owned())])
}

fn content_type_for_extension(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned()
}

/// Errors that prevent an opaque proxy from being constructed or a request
/// from being forwarded. Request-time errors are converted to HTTP responses
/// by [`HttpProxy::handle`].
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The TLS root store could not be initialized.
    #[error("failed to initialize HTTPS client: {0}")]
    TlsClient(String),
    /// The route references an unknown upstream.
    #[error("route `{route}` references missing upstream `{upstream}`")]
    MissingUpstream { route: String, upstream: String },
    /// The configured upstream URL could not be converted to an HTTP URI.
    #[error("invalid upstream URI")]
    InvalidUri,
    /// A configured secret could not be resolved.
    #[error("upstream authentication secret is unavailable")]
    SecretUnavailable,
    /// The proxy limits were invalid.
    #[error("invalid proxy limits: {0}")]
    InvalidLimits(String),
    /// The configured authentication kind is not supported by opaque HTTP.
    #[error("unsupported upstream authentication kind")]
    UnsupportedAuth,
    /// A matched route requires processing that the opaque runtime does not implement.
    #[error("route `{route}` is not opaque and cannot be served by the opaque runtime")]
    UnsupportedBodyMode { route: String },
    /// An HTTP request could not be constructed.
    #[error("failed to build upstream request: {0}")]
    RequestBuild(#[from] http::Error),
    /// A patch request body was not valid for its compiled transform plan.
    #[error("invalid patch request: {0}")]
    InvalidPatch(String),
    /// The selected target rejects a parameter the caller supplied, and the
    /// route's loss policy forbids dropping it.
    #[error("model `{model}` does not accept the `{parameter}` parameter")]
    UnsupportedParameter { parameter: String, model: String },
    /// A buffered or transformed request body exceeded the route limit.
    #[error("request body exceeds configured limit")]
    RequestBodyTooLarge,
    /// A semantic request could not be decoded or converted before upstream.
    #[error("invalid semantic request: {0}")]
    SemanticRequest(String),
    /// A semantic response could not be initialized after upstream headers.
    #[error("invalid semantic response: {0}")]
    SemanticResponse(String),
    /// The downstream WebSocket upgrade request was malformed.
    #[error("invalid WebSocket handshake: {0}")]
    InvalidWebSocketHandshake(String),
    /// Account selection or mutable pooling state failed.
    #[error("account selection failed: {0}")]
    Pool(String),
    /// A supervised external extension failed before the upstream request.
    #[error("external extension failed: {0}")]
    Extension(String),
    /// Native provider credential materialization or refresh failed.
    #[error("native provider request failed: {0}")]
    Native(String),
    /// The upstream request failed before a response was received.
    #[error("upstream request failed: {0}")]
    Upstream(#[source] BoxError),
    /// The upstream did not produce response headers before the deadline.
    #[error("upstream request timed out")]
    Timeout,
    /// The provider rejected a semantic Responses WebSocket handshake.
    #[error("upstream WebSocket handshake failed with status {0}")]
    WebSocketHandshakeStatus(u16),
}

/// A compiled route table and shared Hyper client for one listener.
#[derive(Clone)]
pub struct HttpProxy<A = NoSemanticAdapter> {
    config: Arc<CompiledConfig>,
    listener: Arc<str>,
    client: UpstreamClient,
    h2c_client: UpstreamClient,
    drain: DrainController,
    semantic: A,
    pooling: Arc<PoolingCoordinator>,
    native: Arc<NativeRuntime>,
    extensions: Arc<ExtensionRegistry>,
    caches: BTreeMap<Arc<str>, Arc<ResponseCache>>,
    observability: MetricsRegistry,
    traces: TraceRecorder,
    resources: RuntimeResources,
    openai_websockets: OpenAiResponsesWebSocketPool,
}

impl<A> std::fmt::Debug for HttpProxy<A>
where
    A: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("listener", &self.listener)
            .field("draining", &self.drain.is_draining())
            .field("active", &self.drain.active())
            .field("semantic", &self.semantic)
            .field("cache_routes", &self.caches.len())
            .field("observability", &self.observability)
            .field("traces", &self.traces)
            .finish_non_exhaustive()
    }
}

impl HttpProxy<NoSemanticAdapter> {
    /// Construct a proxy for one compiled listener.
    pub fn new(
        config: Arc<CompiledConfig>,
        listener: impl Into<Arc<str>>,
    ) -> Result<Self, ProxyError> {
        Self::with_semantic_adapter(config, listener, NoSemanticAdapter)
    }
}

impl<A> HttpProxy<A>
where
    A: SemanticAdapter,
{
    /// Construct a proxy for one compiled listener and one semantic adapter.
    pub fn with_semantic_adapter(
        config: Arc<CompiledConfig>,
        listener: impl Into<Arc<str>>,
        semantic: A,
    ) -> Result<Self, ProxyError> {
        let pooling = Arc::new(PoolingCoordinator::new(&config).map_err(pool_error)?);
        Self::with_semantic_adapter_and_pooling(config, listener, semantic, pooling)
    }

    /// Construct a proxy using a coordinator shared with sibling listeners.
    pub fn with_semantic_adapter_and_pooling(
        config: Arc<CompiledConfig>,
        listener: impl Into<Arc<str>>,
        semantic: A,
        pooling: Arc<PoolingCoordinator>,
    ) -> Result<Self, ProxyError> {
        Self::with_semantic_adapter_and_pooling_and_native(
            config,
            listener,
            semantic,
            pooling,
            Arc::new(NativeRuntime::disabled()),
        )
    }

    /// Construct a proxy with a shared account pool and native provider
    /// runtime. Native authorization is loaded for each attempt and is never
    /// retained in the immutable route plan.
    pub fn with_semantic_adapter_and_pooling_and_native(
        config: Arc<CompiledConfig>,
        listener: impl Into<Arc<str>>,
        semantic: A,
        pooling: Arc<PoolingCoordinator>,
        native: Arc<NativeRuntime>,
    ) -> Result<Self, ProxyError> {
        let listener = listener.into();
        if let Some(route) = config.routes().iter().find(|route| {
            route.listener() == listener.as_ref()
                && ((!matches!(route.ingress().mode(), BodyMode::Opaque | BodyMode::Patch)
                    && !semantic.supports(route))
                    || (route.response().mode() != BodyMode::Opaque && !semantic.supports(route)))
        }) {
            return Err(ProxyError::UnsupportedBodyMode {
                route: route.id().to_owned(),
            });
        }
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|error| ProxyError::TlsClient(error.to_string()))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let mut client_builder = Client::builder(TokioExecutor::new());
        client_builder.http2_adaptive_window(true);
        let client = client_builder.build(connector);
        let h2c_connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|error| ProxyError::TlsClient(error.to_string()))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let mut h2c_builder = Client::builder(TokioExecutor::new());
        h2c_builder.http2_only(true).http2_adaptive_window(true);
        let h2c_client = h2c_builder.build(h2c_connector);
        let caches = build_route_caches(&config)?;
        let resources = RuntimeResources::new();
        Ok(Self {
            config,
            listener,
            client,
            h2c_client,
            drain: DrainController::with_resources(resources.clone()),
            semantic,
            pooling,
            native,
            extensions: Arc::new(ExtensionRegistry::default()),
            caches,
            observability: MetricsRegistry::default(),
            traces: TraceRecorder::default(),
            resources,
            openai_websockets: OpenAiResponsesWebSocketPool::default(),
        })
    }

    /// Attach the production resource registry shared by the serving runtime.
    ///
    /// Call this during construction, before the proxy admits requests.
    #[must_use]
    pub fn with_runtime_resources(mut self, resources: RuntimeResources) -> Self {
        self.drain = DrainController::with_resources(resources.clone());
        self.resources = resources;
        self
    }

    /// Replace the default in-process metrics registry with a shared one.
    /// Sharing a registry across listeners gives management callers one
    /// process-wide snapshot without introducing an external metrics backend.
    #[must_use]
    pub fn with_observability(mut self, observability: MetricsRegistry) -> Self {
        self.observability = observability;
        self
    }

    /// Replace the default bounded trace recorder.
    #[must_use]
    pub fn with_trace_recorder(mut self, traces: TraceRecorder) -> Self {
        self.traces = traces;
        self
    }

    /// Attach the immutable registry of supervised external extensions.
    #[must_use]
    pub fn with_extensions(mut self, extensions: Arc<ExtensionRegistry>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Return the process-local metrics registry used by this proxy.
    #[must_use]
    pub fn observability(&self) -> MetricsRegistry {
        self.observability.clone()
    }

    /// Return the bounded trace recorder used by this proxy.
    #[must_use]
    pub fn trace_recorder(&self) -> TraceRecorder {
        self.traces.clone()
    }

    /// Return the listener ID served by this proxy.
    #[must_use]
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// Return the graceful-drain controller shared by listener tasks.
    #[must_use]
    pub fn drain_controller(&self) -> DrainController {
        self.drain.clone()
    }

    /// Handle one downstream request and stream the opaque upstream response.
    pub async fn handle(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        let Some(guard) = self.drain.try_acquire() else {
            return plain_response(StatusCode::SERVICE_UNAVAILABLE, "proxy is draining");
        };

        let route = match self.find_route(&request) {
            Ok(route) => route,
            Err(error) => {
                drop(guard);
                let status = match error {
                    RouteMatchError::NoMatch { .. } => StatusCode::NOT_FOUND,
                    RouteMatchError::MethodNotAllowed { .. } => StatusCode::METHOD_NOT_ALLOWED,
                    RouteMatchError::ContentTypeNotAllowed { .. } => {
                        StatusCode::UNSUPPORTED_MEDIA_TYPE
                    }
                };
                return plain_response(status, "no route matched");
            }
        };
        tracing::info!(
            listener = %self.listener,
            route = route.id(),
            method = %request.method(),
            path = request.uri().path(),
            "request routed"
        );
        let mut observation = Some(self.observability.begin_request(route.id()));
        let request_span = self.traces.span(TraceStage::Request, Some(route.id()));
        tracing::debug!(parent: &request_span, listener = %self.listener, route = route.id(), "request span");
        self.traces.record(
            TraceRecord::new(TraceStage::Match)
                .route(route.id())
                .outcome("matched"),
        );

        if let Err(status) = self.validate_request(route, &request) {
            drop(guard);
            return observe_response(status, observation.take(), CompletionClass::InvalidRequest);
        }

        let downstream_secret = route
            .downstream_auth()
            .map(|_| self.resources.secret_material());
        let auth_result = verify_downstream_auth(route, request.headers());
        drop(downstream_secret);
        if let Err(error) = auth_result {
            drop(guard);
            let response = match error {
                DownstreamAuthError::MissingOrInvalid => unauthorized_response(),
                DownstreamAuthError::SecretUnavailable => plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "authentication unavailable",
                ),
            };
            return observe_response(
                response,
                observation.take(),
                CompletionClass::DownstreamError,
            );
        }
        self.traces.record(
            TraceRecord::new(TraceStage::Authentication)
                .route(route.id())
                .outcome("accepted"),
        );
        let is_websocket = route.matcher().websocket() == Some(true);
        let result = if is_websocket {
            self.forward_websocket(route, request, guard, &mut observation)
                .await
        } else {
            self.forward(route, request, guard, &mut observation).await
        };
        match result {
            Ok(response) => {
                tracing::info!(
                    listener = %self.listener,
                    route = route.id(),
                    status = response.status().as_u16(),
                    "upstream response accepted"
                );
                response
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener,
                    route = route.id(),
                    error = %error,
                    "request failed"
                );
                let class = completion_class_for_error(&error);
                observe_response(error_response(error), observation.take(), class)
            }
        }
    }

    /// Begin graceful drain. New requests receive `503`; active streams keep
    /// their permits until their response body ends or is dropped.
    pub fn begin_drain(&self) {
        self.drain.begin_drain();
    }

    /// Cancel requests that did not finish during graceful drain.
    pub fn cancel_active(&self) {
        self.drain.cancel_active();
    }

    /// Wait for active requests to finish after entering drain.
    pub async fn drain(&self, timeout: Duration) -> Result<(), crate::DrainError> {
        self.drain.drain(timeout).await
    }

    fn find_route<'a>(
        &'a self,
        request: &Request<Incoming>,
    ) -> Result<&'a RoutePlan, RouteMatchError> {
        let route_request = RouteRequest::from_http(Arc::clone(&self.listener), request);
        self.config.match_route_request(&route_request)
    }

    // Returning the final HTTP response keeps request rejection centralized and
    // avoids a second error-to-response conversion layer on the hot path.
    #[allow(clippy::result_large_err)]
    fn validate_request(
        &self,
        route: &RoutePlan,
        request: &Request<Incoming>,
    ) -> Result<(), Response<ProxyBody>> {
        let limits = route.limits();
        let headers = request.headers();
        for value in &headers.get_all(header::CONTENT_ENCODING) {
            let supported = value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .all(|encoding| encoding.trim().eq_ignore_ascii_case("identity"))
            });
            if !supported {
                return Err(plain_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "encoded request bodies are not supported",
                ));
            }
        }
        let count = u32::try_from(headers.len()).unwrap_or(u32::MAX);
        let bytes = header_bytes(headers);
        if limits.check_headers(count, bytes).is_err() {
            return Err(plain_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request headers exceed configured limits",
            ));
        }

        if let Some(length) = headers.get(header::CONTENT_LENGTH) {
            let Ok(length) = length
                .to_str()
                .ok()
                .and_then(|value| value.parse().ok())
                .ok_or(())
            else {
                return Err(plain_response(
                    StatusCode::BAD_REQUEST,
                    "invalid content-length",
                ));
            };
            if limits.check_request_body(length).is_err() {
                return Err(plain_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds configured limit",
                ));
            }
        }
        Ok(())
    }

    async fn forward_websocket(
        &self,
        route: &RoutePlan,
        mut request: Request<Incoming>,
        guard: DrainGuard,
        observation: &mut Option<RequestObservation>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let key = validate_websocket_request(&request)?;
        let offered_protocols = websocket_protocols(request.headers());
        if route.ingress().mode() != BodyMode::Opaque || route.response().mode() != BodyMode::Opaque
        {
            return Err(ProxyError::UnsupportedBodyMode {
                route: route.id().to_owned(),
            });
        }

        let started = StdInstant::now();
        let cancellation = guard.cancellation_token();
        let downstream_uri = request.uri().clone();
        let mut headers = request.headers().clone();
        strip_hop_by_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::AUTHORIZATION);
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::CONTENT_TYPE);
        headers.remove("sec-websocket-key");
        headers.remove("sec-websocket-version");
        headers.remove("sec-websocket-extensions");

        let mut selection = self
            .pooling
            .select(&self.config, route, None, &headers, 1, started)
            .map_err(pool_selection_error)?;
        let upstream = self
            .config
            .upstreams()
            .get(selection.upstream_id())
            .ok_or_else(|| ProxyError::MissingUpstream {
                route: route.id().to_owned(),
                upstream: selection.upstream_id().to_owned(),
            })?;
        if !matches!(upstream.transport(), "ws" | "wss") {
            return Err(ProxyError::InvalidWebSocketHandshake(
                "the selected upstream does not use ws or wss".to_owned(),
            ));
        }
        let _secret = (upstream.native().is_some()
            || selection.account_secret().is_some()
            || upstream.auth().is_some())
        .then(|| self.resources.secret_material());
        let native_auth = self
            .native
            .authorize_selected_attempt(NativeAuthorizationRequest::new(
                upstream,
                selection.account_auth_kind(),
                selection.credential(),
                selection.account_secret(),
                upstream.auth(),
                &headers,
                cancellation.clone(),
            ))
            .await
            .map_err(native_error)?;
        if let Some(native_auth) = native_auth {
            native_auth.apply_once(&mut headers).map_err(native_error)?;
        } else if selection.account_secret().is_some() {
            crate::pool::apply_configured_account_auth(
                &mut headers,
                selection.account_secret(),
                upstream.auth().map(pooler_config::AuthPlan::kind),
            )
            .map_err(pool_error)?;
        } else {
            apply_configured_upstream_auth(&mut headers, upstream)?;
        }

        let uri = websocket_uri(upstream, route, &downstream_uri)?;
        let upstream_key = generate_websocket_key()?;
        let deadline = started + request_timeout(route.limits(), upstream);
        let connect = connect_websocket(&uri, &headers, &upstream_key, &offered_protocols);
        let (upstream_socket, upstream_response) = tokio::select! {
            result = time::timeout_at(Instant::from_std(deadline), connect) => {
                result.map_err(|_| ProxyError::Timeout)?
                    ?
            }
            () = cancellation.cancelled() => return Err(ProxyError::Timeout),
        };

        let downstream_upgrade = hyper::upgrade::on(&mut request);
        let downstream_body = request.into_body();
        drop(downstream_body);
        let mut response = Response::new(
            Full::new(Bytes::new())
                .map_err(|never: Infallible| match never {})
                .boxed(),
        );
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *response.version_mut() = http::Version::HTTP_11;
        let response_headers = response.headers_mut();
        response_headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        response_headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        response_headers.insert(
            "sec-websocket-accept",
            HeaderValue::from_str(&derive_websocket_accept(key.as_bytes()))
                .map_err(|_| ProxyError::InvalidWebSocketHandshake("invalid key".to_owned()))?,
        );
        if let Some(protocol) = upstream_response.protocol {
            response_headers.insert("sec-websocket-protocol", protocol);
        }

        let mut observation = observation
            .take()
            .expect("request observation remains until response is ready");
        observation.mark_headers();
        self.pooling
            .persist_affinity(&selection, crate::pool::timestamp_now());
        let lease = selection.take_lease();
        let max_frame_bytes = route.limits().max_frame_bytes;
        let task = self.resources.task();
        tokio::spawn(async move {
            let _task = task;
            run_websocket_tunnel(
                downstream_upgrade,
                upstream_socket,
                WebSocketTunnelContext {
                    max_frame_bytes,
                    guard,
                    cancellation,
                    deadline,
                    lease,
                    observation,
                },
            )
            .await;
        });
        Ok(response)
    }

    async fn run_external_inspectors(
        &self,
        route: &RoutePlan,
        media_type: String,
        body: &[u8],
        cancellation: CancellationToken,
    ) -> Result<BTreeMap<String, String>, ProxyError> {
        let mut metadata = BTreeMap::new();
        for inspector in route.ingress().inspectors() {
            let Some(id) = external_inspector_id(inspector) else {
                continue;
            };
            let inspection = self
                .extensions
                .inspect(
                    id,
                    ExtensionInput {
                        media_type: media_type.clone(),
                        body: body.to_vec(),
                        metadata: extension_metadata(route),
                    },
                    cancellation.clone(),
                )
                .await
                .map_err(|error| ProxyError::Extension(error.to_string()))?;
            metadata.extend(inspection.metadata);
        }
        Ok(metadata)
    }

    async fn forward(
        &self,
        route: &RoutePlan,
        request: Request<Incoming>,
        guard: DrainGuard,
        observation: &mut Option<RequestObservation>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let started = StdInstant::now();
        let fallback_upstream = self
            .config
            .upstreams()
            .get(route.target().upstream())
            .ok_or_else(|| ProxyError::MissingUpstream {
                route: route.id().to_owned(),
                upstream: route.target().upstream().to_owned(),
            })?;
        let buffer_deadline = Instant::from_std(
            started + patch_buffer_timeout(&self.config, route, fallback_upstream),
        );
        let cancellation = guard.cancellation_token();
        let method = request.method().clone();
        let downstream_uri = request.uri().clone();
        let version = request.version();
        let limits = route.limits();
        let downstream_headers = request.headers().clone();
        let cache_identity_safe = self
            .caches
            .get(route.id())
            .is_none_or(|cache| safe_request_for_cache(request.headers(), cache.policy()));
        let mut headers = request.headers().clone();
        strip_hop_by_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::AUTHORIZATION);
        let incoming = request.into_body();
        let idempotency_key_present = headers.contains_key("idempotency-key");
        let method_safe_for_cache = safe_method_for_cache(method.as_str(), idempotency_key_present);
        let replay = ReplayCheck::for_http_method(method.as_str(), idempotency_key_present);
        let (mut prepared, selected_model, selection_context, semantic_response_hint) = match route
            .ingress()
            .mode()
        {
            BodyMode::Opaque => {
                if route.cache().is_some_and(|cache| cache.enabled()) && method_safe_for_cache {
                    let incoming =
                        FrameLimitedBody::new(incoming, bounded_usize(limits.max_frame_bytes));
                    let bytes = tokio::select! {
                        result = time::timeout_at(
                            buffer_deadline,
                            crate::collect_body_limited(
                                incoming,
                                bounded_usize(limits.max_request_body_bytes),
                            ),
                        ) => result
                            .map_err(|_| ProxyError::Timeout)?
                            .map_err(|error| match error {
                                crate::BodyLimitError::TooLarge { .. }
                                | crate::BodyLimitError::Upstream(crate::BodyLimitError::TooLarge { .. }) => {
                                    ProxyError::RequestBodyTooLarge
                                }
                                other => ProxyError::Upstream(Box::new(other)),
                            })?,
                        () = cancellation.cancelled() => {
                            return Err(ProxyError::Timeout);
                        }
                    };
                    (
                        PreparedBody::Buffered {
                            bytes,
                            patch_model: false,
                        },
                        None,
                        SelectionContext::default(),
                        SemanticResponseHint::default(),
                    )
                } else {
                    let body =
                        LimitedBody::new(incoming, bounded_usize(limits.max_request_body_bytes))
                            .map_err(box_error)
                            .boxed();
                    (
                        PreparedBody::Streaming(Some(body)),
                        None,
                        SelectionContext::default(),
                        SemanticResponseHint::default(),
                    )
                }
            }
            BodyMode::Patch => {
                let incoming =
                    FrameLimitedBody::new(incoming, bounded_usize(limits.max_frame_bytes));
                let bytes = tokio::select! {
                    result = time::timeout_at(
                        buffer_deadline,
                        crate::collect_body_limited(
                            incoming,
                            bounded_usize(limits.max_request_body_bytes),
                        ),
                    ) => result
                        .map_err(|_| ProxyError::Timeout)?
                        .map_err(|error| match error {
                            crate::BodyLimitError::TooLarge { .. } => {
                                ProxyError::RequestBodyTooLarge
                            }
                            crate::BodyLimitError::Upstream(
                                crate::BodyLimitError::TooLarge { .. },
                            ) => ProxyError::RequestBodyTooLarge,
                            other => ProxyError::InvalidPatch(other.to_string()),
                        })?,
                    () = cancellation.cancelled() => {
                        return Err(ProxyError::Timeout);
                    }
                };
                let mut document = PreservedJson::from_bytes(bytes.to_vec())
                    .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
                let external_metadata = self
                    .run_external_inspectors(
                        route,
                        content_type_for_extension(&headers),
                        document.bytes().as_ref(),
                        cancellation.clone(),
                    )
                    .await?;
                let inspected_model =
                    if route.target().model_source() == Some(ModelSource::Inspected) {
                        let body_model = document
                            .extract_model()
                            .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?
                            .map(str::to_owned);
                        body_model.or_else(|| external_metadata.get("model").cloned())
                    } else {
                        None
                    };
                for transform in route.request_steps() {
                    match transform {
                        RequestTransform::JsonSet { pointer, value } => {
                            document
                                .set_pointer_bounded(
                                    pointer,
                                    value.clone(),
                                    JsonPatchLimits::default(),
                                )
                                .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
                        }
                        RequestTransform::JsonSetWhenModelPrefix {
                            prefix,
                            pointer,
                            value,
                        } => {
                            document
                                .set_pointer_when_model_prefix(
                                    prefix,
                                    pointer,
                                    value.clone(),
                                    JsonPatchLimits::default(),
                                )
                                .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
                        }
                    }
                }
                for extension in route.external_transforms() {
                    let transformed = self
                        .extensions
                        .transform(
                            extension,
                            ExtensionInput {
                                media_type: content_type_for_extension(&headers),
                                body: document.bytes().into_owned(),
                                metadata: extension_metadata(route),
                            },
                            cancellation.clone(),
                        )
                        .await
                        .map_err(|error| ProxyError::Extension(error.to_string()))?;
                    document = PreservedJson::from_bytes(transformed)
                        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
                }
                let bytes = document.bytes().into_owned();
                limits
                    .check_request_body(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                limits
                    .check_frame(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                headers.remove(header::CONTENT_LENGTH);
                let selected_model = match route.target().model_source() {
                    Some(ModelSource::Request) => Some(
                        document
                            .require_model()
                            .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?
                            .to_owned(),
                    ),
                    Some(ModelSource::Inspected) => Some(inspected_model.ok_or_else(|| {
                        ProxyError::InvalidPatch("request model is missing".to_owned())
                    })?),
                    None => None,
                };
                (
                    PreparedBody::Buffered {
                        bytes: Bytes::from(bytes),
                        patch_model: selected_model.is_some(),
                    },
                    selected_model,
                    SelectionContext::default(),
                    SemanticResponseHint::default(),
                )
            }
            BodyMode::Semantic => {
                strip_provider_credential_headers(&mut headers);
                let incoming =
                    FrameLimitedBody::new(incoming, bounded_usize(limits.max_frame_bytes));
                let bytes = tokio::select! {
                    result = time::timeout_at(
                        buffer_deadline,
                        crate::collect_body_limited(
                            incoming,
                            bounded_usize(limits.max_request_body_bytes),
                        ),
                    ) => result
                        .map_err(|_| ProxyError::Timeout)?
                        .map_err(|error| match error {
                            crate::BodyLimitError::TooLarge { .. } => {
                                ProxyError::RequestBodyTooLarge
                            }
                            crate::BodyLimitError::Upstream(
                                crate::BodyLimitError::TooLarge { .. },
                            ) => ProxyError::RequestBodyTooLarge,
                            other => ProxyError::SemanticRequest(other.to_string()),
                        })?,
                    () = cancellation.cancelled() => {
                        return Err(ProxyError::Timeout);
                    }
                };
                let selection_context = self
                    .semantic
                    .selection_context_with_uri(route, &downstream_uri, &headers, &bytes)
                    .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
                let prepared = self
                    .semantic
                    .encode_request_with_uri(route, &downstream_uri, &headers, &bytes)
                    .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
                limits
                    .check_request_body(u64::try_from(prepared.body.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                limits
                    .check_frame(u64::try_from(prepared.body.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                headers.insert(header::CONTENT_TYPE, prepared.content_type);
                self.semantic.sanitize_request_headers(&mut headers);
                headers.insert(
                    header::ACCEPT_ENCODING,
                    HeaderValue::from_static("identity"),
                );
                headers.remove(header::CONTENT_LENGTH);
                let response_hint = prepared.response_hint;
                (
                    PreparedBody::Buffered {
                        bytes: Bytes::from(prepared.body),
                        patch_model: route.target().model_source().is_some()
                            && self.semantic.model_in_request_body(route),
                    },
                    None,
                    selection_context,
                    response_hint,
                )
            }
            BodyMode::Inspect => {
                let incoming =
                    FrameLimitedBody::new(incoming, bounded_usize(limits.max_frame_bytes));
                let bytes = tokio::select! {
                    result = time::timeout_at(
                        buffer_deadline,
                        crate::collect_body_limited(
                            incoming,
                            bounded_usize(limits.max_request_body_bytes),
                        ),
                    ) => result
                        .map_err(|_| ProxyError::Timeout)?
                        .map_err(|error| match error {
                            crate::BodyLimitError::TooLarge { .. }
                            | crate::BodyLimitError::Upstream(crate::BodyLimitError::TooLarge { .. }) => {
                                ProxyError::RequestBodyTooLarge
                            }
                            other => ProxyError::InvalidPatch(other.to_string()),
                        })?,
                    () = cancellation.cancelled() => {
                        return Err(ProxyError::Timeout);
                    }
                };
                let _external_metadata = self
                    .run_external_inspectors(
                        route,
                        content_type_for_extension(&headers),
                        &bytes,
                        cancellation.clone(),
                    )
                    .await?;
                limits
                    .check_request_body(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                headers.remove(header::CONTENT_LENGTH);
                (
                    PreparedBody::Buffered {
                        bytes,
                        patch_model: false,
                    },
                    None,
                    SelectionContext::default(),
                    SemanticResponseHint::default(),
                )
            }
        };
        let is_buffered = matches!(prepared, PreparedBody::Buffered { .. });
        let mut cache_leader = None;
        if is_buffered && cache_identity_safe && method_safe_for_cache {
            if let Some(cache) = self.caches.get(route.id()).cloned() {
                let body = match &prepared {
                    PreparedBody::Buffered { bytes, .. } => bytes.as_ref(),
                    PreparedBody::Streaming(_) => &[],
                };
                let target = route.target().path().map_or_else(
                    || route.target().upstream().to_owned(),
                    |path| format!("{}:{path}", route.target().upstream()),
                );
                let request_uri = downstream_uri.to_string();
                let key = CacheKey::from_request(CacheKeyInput {
                    generation: self.config.generation(),
                    route: route.id(),
                    target: &target,
                    method: method.as_str(),
                    uri: &request_uri,
                    headers: &headers,
                    key_headers: cache.policy().key_headers(),
                    body,
                });
                if let Some(cached) = cache.get(&key, StdInstant::now()) {
                    return self
                        .finish_cached_response(route, cached, guard, observation)
                        .await;
                }
                loop {
                    match cache.begin_with_size(key, body.len()) {
                        CacheLookup::Disabled => break,
                        CacheLookup::Leader(owner) => {
                            cache_leader = Some(owner);
                            break;
                        }
                        CacheLookup::Follower(follower) => {
                            if let Some(cached) = follower.wait(&cancellation).await {
                                return self
                                    .finish_cached_response(route, cached, guard, observation)
                                    .await;
                            }
                            if cancellation.is_cancelled() {
                                return Err(ProxyError::Timeout);
                            }
                        }
                    }
                }
            }
        }
        let cancellation = cache_leader.as_ref().map_or_else(
            || cancellation.clone(),
            |leader| {
                link_cancellation(
                    cancellation.clone(),
                    leader.cancellation_token(),
                    &self.resources,
                )
            },
        );
        let mut attempt = 1_u32;
        let mut elapsed_retry_delay = Duration::ZERO;
        let mut elapsed_recovery_wait = Duration::ZERO;
        let mut credentials_used = BTreeSet::new();
        let mut providers_used = BTreeSet::new();
        let mut forced_selection = None;
        let mut native_refresh_attempted = false;

        loop {
            let mut selection = if let Some(selection) = forced_selection.take() {
                selection
            } else {
                self.pooling
                    .select_with_context(
                        &self.config,
                        route,
                        selected_model.as_deref(),
                        &headers,
                        &selection_context,
                        SelectionTiming::new(attempt, started),
                    )
                    .map_err(pool_selection_error)?
            };
            if let Some(explanation) = selection.explanation() {
                let decision = DecisionRecord::from(explanation);
                self.observability.record_decision(&decision);
                self.traces.record_decision(&decision);
            } else {
                self.traces.record(
                    TraceRecord::new(TraceStage::Selection)
                        .route(route.id())
                        .provider(selection.provider().as_str())
                        .attempt(attempt)
                        .outcome("selected"),
                );
            }
            if let Some(credential) = selection.credential() {
                credentials_used.insert(credential.clone());
            }
            providers_used.insert(selection.provider().clone());
            let upstream = self
                .config
                .upstreams()
                .get(selection.upstream_id())
                .ok_or_else(|| ProxyError::MissingUpstream {
                    route: route.id().to_owned(),
                    upstream: selection.upstream_id().to_owned(),
                })?;
            let retry_deadline = retry_deadline(started, limits, upstream, selection.policy());
            let _secret = (upstream.native().is_some()
                || selection.account_secret().is_some()
                || upstream.auth().is_some())
            .then(|| self.resources.secret_material());
            let native_auth = self
                .native
                .authorize_selected_attempt(NativeAuthorizationRequest::new(
                    upstream,
                    selection.account_auth_kind(),
                    selection.credential(),
                    selection.account_secret(),
                    upstream.auth(),
                    &headers,
                    cancellation.clone(),
                ))
                .await
                .map_err(native_error)?;
            // Keep only non-secret identity state after the authorization is
            // moved into this one-shot attempt.
            let native_profile = native_auth
                .as_ref()
                .is_some_and(NativeAuthorization::is_refreshable);
            let native_generation = native_auth
                .as_ref()
                .filter(|authorization| authorization.is_refreshable())
                .map(NativeAuthorization::generation);
            let connection_generation = native_auth.as_ref().map(|authorization| {
                if authorization.is_refreshable() {
                    CredentialGeneration::Native(authorization.generation())
                } else {
                    materialized_authorization_generation(
                        self.config.generation(),
                        authorization.authorization_delta(),
                    )
                }
            });
            let attempt_started = StdInstant::now();
            let attempt_request = AttemptRequest {
                route,
                method: &method,
                downstream_uri: &downstream_uri,
                version,
                headers: &headers,
                upstream,
                selection: &selection,
                native_auth,
                native_profile,
                connection_generation,
                cancellation: &cancellation,
                started,
            };
            let websocket_transport = self.semantic.websocket_transport(route);
            let response = match (
                websocket_transport,
                matches!(upstream.transport(), "ws" | "wss"),
            ) {
                (Some(transport), true) => {
                    match prepared.buffered_bytes_for_attempt(route, &selection) {
                        Ok(bytes) => {
                            self.send_openai_responses_websocket_attempt(
                                attempt_request,
                                bytes,
                                transport,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    }
                }
                _ => match prepared.body_for_attempt(route, &selection) {
                    Ok(attempt_body) => self.send_attempt(attempt_request, attempt_body).await,
                    Err(error) => Err(error),
                },
            };
            let attempt_result = match response.as_ref() {
                Ok(response) if response.status().is_success() => AttemptResult::Success,
                Ok(_) => AttemptResult::Error,
                Err(ProxyError::Timeout) => AttemptResult::Cancelled,
                Err(_) => AttemptResult::Error,
            };
            self.observability.record_attempt(
                AttemptRecord::new(route.id(), selection.provider().as_str(), attempt_result)
                    .duration(attempt_started.elapsed()),
            );
            self.traces.record(
                TraceRecord::new(TraceStage::Attempt)
                    .route(route.id())
                    .provider(selection.provider().as_str())
                    .attempt(attempt)
                    .duration(attempt_started.elapsed())
                    .outcome(attempt_result.to_string()),
            );

            let mut response = match response {
                Ok(response) => response,
                Err(error) => {
                    let failure_status = match &error {
                        ProxyError::WebSocketHandshakeStatus(status) => Some(*status),
                        _ => None,
                    };
                    if failure_status == Some(401)
                        && is_buffered
                        && native_profile
                        && !native_refresh_attempted
                    {
                        native_refresh_attempted = true;
                        let credential = selection.credential().ok_or_else(|| {
                            ProxyError::Native("credential is not configured".to_owned())
                        })?;
                        let generation = native_generation.ok_or_else(|| {
                            ProxyError::Native("authorization is unavailable".to_owned())
                        })?;
                        match self
                            .native
                            .refresh(upstream, credential, generation, cancellation.clone())
                            .await
                        {
                            Ok(_) => {
                                forced_selection = Some(selection);
                                attempt = attempt.saturating_add(1);
                                continue;
                            }
                            Err(NativeRuntimeError::NeedsReauth) => {
                                self.pooling.disable_credential(credential);
                            }
                            Err(_) => {}
                        }
                    }
                    if is_buffered && selection.has_policy() {
                        let mut failure =
                            self.pooling.classify_failure(crate::pool::FailureInput {
                                config: &self.config,
                                route,
                                selection: &mut selection,
                                status: failure_status,
                                provider_code: None,
                                message: None,
                                native_codex: native_profile,
                                quota_observations: &[],
                                retry_after: None,
                                replay,
                                commitment: CommitmentState::Uncommitted,
                                idempotency_key_present,
                                attempt,
                                credentials_used: u32::try_from(credentials_used.len())
                                    .unwrap_or(u32::MAX),
                                providers_used: u32::try_from(providers_used.len())
                                    .unwrap_or(u32::MAX),
                                elapsed_retry_delay,
                                elapsed_recovery_wait,
                                started,
                            });
                        self.observe_failure(route, &selection, &failure);
                        if failure.decision.is_retry() {
                            forced_selection = failure.take_replacement();
                            let delay = failure.decision.delay();
                            if delay > retry_deadline.saturating_duration_since(Instant::now()) {
                                return Err(ProxyError::Timeout);
                            }
                            crate::wait_for_retry(delay, &cancellation)
                                .await
                                .map_err(|_| ProxyError::Timeout)?;
                            elapsed_retry_delay = elapsed_retry_delay.saturating_add(delay);
                            if let Some(recovery) =
                                failure.classification.classification.recovery_after
                            {
                                elapsed_recovery_wait =
                                    elapsed_recovery_wait.saturating_add(recovery);
                            }
                            attempt = attempt.saturating_add(1);
                            continue;
                        }
                    }
                    return Err(error);
                }
            };
            let status = response.status().as_u16();
            let mut retry_after = retry_after_delay(response.headers());
            let mut provider_code = response
                .headers()
                .get("x-error-code")
                .or_else(|| response.headers().get("x-provider-code"))
                .and_then(|value| value.to_str().ok())
                .map(|value| value.chars().take(128).collect());
            let mut quota_observations = Vec::new();
            if native_profile && !matches!(status, 402 | 429) {
                provider_code = None;
            }

            if is_buffered && should_classify(Some(status)) && selection.has_policy() {
                let inspected = self
                    .inspect_failure_response(
                        response,
                        upstream,
                        status,
                        limits,
                        &cancellation,
                        retry_deadline,
                    )
                    .await?;
                response = inspected.response;
                if provider_code.is_none() {
                    provider_code = inspected.provider_code;
                }
                retry_after = retry_after.or(inspected.retry_after);
                quota_observations = inspected.quota_observations;
            }

            // A native OAuth 401 is eligible for exactly one pre-commit refresh. The
            // response is still buffered and no downstream headers have been
            // sent, so retrying remains safe. A failed refresh is returned as
            // the provider response unless invalid_grant disables this account
            // and the configured pool has another eligible target.
            if status == 401 && is_buffered && native_profile && !native_refresh_attempted {
                native_refresh_attempted = true;
                let credential = selection
                    .credential()
                    .ok_or_else(|| ProxyError::Native("credential is not configured".to_owned()))?;
                let generation = native_generation
                    .ok_or_else(|| ProxyError::Native("authorization is unavailable".to_owned()))?;
                match self
                    .native
                    .refresh(upstream, credential, generation, cancellation.clone())
                    .await
                {
                    Ok(_) => {
                        forced_selection = Some(selection);
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    Err(NativeRuntimeError::NeedsReauth) => {
                        self.pooling.disable_credential(credential);
                        let can_fail_over = selection
                            .policy()
                            .is_some_and(|policy| attempt < policy.retry().maximum_attempts());
                        if can_fail_over {
                            attempt = attempt.saturating_add(1);
                            continue;
                        }
                    }
                    Err(_) => {}
                }
            }

            if is_buffered && should_classify(Some(status)) && selection.has_policy() {
                let mut failure = self.pooling.classify_failure(crate::pool::FailureInput {
                    config: &self.config,
                    route,
                    selection: &mut selection,
                    status: Some(status),
                    provider_code: provider_code.clone(),
                    message: None,
                    native_codex: native_profile,
                    quota_observations: &quota_observations,
                    retry_after,
                    replay,
                    commitment: CommitmentState::Uncommitted,
                    idempotency_key_present,
                    attempt,
                    credentials_used: u32::try_from(credentials_used.len()).unwrap_or(u32::MAX),
                    providers_used: u32::try_from(providers_used.len()).unwrap_or(u32::MAX),
                    elapsed_retry_delay,
                    elapsed_recovery_wait,
                    started,
                });
                self.observe_failure(route, &selection, &failure);
                if failure.decision.is_retry() {
                    forced_selection = failure.take_replacement();
                    self.drain_retry_response(response, limits, &cancellation, retry_deadline)
                        .await?;
                    let delay = failure.decision.delay();
                    if delay > retry_deadline.saturating_duration_since(Instant::now()) {
                        return Err(ProxyError::Timeout);
                    }
                    crate::wait_for_retry(delay, &cancellation)
                        .await
                        .map_err(|_| ProxyError::Timeout)?;
                    elapsed_retry_delay = elapsed_retry_delay.saturating_add(delay);
                    if let Some(recovery) = failure.classification.classification.recovery_after {
                        elapsed_recovery_wait = elapsed_recovery_wait.saturating_add(recovery);
                    }
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            }

            let observation = observation
                .take()
                .expect("request observation remains until response is ready");
            return self
                .finish_response(
                    route,
                    response,
                    selection,
                    FinishResponseContext {
                        guard,
                        cancellation,
                        started,
                        observation,
                        request_headers: downstream_headers,
                        semantic_response_hint,
                        cache_leader,
                    },
                )
                .await;
        }
    }

    async fn send_attempt(
        &self,
        request: AttemptRequest<'_>,
        body: ProxyBody,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let AttemptRequest {
            route,
            method,
            downstream_uri,
            version: _downstream_version,
            headers: request_headers,
            upstream,
            selection,
            native_auth,
            native_profile: _,
            connection_generation: _,
            cancellation,
            started,
        } = request;
        let mut headers = request_headers.clone();
        if let Some(native_auth) = native_auth {
            native_auth.apply_once(&mut headers).map_err(native_error)?;
        } else if selection.account_secret().is_some() {
            let _ = crate::pool::apply_configured_account_auth(
                &mut headers,
                selection.account_secret(),
                upstream.auth().map(pooler_config::AuthPlan::kind),
            )
            .map_err(pool_error)?;
        } else {
            apply_configured_upstream_auth(&mut headers, upstream)?;
        }
        let body = FrameLimitedBody::new(body, bounded_usize(route.limits().max_frame_bytes))
            .map_err(box_error)
            .boxed();
        let uri = upstream_uri(upstream, route, downstream_uri)?;
        let uri = self
            .semantic
            .rewrite_upstream_uri(route, downstream_uri, selection.upstream_model(), uri)
            .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
        let header_count = u32::try_from(headers.len()).unwrap_or(u32::MAX);
        route
            .limits()
            .check_headers(header_count, header_bytes(&headers))
            .map_err(|_| ProxyError::InvalidLimits("upstream headers exceed limits".to_owned()))?;
        let mut builder =
            Request::builder()
                .method(method.clone())
                .uri(uri)
                .version(if upstream.http2() {
                    http::Version::HTTP_2
                } else {
                    http::Version::HTTP_11
                });
        *builder.headers_mut().expect("request builder headers") = headers;
        let upstream_request = builder.body(body)?;
        let request_deadline = started + request_timeout(route.limits(), upstream);
        let header_deadline = Instant::from_std(
            (StdInstant::now() + connect_timeout(route.limits(), upstream)).min(request_deadline),
        );
        let response = tokio::select! {
            result = time::timeout_at(
                header_deadline,
                if upstream.http2() {
                    self.h2c_client.request(upstream_request)
                } else {
                    self.client.request(upstream_request)
                },
            ) => {
                result.map_err(|_| ProxyError::Timeout)?.map_err(|error| ProxyError::Upstream(Box::new(error)))?
            }
            () = cancellation.cancelled() => {
                return Err(ProxyError::Timeout);
            }
        };
        route
            .limits()
            .check_headers(
                u32::try_from(response.headers().len()).unwrap_or(u32::MAX),
                header_bytes(response.headers()),
            )
            .map_err(|_| ProxyError::InvalidLimits("upstream headers exceed limits".to_owned()))?;
        if response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| route.limits().check_response_body(length).is_err())
        {
            return Err(ProxyError::InvalidLimits(
                "upstream response body exceeds limits".to_owned(),
            ));
        }
        let (parts, body) = response.into_parts();
        let body = FrameLimitedBody::new(body, bounded_usize(route.limits().max_frame_bytes))
            .map_err(box_error)
            .boxed();
        Ok(Response::from_parts(parts, body))
    }

    async fn send_openai_responses_websocket_attempt(
        &self,
        request: AttemptRequest<'_>,
        body: Bytes,
        transport: SemanticWebSocketTransport,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let AttemptRequest {
            route,
            method: _,
            downstream_uri,
            version: _,
            headers: request_headers,
            upstream,
            selection,
            native_auth,
            native_profile,
            connection_generation,
            cancellation,
            started,
        } = request;
        let mut headers = request_headers.clone();
        if let Some(native_auth) = native_auth {
            native_auth.apply_once(&mut headers).map_err(native_error)?;
        } else if selection.account_secret().is_some() {
            crate::pool::apply_configured_account_auth(
                &mut headers,
                selection.account_secret(),
                upstream.auth().map(pooler_config::AuthPlan::kind),
            )
            .map_err(pool_error)?;
        } else {
            apply_configured_upstream_auth(&mut headers, upstream)?;
        }
        if transport == SemanticWebSocketTransport::OpenAiResponses {
            headers.insert(
                "openai-beta",
                HeaderValue::from_static(RESPONSES_WEBSOCKET_BETA),
            );
        }
        route
            .limits()
            .check_headers(
                u32::try_from(headers.len()).unwrap_or(u32::MAX),
                header_bytes(&headers),
            )
            .map_err(|_| ProxyError::InvalidLimits("upstream headers exceed limits".to_owned()))?;
        let endpoint = websocket_uri(upstream, route, downstream_uri)?;
        let profile = match transport {
            SemanticWebSocketTransport::OpenAiResponses if native_profile => "codex_subscription",
            SemanticWebSocketTransport::OpenAiResponses => "openai_api_key",
            SemanticWebSocketTransport::XaiResponses => "xai_api_key",
        };
        let account = selection
            .credential()
            .map_or_else(|| upstream.id(), pooler_core::CredentialId::as_str);
        let generation = connection_generation
            .unwrap_or_else(|| materialized_generation(self.config.generation(), &headers));
        let session = downstream_session_identity(request_headers, &body);
        let identity = ConnectionIdentity::new(profile, account, endpoint, generation, session);
        let request_timeout = request_timeout(route.limits(), upstream);
        let request_deadline = started + request_timeout;
        let connect_deadline =
            (StdInstant::now() + connect_timeout(route.limits(), upstream)).min(request_deadline);
        let first_event_deadline = selection
            .policy()
            .map(|policy| started + policy.stream().bootstrap_timeout())
            .unwrap_or(request_deadline)
            .min(request_deadline);
        let body = self
            .openai_websockets
            .execute(OpenAiResponsesWebSocketAttempt {
                identity,
                headers,
                request_body: body,
                flavor: match transport {
                    SemanticWebSocketTransport::OpenAiResponses => ResponsesWebSocketFlavor::OpenAi,
                    SemanticWebSocketTransport::XaiResponses => ResponsesWebSocketFlavor::Xai,
                },
                limits: route.limits().clone(),
                loss_policy: route.loss_policy(),
                connect_deadline,
                first_event_deadline,
                request_deadline,
                idle_timeout: request_timeout,
                cancellation: cancellation.clone(),
                resources: self.resources.clone(),
            })
            .await
            .map_err(openai_websocket_error)?;
        let mut response = Response::new(body.boxed());
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        response.extensions_mut().insert(SemanticWebSocketResponse);
        Ok(response)
    }

    async fn drain_retry_response(
        &self,
        response: Response<ProxyBody>,
        limits: &RouteLimits,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), ProxyError> {
        let body =
            FrameLimitedBody::new(response.into_body(), bounded_usize(limits.max_frame_bytes));
        let body = LimitedBody::new(body, bounded_usize(limits.max_response_body_bytes));
        tokio::select! {
            result = time::timeout_at(
                deadline,
                crate::collect_body_limited(body, bounded_usize(limits.max_response_body_bytes)),
            ) => {
                let result = result.map_err(|_| ProxyError::Timeout)?;
                result.map(|_| ()).map_err(|error| ProxyError::Upstream(Box::new(error)))
            }
            () = cancellation.cancelled() => Err(ProxyError::Timeout),
        }
    }

    async fn inspect_failure_response(
        &self,
        response: Response<ProxyBody>,
        upstream: &UpstreamPlan,
        status: u16,
        limits: &RouteLimits,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Result<InspectedFailureResponse, ProxyError> {
        let (parts, body) = response.into_parts();
        let body = LimitedBody::new(body, bounded_usize(limits.max_response_body_bytes));
        let body = tokio::select! {
            result = time::timeout_at(
                deadline,
                crate::collect_body_limited(body, bounded_usize(limits.max_response_body_bytes)),
            ) => result
                .map_err(|_| ProxyError::Timeout)?
                .map_err(|error| ProxyError::Upstream(Box::new(error)))?,
            () = cancellation.cancelled() => return Err(ProxyError::Timeout),
        };
        let (provider_code, retry_after) =
            self.native
                .quota_evidence(upstream, status, &parts.headers, &body);
        let quota_observations =
            provider_quota_observations(upstream, status, &parts.headers, &body);
        let response = Response::from_parts(
            parts,
            Full::new(body)
                .map_err(|never: Infallible| match never {})
                .boxed(),
        );
        Ok(InspectedFailureResponse {
            response,
            provider_code,
            retry_after,
            quota_observations,
        })
    }

    fn observe_failure(
        &self,
        route: &RoutePlan,
        selection: &PoolSelection,
        failure: &crate::pool::PoolFailure,
    ) {
        let class = failure.classification.classification.class;
        if let Some(cooldown) = &failure.classification.cooldown {
            self.observability.record_cooldown(CooldownRecord {
                route: Some(route.id().to_owned()),
                provider: Some(selection.provider().to_string()),
                scope: format!("{:?}", cooldown.scope),
                outcome: "applied".to_owned(),
            });
        }
        if matches!(
            class,
            ErrorClass::CredentialQuotaExhausted | ErrorClass::ModelQuotaExhausted
        ) {
            self.observability.record_quota(QuotaRecord {
                route: Some(route.id().to_owned()),
                provider: selection.provider().to_string(),
                outcome: "exhausted".to_owned(),
            });
        }
        if failure.decision.is_retry() {
            self.observability.record_retry(RetryRecord {
                route: route.id().to_owned(),
                provider: selection.provider().to_string(),
                reason: "policy_retry".to_owned(),
                fallback: true,
            });
        }
    }

    async fn finish_cached_response(
        &self,
        route: &RoutePlan,
        cached: Arc<CachedResponse>,
        guard: DrainGuard,
        observation: &mut Option<RequestObservation>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let mut observation = observation
            .take()
            .expect("request observation remains until cached response is ready");
        observation.mark_headers();
        self.traces.record(
            TraceRecord::new(TraceStage::Persistence)
                .route(route.id())
                .outcome("cache_hit"),
        );
        let body = Full::new(cached.body().clone())
            .map_err(|never: Infallible| match never {})
            .boxed();
        let body = ObservedBody::new(
            body,
            observation,
            completion_class_for_status(cached.status()),
        );
        let body = DrainedBody::new(body, guard).boxed();
        let mut response = Response::new(body);
        *response.status_mut() = cached.status();
        *response.version_mut() = cached.version();
        *response.headers_mut() = cached.headers().clone();
        Ok(response)
    }

    async fn finish_response(
        &self,
        route: &RoutePlan,
        response: Response<ProxyBody>,
        mut selection: PoolSelection,
        context: FinishResponseContext,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let FinishResponseContext {
            guard,
            cancellation,
            started,
            mut observation,
            request_headers,
            semantic_response_hint,
            mut cache_leader,
        } = context;
        let (parts, body) = response.into_parts();
        let semantic_websocket = parts
            .extensions
            .get::<SemanticWebSocketResponse>()
            .is_some();
        let mut response_headers = parts.headers;
        strip_hop_by_hop_headers(&mut response_headers);
        let upstream = self
            .config
            .upstreams()
            .get(selection.upstream_id())
            .ok_or_else(|| ProxyError::MissingUpstream {
                route: route.id().to_owned(),
                upstream: selection.upstream_id().to_owned(),
            })?;
        let body = LimitedBody::new(body, bounded_usize(route.limits().max_response_body_bytes))
            .map_err(box_error)
            .boxed();
        let body = DeadlineBody::new(
            body,
            Instant::from_std(started + request_timeout(route.limits(), upstream)),
        )
        .boxed();
        observation.mark_headers();
        let mut body = if route.response().mode() == BodyMode::Semantic
            && parts.status.is_success()
            && !semantic_websocket
        {
            let transformed = self
                .semantic
                .decode_response_with_hint(
                    route,
                    body,
                    &request_headers,
                    &semantic_response_hint,
                    cancellation.clone(),
                )
                .map_err(|error| {
                    observation.complete(CompletionClass::Unsupported, None);
                    ProxyError::SemanticResponse(error.to_string())
                })?;
            response_headers.remove(header::CONTENT_LENGTH);
            response_headers.remove(header::CONTENT_ENCODING);
            response_headers.insert(header::CONTENT_TYPE, transformed.content_type);
            transformed.body
        } else {
            body
        };
        if let Some(mut leader) = cache_leader.take() {
            let expected_bytes = response_headers
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .and_then(|value| usize::try_from(value).ok());
            if !parts.status.is_success()
                || !safe_response_for_cache(&response_headers)
                || expected_bytes.is_none()
                || !leader.reserve_response_bytes(expected_bytes.unwrap_or(0))
            {
                leader.fail();
            } else {
                let collected = tokio::select! {
                    result = crate::collect_body_limited(
                        body,
                        expected_bytes.expect("cache response length was checked"),
                    ) => result,
                    () = cancellation.cancelled() => {
                        leader.fail();
                        return Err(ProxyError::Timeout);
                    }
                };
                let collected_body =
                    collected.map_err(|error| ProxyError::Upstream(Box::new(error)))?;
                leader.publish(CachedResponse::new(
                    parts.status,
                    parts.version,
                    replayable_response_headers(&response_headers),
                    collected_body.clone(),
                ));
                body = Full::new(collected_body)
                    .map_err(|never: Infallible| match never {})
                    .boxed();
            }
        }
        self.pooling
            .persist_affinity(&selection, crate::pool::timestamp_now());
        let usage_target = UsageTarget {
            provider: selection.provider().as_str().to_owned(),
            model: selection.upstream_model().map(str::to_owned),
        };
        let body = SelectionLeaseBody::new(body, selection.take_lease()).boxed();
        self.traces.record(
            TraceRecord::new(TraceStage::Persistence)
                .route(route.id())
                .provider(selection.provider().as_str())
                .outcome("response_ready"),
        );
        let completion = completion_class_for_status(parts.status);
        let body = ObservedBody::new_for_target(body, observation, completion, usage_target);
        let body = DrainedBody::new(body, guard).boxed();
        let mut response = Response::new(body);
        *response.status_mut() = parts.status;
        *response.version_mut() = parts.version;
        *response.headers_mut() = response_headers;
        Ok(response)
    }
}

enum PreparedBody {
    Streaming(Option<ProxyBody>),
    Buffered { bytes: Bytes, patch_model: bool },
}

struct AttemptRequest<'a> {
    route: &'a RoutePlan,
    method: &'a http::Method,
    downstream_uri: &'a Uri,
    version: http::Version,
    headers: &'a HeaderMap,
    upstream: &'a UpstreamPlan,
    selection: &'a PoolSelection,
    native_auth: Option<NativeAuthorization>,
    native_profile: bool,
    connection_generation: Option<CredentialGeneration>,
    cancellation: &'a CancellationToken,
    started: StdInstant,
}

struct FinishResponseContext {
    guard: DrainGuard,
    cancellation: CancellationToken,
    started: StdInstant,
    observation: RequestObservation,
    request_headers: HeaderMap,
    semantic_response_hint: SemanticResponseHint,
    cache_leader: Option<CacheLeader>,
}

struct InspectedFailureResponse {
    response: Response<ProxyBody>,
    provider_code: Option<String>,
    retry_after: Option<Duration>,
    quota_observations: Vec<QuotaObservation>,
}

impl PreparedBody {
    fn buffered_bytes_for_attempt(
        &self,
        route: &RoutePlan,
        selection: &PoolSelection,
    ) -> Result<Bytes, ProxyError> {
        let Self::Buffered { bytes, patch_model } = self else {
            return Err(ProxyError::SemanticRequest(
                "semantic WebSocket requests must be buffered".to_owned(),
            ));
        };
        if *patch_model {
            if let Some(model) = selection.upstream_model() {
                return patch_body_for_target(bytes, route, model, selection);
            }
        }
        Ok(bytes.clone())
    }

    fn body_for_attempt(
        &mut self,
        route: &RoutePlan,
        selection: &PoolSelection,
    ) -> Result<ProxyBody, ProxyError> {
        match self {
            Self::Streaming(body) => {
                body.take()
                    .ok_or(ProxyError::Upstream(Box::new(io::Error::other(
                        "streaming request body was already used",
                    ))))
            }
            Self::Buffered { bytes, patch_model } => {
                let bytes = if *patch_model {
                    if let Some(model) = selection.upstream_model() {
                        patch_body_for_target(bytes, route, model, selection)?
                    } else {
                        bytes.clone()
                    }
                } else {
                    bytes.clone()
                };
                Ok(Full::new(bytes)
                    .map_err(|never: Infallible| match never {})
                    .boxed())
            }
        }
    }
}

struct SelectionLeaseBody {
    inner: Pin<Box<ProxyBody>>,
    lease: Option<pooler_policy::SelectionLease>,
}

impl SelectionLeaseBody {
    fn new(inner: ProxyBody, lease: Option<pooler_policy::SelectionLease>) -> Self {
        Self {
            inner: Box::pin(inner),
            lease,
        }
    }
}

impl Body for SelectionLeaseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.inner.as_mut().poll_frame(context);
        match &result {
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                self.lease.take();
            }
            _ => {}
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

const MAX_USAGE_OBSERVATION_BYTES: usize = 256 * 1024;

struct UsageTarget {
    provider: String,
    model: Option<String>,
}

struct ObservedBody {
    inner: Pin<Box<ProxyBody>>,
    observation: Option<RequestObservation>,
    completion: CompletionClass,
    usage_target: Option<UsageTarget>,
    usage_bytes: Vec<u8>,
    usage_overflowed: bool,
}

impl ObservedBody {
    fn new(inner: ProxyBody, observation: RequestObservation, completion: CompletionClass) -> Self {
        Self {
            inner: Box::pin(inner),
            observation: Some(observation),
            completion,
            usage_target: None,
            usage_bytes: Vec::new(),
            usage_overflowed: false,
        }
    }

    fn new_for_target(
        inner: ProxyBody,
        observation: RequestObservation,
        completion: CompletionClass,
        usage_target: UsageTarget,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            observation: Some(observation),
            completion,
            usage_target: Some(usage_target),
            usage_bytes: Vec::new(),
            usage_overflowed: false,
        }
    }

    fn complete(&mut self, completion: CompletionClass) {
        let Some(mut observation) = self.observation.take() else {
            return;
        };
        let usage = (!self.usage_overflowed)
            .then(|| extract_observed_usage(&self.usage_bytes))
            .flatten();
        if let Some(target) = self.usage_target.as_ref() {
            observation.complete_for_target(
                completion,
                usage,
                Some(&target.provider),
                target.model.as_deref(),
            );
        } else {
            observation.complete(completion, usage);
        }
    }
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.inner.as_mut().poll_frame(context);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref().filter(|_| self.usage_target.is_some()) {
                    if self.usage_bytes.len().saturating_add(data.len())
                        <= MAX_USAGE_OBSERVATION_BYTES
                    {
                        self.usage_bytes.extend_from_slice(data);
                    } else {
                        self.usage_overflowed = true;
                        self.usage_bytes.clear();
                    }
                }
                if let Some(observation) = self.observation.as_mut() {
                    observation.mark_first_event();
                }
                if self.inner.is_end_stream() {
                    let completion = self.completion.clone();
                    self.complete(completion);
                }
            }
            Poll::Ready(None) => {
                let completion = self.completion.clone();
                self.complete(completion);
            }
            Poll::Ready(Some(Err(_))) => {
                self.usage_overflowed = true;
                let completion = if self.completion == CompletionClass::Success {
                    CompletionClass::IncompleteStream
                } else {
                    self.completion.clone()
                };
                self.complete(completion);
            }
            Poll::Pending => {}
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

impl Drop for ObservedBody {
    fn drop(&mut self) {
        if !self.inner.is_end_stream() {
            self.usage_overflowed = true;
        }
        let completion = if self.inner.is_end_stream() {
            self.completion.clone()
        } else {
            CompletionClass::Cancelled
        };
        self.complete(completion);
    }
}

fn extract_observed_usage(bytes: &[u8]) -> Option<ObservedUsage> {
    let mut usage = ObservedUsage::default();
    let mut found = false;
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        visit_usage_values(&value, &mut usage, &mut found);
    } else if let Ok(text) = std::str::from_utf8(bytes) {
        for line in text.lines() {
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
                visit_usage_values(&value, &mut usage, &mut found);
            }
        }
    }
    if found {
        if usage.total_tokens.is_none() {
            usage.total_tokens = usage
                .input_tokens
                .zip(usage.output_tokens)
                .map(|(input, output)| input.saturating_add(output));
        }
        Some(usage)
    } else {
        None
    }
}

fn visit_usage_values(value: &serde_json::Value, usage: &mut ObservedUsage, found: &mut bool) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "usage" | "usageMetadata" | "usage_metadata") {
                    if let Some(usage_object) = value.as_object() {
                        merge_usage_value(usage_object, usage, found);
                    }
                }
                visit_usage_values(value, usage, found);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                visit_usage_values(value, usage, found);
            }
        }
        _ => {}
    }
}

fn merge_usage_value(
    object: &serde_json::Map<String, serde_json::Value>,
    usage: &mut ObservedUsage,
    found: &mut bool,
) {
    merge_usage_field(
        &mut usage.input_tokens,
        numeric_alias(
            object,
            &["input_tokens", "prompt_tokens", "promptTokenCount"],
        ),
        found,
    );
    merge_usage_field(
        &mut usage.output_tokens,
        numeric_alias(
            object,
            &["output_tokens", "completion_tokens", "candidatesTokenCount"],
        ),
        found,
    );
    merge_usage_field(
        &mut usage.total_tokens,
        numeric_alias(object, &["total_tokens", "totalTokenCount"]),
        found,
    );
    let cost = find_numeric_key(
        &serde_json::Value::Object(object.clone()),
        "cost_in_usd_ticks",
    );
    merge_usage_field(&mut usage.cost_in_usd_ticks, cost, found);
}

fn numeric_alias(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<u64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(serde_json::Value::as_u64))
}

fn find_numeric_key(value: &serde_json::Value, wanted: &str) -> Option<u64> {
    match value {
        serde_json::Value::Object(object) => object
            .get(wanted)
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                object
                    .values()
                    .find_map(|value| find_numeric_key(value, wanted))
            }),
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_numeric_key(value, wanted)),
        _ => None,
    }
}

fn merge_usage_field(target: &mut Option<u64>, value: Option<u64>, found: &mut bool) {
    if let Some(value) = value {
        *found = true;
        *target = Some(target.map_or(value, |current| current.max(value)));
    }
}

fn observe_response(
    response: Response<ProxyBody>,
    observation: Option<RequestObservation>,
    completion: CompletionClass,
) -> Response<ProxyBody> {
    let Some(mut observation) = observation else {
        return response;
    };
    observation.mark_headers();
    response.map(|body| ObservedBody::new(body, observation, completion).boxed())
}

fn completion_class_for_status(status: StatusCode) -> CompletionClass {
    if status.is_success() {
        CompletionClass::Success
    } else if status.is_client_error() {
        CompletionClass::DownstreamError
    } else if status.is_server_error() {
        CompletionClass::UpstreamError
    } else {
        CompletionClass::Unknown
    }
}

fn completion_class_for_error(error: &ProxyError) -> CompletionClass {
    match error {
        ProxyError::InvalidPatch(_)
        | ProxyError::UnsupportedParameter { .. }
        | ProxyError::RequestBodyTooLarge
        | ProxyError::SemanticRequest(_)
        | ProxyError::Extension(_)
        | ProxyError::InvalidWebSocketHandshake(_) => CompletionClass::InvalidRequest,
        ProxyError::UnsupportedBodyMode { .. } | ProxyError::SemanticResponse(_) => {
            CompletionClass::Unsupported
        }
        ProxyError::Upstream(_)
        | ProxyError::Timeout
        | ProxyError::Native(_)
        | ProxyError::WebSocketHandshakeStatus(_) => CompletionClass::UpstreamError,
        ProxyError::TlsClient(_)
        | ProxyError::MissingUpstream { .. }
        | ProxyError::InvalidUri
        | ProxyError::SecretUnavailable
        | ProxyError::InvalidLimits(_)
        | ProxyError::UnsupportedAuth
        | ProxyError::RequestBuild(_)
        | ProxyError::Pool(_) => CompletionClass::InternalError,
    }
}

fn openai_websocket_error(error: OpenAiResponsesWebSocketError) -> ProxyError {
    error.handshake_status().map_or_else(
        || ProxyError::Upstream(Box::new(error)),
        ProxyError::WebSocketHandshakeStatus,
    )
}

fn downstream_session_identity(headers: &HeaderMap, body: &[u8]) -> Option<Arc<str>> {
    for name in [
        "session-id",
        "session_id",
        "x-session-id",
        "x-thread-id",
        "x-conversation-id",
    ] {
        if let Some(value) = headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(Arc::from(value));
        }
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("prompt_cache_key")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            let metadata = value.get("metadata")?;
            ["session_id", "thread_id", "conversation_id"]
                .into_iter()
                .find_map(|key| metadata.get(key).and_then(serde_json::Value::as_str))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(Arc::from)
}

/// Rewrite a buffered JSON request for the target the pool committed to.
///
/// Patch routes forward the caller's body with the minimum rewriting needed to
/// reach that target. Renaming the model is already such a rewrite; dropping a
/// sampling parameter the target rejects is the same class of change, and
/// without it the request is forwarded only to be refused upstream. The drop is
/// recorded rather than silent, and `loss_policy: reject` fails the request
/// before any upstream call instead.
fn patch_body_for_target(
    bytes: &Bytes,
    route: &RoutePlan,
    model: &str,
    selection: &PoolSelection,
) -> Result<Bytes, ProxyError> {
    let profile = selection.profile();
    let dialect = profile.dialect;
    let mut document = PreservedJson::from_bytes(bytes.to_vec())
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    document
        .set_pointer_bounded(
            "/model",
            serde_json::Value::String(model.to_owned()),
            JsonPatchLimits::default(),
        )
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    // Operator-pinned fields are applied before the dialect rules run, so a
    // field the target rejects is still caught below rather than forwarded
    // because configuration asked for it. An operator who means to force such a
    // field overrides the model's dialect too, which is an explicit decision
    // rather than an accident of ordering.
    for (pointer, value) in selection.request_overlay().fields() {
        document
            .set_pointer_bounded(pointer, value.clone(), JsonPatchLimits::default())
            .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    }
    if !dialect.temperature.is_accepted() {
        drop_unsupported_parameter(&mut document, route, model, "/temperature", "temperature")?;
    }
    if profile.reasoning.is_unsupported() {
        drop_unsupported_parameter(&mut document, route, model, "/reasoning", "reasoning")?;
        drop_unsupported_parameter(
            &mut document,
            route,
            model,
            "/reasoning_effort",
            "reasoning_effort",
        )?;
    } else if let Some(effort) = document
        .pointer("/reasoning_effort")
        .and_then(serde_json::Value::as_str)
    {
        if !profile.reasoning_efforts.allows(effort) {
            drop_unsupported_parameter(
                &mut document,
                route,
                model,
                "/reasoning_effort",
                "reasoning_effort",
            )?;
        }
    }
    if profile.tools.is_unsupported() {
        for (pointer, parameter) in [
            ("/tools", "tools"),
            ("/tool_choice", "tool_choice"),
            ("/parallel_tool_calls", "parallel_tool_calls"),
        ] {
            drop_unsupported_parameter(&mut document, route, model, pointer, parameter)?;
        }
    } else if profile.parallel_tools.is_unsupported() {
        drop_unsupported_parameter(
            &mut document,
            route,
            model,
            "/parallel_tool_calls",
            "parallel_tool_calls",
        )?;
    }
    if profile.structured_output.is_unsupported() {
        drop_unsupported_parameter(
            &mut document,
            route,
            model,
            "/response_format",
            "response_format",
        )?;
    }
    if profile.streaming.is_unsupported()
        && document.pointer("/stream") == Some(&serde_json::Value::Bool(true))
    {
        return Err(ProxyError::UnsupportedParameter {
            parameter: "stream".to_owned(),
            model: model.to_owned(),
        });
    }
    enforce_output_limit(&mut document, route, model, profile.output_limit)?;
    Ok(Bytes::from(document.bytes().into_owned()))
}

fn drop_unsupported_parameter(
    document: &mut PreservedJson,
    route: &RoutePlan,
    model: &str,
    pointer: &str,
    parameter: &str,
) -> Result<(), ProxyError> {
    if document.pointer(pointer).is_none() {
        return Ok(());
    }
    // A patch body has no extension namespace, so `preserve` cannot keep the
    // field anywhere the target would accept. Only `degrade` drops it.
    if !route.loss_policy().allows_degradation() {
        return Err(ProxyError::UnsupportedParameter {
            parameter: parameter.to_owned(),
            model: model.to_owned(),
        });
    }
    document
        .remove(pointer)
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    tracing::warn!(
        route = route.id(),
        upstream_model = model,
        parameter,
        "request parameter dropped because the target model rejects it"
    );
    Ok(())
}

fn enforce_output_limit(
    document: &mut PreservedJson,
    route: &RoutePlan,
    model: &str,
    output_limit: Option<u64>,
) -> Result<(), ProxyError> {
    let Some(output_limit) = output_limit else {
        return Ok(());
    };
    for (pointer, parameter) in [
        ("/max_tokens", "max_tokens"),
        ("/max_completion_tokens", "max_completion_tokens"),
        ("/max_output_tokens", "max_output_tokens"),
    ] {
        let exceeds_limit = document
            .pointer(pointer)
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|requested| requested > output_limit);
        if !exceeds_limit {
            continue;
        }
        if !route.loss_policy().allows_degradation() {
            return Err(ProxyError::UnsupportedParameter {
                parameter: parameter.to_owned(),
                model: model.to_owned(),
            });
        }
        document
            .set_pointer_bounded(
                pointer,
                serde_json::Value::from(output_limit),
                JsonPatchLimits::default(),
            )
            .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
        tracing::warn!(
            route = route.id(),
            upstream_model = model,
            parameter,
            output_limit,
            "request token limit clamped to the target model maximum"
        );
    }
    Ok(())
}

fn should_classify(status: Option<u16>) -> bool {
    status.is_some_and(|status| status >= 400)
}

fn provider_quota_observations(
    upstream: &UpstreamPlan,
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
) -> Vec<QuotaObservation> {
    let provider = match upstream.native().map(|native| native.kind()) {
        Some(kind) if kind.eq_ignore_ascii_case("kimi") => ProviderKind::Kimi,
        Some(kind) if kind.eq_ignore_ascii_case("vertex") => ProviderKind::Vertex,
        Some(kind) if kind.eq_ignore_ascii_case("antigravity") => ProviderKind::Antigravity,
        _ => ProviderKind::OpenAiCompatible,
    };
    ProviderResponseClassifier::new(provider)
        .parse_policy_observations(status, headers, body)
        .unwrap_or_default()
}

fn upstream_uri(
    upstream: &UpstreamPlan,
    route: &RoutePlan,
    downstream: &Uri,
) -> Result<Uri, ProxyError> {
    let mut url = upstream.url().clone();
    let path = route.target().path().unwrap_or_else(|| {
        if upstream.native().is_some_and(|native| {
            native
                .kind()
                .eq_ignore_ascii_case(adapter_codex::CODEX_PROVIDER_ID)
        }) {
            adapter_codex::CODEX_RESPONSES_PATH
        } else {
            downstream.path()
        }
    });
    url.set_path(path);
    url.set_query(downstream.query());
    apply_upstream_query(&mut url, upstream.query());
    url.as_str().parse().map_err(|_| ProxyError::InvalidUri)
}

/// Add the query parameters an upstream requires without overriding the caller.
///
/// Some providers reject a request that omits a parameter the caller has no
/// reason to know about, such as Azure OpenAI's `api-version`. A caller that
/// did send the parameter chose a value deliberately, so configuration fills
/// the gap rather than replacing the choice.
fn apply_upstream_query(url: &mut url::Url, required: &[(Arc<str>, Arc<str>)]) {
    for (name, value) in required {
        if url
            .query_pairs()
            .any(|(existing, _)| existing == name.as_ref())
        {
            continue;
        }
        url.query_pairs_mut().append_pair(name, value);
    }
}

fn request_is_websocket_upgrade(request: &Request<Incoming>) -> bool {
    request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .any(|value| {
                value.to_str().ok().is_some_and(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                })
            })
}

fn validate_websocket_request(request: &Request<Incoming>) -> Result<String, ProxyError> {
    if request.method() != http::Method::GET || request.version() != http::Version::HTTP_11 {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "WebSocket upgrades require GET over HTTP/1.1".to_owned(),
        ));
    }
    if !request_is_websocket_upgrade(request) {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "Upgrade: websocket and Connection: Upgrade are required".to_owned(),
        ));
    }
    if request
        .headers()
        .get("sec-websocket-version")
        .and_then(|value| value.to_str().ok())
        != Some("13")
    {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "Sec-WebSocket-Version: 13 is required".to_owned(),
        ));
    }
    if request
        .headers()
        .get_all("sec-websocket-version")
        .iter()
        .count()
        != 1
    {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "Sec-WebSocket-Version must appear exactly once".to_owned(),
        ));
    }
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    != Some(0)
            })
    {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "WebSocket upgrades must not carry a request body".to_owned(),
        ));
    }
    if request
        .headers()
        .get_all("sec-websocket-key")
        .iter()
        .count()
        != 1
    {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "Sec-WebSocket-Key must appear exactly once".to_owned(),
        ));
    }
    let key = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ProxyError::InvalidWebSocketHandshake("Sec-WebSocket-Key is required".to_owned())
        })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .map_err(|_| {
            ProxyError::InvalidWebSocketHandshake("Sec-WebSocket-Key is not base64".to_owned())
        })?;
    if decoded.len() != 16 {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "Sec-WebSocket-Key must decode to 16 bytes".to_owned(),
        ));
    }
    Ok(key.to_owned())
}

fn websocket_protocols(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn websocket_uri(
    upstream: &UpstreamPlan,
    route: &RoutePlan,
    downstream: &Uri,
) -> Result<String, ProxyError> {
    if !matches!(upstream.transport(), "ws" | "wss") {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "the selected upstream does not use ws or wss".to_owned(),
        ));
    }
    let mut url = upstream.url().clone();
    let path = route.target().path().unwrap_or_else(|| {
        if upstream.native().is_some_and(|native| {
            native
                .kind()
                .eq_ignore_ascii_case(adapter_codex::CODEX_PROVIDER_ID)
        }) {
            adapter_codex::CODEX_RESPONSES_PATH
        } else {
            downstream.path()
        }
    });
    url.set_path(path);
    url.set_query(downstream.query());
    Ok(url.to_string())
}

fn derive_websocket_accept(key: &[u8]) -> String {
    const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = Vec::with_capacity(key.len() + GUID.len());
    input.extend_from_slice(key);
    input.extend_from_slice(GUID);
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

fn generate_websocket_key() -> Result<String, ProxyError> {
    let mut key = [0_u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| ProxyError::SecretUnavailable)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key))
}

#[derive(Debug)]
struct WebSocketHandshakeResponse {
    protocol: Option<HeaderValue>,
}

#[derive(Debug)]
enum UpstreamSocket {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for UpstreamSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for UpstreamSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, bytes),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}

async fn connect_websocket(
    uri: &str,
    headers: &HeaderMap,
    key: &str,
    offered_protocols: &[String],
) -> Result<(UpstreamSocket, WebSocketHandshakeResponse), ProxyError> {
    let parsed = uri
        .parse::<Uri>()
        .map_err(|_| ProxyError::InvalidWebSocketHandshake("invalid upstream URI".to_owned()))?;
    let scheme = parsed.scheme_str().ok_or_else(|| {
        ProxyError::InvalidWebSocketHandshake("upstream URI has no scheme".to_owned())
    })?;
    let authority = parsed.authority().ok_or_else(|| {
        ProxyError::InvalidWebSocketHandshake("upstream URI has no host".to_owned())
    })?;
    let host = authority.host().to_owned();
    let port = authority
        .port_u16()
        .unwrap_or(if scheme.eq_ignore_ascii_case("wss") {
            443
        } else {
            80
        });
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|error| ProxyError::Upstream(Box::new(error)))?;
    let mut stream = if scheme.eq_ignore_ascii_case("wss") {
        let roots = native_root_store()?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(host.clone()).map_err(|_| {
            ProxyError::Upstream(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid upstream TLS server name",
            )))
        })?;
        let stream = TlsConnector::from(Arc::new(config))
            .connect(server_name, stream)
            .await
            .map_err(|error| ProxyError::Upstream(Box::new(error)))?;
        UpstreamSocket::Tls(Box::new(stream))
    } else if scheme.eq_ignore_ascii_case("ws") {
        UpstreamSocket::Plain(stream)
    } else {
        return Err(ProxyError::InvalidWebSocketHandshake(
            "upstream URL must use ws or wss".to_owned(),
        ));
    };

    let path = parsed
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let mut request = Vec::with_capacity(512);
    request.extend_from_slice(b"GET ");
    request.extend_from_slice(path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(authority.as_str().as_bytes());
    request.extend_from_slice(
        b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ",
    );
    request.extend_from_slice(key.as_bytes());
    request.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "upgrade"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-extensions"
        ) {
            continue;
        }
        request.extend_from_slice(name.as_str().as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    stream
        .write_all(&request)
        .await
        .map_err(|error| ProxyError::Upstream(Box::new(error)))?;
    stream
        .flush()
        .await
        .map_err(|error| ProxyError::Upstream(Box::new(error)))?;
    let response = read_websocket_handshake(&mut stream, key, offered_protocols).await?;
    Ok((stream, response))
}

fn native_root_store() -> Result<RootCertStore, ProxyError> {
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        return Err(ProxyError::Upstream(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            "no native TLS roots are available",
        ))));
    }
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(result.certs);
    if added == 0 {
        return Err(ProxyError::Upstream(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "native TLS roots contain no parsable certificates",
        ))));
    }
    Ok(roots)
}

async fn read_websocket_handshake(
    stream: &mut UpstreamSocket,
    key: &str,
    offered_protocols: &[String],
) -> Result<WebSocketHandshakeResponse, ProxyError> {
    const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
    let mut bytes = Vec::with_capacity(1024);
    loop {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|error| ProxyError::Upstream(Box::new(error)))?;
        bytes.push(byte[0]);
        if bytes.len() > MAX_HANDSHAKE_BYTES {
            return Err(ProxyError::Upstream(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream WebSocket handshake is too large",
            ))));
        }
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        ProxyError::Upstream(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream WebSocket handshake is not UTF-8",
        )))
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok());
    if version != Some("HTTP/1.1") || status != Some(101) {
        return Err(ProxyError::Upstream(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream did not accept the WebSocket upgrade",
        ))));
    }
    let expected_accept = derive_websocket_accept(key.as_bytes());
    let mut accepted = None;
    let mut protocol = None;
    let mut upgrade_websocket = false;
    let mut connection_upgrade = false;
    let mut upgrade_seen = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ProxyError::Upstream(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream returned a malformed WebSocket header",
            ))));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            if upgrade_seen {
                return Err(ProxyError::Upstream(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream returned duplicate Upgrade headers",
                ))));
            }
            upgrade_seen = true;
            upgrade_websocket = value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade = value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            if accepted.is_some() {
                return Err(ProxyError::Upstream(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream returned duplicate Sec-WebSocket-Accept headers",
                ))));
            }
            accepted = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            if protocol.is_some() {
                return Err(ProxyError::Upstream(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream returned duplicate Sec-WebSocket-Protocol headers",
                ))));
            }
            if !offered_protocols.iter().any(|offered| offered == value) {
                return Err(ProxyError::Upstream(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream selected an unrequested WebSocket protocol",
                ))));
            }
            protocol = Some(HeaderValue::from_str(value).map_err(|_| {
                ProxyError::Upstream(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream returned an invalid WebSocket protocol",
                )))
            })?);
        }
    }
    if !upgrade_websocket || !connection_upgrade {
        return Err(ProxyError::Upstream(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream WebSocket response must include Upgrade and Connection",
        ))));
    }
    if accepted.as_deref() != Some(expected_accept.as_str()) {
        return Err(ProxyError::Upstream(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream WebSocket accept key did not match",
        ))));
    }
    Ok(WebSocketHandshakeResponse { protocol })
}

#[derive(Debug)]
struct RawWebSocketFrame {
    bytes: Vec<u8>,
    payload: Vec<u8>,
    fin: bool,
    opcode: u8,
    payload_len: u64,
}

#[derive(Debug)]
enum WebSocketFrameError {
    TooLarge,
    Protocol,
    InvalidClose,
    InvalidText,
    Io,
}

async fn read_raw_websocket_frame<S>(
    stream: &mut S,
    max_frame_bytes: usize,
    expect_mask: bool,
) -> Result<RawWebSocketFrame, WebSocketFrameError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| WebSocketFrameError::Io)?;
    let fin = header[0] & 0x80 != 0;
    let reserved = header[0] & 0x70;
    let opcode = header[0] & 0x0F;
    let masked = header[1] & 0x80 != 0;
    let mut length = u64::from(header[1] & 0x7F);
    let mut bytes = Vec::with_capacity(14);
    if reserved != 0 || !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) || masked != expect_mask {
        return Err(WebSocketFrameError::Protocol);
    }
    bytes.extend_from_slice(&header);
    if length == 126 {
        let mut extended = [0_u8; 2];
        stream
            .read_exact(&mut extended)
            .await
            .map_err(|_| WebSocketFrameError::Io)?;
        length = u64::from(u16::from_be_bytes(extended));
        bytes.extend_from_slice(&extended);
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        stream
            .read_exact(&mut extended)
            .await
            .map_err(|_| WebSocketFrameError::Io)?;
        if extended[0] & 0x80 != 0 {
            return Err(WebSocketFrameError::Protocol);
        }
        length = u64::from_be_bytes(extended);
        bytes.extend_from_slice(&extended);
    }
    let control = opcode >= 8;
    if (control && (!fin || length > 125)) || length > max_frame_bytes as u64 {
        return Err(if length > max_frame_bytes as u64 {
            WebSocketFrameError::TooLarge
        } else {
            WebSocketFrameError::Protocol
        });
    }
    let mask = if masked {
        let mut mask = [0_u8; 4];
        stream
            .read_exact(&mut mask)
            .await
            .map_err(|_| WebSocketFrameError::Io)?;
        bytes.extend_from_slice(&mask);
        Some(mask)
    } else {
        None
    };
    let payload_len = usize::try_from(length).map_err(|_| WebSocketFrameError::TooLarge)?;
    let mut payload = vec![0_u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|_| WebSocketFrameError::Io)?;
    let wire_payload = payload.clone();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }
    bytes.extend_from_slice(&wire_payload);
    Ok(RawWebSocketFrame {
        bytes,
        payload,
        fin,
        opcode,
        payload_len: length,
    })
}

#[derive(Debug, Default)]
struct WebSocketMessageState {
    fragmented: bool,
    bytes: u64,
    text: bool,
    text_bytes: Vec<u8>,
}

fn validate_websocket_message(
    frame: &RawWebSocketFrame,
    state: &mut WebSocketMessageState,
    max_message_bytes: u64,
) -> Result<(), WebSocketFrameError> {
    match frame.opcode {
        1 | 2 => {
            if state.fragmented {
                return Err(WebSocketFrameError::Protocol);
            }
            if frame.fin {
                if frame.payload_len > max_message_bytes {
                    return Err(WebSocketFrameError::TooLarge);
                }
                if frame.opcode == 1 && std::str::from_utf8(&frame.payload).is_err() {
                    return Err(WebSocketFrameError::InvalidText);
                }
            } else {
                state.fragmented = true;
                state.bytes = frame.payload_len;
                state.text = frame.opcode == 1;
                state.text_bytes = if state.text {
                    frame.payload.clone()
                } else {
                    Vec::new()
                };
            }
        }
        0 => {
            if !state.fragmented {
                return Err(WebSocketFrameError::Protocol);
            }
            state.bytes = state.bytes.saturating_add(frame.payload_len);
            if state.bytes > max_message_bytes {
                return Err(WebSocketFrameError::TooLarge);
            }
            if state.text {
                state.text_bytes.extend_from_slice(&frame.payload);
            }
            if frame.fin {
                if state.text && std::str::from_utf8(&state.text_bytes).is_err() {
                    return Err(WebSocketFrameError::InvalidText);
                }
                state.fragmented = false;
                state.bytes = 0;
                state.text = false;
                state.text_bytes.clear();
            }
        }
        8 => validate_close_payload(&frame.payload)?,
        _ => {}
    }
    Ok(())
}

fn validate_close_payload(payload: &[u8]) -> Result<(), WebSocketFrameError> {
    if payload.len() == 1 {
        return Err(WebSocketFrameError::InvalidClose);
    }
    if payload.len() < 2 {
        return Ok(());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let valid_code = matches!(
        code,
        1000..=1003 | 1007..=1014 | 3000..=4999
    );
    if !valid_code || std::str::from_utf8(&payload[2..]).is_err() {
        return Err(WebSocketFrameError::InvalidClose);
    }
    Ok(())
}

fn websocket_error_close_code(error: &WebSocketFrameError) -> u16 {
    match error {
        WebSocketFrameError::TooLarge => 1009,
        WebSocketFrameError::InvalidText => 1007,
        WebSocketFrameError::Protocol | WebSocketFrameError::InvalidClose => 1002,
        WebSocketFrameError::Io => 1001,
    }
}

enum WebSocketReadEvent {
    Down(Result<RawWebSocketFrame, WebSocketFrameError>),
    Up(Result<RawWebSocketFrame, WebSocketFrameError>),
    Timeout,
    Cancelled,
}

struct WebSocketTunnelContext {
    max_frame_bytes: u64,
    guard: DrainGuard,
    cancellation: CancellationToken,
    deadline: StdInstant,
    lease: Option<SelectionLease>,
    observation: RequestObservation,
}

async fn run_websocket_tunnel(
    downstream_upgrade: hyper::upgrade::OnUpgrade,
    mut upstream: UpstreamSocket,
    context: WebSocketTunnelContext,
) {
    let WebSocketTunnelContext {
        max_frame_bytes,
        guard,
        cancellation,
        deadline,
        lease,
        mut observation,
    } = context;
    let upgraded = tokio::select! {
        result = downstream_upgrade => match result {
            Ok(upgraded) => upgraded,
            Err(_) => {
                observation.complete(CompletionClass::Cancelled, None);
                return;
            }
        },
        () = cancellation.cancelled() => {
            observation.complete(CompletionClass::Cancelled, None);
            return;
        }
    };
    let mut downstream = hyper_util::rt::TokioIo::new(upgraded);
    let max_frame = bounded_usize(max_frame_bytes).max(1);
    let max_message = max_frame as u64;
    let mut downstream_state = WebSocketMessageState::default();
    let mut upstream_state = WebSocketMessageState::default();
    let mut timeout = Box::pin(time::sleep_until(Instant::from_std(deadline)));
    let mut completion = CompletionClass::Success;

    loop {
        let mut downstream_read =
            Box::pin(read_raw_websocket_frame(&mut downstream, max_frame, true));
        let mut upstream_read = Box::pin(read_raw_websocket_frame(&mut upstream, max_frame, false));
        let event = tokio::select! {
            () = &mut timeout => WebSocketReadEvent::Timeout,
            () = cancellation.cancelled() => WebSocketReadEvent::Cancelled,
            result = &mut downstream_read => WebSocketReadEvent::Down(result),
            result = &mut upstream_read => WebSocketReadEvent::Up(result),
        };
        drop(downstream_read);
        drop(upstream_read);

        match event {
            WebSocketReadEvent::Timeout | WebSocketReadEvent::Cancelled => {
                completion = CompletionClass::Cancelled;
                send_websocket_closes(&mut downstream, &mut upstream, 1001).await;
                break;
            }
            WebSocketReadEvent::Down(result) => match result {
                Ok(frame) => {
                    if let Err(error) =
                        validate_websocket_message(&frame, &mut downstream_state, max_message)
                    {
                        completion = CompletionClass::IncompleteStream;
                        send_websocket_closes(
                            &mut downstream,
                            &mut upstream,
                            websocket_error_close_code(&error),
                        )
                        .await;
                        break;
                    }
                    let close = frame.opcode == 8;
                    if write_websocket_frame(&mut upstream, &frame.bytes, deadline, &cancellation)
                        .await
                        .is_err()
                    {
                        completion = CompletionClass::IncompleteStream;
                        break;
                    }
                    if close {
                        break;
                    }
                }
                Err(WebSocketFrameError::TooLarge) => {
                    completion = CompletionClass::IncompleteStream;
                    send_websocket_closes(&mut downstream, &mut upstream, 1009).await;
                    break;
                }
                Err(WebSocketFrameError::Protocol) => {
                    completion = CompletionClass::IncompleteStream;
                    send_websocket_closes(&mut downstream, &mut upstream, 1002).await;
                    break;
                }
                Err(
                    error @ (WebSocketFrameError::InvalidClose | WebSocketFrameError::InvalidText),
                ) => {
                    completion = CompletionClass::IncompleteStream;
                    send_websocket_closes(
                        &mut downstream,
                        &mut upstream,
                        websocket_error_close_code(&error),
                    )
                    .await;
                    break;
                }
                Err(WebSocketFrameError::Io) => {
                    completion = CompletionClass::Cancelled;
                    send_websocket_closes(&mut downstream, &mut upstream, 1001).await;
                    break;
                }
            },
            WebSocketReadEvent::Up(result) => match result {
                Ok(frame) => {
                    if let Err(error) =
                        validate_websocket_message(&frame, &mut upstream_state, max_message)
                    {
                        completion = CompletionClass::IncompleteStream;
                        send_websocket_closes(
                            &mut downstream,
                            &mut upstream,
                            websocket_error_close_code(&error),
                        )
                        .await;
                        break;
                    }
                    let close = frame.opcode == 8;
                    if write_websocket_frame(&mut downstream, &frame.bytes, deadline, &cancellation)
                        .await
                        .is_err()
                    {
                        completion = CompletionClass::IncompleteStream;
                        break;
                    }
                    if close {
                        break;
                    }
                }
                Err(WebSocketFrameError::TooLarge) => {
                    completion = CompletionClass::IncompleteStream;
                    send_websocket_closes(&mut downstream, &mut upstream, 1009).await;
                    break;
                }
                Err(WebSocketFrameError::Protocol) => {
                    completion = CompletionClass::IncompleteStream;
                    send_websocket_closes(&mut downstream, &mut upstream, 1002).await;
                    break;
                }
                Err(
                    error @ (WebSocketFrameError::InvalidClose | WebSocketFrameError::InvalidText),
                ) => {
                    completion = CompletionClass::IncompleteStream;
                    send_websocket_closes(
                        &mut downstream,
                        &mut upstream,
                        websocket_error_close_code(&error),
                    )
                    .await;
                    break;
                }
                Err(WebSocketFrameError::Io) => {
                    completion = CompletionClass::Cancelled;
                    send_websocket_closes(&mut downstream, &mut upstream, 1001).await;
                    break;
                }
            },
        }
    }
    let _ = downstream.shutdown().await;
    let _ = upstream.shutdown().await;
    observation.complete(completion, None);
    drop(lease);
    drop(guard);
}
async fn write_websocket_frame<S>(
    stream: &mut S,
    bytes: &[u8],
    deadline: StdInstant,
    cancellation: &CancellationToken,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    tokio::select! {
        result = time::timeout_at(Instant::from_std(deadline), async {
            stream.write_all(bytes).await?;
            stream.flush().await
        }) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket write timed out"))?,
        () = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "WebSocket write canceled")),
    }
}

async fn send_websocket_closes(
    downstream: &mut (impl AsyncWrite + Unpin),
    upstream: &mut (impl AsyncWrite + Unpin),
    code: u16,
) {
    let reason = b"pooler closed";
    let mut server_frame = Vec::with_capacity(2 + 2 + reason.len());
    server_frame.push(0x88);
    server_frame.push((2 + reason.len()) as u8);
    server_frame.extend_from_slice(&code.to_be_bytes());
    server_frame.extend_from_slice(reason);
    let mut client_frame = Vec::with_capacity(server_frame.len() + 4);
    client_frame.push(0x88);
    client_frame.push(0x80 | (2 + reason.len()) as u8);
    let mut mask = [0_u8; 4];
    if ring::rand::SystemRandom::new().fill(&mut mask).is_err() {
        return;
    }
    client_frame.extend_from_slice(&mask);
    client_frame.extend(
        server_frame[2..]
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    let _ = time::timeout(Duration::from_millis(100), async {
        let _ = downstream.write_all(&server_frame).await;
        let _ = downstream.flush().await;
    })
    .await;
    let _ = time::timeout(Duration::from_millis(100), async {
        let _ = upstream.write_all(&client_frame).await;
        let _ = upstream.flush().await;
    })
    .await;
}
/// Resolve and apply one compiled upstream credential at the outbound boundary.
pub fn apply_configured_upstream_headers(
    headers: &mut HeaderMap,
    upstream: &UpstreamPlan,
) -> Result<(), ProxyError> {
    for (name, value) in upstream.required_headers() {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ProxyError::UnsupportedAuth)?;
        let value = HeaderValue::from_str(value).map_err(|_| ProxyError::UnsupportedAuth)?;
        headers.insert(name, value);
    }
    Ok(())
}

pub fn apply_configured_upstream_auth(
    headers: &mut HeaderMap,
    upstream: &UpstreamPlan,
) -> Result<(), ProxyError> {
    apply_configured_upstream_headers(headers, upstream)?;
    let Some(auth) = upstream.auth() else {
        return Ok(());
    };
    let placement =
        AuthPlacement::from_configured_parts(auth.kind(), auth.header(), auth.value_prefix())
            .map_err(|_| ProxyError::UnsupportedAuth)?;
    let secret = resolve_secret(auth.secret())?;
    let authorization = placement
        .materialize(&secret)
        .map_err(|_| ProxyError::SecretUnavailable)?;
    authorization.apply_to(headers);
    Ok(())
}

fn strip_provider_credential_headers(headers: &mut HeaderMap) {
    headers.remove(header::AUTHORIZATION);
    headers.remove("x-api-key");
    headers.remove("x-goog-api-key");
}

fn resolve_secret(secret: &SecretRef) -> Result<SecretValue, ProxyError> {
    let reference = match secret {
        SecretRef::Env(name) => AuthSecretRef::Env(name.to_string()),
        SecretRef::File(path) => AuthSecretRef::File(path.as_ref().into()),
        SecretRef::Keyring { service, account } => AuthSecretRef::Keyring {
            service: service.to_string(),
            account: account.to_string(),
        },
    };
    let secret = reference
        .resolve()
        .map_err(|_| ProxyError::SecretUnavailable)?;
    if secret.expose_secret().chars().any(char::is_whitespace) {
        return Err(ProxyError::SecretUnavailable);
    }
    Ok(secret)
}

fn header_bytes(headers: &HeaderMap) -> u64 {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().len() + value.as_bytes().len()) as u64)
        .sum()
}

fn bounded_usize(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

fn request_timeout(limits: &RouteLimits, upstream: &UpstreamPlan) -> Duration {
    [limits.request_timeout, upstream.request_timeout()]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT)
}

fn retry_deadline(
    started: StdInstant,
    limits: &RouteLimits,
    upstream: &UpstreamPlan,
    policy: Option<&pooler_config::PolicyPlan>,
) -> Instant {
    let request_deadline = started + request_timeout(limits, upstream);
    let retry_deadline = policy
        .and_then(|policy| policy.retry().maximum_elapsed())
        .map_or(request_deadline, |elapsed| {
            request_deadline.min(started + elapsed)
        });
    Instant::from_std(retry_deadline)
}

fn patch_buffer_timeout(
    config: &CompiledConfig,
    route: &RoutePlan,
    fallback: &UpstreamPlan,
) -> Duration {
    let mut timeout = request_timeout(route.limits(), fallback);
    if route.target().model_source().is_some() {
        for target in config.models().values().flat_map(|model| model.targets()) {
            if let Some(upstream) = config.upstreams().get(target.provider()) {
                timeout = timeout.min(request_timeout(route.limits(), upstream));
            }
        }
    }
    timeout
}

fn connect_timeout(limits: &RouteLimits, upstream: &UpstreamPlan) -> Duration {
    [limits.connect_timeout, upstream.connect_timeout()]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or_else(|| request_timeout(limits, upstream))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DownstreamAuthError {
    MissingOrInvalid,
    SecretUnavailable,
}

fn verify_downstream_auth(
    route: &RoutePlan,
    headers: &HeaderMap,
) -> Result<(), DownstreamAuthError> {
    let Some(auth) = route.downstream_auth() else {
        return Ok(());
    };
    if !auth.kind().eq_ignore_ascii_case("bearer_secret")
        && !auth.kind().eq_ignore_ascii_case("bearer")
    {
        return Err(DownstreamAuthError::SecretUnavailable);
    }
    let expected =
        resolve_secret(auth.secret()).map_err(|_| DownstreamAuthError::SecretUnavailable)?;
    let actual = extract_bearer_token(headers)
        .map_err(|_| DownstreamAuthError::MissingOrInvalid)?
        .ok_or(DownstreamAuthError::MissingOrInvalid)?;
    if constant_time_eq(actual.as_str().as_bytes(), expected.expose_bytes()) {
        Ok(())
    } else {
        Err(DownstreamAuthError::MissingOrInvalid)
    }
}

fn box_error<E>(error: E) -> BoxError
where
    E: Error + Send + Sync + 'static,
{
    Box::new(error)
}

fn plain_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::copy_from_slice(body.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(DEFAULT_ERROR_CONTENT_TYPE),
    );
    response
}

fn unauthorized_response() -> Response<ProxyBody> {
    let mut response = plain_response(StatusCode::UNAUTHORIZED, "bearer authentication required");
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn error_response(error: ProxyError) -> Response<ProxyBody> {
    let (status, message) = match error {
        ProxyError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "upstream request failed"),
        ProxyError::UnsupportedAuth | ProxyError::SecretUnavailable => {
            (StatusCode::BAD_GATEWAY, "upstream request failed")
        }
        ProxyError::MissingUpstream { .. }
        | ProxyError::InvalidUri
        | ProxyError::InvalidLimits(_)
        | ProxyError::RequestBuild(_)
        | ProxyError::Upstream(_)
        | ProxyError::WebSocketHandshakeStatus(_)
        | ProxyError::Native(_)
        | ProxyError::Pool(_)
        | ProxyError::UnsupportedBodyMode { .. } => {
            (StatusCode::BAD_GATEWAY, "upstream request failed")
        }
        ProxyError::Extension(_) => (StatusCode::BAD_GATEWAY, "external extension failed"),
        ProxyError::InvalidPatch(_) => (StatusCode::BAD_REQUEST, "invalid request"),
        ProxyError::UnsupportedParameter { .. } => {
            (StatusCode::BAD_REQUEST, "unsupported request parameter")
        }
        ProxyError::InvalidWebSocketHandshake(_) => {
            (StatusCode::BAD_REQUEST, "invalid WebSocket handshake")
        }
        ProxyError::SemanticRequest(_) => (StatusCode::BAD_REQUEST, "invalid request"),
        ProxyError::RequestBodyTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
        ProxyError::SemanticResponse(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream response could not be converted",
        ),
        ProxyError::TlsClient(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "proxy initialization failed",
        ),
    };
    plain_response(status, message)
}

fn pool_error(error: PoolError) -> ProxyError {
    ProxyError::Pool(error.to_string())
}

fn pool_selection_error(error: PoolError) -> ProxyError {
    match error {
        PoolError::UnknownModel { model } => {
            ProxyError::InvalidPatch(format!("unknown public model `{model}`"))
        }
        PoolError::ModelDisabled { model } => {
            ProxyError::InvalidPatch(format!("public model `{model}` is disabled"))
        }
        PoolError::InvalidModel => ProxyError::InvalidPatch("request model is invalid".to_owned()),
        other => pool_error(other),
    }
}

fn link_cancellation(
    first: CancellationToken,
    second: CancellationToken,
    resources: &RuntimeResources,
) -> CancellationToken {
    let linked = CancellationToken::new();
    let linked_clone = linked.clone();
    let task = resources.task();
    tokio::spawn(async move {
        let _task = task;
        tokio::select! {
            () = first.cancelled() => linked_clone.cancel(),
            () = second.cancelled() => linked_clone.cancel(),
        }
    });
    linked
}

fn build_route_caches(
    config: &CompiledConfig,
) -> Result<BTreeMap<Arc<str>, Arc<ResponseCache>>, ProxyError> {
    let mut caches = BTreeMap::new();
    for route in config.routes() {
        let Some(plan) = route.cache() else {
            continue;
        };
        let mut configured_headers = [
            "accept",
            "accept-encoding",
            "content-type",
            "idempotency-key",
            "user-agent",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        for name in plan.key_headers() {
            if !configured_headers
                .iter()
                .any(|configured| configured == name.as_ref())
            {
                configured_headers.push(name.to_string());
            }
        }
        let mut key_headers = Vec::with_capacity(configured_headers.len());
        for name in configured_headers {
            let name = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ProxyError::InvalidLimits("cache key header is invalid".to_owned()))?;
            key_headers.push(name);
        }
        caches.insert(
            Arc::from(route.id()),
            Arc::new(ResponseCache::new(CachePolicy {
                enabled: plan.enabled(),
                ttl: plan.ttl(),
                max_entries: plan.max_entries(),
                max_bytes: usize::try_from(plan.max_bytes()).map_err(|_| {
                    ProxyError::InvalidLimits("cache byte bound is too large".to_owned())
                })?,
                coalesce: plan.coalesce(),
                key_headers,
            })),
        );
    }
    Ok(caches)
}

fn native_error(error: NativeRuntimeError) -> ProxyError {
    ProxyError::Native(error.to_string())
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use http_body_util::StreamBody;

    use super::*;
    use pooler_config::compile_yaml;

    #[test]
    fn route_matcher_handles_exact_prefix_template_and_headers() {
        let config = compile_yaml(
            "test.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: exact
    listen: local
    match: {method: POST, path: /exact, headers: {x-route: yes}}
    target: local
  - id: templated
    listen: local
    match:
      path_template: /users/{id}
    target: local
  - id: prefix
    listen: local
    match: {path_prefix: /}
    target: local
"#,
        )
        .unwrap();
        let request = RouteRequest::new("local", http::Method::GET, "/users/42");
        let route = config
            .match_route_request(&request)
            .expect("template route matches");
        assert_eq!(route.id(), "templated");
    }

    #[test]
    fn usage_observation_normalizes_json_and_streaming_provider_shapes() {
        let json = br#"{"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":7,"totalTokenCount":18}}"#;
        assert_eq!(
            extract_observed_usage(json),
            Some(ObservedUsage {
                input_tokens: Some(11),
                output_tokens: Some(7),
                total_tokens: Some(18),
                cost_in_usd_ticks: None,
            })
        );

        let sse = b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":13,\"output_tokens\":1}}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":9,\"details\":{\"cost_in_usd_ticks\":42}}}}\n\n";
        assert_eq!(
            extract_observed_usage(sse),
            Some(ObservedUsage {
                input_tokens: Some(13),
                output_tokens: Some(9),
                total_tokens: Some(22),
                cost_in_usd_ticks: Some(42),
            })
        );
    }

    #[test]
    fn remaining_high_regression_provider_dispatch_parses_mixed_quota_dimensions() {
        let config = compile_yaml(
            "provider-quota-dispatch.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {provider: {url: http://127.0.0.1:8319}}
routes: [{id: route, listen: local, target: provider}]
"#,
        )
        .expect("quota dispatch config");
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-ratelimit-limit-requests", "100"),
            ("x-ratelimit-remaining-requests", "7"),
            ("x-ratelimit-reset-requests", "2s"),
            ("x-ratelimit-limit-tokens", "10000"),
            ("x-ratelimit-remaining-tokens", "0"),
            ("x-ratelimit-reset-tokens", "30s"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let observations = provider_quota_observations(
            &config.upstreams()["provider"],
            429,
            &headers,
            br#"{"error":{"code":"rate_limit_exceeded"}}"#,
        );
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].unit, pooler_policy::QuotaUnit::Requests);
        assert_eq!(observations[0].remaining, Some(7));
        assert_eq!(observations[1].unit, pooler_policy::QuotaUnit::Tokens);
        assert_eq!(observations[1].remaining, Some(0));
    }

    #[test]
    fn upstream_path_replaces_base_path_and_keeps_query() {
        let config = compile_yaml(
            "test.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:8319/base}}
routes:
  - id: route
    listen: local
    match: {path: /request}
    target: {provider: local, upstream_path: /v1/infer}
"#,
        )
        .unwrap();
        let uri = upstream_uri(
            &config.upstreams()["local"],
            &config.routes()[0],
            &"/request?stream=true".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(uri, "http://127.0.0.1:8319/v1/infer?stream=true");
    }

    #[test]
    fn websocket_message_validation_rejects_invalid_text_and_close_codes() {
        let mut state = WebSocketMessageState::default();
        let first = RawWebSocketFrame {
            bytes: Vec::new(),
            payload: vec![0xC3],
            fin: false,
            opcode: 1,
            payload_len: 1,
        };
        assert!(validate_websocket_message(&first, &mut state, 8).is_ok());
        let continuation = RawWebSocketFrame {
            bytes: Vec::new(),
            payload: vec![0x28],
            fin: true,
            opcode: 0,
            payload_len: 1,
        };
        assert!(matches!(
            validate_websocket_message(&continuation, &mut state, 8),
            Err(WebSocketFrameError::InvalidText)
        ));

        let close = RawWebSocketFrame {
            bytes: Vec::new(),
            payload: vec![0x03, 0xED],
            fin: true,
            opcode: 8,
            payload_len: 2,
        };
        assert!(matches!(
            validate_websocket_message(&close, &mut WebSocketMessageState::default(), 8),
            Err(WebSocketFrameError::InvalidClose)
        ));
    }

    #[tokio::test]
    async fn response_deadline_wakes_a_pending_body() {
        let stream = stream::pending::<Result<Frame<Bytes>, BoxError>>();
        let body = StreamBody::new(stream).boxed();
        let mut body = DeadlineBody::new(body, Instant::now() + Duration::from_millis(1));
        let frame = body.frame().await.expect("timeout frame");
        assert_eq!(
            frame.expect_err("deadline should fail").to_string(),
            "upstream response exceeded its request timeout"
        );
    }

    #[test]
    fn connect_and_request_timeouts_are_independent() {
        let config = compile_yaml(
            "timeout.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: route
    listen: local
    limits: {connect_timeout: 1s, request_timeout: 10s}
    target: local
"#,
        )
        .expect("timeout config");
        let route = &config.routes()[0];
        let upstream = &config.upstreams()["local"];
        assert_eq!(
            connect_timeout(route.limits(), upstream),
            Duration::from_secs(1)
        );
        assert_eq!(
            request_timeout(route.limits(), upstream),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn patch_buffer_uses_shortest_selectable_provider_timeout() {
        let config = compile_yaml(
            "selection-timeout.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  fallback:
    transport: {kind: http, base_url: http://127.0.0.1:8319, request_timeout: 10s}
  selected:
    transport: {kind: http, base_url: http://127.0.0.1:8320, request_timeout: 1s}
models:
  - id: public
    targets: [{provider: selected, upstream_model: private}]
routes:
  - id: route
    listen: local
    ingress: {mode: patch, inspectors: [inspect.openai.model]}
    target: {provider: fallback, model_from: inspected.model}
    response: {mode: opaque}
"#,
        )
        .expect("selection timeout config");
        let route = &config.routes()[0];
        let fallback = &config.upstreams()["fallback"];
        assert_eq!(
            patch_buffer_timeout(&config, route, fallback),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn completion_mapping_preserves_early_error_classes() {
        assert_eq!(
            completion_class_for_error(&ProxyError::InvalidPatch("bad".to_owned())),
            CompletionClass::InvalidRequest
        );
        assert_eq!(
            completion_class_for_error(&ProxyError::RequestBodyTooLarge),
            CompletionClass::InvalidRequest
        );
        assert_eq!(
            completion_class_for_error(&ProxyError::SemanticResponse("unsupported".to_owned())),
            CompletionClass::Unsupported
        );
        assert_eq!(
            completion_class_for_error(&ProxyError::Timeout),
            CompletionClass::UpstreamError
        );
        assert_ne!(
            completion_class_for_error(&ProxyError::Pool("state".to_owned())),
            CompletionClass::Cancelled
        );
    }
}
