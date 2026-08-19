//! HTTP forwarding for opaque and bounded JSON-patch routes.
//!
//! Opaque bodies remain Hyper streams. Patch routes buffer within their route
//! limit, apply the compiled transforms, and keep responses opaque.

use std::{
    collections::BTreeSet,
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
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
use pooler_observe::{
    AttemptRecord, AttemptResult, CompletionClass, CooldownRecord, DecisionRecord, MetricsRegistry,
    QuotaRecord, RequestObservation, RetryRecord, TraceRecord, TraceRecorder, TraceStage,
};
use pooler_policy::ReplayCheck;
use pooler_protocol::{JsonPatchLimits, PreservedJson};
use thiserror::Error;
use tokio::time::{self, Instant, Sleep};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    extract_bearer_token, retry_after_delay, strip_hop_by_hop_headers, DrainController, DrainGuard,
    DrainedBody, FrameLimitedBody, LimitedBody, NativeAuthorization, NativeRuntime,
    NativeRuntimeError, PoolError, PoolSelection, PoolingCoordinator,
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
    /// A buffered or transformed request body exceeded the route limit.
    #[error("request body exceeds configured limit")]
    RequestBodyTooLarge,
    /// A semantic request could not be decoded or converted before upstream.
    #[error("invalid semantic request: {0}")]
    SemanticRequest(String),
    /// A semantic response could not be initialized after upstream headers.
    #[error("invalid semantic response: {0}")]
    SemanticResponse(String),
    /// Account selection or mutable pooling state failed.
    #[error("account selection failed: {0}")]
    Pool(String),
    /// Native provider credential materialization or refresh failed.
    #[error("native provider request failed: {0}")]
    Native(String),
    /// The upstream request failed before a response was received.
    #[error("upstream request failed: {0}")]
    Upstream(#[source] BoxError),
    /// The upstream did not produce response headers before the deadline.
    #[error("upstream request timed out")]
    Timeout,
}

/// A compiled route table and shared Hyper client for one listener.
#[derive(Clone)]
pub struct HttpProxy<A = NoSemanticAdapter> {
    config: Arc<CompiledConfig>,
    listener: Arc<str>,
    client: UpstreamClient,
    drain: DrainController,
    semantic: A,
    pooling: Arc<PoolingCoordinator>,
    native: Arc<NativeRuntime>,
    observability: MetricsRegistry,
    traces: TraceRecorder,
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
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            config,
            listener,
            client,
            drain: DrainController::new(),
            semantic,
            pooling,
            native,
            observability: MetricsRegistry::default(),
            traces: TraceRecorder::default(),
        })
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

        if let Err(error) = verify_downstream_auth(route, request.headers()) {
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
        let result = self.forward(route, request, guard, &mut observation).await;
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
        let mut headers = request.headers().clone();
        strip_hop_by_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::AUTHORIZATION);
        let incoming = request.into_body();
        let idempotency_key_present = headers.contains_key("idempotency-key");
        let replay = ReplayCheck::for_http_method(method.as_str(), idempotency_key_present);
        let (mut prepared, selected_model) = match route.ingress().mode() {
            BodyMode::Opaque => {
                let body = LimitedBody::new(incoming, bounded_usize(limits.max_request_body_bytes))
                    .map_err(box_error)
                    .boxed();
                (PreparedBody::Streaming(Some(body)), None)
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
                let inspected_model =
                    if route.target().model_source() == Some(ModelSource::Inspected) {
                        document
                            .extract_model()
                            .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?
                            .map(str::to_owned)
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
                )
            }
            BodyMode::Semantic => {
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
                let prepared = self
                    .semantic
                    .encode_request(route, &headers, &bytes)
                    .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
                limits
                    .check_request_body(u64::try_from(prepared.body.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                limits
                    .check_frame(u64::try_from(prepared.body.len()).unwrap_or(u64::MAX))
                    .map_err(|_| ProxyError::RequestBodyTooLarge)?;
                headers.insert(header::CONTENT_TYPE, prepared.content_type);
                self.semantic.sanitize_request_headers(&mut headers);
                headers.remove(header::CONTENT_LENGTH);
                (
                    PreparedBody::Buffered {
                        bytes: Bytes::from(prepared.body),
                        patch_model: false,
                    },
                    None,
                )
            }
            BodyMode::Inspect => {
                return Err(ProxyError::UnsupportedBodyMode {
                    route: route.id().to_owned(),
                });
            }
        };
        let is_buffered = matches!(prepared, PreparedBody::Buffered { .. });
        let mut attempt = 1_u32;
        let mut elapsed_retry_delay = Duration::ZERO;
        let mut elapsed_recovery_wait = Duration::ZERO;
        let mut credentials_used = BTreeSet::new();
        let mut providers_used = BTreeSet::new();
        let mut forced_selection = None;
        let mut native_refresh_attempted = false;

        loop {
            let selection = if let Some(selection) = forced_selection.take() {
                selection
            } else {
                self.pooling
                    .select(
                        &self.config,
                        route,
                        selected_model.as_deref(),
                        &headers,
                        attempt,
                        started,
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
            let native_auth = if self.native.supports(upstream) {
                let credential = selection
                    .credential()
                    .ok_or_else(|| ProxyError::Native("credential is not configured".to_owned()))?;
                Some(
                    self.native
                        .authorize(upstream, credential, &headers, cancellation.clone())
                        .await
                        .map_err(native_error)?,
                )
            } else {
                None
            };
            let attempt_body = prepared.body_for_attempt(selection.upstream_model())?;
            let attempt_started = StdInstant::now();
            let response = self
                .send_attempt(
                    AttemptRequest {
                        route,
                        method: &method,
                        downstream_uri: &downstream_uri,
                        version,
                        headers: &headers,
                        upstream,
                        selection: &selection,
                        native_auth: native_auth.as_ref(),
                        cancellation: &cancellation,
                        started,
                    },
                    attempt_body,
                )
                .await;
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
                    if is_buffered && selection.has_policy() {
                        let failure = self.pooling.classify_failure(crate::pool::FailureInput {
                            config: &self.config,
                            route,
                            selection: &selection,
                            status: None,
                            provider_code: None,
                            message: None,
                            native_codex: false,
                            retry_after: None,
                            replay,
                            idempotency_key_present,
                            attempt,
                            credentials_used: u32::try_from(credentials_used.len())
                                .unwrap_or(u32::MAX),
                            providers_used: u32::try_from(providers_used.len()).unwrap_or(u32::MAX),
                            elapsed_retry_delay,
                            elapsed_recovery_wait,
                            started,
                        });
                        self.observe_failure(route, &selection, &failure);
                        if failure.decision.is_retry() {
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
            if self.native.supports(upstream) && !matches!(status, 402 | 429) {
                provider_code = None;
            }

            if self.native.supports(upstream) && is_buffered && should_classify(Some(status)) {
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
            }

            // A native 401 is eligible for exactly one pre-commit refresh. The
            // response is still buffered and no downstream headers have been
            // sent, so retrying remains safe. A failed refresh is returned as
            // the provider response unless invalid_grant disables this account
            // and the configured pool has another eligible target.
            if status == 401
                && is_buffered
                && self.native.supports(upstream)
                && !native_refresh_attempted
            {
                native_refresh_attempted = true;
                let credential = selection
                    .credential()
                    .ok_or_else(|| ProxyError::Native("credential is not configured".to_owned()))?;
                let generation = native_auth
                    .as_ref()
                    .map(NativeAuthorization::generation)
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
                let failure = self.pooling.classify_failure(crate::pool::FailureInput {
                    config: &self.config,
                    route,
                    selection: &selection,
                    status: Some(status),
                    provider_code: provider_code.clone(),
                    message: None,
                    native_codex: self.native.supports(upstream),
                    retry_after,
                    replay,
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
            version,
            headers: request_headers,
            upstream,
            selection,
            native_auth,
            cancellation,
            started,
        } = request;
        let mut headers = request_headers.clone();
        if let Some(native_auth) = native_auth {
            native_auth.apply_to(&mut headers).map_err(native_error)?;
        } else if selection.account_secret().is_some() {
            let _ = crate::pool::apply_account_auth(&mut headers, selection.account_secret())
                .map_err(pool_error)?;
        } else {
            apply_upstream_auth(&mut headers, upstream)?;
        }
        let body = FrameLimitedBody::new(body, bounded_usize(route.limits().max_frame_bytes))
            .map_err(box_error)
            .boxed();
        let uri = upstream_uri(upstream, route, downstream_uri)?;
        let header_count = u32::try_from(headers.len()).unwrap_or(u32::MAX);
        route
            .limits()
            .check_headers(header_count, header_bytes(&headers))
            .map_err(|_| ProxyError::InvalidLimits("upstream headers exceed limits".to_owned()))?;
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(uri)
            .version(version);
        *builder.headers_mut().expect("request builder headers") = headers;
        let upstream_request = builder.body(body)?;
        let request_deadline = started + request_timeout(route.limits(), upstream);
        let header_deadline = Instant::from_std(
            (StdInstant::now() + connect_timeout(route.limits(), upstream)).min(request_deadline),
        );
        let response = tokio::select! {
            result = time::timeout_at(header_deadline, self.client.request(upstream_request)) => {
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
        } = context;
        let (parts, body) = response.into_parts();
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
        let body = if route.response().mode() == BodyMode::Semantic && parts.status.is_success() {
            let transformed = self
                .semantic
                .decode_response(route, body, cancellation.clone())
                .map_err(|error| {
                    observation.complete(CompletionClass::Unsupported, None);
                    ProxyError::SemanticResponse(error.to_string())
                })?;
            response_headers.remove(header::CONTENT_LENGTH);
            response_headers.insert(header::CONTENT_TYPE, transformed.content_type);
            transformed.body
        } else {
            body
        };
        self.pooling
            .persist_affinity(&selection, crate::pool::timestamp_now());
        let body = SelectionLeaseBody::new(body, selection.take_lease()).boxed();
        self.traces.record(
            TraceRecord::new(TraceStage::Persistence)
                .route(route.id())
                .provider(selection.provider().as_str())
                .outcome("response_ready"),
        );
        let completion = completion_class_for_status(parts.status);
        let body = ObservedBody::new(body, observation, completion);
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
    native_auth: Option<&'a NativeAuthorization>,
    cancellation: &'a CancellationToken,
    started: StdInstant,
}

struct FinishResponseContext {
    guard: DrainGuard,
    cancellation: CancellationToken,
    started: StdInstant,
    observation: RequestObservation,
}

struct InspectedFailureResponse {
    response: Response<ProxyBody>,
    provider_code: Option<String>,
    retry_after: Option<Duration>,
}

impl PreparedBody {
    fn body_for_attempt(&mut self, upstream_model: Option<&str>) -> Result<ProxyBody, ProxyError> {
        match self {
            Self::Streaming(body) => {
                body.take()
                    .ok_or(ProxyError::Upstream(Box::new(io::Error::new(
                        io::ErrorKind::Other,
                        "streaming request body was already used",
                    ))))
            }
            Self::Buffered { bytes, patch_model } => {
                let bytes = if *patch_model {
                    if let Some(model) = upstream_model {
                        patch_model_bytes(bytes, model)?
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

struct ObservedBody {
    inner: Pin<Box<ProxyBody>>,
    observation: Option<RequestObservation>,
    completion: CompletionClass,
}

impl ObservedBody {
    fn new(inner: ProxyBody, observation: RequestObservation, completion: CompletionClass) -> Self {
        Self {
            inner: Box::pin(inner),
            observation: Some(observation),
            completion,
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
            Poll::Ready(Some(Ok(_))) => {
                if let Some(observation) = self.observation.as_mut() {
                    observation.mark_first_event();
                }
                if self.inner.is_end_stream() {
                    if let Some(mut observation) = self.observation.take() {
                        observation.complete(self.completion.clone(), None);
                    }
                }
            }
            Poll::Ready(None) => {
                if let Some(mut observation) = self.observation.take() {
                    observation.complete(self.completion.clone(), None);
                }
            }
            Poll::Ready(Some(Err(_))) => {
                if let Some(mut observation) = self.observation.take() {
                    let completion = if self.completion == CompletionClass::Success {
                        CompletionClass::IncompleteStream
                    } else {
                        self.completion.clone()
                    };
                    observation.complete(completion, None);
                }
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
        let Some(mut observation) = self.observation.take() else {
            return;
        };
        let completion = if self.inner.is_end_stream() {
            self.completion.clone()
        } else {
            CompletionClass::Cancelled
        };
        observation.complete(completion, None);
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
        | ProxyError::RequestBodyTooLarge
        | ProxyError::SemanticRequest(_) => CompletionClass::InvalidRequest,
        ProxyError::UnsupportedBodyMode { .. } | ProxyError::SemanticResponse(_) => {
            CompletionClass::Unsupported
        }
        ProxyError::Upstream(_) | ProxyError::Timeout | ProxyError::Native(_) => {
            CompletionClass::UpstreamError
        }
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

fn patch_model_bytes(bytes: &Bytes, model: &str) -> Result<Bytes, ProxyError> {
    let mut document = PreservedJson::from_bytes(bytes.to_vec())
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    document
        .set_pointer_bounded(
            "/model",
            serde_json::Value::String(model.to_owned()),
            JsonPatchLimits::default(),
        )
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    Ok(Bytes::from(document.bytes().into_owned()))
}

fn should_classify(status: Option<u16>) -> bool {
    status.is_some_and(|status| status >= 400)
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
    url.as_str().parse().map_err(|_| ProxyError::InvalidUri)
}

fn apply_upstream_auth(headers: &mut HeaderMap, upstream: &UpstreamPlan) -> Result<(), ProxyError> {
    let Some(auth) = upstream.auth() else {
        return Ok(());
    };
    if !auth.kind().eq_ignore_ascii_case("bearer_secret")
        && !auth.kind().eq_ignore_ascii_case("bearer")
    {
        return Err(ProxyError::UnsupportedAuth);
    }
    let secret = resolve_secret(auth.secret())?;
    let mut value = Zeroizing::new(Vec::with_capacity(7 + secret.expose_bytes().len()));
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(secret.expose_bytes());
    let value = HeaderValue::from_bytes(&value).map_err(|_| ProxyError::SecretUnavailable)?;
    headers.insert(header::AUTHORIZATION, value);
    Ok(())
}

fn resolve_secret(secret: &SecretRef) -> Result<SecretValue, ProxyError> {
    let reference = match secret {
        SecretRef::Env(name) => AuthSecretRef::Env(name.to_string()),
        SecretRef::File(path) => AuthSecretRef::File(path.as_ref().into()),
        SecretRef::Keyring { .. } => return Err(ProxyError::SecretUnavailable),
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
        | ProxyError::Native(_)
        | ProxyError::Pool(_)
        | ProxyError::UnsupportedBodyMode { .. } => {
            (StatusCode::BAD_GATEWAY, "upstream request failed")
        }
        ProxyError::InvalidPatch(_) => (StatusCode::BAD_REQUEST, "invalid request"),
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
        PoolError::InvalidModel => ProxyError::InvalidPatch("request model is invalid".to_owned()),
        other => pool_error(other),
    }
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
