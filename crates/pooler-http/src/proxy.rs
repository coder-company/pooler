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
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant as StdInstant},
};

#[cfg(test)]
use adapter_providers::KimiAdapter;
use adapter_providers::{
    AuthPlacement, ProviderAdapter, ProviderKind, ProviderOperation, ProviderResponseClassifier,
    VertexAdapter,
};
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
    SecretRef, ServedResource, UpstreamPlan, UsageAmounts, UsagePriceBookPlan,
};
use pooler_core::{BodyMode, ErrorClass, RouteLimits};
use pooler_extension::{ExtensionInput, ExtensionRegistry};
use pooler_observe::{
    AttemptRecord, AttemptResult, CompletionClass, CooldownRecord, DecisionRecord, MetricsRegistry,
    QuotaRecord, RequestObservation, RetryRecord, RoutingTelemetryRecord, TraceRecord,
    TraceRecorder, TraceStage, Usage as ObservedUsage,
};
use pooler_policy::{
    CommitmentState, QuotaObservation, ReplayCheck, SelectionLease, TelemetrySample,
};
use pooler_protocol::{JsonPatchLimits, PreservedJson};
use pooler_store::{CostProvenance, RequestEvent, RequestEventKind, Store, UsageRecord};
use ring::rand::SecureRandom;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::{self, Instant},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tower_service::Service;

use crate::openai_realtime::{
    OpenAiRealtimeValidator, CLIENT_DECODER as OPENAI_REALTIME_CLIENT_DECODER,
    SERVER_DECODER as OPENAI_REALTIME_SERVER_DECODER,
};
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
    NativeAuthorizationRequest, NativeRuntime, NativeRuntimeError, PersistenceStatus,
    PersistenceStream, PoolError, PoolSelection, PoolingCoordinator, ResponseCache,
    RuntimeResources, SelectionContext, SelectionTiming, SseLimits, SseParser,
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
    /// Actual representation requested from the selected upstream.
    ///
    /// This differs from `mode` only for provider bridges that must consume a
    /// streaming upstream before returning one unary downstream document.
    pub upstream_mode: SemanticResponseMode,
    /// Wire protocol selected after model/provider routing.
    pub upstream_wire: Option<SemanticWire>,
    /// Model resolved from the downstream request before upstream translation.
    pub requested_model: Option<String>,
}

/// Provider wire selected after model and account routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticWire {
    /// OpenAI Chat Completions chunks.
    OpenAiChat,
    /// OpenAI Responses named events.
    OpenAiResponses,
    /// Anthropic Messages JSON and named events.
    AnthropicMessages,
    /// Google Gemini GenerateContent JSON and SSE chunks.
    GeminiGenerateContent,
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

    /// Re-encode a validated semantic request for the wire selected after
    /// model/provider routing. The default preserves adapters whose upstream
    /// wire is fixed by the route.
    fn reencode_request_for_wire(
        &self,
        _route: &RoutePlan,
        body: &[u8],
        _wire: SemanticWire,
    ) -> Result<Vec<u8>, BoxError> {
        Ok(body.to_vec())
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

#[derive(Clone)]
struct ConnectTimeoutConnector<C> {
    inner: C,
    timeout: Duration,
}

impl<C> ConnectTimeoutConnector<C> {
    const fn new(inner: C, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<C> Service<Uri> for ConnectTimeoutConnector<C>
where
    C: Service<Uri> + Send,
    C::Future: Send + 'static,
    C::Response: Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let future = self.inner.call(uri);
        let timeout = self.timeout;
        Box::pin(async move {
            time::timeout(timeout, future)
                .await
                .map_err(|_| {
                    Box::new(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream TCP/TLS connection timed out",
                    )) as BoxError
                })?
                .map_err(Into::into)
        })
    }
}

type UpstreamConnector = ConnectTimeoutConnector<hyper_rustls::HttpsConnector<HttpConnector>>;
type UpstreamClient = Client<UpstreamConnector, ProxyBody>;

struct AttachedResponseDeadlineCleanup {
    cleanup: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl AttachedResponseDeadlineCleanup {
    fn release(&self) {
        let cleanup = self
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(cleanup) = cleanup {
            cleanup();
        }
    }
}

#[derive(Default)]
struct ResponseDeadlineCleanupState {
    released: bool,
    values: Vec<Arc<AttachedResponseDeadlineCleanup>>,
}

struct ResponseDeadlineInner {
    elapsed: AtomicBool,
    cleanup: Mutex<ResponseDeadlineCleanupState>,
}

/// Shared cleanup boundary for one committed response deadline.
///
/// The response body owns the timer. Runtime wrappers outside that body may
/// attach guards to this handle so the same terminal transition releases all
/// request-owned state even when downstream flow control prevents another
/// body poll.
#[derive(Clone)]
pub struct ResponseDeadline {
    inner: Arc<ResponseDeadlineInner>,
}

impl std::fmt::Debug for ResponseDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseDeadline")
            .field("elapsed", &self.is_elapsed())
            .finish_non_exhaustive()
    }
}

impl ResponseDeadline {
    fn new() -> Self {
        Self {
            inner: Arc::new(ResponseDeadlineInner {
                elapsed: AtomicBool::new(false),
                cleanup: Mutex::new(ResponseDeadlineCleanupState::default()),
            }),
        }
    }

    /// Attach cleanup that must run when this response reaches any terminal
    /// state. Dropping the returned handle runs it earlier.
    #[must_use]
    pub fn attach_cleanup<F>(&self, cleanup: F) -> ResponseDeadlineCleanupGuard
    where
        F: FnOnce() + Send + 'static,
    {
        let value = Arc::new(AttachedResponseDeadlineCleanup {
            cleanup: Mutex::new(Some(Box::new(cleanup))),
        });
        let mut cleanup = self
            .inner
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cleanup.released {
            drop(cleanup);
            value.release();
        } else {
            cleanup.values.push(Arc::clone(&value));
        }
        ResponseDeadlineCleanupGuard { value }
    }

    fn is_elapsed(&self) -> bool {
        self.inner.elapsed.load(Ordering::Acquire)
    }

    fn expire(&self) {
        self.inner.elapsed.store(true, Ordering::Release);
        self.release();
    }

    fn finish(&self) {
        self.release();
    }

    fn release(&self) {
        let values = {
            let mut cleanup = self
                .inner
                .cleanup
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cleanup.released {
                return;
            }
            cleanup.released = true;
            std::mem::take(&mut cleanup.values)
        };
        for value in values {
            value.release();
        }
    }
}

/// Idempotent ownership of cleanup attached to a response deadline.
pub struct ResponseDeadlineCleanupGuard {
    value: Arc<AttachedResponseDeadlineCleanup>,
}

impl std::fmt::Debug for ResponseDeadlineCleanupGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseDeadlineCleanupGuard")
            .finish_non_exhaustive()
    }
}

impl Drop for ResponseDeadlineCleanupGuard {
    fn drop(&mut self) {
        self.value.release();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeadlineBodyPhase {
    Streaming,
    TimedOut { error_emitted: bool },
    Complete,
}

struct DeadlineBodyState<B> {
    inner: Option<Pin<Box<B>>>,
    phase: DeadlineBodyPhase,
    downstream_waker: Option<Waker>,
}

struct DeadlineBody<B> {
    state: Arc<Mutex<DeadlineBodyState<B>>>,
    deadline: Instant,
    cleanup: ResponseDeadline,
    timer: tokio::task::JoinHandle<()>,
}

fn expire_deadline_state<B>(
    state: &Mutex<DeadlineBodyState<B>>,
    cleanup: &ResponseDeadline,
) -> Option<Waker> {
    let (inner, downstream_waker) = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != DeadlineBodyPhase::Streaming {
            return None;
        }
        state.phase = DeadlineBodyPhase::TimedOut {
            error_emitted: false,
        };
        (state.inner.take(), state.downstream_waker.take())
    };
    // Publish the cause before dropping ObservedBody so committed truncation
    // is recorded as an incomplete stream, not as caller cancellation.
    cleanup.expire();
    drop(inner);
    downstream_waker
}

impl<B> DeadlineBody<B>
where
    B: Send + 'static,
{
    fn new(
        inner: B,
        deadline: Instant,
        cleanup: ResponseDeadline,
        resources: RuntimeResources,
    ) -> Self {
        let state = Arc::new(Mutex::new(DeadlineBodyState {
            inner: Some(Box::pin(inner)),
            phase: DeadlineBodyPhase::Streaming,
            downstream_waker: None,
        }));
        let timer_state = Arc::clone(&state);
        let timer_cleanup = cleanup.clone();
        let task = resources.task();
        let timer = tokio::spawn(async move {
            let _task = task;
            time::sleep_until(deadline).await;
            if let Some(waker) = expire_deadline_state(timer_state.as_ref(), &timer_cleanup) {
                waker.wake();
            }
        });
        Self {
            state,
            deadline,
            cleanup,
            timer,
        }
    }
}

impl<B> DeadlineBody<B> {
    fn expire_now(&mut self) {
        if let Some(waker) = expire_deadline_state(self.state.as_ref(), &self.cleanup) {
            waker.wake();
        }
        self.timer.abort();
    }

    fn finish(&mut self) {
        let inner = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.phase = DeadlineBodyPhase::Complete;
            state.downstream_waker = None;
            state.inner.take()
        };
        self.cleanup.finish();
        drop(inner);
        self.timer.abort();
    }
}

impl<B> Body for DeadlineBody<B>
where
    B: Body<Data = Bytes, Error = BoxError> + Send + 'static,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if Instant::now() >= this.deadline {
            this.expire_now();
        }

        let (result, terminal_inner) = {
            let mut state = this
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &mut state.phase {
                DeadlineBodyPhase::TimedOut { error_emitted } => {
                    if *error_emitted {
                        return Poll::Ready(None);
                    }
                    *error_emitted = true;
                    return Poll::Ready(Some(Err(Box::new(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream response exceeded its request timeout",
                    )))));
                }
                DeadlineBodyPhase::Complete => return Poll::Ready(None),
                DeadlineBodyPhase::Streaming => {}
            }

            let result = state
                .inner
                .as_mut()
                .expect("streaming deadline body retains its inner body")
                .as_mut()
                .poll_frame(context);
            let terminal = match &result {
                Poll::Ready(None) | Poll::Ready(Some(Err(_))) => true,
                Poll::Ready(Some(Ok(_))) => state
                    .inner
                    .as_ref()
                    .is_some_and(|inner| inner.is_end_stream()),
                Poll::Pending => false,
            };
            if terminal {
                state.phase = DeadlineBodyPhase::Complete;
                state.downstream_waker = None;
                (result, state.inner.take())
            } else {
                if result.is_pending() {
                    state.downstream_waker = Some(context.waker().clone());
                } else {
                    state.downstream_waker = None;
                }
                (result, None)
            }
        };
        if terminal_inner.is_some() {
            this.cleanup.finish();
            drop(terminal_inner);
            this.timer.abort();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.phase {
            DeadlineBodyPhase::Streaming => state
                .inner
                .as_ref()
                .is_none_or(|inner| inner.is_end_stream()),
            DeadlineBodyPhase::TimedOut { error_emitted } => error_emitted,
            DeadlineBodyPhase::Complete => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .inner
            .as_ref()
            .map_or_else(SizeHint::default, |inner| inner.size_hint())
    }
}

impl<B> Drop for DeadlineBody<B> {
    fn drop(&mut self) {
        self.finish();
    }
}

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ERROR_CONTENT_TYPE: &str = "application/json";

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

struct RequestLifecycleState {
    public_model: Option<String>,
    upstream_model: Option<String>,
    provider: Option<String>,
    account_pseudonym: Option<String>,
    target_binding_id: Option<String>,
    priority_tier: Option<u32>,
    attempt: Option<u32>,
    ttft_ms: Option<u64>,
    semantic_losses: Vec<String>,
}

#[derive(Clone)]
struct RequestLifecycle {
    store: Arc<dyn Store>,
    persistence: PersistenceStatus,
    request_id: Arc<str>,
    listener: Arc<str>,
    route: Arc<str>,
    configuration_generation: u64,
    catalog_generation: Option<u64>,
    price_book: Option<Arc<UsagePriceBookPlan>>,
    started: StdInstant,
    next_event: Arc<AtomicU32>,
    completed: Arc<AtomicBool>,
    state: Arc<Mutex<RequestLifecycleState>>,
}

impl RequestLifecycle {
    fn new(
        history: (Arc<dyn Store>, PersistenceStatus),
        request_id: impl Into<Arc<str>>,
        listener: Arc<str>,
        route: impl Into<Arc<str>>,
        configuration_generation: u64,
        catalog_generation: Option<u64>,
        price_book: Option<Arc<UsagePriceBookPlan>>,
    ) -> Self {
        let (store, persistence) = history;
        let lifecycle = Self {
            store,
            persistence,
            request_id: request_id.into(),
            listener,
            route: route.into(),
            configuration_generation,
            catalog_generation,
            price_book,
            started: StdInstant::now(),
            next_event: Arc::new(AtomicU32::new(0)),
            completed: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(RequestLifecycleState {
                public_model: None,
                upstream_model: None,
                provider: None,
                account_pseudonym: None,
                target_binding_id: None,
                priority_tier: None,
                attempt: None,
                ttft_ms: None,
                semantic_losses: Vec::new(),
            })),
        };
        lifecycle.record(RequestEventKind::Admission, |_| {});
        lifecycle
    }

    fn record(&self, kind: RequestEventKind, update: impl FnOnce(&mut RequestEvent)) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut event = RequestEvent::new(
            self.request_id.as_ref(),
            self.next_event.fetch_add(1, Ordering::Relaxed),
            kind,
            self.listener.as_ref(),
            self.route.as_ref(),
            request_timestamp_now(),
        );
        event.public_model = state.public_model.clone();
        event.upstream_model = state.upstream_model.clone();
        event.provider = state.provider.clone();
        event.account_pseudonym = state.account_pseudonym.clone();
        event.target_binding_id = state.target_binding_id.clone();
        event.priority_tier = state.priority_tier;
        event.attempt = state.attempt;
        event.ttft_ms = state.ttft_ms;
        event.semantic_losses = state.semantic_losses.clone();
        event.configuration_generation = self.configuration_generation;
        event.catalog_generation = self.catalog_generation;
        drop(state);
        update(&mut event);
        match self.store.append_request_event(event) {
            Ok(_) => self
                .persistence
                .record_success(PersistenceStream::RequestEvents, request_timestamp_now()),
            Err(error) => {
                self.persistence
                    .record_failure(PersistenceStream::RequestEvents, &error);
                tracing::warn!(request_id = %self.request_id, error = %error, "request history event was not persisted");
            }
        }
    }

    fn selected(&self, selection: &PoolSelection, attempt: u32) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.public_model = Some(selection.model().as_str().to_owned());
            state.upstream_model = selection.upstream_model().map(str::to_owned);
            state.provider = Some(selection.provider().as_str().to_owned());
            state.account_pseudonym = selection
                .explanation()
                .and_then(|value| value.selected_credential_pseudonym())
                .map(|value| value.as_str().to_owned());
            state.target_binding_id = selection.target_binding_id().map(str::to_owned);
            state.priority_tier = selection.priority_tier();
            state.attempt = Some(attempt);
        }
        self.record(RequestEventKind::Selection, |event| {
            event.eligible = Some(true);
        });
    }

    fn attempt(&self, attempt: u32, result: AttemptResult, duration: Duration) {
        self.record(RequestEventKind::Attempt, |event| {
            event.attempt = Some(attempt);
            event.latency_ms = Some(duration_to_history_millis(duration));
            event.error_class = (result != AttemptResult::Success).then(|| result.to_string());
        });
    }

    fn retry(
        &self,
        attempt: u32,
        reason: impl Into<String>,
        delay: Duration,
        quota_effect: Option<String>,
        cooldown_effect: Option<String>,
    ) {
        self.record(RequestEventKind::Retry, |event| {
            event.attempt = Some(attempt);
            event.retry_reason = Some(reason.into());
            event.latency_ms = Some(duration_to_history_millis(delay));
            event.quota_effect = quota_effect;
            event.cooldown_effect = cooldown_effect;
        });
    }

    fn semantic_loss(&self, parameter: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.semantic_losses.len() < 16
            && !state.semantic_losses.iter().any(|value| value == parameter)
        {
            state.semantic_losses.push(parameter.to_owned());
        }
    }

    fn committed(&self, status: u16) {
        self.record(RequestEventKind::Commitment, |event| {
            event.commitment = Some("response_headers".to_owned());
            event.status = Some(status);
        });
    }

    fn mark_first_event(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.ttft_ms.is_none() {
            state.ttft_ms = Some(duration_to_history_millis(self.started.elapsed()));
        }
    }

    fn complete(&self, class: CompletionClass, status: Option<u16>) {
        self.complete_with_usage(class, status, None);
    }

    fn complete_with_usage(
        &self,
        class: CompletionClass,
        status: Option<u16>,
        usage: Option<&ObservedUsage>,
    ) {
        if self.completed.swap(true, Ordering::AcqRel) {
            return;
        }
        let recorded_at = request_timestamp_now();
        let latency_ms = duration_to_history_millis(self.started.elapsed());
        self.record(RequestEventKind::Completion, |event| {
            event.status = status;
            event.error_class = Some(class.to_string());
            event.latency_ms = Some(latency_ms);
        });

        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut record = UsageRecord::new(
            recorded_at,
            self.request_id.as_ref(),
            self.route.as_ref(),
            class.to_string(),
        );
        record.provider.clone_from(&state.provider);
        record.public_model.clone_from(&state.public_model);
        record.upstream_model.clone_from(&state.upstream_model);
        record
            .account_pseudonym
            .clone_from(&state.account_pseudonym);
        record.latency_ms = latency_ms;
        record.ttft_ms = state.ttft_ms;
        record.configuration_generation = self.configuration_generation;
        record.catalog_generation = self.catalog_generation;
        drop(state);
        if let Some(usage) = usage {
            record.input_tokens = usage.input_tokens;
            record.output_tokens = usage.output_tokens;
            record.reasoning_tokens = usage.reasoning_tokens;
            record.cache_tokens = usage.cache_tokens;
            record.image_units = usage.image_units;
            record.audio_units = usage.audio_units;
            record.video_units = usage.video_units;
            record.service_tier.clone_from(&usage.service_tier);
            if let Some(cost) = usage.cost_in_usd_ticks {
                record.cost_in_usd_ticks = Some(cost);
                record.cost_provenance = CostProvenance::ProviderReported;
            } else if let (Some(price_book), Some(provider), Some(model)) = (
                self.price_book.as_ref(),
                record.provider.as_deref(),
                record.upstream_model.as_deref(),
            ) {
                if let Some(cost) = price_book.estimate(
                    provider,
                    model,
                    UsageAmounts {
                        input_tokens: usage.input_tokens,
                        output_tokens: usage.output_tokens,
                        reasoning_tokens: usage.reasoning_tokens,
                        cache_tokens: usage.cache_tokens,
                        image_units: usage.image_units,
                        audio_units: usage.audio_units,
                        video_units: usage.video_units,
                    },
                ) {
                    record.cost_in_usd_ticks = Some(cost);
                    record.cost_provenance = CostProvenance::OperatorEstimated;
                    record.price_book_version = Some(price_book.version().to_owned());
                }
            }
        }
        match self.store.append_usage_record(record) {
            Ok(_) => self
                .persistence
                .record_success(PersistenceStream::UsageRecords, request_timestamp_now()),
            Err(error) => {
                self.persistence
                    .record_failure(PersistenceStream::UsageRecords, &error);
                tracing::warn!(
                    request_id = %self.request_id,
                    error = %error,
                    "usage record was not persisted"
                );
            }
        }
    }
}

fn request_timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn duration_to_history_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

/// A compiled route table and shared Hyper client for one listener.
#[derive(Clone)]
pub struct HttpProxy<A = NoSemanticAdapter> {
    config: Arc<CompiledConfig>,
    listener: Arc<str>,
    clients: BTreeMap<Duration, UpstreamClient>,
    h2c_clients: BTreeMap<Duration, UpstreamClient>,
    drain: DrainController,
    semantic: A,
    pooling: Arc<PoolingCoordinator>,
    native: Arc<NativeRuntime>,
    extensions: Arc<ExtensionRegistry>,
    caches: BTreeMap<Arc<str>, Arc<ResponseCache>>,
    price_book: Option<Arc<UsagePriceBookPlan>>,
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
                && !is_openai_realtime_websocket(route)
                && ((!matches!(route.ingress().mode(), BodyMode::Opaque | BodyMode::Patch)
                    && !semantic.supports(route))
                    || (route.response().mode() != BodyMode::Opaque && !semantic.supports(route)))
        }) {
            return Err(ProxyError::UnsupportedBodyMode {
                route: route.id().to_owned(),
            });
        }
        let tls_config = ClientConfig::builder()
            .with_root_certificates(native_root_store()?)
            .with_no_client_auth();
        let mut clients = BTreeMap::new();
        let mut h2c_clients = BTreeMap::new();
        for timeout in configured_connect_timeouts(&config) {
            clients.insert(timeout, build_upstream_client(&tls_config, timeout, false));
            h2c_clients.insert(timeout, build_upstream_client(&tls_config, timeout, true));
        }
        let caches = build_route_caches(&config)?;
        let price_book = config.usage_price_book().cloned().map(Arc::new);
        let resources = RuntimeResources::new();
        Ok(Self {
            config,
            listener,
            clients,
            h2c_clients,
            drain: DrainController::with_resources(resources.clone()),
            semantic,
            pooling,
            native,
            extensions: Arc::new(ExtensionRegistry::default()),
            caches,
            price_book,
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

    /// Answer `/v1/models` from the active public model view.
    ///
    /// The shape is the stable OpenAI list. Provider IDs, upstream model names,
    /// account IDs, secret references, and upstream endpoints are absent by
    /// construction: only public model IDs reach this response.
    fn serve_model_catalog(&self, route: &RoutePlan) -> Response<ProxyBody> {
        let published = match self.pooling.published_models(
            &self.config,
            route.target().upstream(),
            route.target().capabilities(),
        ) {
            Ok(published) => published,
            Err(_) => {
                return openai_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "model view is unavailable",
                    "service_unavailable",
                );
            }
        };
        let data = published
            .models()
            .iter()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "object": "model",
                    "owned_by": "pooler",
                })
            })
            .collect::<Vec<_>>();
        let mut body = serde_json::json!({
            "object": "list",
            "data": data,
            "configuration_generation": published.configuration_generation(),
        });
        if let Some(generation) = published.catalog_generation() {
            body["catalog_generation"] = serde_json::json!(generation);
        }
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()));
        let body = Full::new(bytes)
            .map_err(|never: Infallible| match never {})
            .boxed();
        let (body, content_type) = if route.response().mode() == BodyMode::Semantic {
            match self
                .semantic
                .decode_response(route, body, CancellationToken::new())
            {
                Ok(transformed) => (transformed.body, transformed.content_type),
                Err(_) => {
                    return openai_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "model view encoding failed",
                        "internal_error",
                    );
                }
            }
        } else {
            (body, HeaderValue::from_static("application/json"))
        };
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::OK;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    /// Handle one downstream request and stream the opaque upstream response.
    pub async fn handle(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        let Some(guard) = self.drain.try_acquire() else {
            return openai_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "proxy is draining",
                "service_unavailable",
            );
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
                let code = match status {
                    StatusCode::NOT_FOUND => "route_not_found",
                    StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
                    _ => "invalid_request",
                };
                return openai_error_response(status, "no route matched", code);
            }
        };
        tracing::info!(
            listener = %self.listener,
            route = route.id(),
            method = %request.method(),
            path = request.uri().path(),
            "request routed"
        );
        let lifecycle = RequestLifecycle::new(
            (self.pooling.store(), self.pooling.persistence_status()),
            self.pooling.next_logical_request_id(),
            Arc::clone(&self.listener),
            route.id(),
            self.config.generation(),
            self.pooling.catalog_generation(),
            self.price_book.clone(),
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
            lifecycle.complete(
                CompletionClass::InvalidRequest,
                Some(status.status().as_u16()),
            );
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
                DownstreamAuthError::SecretUnavailable => openai_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "authentication unavailable",
                    "authentication_unavailable",
                ),
            };
            lifecycle.complete(
                CompletionClass::DownstreamError,
                Some(response.status().as_u16()),
            );
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
        // A served route is answered from Pooler's own state. No upstream
        // request is made, so no credential is materialized and nothing can be
        // forwarded to a provider.
        if let Some(ServedResource::ModelCatalog) = route.served() {
            drop(guard);
            let response = self.serve_model_catalog(route);
            let class = if response.status().is_success() {
                CompletionClass::Success
            } else {
                CompletionClass::InternalError
            };
            lifecycle.complete(class.clone(), Some(response.status().as_u16()));
            return observe_response(response, observation.take(), class);
        }
        let is_websocket = route.matcher().websocket() == Some(true);
        let result = if is_websocket {
            self.forward_websocket(route, request, guard, &mut observation, &lifecycle)
                .await
        } else {
            self.forward(route, request, guard, &mut observation, &lifecycle)
                .await
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
                let response = error_response(error);
                lifecycle.complete(class.clone(), Some(response.status().as_u16()));
                observe_response(response, observation.take(), class)
            }
        }
    }

    /// Begin graceful drain. New requests receive `503`; active streams keep
    /// their permits until their response body ends or is dropped.
    pub fn begin_drain(&self) {
        self.openai_websockets.cancel_all();
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
                return Err(openai_error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "encoded request bodies are not supported",
                    "unsupported_media_type",
                ));
            }
        }
        let count = u32::try_from(headers.len()).unwrap_or(u32::MAX);
        let bytes = header_bytes(headers);
        if limits.check_headers(count, bytes).is_err() {
            return Err(openai_error_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request headers exceed configured limits",
                "request_headers_too_large",
            ));
        }

        if let Some(length) = headers.get(header::CONTENT_LENGTH) {
            let Ok(length) = length
                .to_str()
                .ok()
                .and_then(|value| value.parse().ok())
                .ok_or(())
            else {
                return Err(openai_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid content-length",
                    "invalid_request",
                ));
            };
            if limits.check_request_body(length).is_err() {
                return Err(openai_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds configured limit",
                    "request_too_large",
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
        lifecycle: &RequestLifecycle,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let key = validate_websocket_request(&request)?;
        let offered_protocols = websocket_protocols(request.headers())
            .into_iter()
            .filter(|protocol| !protocol.starts_with("openai-insecure-api-key."))
            .collect::<Vec<_>>();
        let realtime_validator = websocket_realtime_validator(route)?;

        let started = StdInstant::now();
        let cancellation = guard.cancellation_token();
        let downstream_uri = request.uri().clone();
        let mut headers = request.headers().clone();
        let routing_metadata_requested = routing_metadata_opt_in(&headers);
        strip_hop_by_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove("x-pooler-routing-metadata");
        strip_downstream_authorization(route, &mut headers);
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::CONTENT_TYPE);
        headers.remove("sec-websocket-key");
        headers.remove("sec-websocket-version");
        headers.remove("sec-websocket-extensions");
        headers.remove("sec-websocket-protocol");
        if !offered_protocols.is_empty() {
            let protocols = HeaderValue::from_str(&offered_protocols.join(", ")).map_err(|_| {
                ProxyError::InvalidWebSocketHandshake(
                    "invalid Sec-WebSocket-Protocol value".to_owned(),
                )
            })?;
            headers.insert("sec-websocket-protocol", protocols);
        }

        let mut selection =
            match self
                .pooling
                .select(&self.config, route, None, &headers, 1, started)
            {
                Ok(selection) => selection,
                Err(error) => {
                    lifecycle.record(RequestEventKind::Selection, |event| {
                        event.attempt = Some(1);
                        event.eligible = Some(false);
                        event.error_class = Some(error.to_string());
                    });
                    return Err(pool_selection_error(error));
                }
            };
        lifecycle.selected(&selection, 1);
        let selected_upstream = self
            .config
            .upstreams()
            .get(selection.upstream_id())
            .ok_or_else(|| ProxyError::MissingUpstream {
                route: route.id().to_owned(),
                upstream: selection.upstream_id().to_owned(),
            })?;
        let upstream = route.target().transport_upstream().map_or(
            Ok(selected_upstream),
            |transport_upstream| {
                self.config
                    .upstreams()
                    .get(transport_upstream)
                    .ok_or_else(|| ProxyError::MissingUpstream {
                        route: route.id().to_owned(),
                        upstream: transport_upstream.to_owned(),
                    })
            },
        )?;
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
        strip_caller_credentials_when_authenticating(
            &mut headers,
            native_auth.is_some(),
            &selection,
            upstream,
        );
        if let Some(native_auth) = native_auth {
            native_auth.apply_once(&mut headers).map_err(native_error)?;
        } else if let Some(account_secret) = selection.account_secret() {
            if !self
                .native
                .apply_managed_account_auth(
                    &mut headers,
                    account_secret,
                    upstream.auth(),
                    upstream,
                    selection.credential(),
                )
                .map_err(native_error)?
            {
                crate::pool::apply_configured_account_auth(
                    &mut headers,
                    Some(account_secret),
                    upstream.auth(),
                )
                .map_err(pool_error)?;
            }
        } else if let Some(auth) = upstream.auth() {
            if !self
                .native
                .apply_managed_account_auth(&mut headers, auth.secret(), Some(auth), upstream, None)
                .map_err(native_error)?
            {
                apply_configured_upstream_auth(&mut headers, upstream)?;
            }
        } else {
            apply_configured_upstream_auth(&mut headers, upstream)?;
        }

        let uri = selection
            .upstream_uri_for(upstream, route, &downstream_uri)
            .map_err(pool_error)?
            .to_string();
        let upstream_key = generate_websocket_key()?;
        let hard_deadline = websocket_hard_deadline(started, route.limits(), upstream);
        let connect_deadline = StdInstant::now() + connect_timeout(route.limits(), upstream);
        let connect_deadline =
            hard_deadline.map_or(connect_deadline, |hard| connect_deadline.min(hard));
        let connect = connect_websocket(&uri, &headers, &upstream_key, &offered_protocols);
        let attempt_started = StdInstant::now();
        let (upstream_socket, upstream_response) = tokio::select! {
            result = time::timeout_at(Instant::from_std(connect_deadline), connect) => {
                result.map_err(|_| ProxyError::Timeout)?
                    ?
            }
            () = cancellation.cancelled() => return Err(ProxyError::Timeout),
        };

        lifecycle.attempt(1, AttemptResult::Success, attempt_started.elapsed());
        lifecycle.committed(StatusCode::SWITCHING_PROTOCOLS.as_u16());
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
        if routing_metadata_requested {
            add_routing_metadata_headers(response_headers, &selection, 1);
        }

        let mut observation = observation
            .take()
            .expect("request observation remains until response is ready");
        observation.mark_headers();
        let affinity_commit = selection
            .affinity_commit()
            .map(|commit| (Arc::clone(&self.pooling), commit));
        let lease = selection.take_lease();
        let max_frame_bytes = route.limits().max_frame_bytes;
        let task = self.resources.task();
        let lifecycle = lifecycle.clone();
        tokio::spawn(async move {
            let _task = task;
            run_websocket_tunnel(
                downstream_upgrade,
                upstream_socket,
                WebSocketTunnelContext {
                    max_frame_bytes,
                    realtime_validator,
                    guard,
                    cancellation,
                    hard_deadline,
                    lease,
                    observation,
                    lifecycle,
                    affinity_commit,
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
        lifecycle: &RequestLifecycle,
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
        let gemini_interaction_create =
            is_exact_gemini_interaction_create(&method, downstream_uri.path());
        let version = request.version();
        let limits = route.limits();
        let downstream_headers = request.headers().clone();
        let cache_identity_safe = self
            .caches
            .get(route.id())
            .is_none_or(|cache| safe_request_for_cache(request.headers(), cache.policy()));
        let mut headers = request.headers().clone();
        let routing_metadata_requested = routing_metadata_opt_in(&headers);
        strip_hop_by_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove("x-pooler-routing-metadata");
        strip_downstream_authorization(route, &mut headers);
        if route.ingress().mode() != BodyMode::Opaque {
            headers.remove(header::AUTHORIZATION);
        }
        if gemini_interaction_create {
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
        }
        let incoming = request.into_body();
        let idempotency_key_present = headers.contains_key("idempotency-key");
        let method_safe_for_cache = safe_method_for_cache(method.as_str(), idempotency_key_present);
        let replay = ReplayCheck::for_http_method(method.as_str(), idempotency_key_present);
        let (mut prepared, selected_model, mut selection_context, semantic_response_hint) =
            match route.ingress().mode() {
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
                        let body = LimitedBody::new(
                            incoming,
                            bounded_usize(limits.max_request_body_bytes),
                        )
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
                            patch_model: self.semantic.model_in_request_body(route),
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
        if let Some(interaction_id) = gemini_interaction_id_from_path(downstream_uri.path()) {
            selection_context.with_affinity_value("gemini.interaction_id", interaction_id);
        }
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
                        .finish_cached_response(route, cached, guard, observation, lifecycle)
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
                                    .finish_cached_response(
                                        route,
                                        cached,
                                        guard,
                                        observation,
                                        lifecycle,
                                    )
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
        let mut websocket_http_fallback_attempted = false;

        loop {
            let mut selection = if let Some(selection) = forced_selection.take() {
                selection
            } else {
                match self.pooling.select_with_context(
                    &self.config,
                    route,
                    selected_model.as_deref(),
                    &headers,
                    &selection_context,
                    SelectionTiming::new(attempt, started),
                ) {
                    Ok(selection) => selection,
                    Err(error) => {
                        lifecycle.record(RequestEventKind::Selection, |event| {
                            event.public_model = selected_model.clone();
                            event.attempt = Some(attempt);
                            event.eligible = Some(false);
                            event.error_class = Some(error.to_string());
                        });
                        return Err(pool_selection_error(error));
                    }
                }
            };
            lifecycle.selected(&selection, attempt);
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
            let selected_upstream = self
                .config
                .upstreams()
                .get(selection.upstream_id())
                .ok_or_else(|| ProxyError::MissingUpstream {
                    route: route.id().to_owned(),
                    upstream: selection.upstream_id().to_owned(),
                })?;
            // A unary semantic request needs the selected HTTP upstream even
            // when the route also declares a reusable Responses WebSocket
            // transport. The response hint is decoded from this request, so
            // it is the authoritative per-request transport choice.
            let websocket_transport = (semantic_response_hint.mode != SemanticResponseMode::Json
                && !websocket_http_fallback_attempted)
                .then(|| {
                    self.semantic.websocket_transport(route).or_else(|| {
                        selected_upstream
                            .native()
                            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
                            .then_some(SemanticWebSocketTransport::OpenAiResponses)
                    })
                })
                .flatten();
            // Semantic Responses selection uses the REST provider identity so
            // catalog aliases and account state match the discovered target.
            // An explicit target transport binding supplies the WebSocket
            // endpoint only for the transport attempt.
            let upstream = if websocket_transport.is_some() {
                route.target().transport_upstream().map_or(
                    Ok(selected_upstream),
                    |transport_upstream| {
                        self.config
                            .upstreams()
                            .get(transport_upstream)
                            .ok_or_else(|| ProxyError::MissingUpstream {
                                route: route.id().to_owned(),
                                upstream: transport_upstream.to_owned(),
                            })
                    },
                )?
            } else {
                selected_upstream
            };
            let force_unary_responses_stream = semantic_unary_responses_requires_streaming(
                route,
                &selection,
                upstream,
                &semantic_response_hint,
            );
            if websocket_transport.is_some()
                && route.target().transport_upstream().is_some()
                && !matches!(upstream.transport(), "ws" | "wss")
            {
                return Err(ProxyError::InvalidWebSocketHandshake(
                    "semantic WebSocket transport requires a ws or wss target transport".to_owned(),
                ));
            }
            let websocket_attempt = websocket_transport.is_some()
                && (matches!(upstream.transport(), "ws" | "wss")
                    || upstream
                        .native()
                        .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex")));
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
            let selected_upstream_uri = selection
                .upstream_uri_for(upstream, route, &downstream_uri)
                .map_err(pool_error)?;
            let attempt_started = StdInstant::now();
            let attempt_request = AttemptRequest {
                route,
                method: &method,
                downstream_uri: &downstream_uri,
                version,
                headers: &headers,
                upstream,
                upstream_uri: selected_upstream_uri,
                selection: &selection,
                native_auth,
                native_profile,
                connection_generation,
                cancellation: &cancellation,
                started,
            };
            let response = match (websocket_transport, websocket_attempt) {
                (Some(transport), true) => {
                    match prepared.buffered_bytes_for_attempt(
                        route,
                        &selection,
                        upstream,
                        &self.semantic,
                        lifecycle,
                    ) {
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
                _ => {
                    let attempt_body = if force_unary_responses_stream {
                        prepared
                            .buffered_bytes_for_attempt(
                                route,
                                &selection,
                                upstream,
                                &self.semantic,
                                lifecycle,
                            )
                            .and_then(|bytes| force_responses_streaming_request(&bytes, limits))
                            .map(|bytes| {
                                Full::new(bytes)
                                    .map_err(|never: Infallible| match never {})
                                    .boxed()
                            })
                    } else {
                        prepared.body_for_attempt(
                            route,
                            &selection,
                            upstream,
                            &self.semantic,
                            lifecycle,
                        )
                    };
                    match attempt_body {
                        Ok(attempt_body) => self.send_attempt(attempt_request, attempt_body).await,
                        Err(error) => Err(error),
                    }
                }
            };
            let attempt_result = match response.as_ref() {
                Ok(response) if response.status().is_success() => AttemptResult::Success,
                Ok(_) => AttemptResult::Error,
                Err(ProxyError::Timeout) => AttemptResult::Cancelled,
                Err(_) => AttemptResult::Error,
            };
            let attempt_duration = attempt_started.elapsed();
            lifecycle.attempt(attempt, attempt_result, attempt_duration);
            if let Some(binding) = selection.binding_key().cloned() {
                let latency_ms = duration_to_history_millis(attempt_duration);
                self.pooling.record_routing_telemetry(
                    binding,
                    TelemetrySample {
                        observed_at_ms: request_timestamp_now(),
                        sample_count: 1,
                        rolling_window_ms: 5 * 60 * 1_000,
                        stale_after_ms: 5 * 60 * 1_000,
                        latency_ms: Some(latency_ms),
                        ttft_ms: None,
                        throughput_per_second: None,
                    },
                );
                if let Some(target) = selection.target_binding_id() {
                    self.observability
                        .record_routing_telemetry(RoutingTelemetryRecord {
                            route: route.id().to_owned(),
                            provider: selection.provider().as_str().to_owned(),
                            binding: target.to_owned(),
                            observed_at_ms: request_timestamp_now(),
                            sample_count: 1,
                            rolling_window_ms: 5 * 60 * 1_000,
                            stale_after_ms: 5 * 60 * 1_000,
                            latency_ms: Some(latency_ms),
                            ttft_ms: None,
                            throughput_per_second: None,
                        });
                }
            }
            self.observability.record_attempt(
                AttemptRecord::new(route.id(), selection.provider().as_str(), attempt_result)
                    .duration(attempt_duration),
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
                    if websocket_attempt
                        && !websocket_http_fallback_attempted
                        && websocket_http_fallback_safe(&error)
                    {
                        websocket_http_fallback_attempted = true;
                        lifecycle.retry(
                            attempt,
                            "responses_websocket_http_fallback",
                            Duration::ZERO,
                            None,
                            None,
                        );
                        forced_selection = Some(selection);
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
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
                                lifecycle.retry(
                                    attempt,
                                    "native_authorization_refresh",
                                    Duration::ZERO,
                                    None,
                                    None,
                                );
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
                            lifecycle.retry(
                                attempt,
                                format!("{:?}", failure.decision),
                                delay,
                                None,
                                failure
                                    .classification
                                    .cooldown
                                    .as_ref()
                                    .map(|cooldown| format!("{:?}", cooldown.scope)),
                            );
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
                        lifecycle.retry(
                            attempt,
                            "native_authorization_refresh",
                            Duration::ZERO,
                            None,
                            None,
                        );
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
                            lifecycle.retry(
                                attempt,
                                "native_account_requires_reauthentication",
                                Duration::ZERO,
                                None,
                                Some("credential_disabled".to_owned()),
                            );
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
                    lifecycle.retry(
                        attempt,
                        format!("{:?}", failure.decision),
                        delay,
                        (!quota_observations.is_empty()).then(|| "provider_quota".to_owned()),
                        failure
                            .classification
                            .cooldown
                            .as_ref()
                            .map(|cooldown| format!("{:?}", cooldown.scope)),
                    );
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
            let mut final_response_hint = semantic_response_hint;
            if force_unary_responses_stream {
                final_response_hint.upstream_mode = SemanticResponseMode::ServerSentEvents;
            }
            if route.ingress().mode() == BodyMode::Semantic {
                final_response_hint.upstream_wire =
                    selected_semantic_wire(&selection, route, upstream);
            }
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
                        routing_metadata_requested,
                        attempt,
                        semantic_response_hint: final_response_hint,
                        cache_leader,
                        gemini_interaction_create,
                        lifecycle: lifecycle.clone(),
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
            upstream_uri,
            selection,
            native_auth,
            native_profile: _,
            connection_generation: _,
            cancellation,
            started,
        } = request;
        let mut headers = request_headers.clone();
        strip_caller_credentials_when_authenticating(
            &mut headers,
            native_auth.is_some(),
            selection,
            upstream,
        );
        if let Some(native_auth) = native_auth {
            native_auth.apply_once(&mut headers).map_err(native_error)?;
        } else if let Some(account_secret) = selection.account_secret() {
            if !self
                .native
                .apply_managed_account_auth(
                    &mut headers,
                    account_secret,
                    upstream.auth(),
                    upstream,
                    selection.credential(),
                )
                .map_err(native_error)?
            {
                let _ = crate::pool::apply_configured_account_auth(
                    &mut headers,
                    Some(account_secret),
                    upstream.auth(),
                )
                .map_err(pool_error)?;
            }
        } else if let Some(auth) = upstream.auth() {
            if !self
                .native
                .apply_managed_account_auth(&mut headers, auth.secret(), Some(auth), upstream, None)
                .map_err(native_error)?
            {
                apply_configured_upstream_auth(&mut headers, upstream)?;
            }
        } else {
            apply_configured_upstream_auth(&mut headers, upstream)?;
        }
        if upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
            && route.ingress().mode() == BodyMode::Semantic
        {
            headers.insert(
                header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );
            headers.insert(header::CONNECTION, HeaderValue::from_static("Keep-Alive"));
        }
        let body = FrameLimitedBody::new(body, bounded_usize(route.limits().max_frame_bytes))
            .map_err(box_error)
            .boxed();
        let uri = upstream_uri;
        let uri = self
            .semantic
            .rewrite_upstream_uri(route, downstream_uri, selection.upstream_model(), uri)
            .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
        let uri =
            rewrite_native_upstream_uri(upstream, downstream_uri, selection.upstream_model(), uri)?;
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
        let request_deadline = started + effective_request_timeout(route.limits(), upstream);
        let connection_timeout = connect_timeout(route.limits(), upstream);
        let client = if upstream.http2() {
            &self.h2c_clients
        } else {
            &self.clients
        }
        .get(&connection_timeout)
        .ok_or_else(|| {
            ProxyError::InvalidLimits("upstream connect timeout client is unavailable".to_owned())
        })?;
        let response = tokio::select! {
            result = time::timeout_at(
                Instant::from_std(request_deadline),
                client.request(upstream_request),
            ) => {
                result.map_err(|_| ProxyError::Timeout)?.map_err(upstream_client_error)?
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
            downstream_uri: _,
            version: _,
            headers: request_headers,
            upstream,
            upstream_uri,
            selection,
            native_auth,
            native_profile,
            connection_generation,
            cancellation,
            started,
        } = request;
        let mut headers = request_headers.clone();
        strip_caller_credentials_when_authenticating(
            &mut headers,
            native_auth.is_some(),
            selection,
            upstream,
        );
        if let Some(native_auth) = native_auth {
            native_auth.apply_once(&mut headers).map_err(native_error)?;
        } else if let Some(account_secret) = selection.account_secret() {
            if !self
                .native
                .apply_managed_account_auth(
                    &mut headers,
                    account_secret,
                    upstream.auth(),
                    upstream,
                    selection.credential(),
                )
                .map_err(native_error)?
            {
                crate::pool::apply_configured_account_auth(
                    &mut headers,
                    Some(account_secret),
                    upstream.auth(),
                )
                .map_err(pool_error)?;
            }
        } else if let Some(auth) = upstream.auth() {
            if !self
                .native
                .apply_managed_account_auth(&mut headers, auth.secret(), Some(auth), upstream, None)
                .map_err(native_error)?
            {
                apply_configured_upstream_auth(&mut headers, upstream)?;
            }
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
        let upstream_uri = rewrite_native_upstream_uri(
            upstream,
            &upstream_uri,
            selection.upstream_model(),
            upstream_uri.clone(),
        )?;
        let endpoint = responses_websocket_endpoint(&upstream_uri)?;
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
        let request_timeout = effective_request_timeout(route.limits(), upstream);
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
        lifecycle: &RequestLifecycle,
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
        lifecycle.record(RequestEventKind::Selection, |event| {
            event.provider = Some("response_cache".to_owned());
            event.eligible = Some(true);
        });
        lifecycle.committed(cached.status().as_u16());
        let body = ObservedBody::new_tracked(
            body,
            observation,
            completion_class_for_status(cached.status()),
            lifecycle.clone(),
            cached.status().as_u16(),
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
            routing_metadata_requested,
            semantic_response_hint,
            attempt,
            mut cache_leader,
            gemini_interaction_create,
            lifecycle,
        } = context;
        let (parts, body) = response.into_parts();
        let mut response_headers = parts.headers;
        strip_hop_by_hop_headers(&mut response_headers);
        if routing_metadata_requested {
            add_routing_metadata_headers(&mut response_headers, &selection, attempt);
        }
        if gemini_interaction_create
            && parts.status.is_success()
            && response_headers
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .any(|value| {
                    value.to_str().map_or(true, |value| {
                        value
                            .split(',')
                            .any(|coding| !coding.trim().eq_ignore_ascii_case("identity"))
                    })
                })
        {
            observation.complete(CompletionClass::Unsupported, None);
            return Err(ProxyError::SemanticResponse(
                "compressed Gemini Interaction create responses are not supported".to_owned(),
            ));
        }
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
        let response_deadline =
            Instant::from_std(started + effective_request_timeout(route.limits(), upstream));
        observation.mark_headers();
        let mut body = if route.response().mode() == BodyMode::Semantic && parts.status.is_success()
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
                    result = time::timeout_at(
                        response_deadline,
                        crate::collect_body_limited(
                            body,
                            expected_bytes.expect("cache response length was checked"),
                        ),
                    ) => match result {
                        Ok(result) => result,
                        Err(_) => {
                            leader.fail();
                            return Err(ProxyError::Timeout);
                        }
                    },
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
        let affinity_commit = selection
            .affinity_commit()
            .map(|commit| (Arc::clone(&self.pooling), commit));
        if gemini_interaction_create && parts.status.is_success() {
            if let Some(binding) = self.pooling.interaction_affinity_binding(&selection) {
                let is_sse = response_headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.split(';').next().is_some_and(|mime| {
                            mime.trim().eq_ignore_ascii_case("text/event-stream")
                        })
                    });
                body = GeminiInteractionAffinityBody::new(
                    body,
                    Arc::clone(&self.pooling),
                    binding,
                    is_sse,
                )
                .boxed();
            }
        }
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
        lifecycle.committed(parts.status.as_u16());
        let completion = completion_class_for_status(parts.status);
        let deadline_cleanup = ResponseDeadline::new();
        let body = ObservedBody::new_for_target(
            body,
            observation,
            completion,
            usage_target,
            lifecycle,
            parts.status.as_u16(),
            deadline_cleanup.clone(),
            affinity_commit,
        );
        let body = DrainedBody::new(body, guard);
        let body = DeadlineBody::new(
            body,
            response_deadline,
            deadline_cleanup.clone(),
            self.resources.clone(),
        )
        .boxed();
        let mut response = Response::new(body);
        *response.status_mut() = parts.status;
        *response.version_mut() = parts.version;
        *response.headers_mut() = response_headers;
        response.extensions_mut().insert(deadline_cleanup);
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
    upstream_uri: Uri,
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
    routing_metadata_requested: bool,
    attempt: u32,
    semantic_response_hint: SemanticResponseHint,
    cache_leader: Option<CacheLeader>,
    gemini_interaction_create: bool,
    lifecycle: RequestLifecycle,
}

struct InspectedFailureResponse {
    response: Response<ProxyBody>,
    provider_code: Option<String>,
    retry_after: Option<Duration>,
    quota_observations: Vec<QuotaObservation>,
}

impl PreparedBody {
    fn buffered_bytes_for_attempt<S: SemanticAdapter>(
        &self,
        route: &RoutePlan,
        selection: &PoolSelection,
        upstream: &UpstreamPlan,
        semantic: &S,
        lifecycle: &RequestLifecycle,
    ) -> Result<Bytes, ProxyError> {
        let Self::Buffered { bytes, patch_model } = self else {
            return Err(ProxyError::SemanticRequest(
                "semantic WebSocket requests must be buffered".to_owned(),
            ));
        };
        if *patch_model {
            if let Some(model) = selection.upstream_model() {
                return patch_body_for_target(
                    bytes, route, model, selection, upstream, semantic, lifecycle,
                );
            }
        }
        Ok(bytes.clone())
    }

    fn body_for_attempt<S: SemanticAdapter>(
        &mut self,
        route: &RoutePlan,
        selection: &PoolSelection,
        upstream: &UpstreamPlan,
        semantic: &S,
        lifecycle: &RequestLifecycle,
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
                        patch_body_for_target(
                            bytes, route, model, selection, upstream, semantic, lifecycle,
                        )?
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

const MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES: usize = 256 * 1024;

struct GeminiInteractionAffinityBody {
    inner: Pin<Box<ProxyBody>>,
    pooling: Arc<PoolingCoordinator>,
    binding: crate::pool::InteractionAffinityBinding,
    observation: InteractionIdObservation,
    pending_interaction_id: Option<String>,
}

enum InteractionIdObservation {
    Json(Vec<u8>),
    Sse {
        parser: SseParser,
        observed_bytes: usize,
    },
    Done,
}

impl GeminiInteractionAffinityBody {
    fn new(
        inner: ProxyBody,
        pooling: Arc<PoolingCoordinator>,
        binding: crate::pool::InteractionAffinityBinding,
        sse: bool,
    ) -> Self {
        let observation = if sse {
            InteractionIdObservation::sse()
        } else {
            InteractionIdObservation::json()
        };
        Self {
            inner: Box::pin(inner),
            pooling,
            binding,
            observation,
            pending_interaction_id: None,
        }
    }

    fn observe(&mut self, bytes: &[u8], end_stream: bool) {
        if let Some(interaction_id) = self.observation.observe(bytes, end_stream) {
            self.pending_interaction_id = Some(interaction_id);
        }
    }

    fn finish_success(&mut self) {
        if let Some(interaction_id) = self.pending_interaction_id.take() {
            self.pooling.bind_interaction_affinity(
                &self.binding,
                interaction_id,
                crate::pool::timestamp_now(),
            );
        }
    }
}

impl InteractionIdObservation {
    fn json() -> Self {
        Self::Json(Vec::new())
    }

    fn sse() -> Self {
        Self::Sse {
            parser: SseParser::with_limits(SseLimits::new(
                MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES,
                MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES,
            )),
            observed_bytes: 0,
        }
    }

    fn observe(&mut self, bytes: &[u8], end_stream: bool) -> Option<String> {
        let interaction_id = match self {
            Self::Json(buffer) => {
                if buffer.len().saturating_add(bytes.len())
                    > MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES
                {
                    *self = Self::Done;
                    return None;
                }
                buffer.extend_from_slice(bytes);
                if !end_stream {
                    return None;
                }
                serde_json::from_slice::<serde_json::Value>(buffer)
                    .ok()
                    .and_then(|value| interaction_id_from_json(&value).map(str::to_owned))
            }
            Self::Sse {
                parser,
                observed_bytes,
            } => {
                let remaining =
                    MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES.saturating_sub(*observed_bytes);
                let observed = bytes.len().min(remaining);
                *observed_bytes = observed_bytes.saturating_add(observed);
                let interaction_id = match parser.feed(&bytes[..observed]) {
                    Ok(events) => events.into_iter().find_map(|event| {
                        serde_json::from_str::<serde_json::Value>(&event.data)
                            .ok()
                            .and_then(|value| interaction_id_from_json(&value).map(str::to_owned))
                    }),
                    Err(_) => {
                        *self = Self::Done;
                        return None;
                    }
                };
                if interaction_id.is_none()
                    && (observed < bytes.len()
                        || *observed_bytes == MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES)
                {
                    *self = Self::Done;
                    return None;
                }
                interaction_id
            }
            Self::Done => return None,
        };
        if interaction_id.is_some() || end_stream {
            *self = Self::Done;
        }
        interaction_id
    }
}

impl Body for GeminiInteractionAffinityBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.inner.as_mut().poll_frame(context);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let end_stream = self.inner.is_end_stream();
                    self.observe(data, end_stream);
                    if end_stream {
                        self.finish_success();
                    }
                }
            }
            Poll::Ready(None) => {
                self.observe(&[], true);
                self.finish_success();
            }
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
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

fn interaction_id_from_json(value: &serde_json::Value) -> Option<&str> {
    value
        .get("interaction")
        .unwrap_or(value)
        .as_object()?
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn gemini_interaction_id_from_path(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix("/v1beta/interactions/")?;
    let interaction_id = suffix.strip_suffix("/cancel").unwrap_or(suffix);
    (!interaction_id.is_empty()
        && !interaction_id.contains('/')
        && interaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(interaction_id)
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
    lifecycle: Option<RequestLifecycle>,
    status: Option<u16>,
    usage_target: Option<UsageTarget>,
    usage_bytes: Vec<u8>,
    usage_overflowed: bool,
    response_deadline: Option<ResponseDeadline>,
    affinity_commit: Option<(Arc<PoolingCoordinator>, crate::pool::AffinityCommit)>,
}

impl ObservedBody {
    fn new(inner: ProxyBody, observation: RequestObservation, completion: CompletionClass) -> Self {
        Self {
            inner: Box::pin(inner),
            observation: Some(observation),
            completion,
            lifecycle: None,
            status: None,
            usage_target: None,
            usage_bytes: Vec::new(),
            usage_overflowed: false,
            response_deadline: None,
            affinity_commit: None,
        }
    }

    fn new_tracked(
        inner: ProxyBody,
        observation: RequestObservation,
        completion: CompletionClass,
        lifecycle: RequestLifecycle,
        status: u16,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            observation: Some(observation),
            completion,
            lifecycle: Some(lifecycle),
            status: Some(status),
            usage_target: None,
            usage_bytes: Vec::new(),
            usage_overflowed: false,
            response_deadline: None,
            affinity_commit: None,
        }
    }

    #[allow(clippy::too_many_arguments)] // Body lifecycle ownership stays explicit at commitment.
    fn new_for_target(
        inner: ProxyBody,
        observation: RequestObservation,
        completion: CompletionClass,
        usage_target: UsageTarget,
        lifecycle: RequestLifecycle,
        status: u16,
        response_deadline: ResponseDeadline,
        affinity_commit: Option<(Arc<PoolingCoordinator>, crate::pool::AffinityCommit)>,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            observation: Some(observation),
            completion,
            lifecycle: Some(lifecycle),
            status: Some(status),
            usage_target: Some(usage_target),
            usage_bytes: Vec::new(),
            usage_overflowed: false,
            response_deadline: Some(response_deadline),
            affinity_commit,
        }
    }

    fn complete(&mut self, completion: CompletionClass) {
        let Some(mut observation) = self.observation.take() else {
            return;
        };
        let usage = (!self.usage_overflowed)
            .then(|| extract_observed_usage(&self.usage_bytes))
            .flatten();
        if matches!(completion, CompletionClass::Success)
            && self
                .status
                .is_some_and(|status| (200..300).contains(&status))
        {
            if let Some((pooling, commit)) = self.affinity_commit.take() {
                pooling.persist_affinity_commit(commit, crate::pool::timestamp_now());
            }
        }
        if let Some(lifecycle) = self.lifecycle.as_ref() {
            lifecycle.complete_with_usage(completion.clone(), self.status, usage.as_ref());
        }
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
                    if let Some(lifecycle) = self.lifecycle.as_ref() {
                        lifecycle.mark_first_event();
                    }
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
        } else if self
            .response_deadline
            .as_ref()
            .is_some_and(ResponseDeadline::is_elapsed)
        {
            if self.completion == CompletionClass::Success {
                CompletionClass::IncompleteStream
            } else {
                self.completion.clone()
            }
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

fn merge_observed_usage(target: &mut Option<ObservedUsage>, update: ObservedUsage) {
    let current = target.get_or_insert_with(ObservedUsage::default);
    if update.input_tokens.is_some() {
        current.input_tokens = update.input_tokens;
    }
    if update.output_tokens.is_some() {
        current.output_tokens = update.output_tokens;
    }
    if update.reasoning_tokens.is_some() {
        current.reasoning_tokens = update.reasoning_tokens;
    }
    if update.cache_tokens.is_some() {
        current.cache_tokens = update.cache_tokens;
    }
    if update.image_units.is_some() {
        current.image_units = update.image_units;
    }
    if update.audio_units.is_some() {
        current.audio_units = update.audio_units;
    }
    if update.video_units.is_some() {
        current.video_units = update.video_units;
    }
    if update.service_tier.is_some() {
        current.service_tier = update.service_tier;
    }
    if update.total_tokens.is_some() {
        current.total_tokens = update.total_tokens;
    }
    if update.cost_in_usd_ticks.is_some() {
        current.cost_in_usd_ticks = update.cost_in_usd_ticks;
    }
}

fn visit_usage_values(value: &serde_json::Value, usage: &mut ObservedUsage, found: &mut bool) {
    let Some(root) = value.as_object() else {
        return;
    };
    merge_usage_envelope(root, usage, found);
    // Provider streaming events place accounting directly under one response
    // or message envelope. Do not recurse through repeated envelope names or
    // generated output/content trees looking for usage-shaped user data.
    for key in ["response", "message"] {
        if let Some(envelope) = root.get(key).and_then(serde_json::Value::as_object) {
            merge_usage_envelope(envelope, usage, found);
        }
    }
}

fn merge_usage_envelope(
    object: &serde_json::Map<String, serde_json::Value>,
    usage: &mut ObservedUsage,
    found: &mut bool,
) {
    for key in ["usage", "usageMetadata", "usage_metadata"] {
        if let Some(usage_object) = object.get(key).and_then(serde_json::Value::as_object) {
            merge_usage_value(usage_object, usage, found);
        }
    }
    if usage.service_tier.is_none() {
        if let Some(tier) = object
            .get("service_tier")
            .and_then(serde_json::Value::as_str)
        {
            usage.service_tier = Some(tier.chars().take(64).collect());
            *found = true;
        }
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
        &mut usage.reasoning_tokens,
        numeric_alias(object, &["reasoning_tokens", "thoughtsTokenCount"]).or_else(|| {
            nested_numeric_alias(object, "output_tokens_details", &["reasoning_tokens"])
        }),
        found,
    );
    merge_usage_field(
        &mut usage.cache_tokens,
        numeric_alias(
            object,
            &["cached_tokens", "cache_tokens", "cachedContentTokenCount"],
        )
        .or_else(|| nested_numeric_alias(object, "input_tokens_details", &["cached_tokens"])),
        found,
    );
    merge_usage_field(
        &mut usage.image_units,
        numeric_alias(object, &["image_units"]),
        found,
    );
    merge_usage_field(
        &mut usage.audio_units,
        numeric_alias(object, &["audio_units"]),
        found,
    );
    merge_usage_field(
        &mut usage.video_units,
        numeric_alias(object, &["video_units"]),
        found,
    );
    merge_usage_field(
        &mut usage.total_tokens,
        numeric_alias(object, &["total_tokens", "totalTokenCount"]),
        found,
    );
    let cost = numeric_alias(object, &["cost_in_usd_ticks"])
        .or_else(|| nested_numeric_alias(object, "details", &["cost_in_usd_ticks"]));
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

fn nested_numeric_alias(
    object: &serde_json::Map<String, serde_json::Value>,
    container: &str,
    names: &[&str],
) -> Option<u64> {
    object
        .get(container)
        .and_then(serde_json::Value::as_object)
        .and_then(|nested| numeric_alias(nested, names))
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

fn websocket_http_fallback_safe(error: &ProxyError) -> bool {
    match error {
        ProxyError::WebSocketHandshakeStatus(_) => true,
        ProxyError::Upstream(error) => error
            .downcast_ref::<OpenAiResponsesWebSocketError>()
            .is_some_and(|error| matches!(error, OpenAiResponsesWebSocketError::Connect)),
        _ => false,
    }
}

fn responses_websocket_endpoint(uri: &Uri) -> Result<String, ProxyError> {
    let mut endpoint = url::Url::parse(&uri.to_string()).map_err(|_| ProxyError::InvalidUri)?;
    match endpoint.scheme() {
        "http" => endpoint
            .set_scheme("ws")
            .map_err(|_| ProxyError::InvalidUri)?,
        "https" => endpoint
            .set_scheme("wss")
            .map_err(|_| ProxyError::InvalidUri)?,
        "ws" | "wss" => {}
        _ => return Err(ProxyError::InvalidUri),
    }
    Ok(endpoint.to_string())
}

fn upstream_client_error(error: hyper_util::client::legacy::Error) -> ProxyError {
    let mut source: Option<&(dyn Error + 'static)> = Some(&error);
    while let Some(current) = source {
        if current
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
        {
            return ProxyError::Timeout;
        }
        source = current.source();
    }
    ProxyError::Upstream(Box::new(error))
}

fn is_exact_gemini_interaction_create(method: &http::Method, path: &str) -> bool {
    method == http::Method::POST
        && matches!(
            path,
            "/v1/interactions" | "/v1beta/interactions" | "/v1beta2/interactions"
        )
}

fn semantic_unary_responses_requires_streaming(
    route: &RoutePlan,
    selection: &PoolSelection,
    upstream: &UpstreamPlan,
    hint: &SemanticResponseHint,
) -> bool {
    let responses_upstream =
        selected_semantic_wire(selection, route, upstream) == Some(SemanticWire::OpenAiResponses);
    let cross_protocol = route.ingress().decoder() != Some("decode.openai.responses");
    let codex = upstream.native().is_some_and(|native| {
        native
            .kind()
            .eq_ignore_ascii_case(adapter_codex::CODEX_PROVIDER_ID)
    });
    hint.mode == SemanticResponseMode::Json
        && route.ingress().mode() == BodyMode::Semantic
        && route.response().mode() == BodyMode::Semantic
        && responses_upstream
        && (codex || cross_protocol)
}

fn force_responses_streaming_request(
    bytes: &Bytes,
    limits: &RouteLimits,
) -> Result<Bytes, ProxyError> {
    let mut document = PreservedJson::from_bytes(bytes.to_vec())
        .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
    document
        .set_pointer_bounded(
            "/stream",
            serde_json::Value::Bool(true),
            JsonPatchLimits::default(),
        )
        .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
    let bytes = document.bytes().into_owned();
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    limits
        .check_request_body(observed)
        .map_err(|_| ProxyError::RequestBodyTooLarge)?;
    limits
        .check_frame(observed)
        .map_err(|_| ProxyError::RequestBodyTooLarge)?;
    Ok(Bytes::from(bytes))
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
fn patch_body_for_target<S: SemanticAdapter>(
    bytes: &Bytes,
    route: &RoutePlan,
    model: &str,
    selection: &PoolSelection,
    upstream: &UpstreamPlan,
    semantic: &S,
    lifecycle: &RequestLifecycle,
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
        drop_unsupported_parameter(
            &mut document,
            lifecycle,
            route,
            model,
            "/temperature",
            "temperature",
        )?;
    }
    if profile.reasoning.is_unsupported() {
        drop_unsupported_parameter(
            &mut document,
            lifecycle,
            route,
            model,
            "/reasoning",
            "reasoning",
        )?;
        drop_unsupported_parameter(
            &mut document,
            lifecycle,
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
                lifecycle,
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
            drop_unsupported_parameter(&mut document, lifecycle, route, model, pointer, parameter)?;
        }
    } else if profile.parallel_tools.is_unsupported() {
        drop_unsupported_parameter(
            &mut document,
            lifecycle,
            route,
            model,
            "/parallel_tool_calls",
            "parallel_tool_calls",
        )?;
    }
    if profile.structured_output.is_unsupported() {
        drop_unsupported_parameter(
            &mut document,
            lifecycle,
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
    if upstream
        .native()
        .is_some_and(|native| native.kind().eq_ignore_ascii_case("palantir_aip"))
    {
        drop_unsupported_parameter(
            &mut document,
            lifecycle,
            route,
            model,
            "/context_management",
            "context_management",
        )?;
    }
    enforce_output_limit(&mut document, route, model, profile.output_limit)?;
    let mut bytes = Bytes::from(document.bytes().into_owned());
    if route.ingress().mode() == BodyMode::Semantic {
        let wire = selected_semantic_wire(selection, route, upstream).ok_or_else(|| {
            ProxyError::SemanticRequest(
                "selected provider has no compatible semantic endpoint".to_owned(),
            )
        })?;
        bytes = Bytes::from(
            semantic
                .reencode_request_for_wire(route, &bytes, wire)
                .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?,
        );
    }
    if upstream
        .native()
        .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
    {
        return normalize_codex_responses_request(&bytes);
    }
    Ok(bytes)
}

fn selected_semantic_wire(
    selection: &PoolSelection,
    route: &RoutePlan,
    upstream: &UpstreamPlan,
) -> Option<SemanticWire> {
    if upstream
        .native()
        .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
    {
        return Some(SemanticWire::OpenAiResponses);
    }
    match selection.endpoint_family_for(route) {
        Some("responses") => Some(SemanticWire::OpenAiResponses),
        Some("chat_completions") => Some(SemanticWire::OpenAiChat),
        Some("messages") => Some(SemanticWire::AnthropicMessages),
        Some("generate_content") => Some(SemanticWire::GeminiGenerateContent),
        _ => None,
    }
}

fn normalize_codex_responses_request(bytes: &Bytes) -> Result<Bytes, ProxyError> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        ProxyError::InvalidPatch("OpenAI Responses request is not an object".to_owned())
    })?;

    if let Some(input) = object.get_mut("input") {
        if let Some(text) = input.as_str() {
            *input = serde_json::json!([{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": text}]
            }]);
        }
        if let Some(items) = input.as_array_mut() {
            for item in items {
                let Some(item) = item.as_object_mut() else {
                    continue;
                };
                if item.get("role").and_then(serde_json::Value::as_str) == Some("system") {
                    item.insert(
                        "role".to_owned(),
                        serde_json::Value::String("developer".to_owned()),
                    );
                }
                if let Some(content) = item
                    .get_mut("content")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for part in content {
                        if let Some(part) = part.as_object_mut() {
                            part.remove("prompt_cache_breakpoint");
                        }
                    }
                }
            }
        }
    }

    object.insert("stream".to_owned(), serde_json::Value::Bool(true));
    object.insert("store".to_owned(), serde_json::Value::Bool(false));
    object.insert(
        "parallel_tool_calls".to_owned(),
        serde_json::Value::Bool(true),
    );
    object.insert(
        "include".to_owned(),
        serde_json::json!(["reasoning.encrypted_content"]),
    );
    for field in [
        "max_output_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "truncation",
        "prompt_cache_options",
        "prompt_cache_retention",
        "safety_identifier",
        "user",
    ] {
        object.remove(field);
    }
    if object
        .get("service_tier")
        .and_then(serde_json::Value::as_str)
        != Some("priority")
    {
        object.remove("service_tier");
    }
    if let Some(tools) = object
        .get_mut("tools")
        .and_then(serde_json::Value::as_array_mut)
    {
        for tool in tools {
            let Some(tool) = tool.as_object_mut() else {
                continue;
            };
            if matches!(
                tool.get("type").and_then(serde_json::Value::as_str),
                Some("web_search_preview" | "web_search_preview_2025_03_11")
            ) {
                tool.insert(
                    "type".to_owned(),
                    serde_json::Value::String("web_search".to_owned()),
                );
            }
        }
    }

    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| ProxyError::InvalidPatch(error.to_string()))
}

fn drop_unsupported_parameter(
    document: &mut PreservedJson,
    lifecycle: &RequestLifecycle,
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
    lifecycle.semantic_loss(parameter);
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
        Some(kind) if kind.eq_ignore_ascii_case("gemini") => ProviderKind::AiStudio,
        Some(kind) if kind.eq_ignore_ascii_case("vertex") => ProviderKind::Vertex,
        Some(kind) if kind.eq_ignore_ascii_case("antigravity") => ProviderKind::Antigravity,
        _ => ProviderKind::OpenAiCompatible,
    };
    ProviderResponseClassifier::new(provider)
        .parse_policy_observations(status, headers, body)
        .unwrap_or_default()
}

fn rewrite_native_upstream_uri(
    upstream: &UpstreamPlan,
    downstream: &Uri,
    upstream_model: Option<&str>,
    upstream_uri: Uri,
) -> Result<Uri, ProxyError> {
    let Some(native) = upstream.native() else {
        return Ok(upstream_uri);
    };
    if native.kind().eq_ignore_ascii_case("codex") {
        let path = match upstream_uri.path() {
            "/v1/responses" | "/v1/chat/completions" | adapter_codex::CODEX_RESPONSES_PATH => {
                adapter_codex::CODEX_RESPONSES_PATH
            }
            "/v1/models" | adapter_codex::CODEX_MODELS_PATH => {
                adapter_codex::CODEX_MODELS_PATH_AND_QUERY
            }
            "/v1/images/generations" => "/backend-api/codex/images/generations",
            _ => return Ok(upstream_uri),
        };
        let mut target =
            url::Url::parse(&upstream_uri.to_string()).map_err(|_| ProxyError::InvalidUri)?;
        if let Some((path, query)) = path.split_once('?') {
            target.set_path(path);
            target.set_query(Some(query));
        } else {
            target.set_path(path);
        }
        return target.as_str().parse().map_err(|_| ProxyError::InvalidUri);
    }
    if !native.kind().eq_ignore_ascii_case("vertex") {
        return Ok(upstream_uri);
    }
    let Some(project) = native.project() else {
        return Ok(upstream_uri);
    };
    let Some(location) = native.location() else {
        return Ok(upstream_uri);
    };
    let operation = match downstream.path().rsplit_once(':').map(|(_, action)| action) {
        Some("generateContent") => ProviderOperation::GenerateContent,
        Some("streamGenerateContent") => ProviderOperation::StreamGenerateContent,
        Some("countTokens") => ProviderOperation::CountTokens,
        Some("predict") => ProviderOperation::Predict,
        _ => return Ok(upstream_uri),
    };
    let model = upstream_model.ok_or_else(|| {
        ProxyError::SemanticRequest("Vertex model action requires a selected model".to_owned())
    })?;
    let mut adapter = VertexAdapter::project(project, location)
        .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
    if let Some(publisher) = native.publisher() {
        adapter = adapter
            .with_publisher(publisher)
            .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?;
    }
    let endpoint = adapter
        .endpoint_candidates(operation, Some(model))
        .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| ProxyError::InvalidUri)?;
    let mut target =
        url::Url::parse(&upstream_uri.to_string()).map_err(|_| ProxyError::InvalidUri)?;
    target.set_path(endpoint.path());
    let query = merge_endpoint_query(upstream_uri.query(), endpoint.query());
    target.set_query(query.as_deref());
    target.as_str().parse().map_err(|_| ProxyError::InvalidUri)
}

#[cfg(test)]
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
    let path = if upstream
        .known_provider()
        .is_some_and(|provider| provider.eq_ignore_ascii_case("kimi-for-coding"))
    {
        KimiAdapter::coding_subscription()
            .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?
            .openai_endpoint_path(path)
            .map_err(|error| ProxyError::SemanticRequest(error.to_string()))?
    } else {
        path.to_owned()
    };
    url.set_path(&path);
    merge_upstream_query(&mut url, downstream.query());
    apply_upstream_query(&mut url, upstream.query());
    url.as_str().parse().map_err(|_| ProxyError::InvalidUri)
}

/// Add the query parameters an upstream requires without overriding the caller.
///
/// Some providers reject a request that omits a parameter the caller has no
/// reason to know about, such as Azure OpenAI's `api-version`. A caller that
/// did send the parameter chose a value deliberately, so configuration fills
/// the gap rather than replacing the choice.
#[cfg(test)]
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

/// Preserve query parameters embedded in an upstream base URL while adding
/// the downstream request's query. The downstream query remains in the same
/// order and encoding supplied by the caller; configured required parameters
/// are appended separately by [`apply_upstream_query`].
#[cfg(test)]
fn merge_upstream_query(url: &mut url::Url, downstream: Option<&str>) {
    let base = url
        .query()
        .filter(|query| !query.is_empty())
        .map(str::to_owned);
    let merged = match (
        base.as_deref(),
        downstream.filter(|query| !query.is_empty()),
    ) {
        (Some(base), Some(downstream)) => Some(format!("{base}&{downstream}")),
        (Some(base), None) => Some(base.to_owned()),
        (None, Some(downstream)) => Some(downstream.to_owned()),
        (None, None) => None,
    };
    url.set_query(merged.as_deref());
}

/// Merge provider-generated query parameters after preserving caller and base
/// URL parameters. Provider parameters take precedence by name; this is
/// required for Vertex streaming, whose adapter-generated `alt=sse` must not
/// be replaced by a caller's `alt=json`.
fn merge_endpoint_query(existing: Option<&str>, endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint.filter(|query| !query.is_empty());
    let Some(endpoint) = endpoint else {
        return existing.map(str::to_owned);
    };
    let endpoint_names = endpoint
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.split_once('=')
                .map_or(part, |(name, _)| name)
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let mut parts = existing
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter(|part| {
            let part = *part;
            let name = part.split_once('=').map_or(part, |(name, _)| name);
            !part.is_empty() && !endpoint_names.iter().any(|candidate| candidate == name)
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    parts.extend(
        endpoint
            .split('&')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    (!parts.is_empty()).then(|| parts.join("&"))
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

#[cfg(test)]
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
    merge_upstream_query(&mut url, downstream.query());
    apply_upstream_query(&mut url, upstream.query());
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
    Semantic,
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
) -> Result<Option<Vec<u8>>, WebSocketFrameError> {
    let mut complete_text = None;
    match frame.opcode {
        1 | 2 => {
            if state.fragmented {
                return Err(WebSocketFrameError::Protocol);
            }
            if frame.fin {
                if frame.payload_len > max_message_bytes {
                    return Err(WebSocketFrameError::TooLarge);
                }
                if frame.opcode == 1 {
                    if std::str::from_utf8(&frame.payload).is_err() {
                        return Err(WebSocketFrameError::InvalidText);
                    }
                    complete_text = Some(frame.payload.clone());
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
                if state.text {
                    if std::str::from_utf8(&state.text_bytes).is_err() {
                        return Err(WebSocketFrameError::InvalidText);
                    }
                    complete_text = Some(state.text_bytes.clone());
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
    Ok(complete_text)
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
        WebSocketFrameError::Semantic => 1008,
        WebSocketFrameError::Io => 1001,
    }
}

fn is_openai_realtime_websocket(route: &RoutePlan) -> bool {
    route.matcher().websocket() == Some(true)
        && route.ingress().mode() == BodyMode::Semantic
        && route.response().mode() == BodyMode::Semantic
        && route.ingress().decoder() == Some(OPENAI_REALTIME_CLIENT_DECODER)
        && route.response().decoder() == Some(OPENAI_REALTIME_SERVER_DECODER)
}

fn websocket_realtime_validator(
    route: &RoutePlan,
) -> Result<Option<OpenAiRealtimeValidator>, ProxyError> {
    if route.ingress().mode() == BodyMode::Opaque && route.response().mode() == BodyMode::Opaque {
        Ok(None)
    } else if is_openai_realtime_websocket(route) {
        Ok(Some(OpenAiRealtimeValidator::default()))
    } else {
        Err(ProxyError::UnsupportedBodyMode {
            route: route.id().to_owned(),
        })
    }
}

fn validate_realtime_message(
    frame: &RawWebSocketFrame,
    complete_text: Option<&[u8]>,
    validator: &mut OpenAiRealtimeValidator,
    from_client: bool,
) -> Result<(), WebSocketFrameError> {
    if let Some(text) = complete_text {
        let result = if from_client {
            validator.validate_client(text)
        } else {
            validator.validate_server(text)
        };
        return result.map_err(|_| WebSocketFrameError::Semantic);
    }
    match frame.opcode {
        0 | 1 | 8..=10 => Ok(()),
        _ => Err(WebSocketFrameError::Semantic),
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
    realtime_validator: Option<OpenAiRealtimeValidator>,
    guard: DrainGuard,
    cancellation: CancellationToken,
    hard_deadline: Option<StdInstant>,
    lease: Option<SelectionLease>,
    observation: RequestObservation,
    lifecycle: RequestLifecycle,
    affinity_commit: Option<(Arc<PoolingCoordinator>, crate::pool::AffinityCommit)>,
}

async fn run_websocket_tunnel(
    downstream_upgrade: hyper::upgrade::OnUpgrade,
    mut upstream: UpstreamSocket,
    context: WebSocketTunnelContext,
) {
    let WebSocketTunnelContext {
        max_frame_bytes,
        mut realtime_validator,
        guard,
        cancellation,
        hard_deadline,
        lease,
        mut observation,
        lifecycle,
        affinity_commit,
    } = context;
    let upgraded = tokio::select! {
        result = downstream_upgrade => match result {
            Ok(upgraded) => upgraded,
            Err(_) => {
                observation.complete(CompletionClass::Cancelled, None);
                lifecycle.complete(
                    CompletionClass::Cancelled,
                    Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                );
                return;
            }
        },
        () = cancellation.cancelled() => {
            observation.complete(CompletionClass::Cancelled, None);
            lifecycle.complete(
                CompletionClass::Cancelled,
                Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
            );
            return;
        }
    };
    let mut downstream = hyper_util::rt::TokioIo::new(upgraded);
    let max_frame = bounded_usize(max_frame_bytes).max(1);
    let max_message = max_frame as u64;
    let mut downstream_state = WebSocketMessageState::default();
    let mut upstream_state = WebSocketMessageState::default();
    let mut timeout: Pin<Box<dyn Future<Output = ()> + Send>> = match hard_deadline {
        Some(deadline) => Box::pin(time::sleep_until(Instant::from_std(deadline))),
        None => Box::pin(std::future::pending()),
    };
    let mut completion = CompletionClass::Success;
    let mut observed_usage = None;

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
                    let complete_text = match validate_websocket_message(
                        &frame,
                        &mut downstream_state,
                        max_message,
                    ) {
                        Ok(complete_text) => complete_text,
                        Err(error) => {
                            completion = CompletionClass::IncompleteStream;
                            send_websocket_closes(
                                &mut downstream,
                                &mut upstream,
                                websocket_error_close_code(&error),
                            )
                            .await;
                            break;
                        }
                    };
                    if let Some(validator) = realtime_validator.as_mut() {
                        if validate_realtime_message(
                            &frame,
                            complete_text.as_deref(),
                            validator,
                            true,
                        )
                        .is_err()
                        {
                            completion = CompletionClass::IncompleteStream;
                            send_websocket_closes(&mut downstream, &mut upstream, 1008).await;
                            break;
                        }
                    }
                    let close = frame.opcode == 8;
                    if write_websocket_frame(
                        &mut upstream,
                        &frame.bytes,
                        hard_deadline,
                        &cancellation,
                    )
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
                    error @ (WebSocketFrameError::InvalidClose
                    | WebSocketFrameError::InvalidText
                    | WebSocketFrameError::Semantic),
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
                    let complete_text = match validate_websocket_message(
                        &frame,
                        &mut upstream_state,
                        max_message,
                    ) {
                        Ok(complete_text) => complete_text,
                        Err(error) => {
                            completion = CompletionClass::IncompleteStream;
                            send_websocket_closes(
                                &mut downstream,
                                &mut upstream,
                                websocket_error_close_code(&error),
                            )
                            .await;
                            break;
                        }
                    };
                    if let Some(validator) = realtime_validator.as_mut() {
                        let invalid_event = validate_realtime_message(
                            &frame,
                            complete_text.as_deref(),
                            validator,
                            false,
                        )
                        .is_err();
                        let incomplete_close = frame.opcode == 8 && validator.finish().is_err();
                        if invalid_event || incomplete_close {
                            completion = CompletionClass::IncompleteStream;
                            send_websocket_closes(&mut downstream, &mut upstream, 1008).await;
                            break;
                        }
                    }
                    if matches!(frame.opcode, 1 | 2) {
                        observation.mark_first_event();
                        lifecycle.mark_first_event();
                    }
                    if let Some(text) = complete_text {
                        if let Some(update) = extract_observed_usage(&text) {
                            merge_observed_usage(&mut observed_usage, update);
                        }
                    }
                    let close = frame.opcode == 8;
                    if write_websocket_frame(
                        &mut downstream,
                        &frame.bytes,
                        hard_deadline,
                        &cancellation,
                    )
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
                    error @ (WebSocketFrameError::InvalidClose
                    | WebSocketFrameError::InvalidText
                    | WebSocketFrameError::Semantic),
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
    observation.complete(completion.clone(), None);
    lifecycle.complete_with_usage(
        completion.clone(),
        Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
        observed_usage.as_ref(),
    );
    if matches!(completion, CompletionClass::Success) {
        if let Some((pooling, commit)) = affinity_commit {
            pooling.persist_affinity_commit(commit, crate::pool::timestamp_now());
        }
    }
    drop(lease);
    drop(guard);
}
async fn write_websocket_frame<S>(
    stream: &mut S,
    bytes: &[u8],
    hard_deadline: Option<StdInstant>,
    cancellation: &CancellationToken,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if let Some(deadline) = hard_deadline {
        tokio::select! {
            result = time::timeout_at(Instant::from_std(deadline), async {
                stream.write_all(bytes).await?;
                stream.flush().await
            }) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket write timed out"))?,
            () = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "WebSocket write canceled")),
        }
    } else {
        tokio::select! {
            result = async {
                stream.write_all(bytes).await?;
                stream.flush().await
            } => result,
            () = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "WebSocket write canceled")),
        }
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

/// Remove caller-supplied provider credential headers when Pooler supplies its
/// own credential for this attempt.
///
/// Without this a downstream caller could attach `authorization`, `api-key`,
/// `x-api-key`, or `x-goog-api-key` and have it forwarded to the provider
/// alongside — or instead of — Pooler's credential. Only the semantic body
/// mode stripped them before, so every opaque, inspect, and patch route was a
/// credential smuggling path. When Pooler supplies no credential the route is
/// a pure tunnel and the caller's headers remain its own business.
fn strip_caller_credentials_when_authenticating(
    headers: &mut HeaderMap,
    native: bool,
    selection: &PoolSelection,
    upstream: &UpstreamPlan,
) {
    if native || selection.account_secret().is_some() || upstream.auth().is_some() {
        strip_provider_credential_headers(headers);
    }
}

/// A downstream bearer token authenticates the caller to Pooler; it is not an
/// upstream credential. Remove it before forwarding an opaque request after
/// [`HttpProxy::handle`] has verified it.
fn strip_downstream_authorization(route: &RoutePlan, headers: &mut HeaderMap) {
    if route.downstream_auth().is_some() {
        headers.remove(header::AUTHORIZATION);
    }
}

fn routing_metadata_opt_in(headers: &HeaderMap) -> bool {
    headers
        .get("x-pooler-routing-metadata")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes"))
}

fn add_routing_metadata_headers(headers: &mut HeaderMap, selection: &PoolSelection, attempt: u32) {
    insert_bounded_header(
        headers,
        "x-pooler-routing-provider",
        selection.provider().as_str(),
    );
    insert_bounded_header(
        headers,
        "x-pooler-routing-model",
        selection.model().as_str(),
    );
    insert_bounded_header(headers, "x-pooler-routing-attempt", &attempt.to_string());
    if let Some(target) = selection.target_binding_id() {
        insert_bounded_header(headers, "x-pooler-routing-target", target);
    }
}

fn insert_bounded_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if value.len() <= 128 {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    }
}

fn strip_provider_credential_headers(headers: &mut HeaderMap) {
    headers.remove(header::AUTHORIZATION);
    headers.remove("api-key");
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
        SecretRef::Managed(_) => return Err(ProxyError::SecretUnavailable),
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

fn request_timeout(limits: &RouteLimits, upstream: &UpstreamPlan) -> Option<Duration> {
    [limits.request_timeout, upstream.request_timeout()]
        .into_iter()
        .flatten()
        .min()
}

fn effective_request_timeout(limits: &RouteLimits, upstream: &UpstreamPlan) -> Duration {
    request_timeout(limits, upstream).unwrap_or(DEFAULT_REQUEST_TIMEOUT)
}

fn websocket_hard_deadline(
    started: StdInstant,
    limits: &RouteLimits,
    upstream: &UpstreamPlan,
) -> Option<StdInstant> {
    request_timeout(limits, upstream).map(|timeout| started + timeout)
}

fn retry_deadline(
    started: StdInstant,
    limits: &RouteLimits,
    upstream: &UpstreamPlan,
    policy: Option<&pooler_config::PolicyPlan>,
) -> Instant {
    let request_deadline = started + effective_request_timeout(limits, upstream);
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
    let mut timeout = effective_request_timeout(route.limits(), fallback);
    if route.target().model_source().is_some() {
        for target in config.models().values().flat_map(|model| model.targets()) {
            if let Some(upstream) = config.upstreams().get(target.provider()) {
                timeout = timeout.min(effective_request_timeout(route.limits(), upstream));
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
        .unwrap_or(DEFAULT_CONNECT_TIMEOUT)
}

fn configured_connect_timeouts(config: &CompiledConfig) -> BTreeSet<Duration> {
    let mut timeouts = BTreeSet::from([DEFAULT_CONNECT_TIMEOUT]);
    timeouts.extend(
        config
            .routes()
            .iter()
            .filter_map(|route| route.limits().connect_timeout),
    );
    timeouts.extend(
        config
            .upstreams()
            .values()
            .filter_map(UpstreamPlan::connect_timeout),
    );
    timeouts
}

fn build_upstream_client(
    tls_config: &ClientConfig,
    timeout: Duration,
    http2_only: bool,
) -> UpstreamClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config.clone())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    let connector = ConnectTimeoutConnector::new(connector, timeout);
    let mut builder = Client::builder(TokioExecutor::new());
    builder.http2_adaptive_window(true);
    if http2_only {
        builder.http2_only(true);
    }
    builder.build(connector)
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

fn openai_error_response(
    status: StatusCode,
    message: &str,
    code: &'static str,
) -> Response<ProxyBody> {
    let error_type = if status == StatusCode::UNAUTHORIZED {
        "authentication_error"
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        "rate_limit_error"
    } else if status.is_client_error() {
        "invalid_request_error"
    } else {
        "server_error"
    };
    let value = serde_json::json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": null,
            "code": code,
        }
    });
    let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| {
        br#"{"error":{"message":"internal error","type":"server_error","param":null,"code":"internal_error"}}"#
            .to_vec()
    });
    let body = Full::new(Bytes::from(encoded))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(DEFAULT_ERROR_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unauthorized_response() -> Response<ProxyBody> {
    let mut response = openai_error_response(
        StatusCode::UNAUTHORIZED,
        "bearer authentication required",
        "invalid_api_key",
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn error_response(error: ProxyError) -> Response<ProxyBody> {
    let (status, message, code) = match error {
        ProxyError::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            "upstream request failed",
            "upstream_timeout",
        ),
        ProxyError::UnsupportedAuth | ProxyError::SecretUnavailable => (
            StatusCode::BAD_GATEWAY,
            "upstream request failed",
            "upstream_error",
        ),
        ProxyError::MissingUpstream { .. }
        | ProxyError::InvalidUri
        | ProxyError::InvalidLimits(_)
        | ProxyError::RequestBuild(_)
        | ProxyError::Upstream(_)
        | ProxyError::WebSocketHandshakeStatus(_)
        | ProxyError::Native(_)
        | ProxyError::Pool(_)
        | ProxyError::UnsupportedBodyMode { .. } => (
            StatusCode::BAD_GATEWAY,
            "upstream request failed",
            "upstream_error",
        ),
        ProxyError::Extension(_) => (
            StatusCode::BAD_GATEWAY,
            "external extension failed",
            "extension_error",
        ),
        ProxyError::InvalidPatch(_) | ProxyError::SemanticRequest(_) => (
            StatusCode::BAD_REQUEST,
            "invalid request",
            "invalid_request",
        ),
        ProxyError::UnsupportedParameter { .. } => (
            StatusCode::BAD_REQUEST,
            "unsupported request parameter",
            "unsupported_parameter",
        ),
        ProxyError::InvalidWebSocketHandshake(_) => (
            StatusCode::BAD_REQUEST,
            "invalid WebSocket handshake",
            "invalid_websocket_handshake",
        ),
        ProxyError::RequestBodyTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request too large",
            "request_too_large",
        ),
        ProxyError::SemanticResponse(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream response could not be converted",
            "invalid_upstream_response",
        ),
        ProxyError::TlsClient(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "proxy initialization failed",
            "internal_error",
        ),
    };
    openai_error_response(status, message, code)
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
    use std::sync::atomic::AtomicUsize;

    use futures_util::stream;
    use http_body_util::StreamBody;

    use super::*;
    use pooler_config::compile_yaml;

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct DropTrackedPendingBody(Arc<AtomicUsize>);

    impl Body for DropTrackedPendingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    impl Drop for DropTrackedPendingBody {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn route_matcher_handles_exact_prefix_template_and_headers() {
        let config = compile_yaml(
            "test.yaml",
            r#"
version: 2
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
    fn gemini_create_detection_is_exact() {
        for path in [
            "/v1/interactions",
            "/v1beta/interactions",
            "/v1beta2/interactions",
        ] {
            assert!(is_exact_gemini_interaction_create(
                &http::Method::POST,
                path
            ));
        }
        assert!(!is_exact_gemini_interaction_create(
            &http::Method::GET,
            "/v1beta/interactions"
        ));
        assert!(!is_exact_gemini_interaction_create(
            &http::Method::POST,
            "/v1beta/interactions/int_123"
        ));
        assert!(!is_exact_gemini_interaction_create(
            &http::Method::POST,
            "/prefix/v1beta/interactions"
        ));
    }

    #[test]
    fn gemini_interaction_observation_handles_fragmented_json_and_sse_with_bounds() {
        let mut json = InteractionIdObservation::json();
        assert_eq!(json.observe(br#"{"id":"int_"#, false), None);
        assert_eq!(
            json.observe(br#"json","status":"completed"}"#, true),
            Some("int_json".to_owned())
        );
        assert!(matches!(json, InteractionIdObservation::Done));

        let mut sse = InteractionIdObservation::sse();
        assert_eq!(
            sse.observe(
                b"event: interaction.start\ndata: {\"interaction\":{\"id\":\"int_",
                false
            ),
            None
        );
        assert_eq!(
            sse.observe(b"sse\",\"status\":\"in_progress\"}}\n\n", false),
            Some("int_sse".to_owned())
        );
        assert!(matches!(sse, InteractionIdObservation::Done));

        let mut oversized = InteractionIdObservation::json();
        assert_eq!(
            oversized.observe(
                &vec![b'x'; MAX_INTERACTION_AFFINITY_OBSERVATION_BYTES + 1],
                false
            ),
            None
        );
        assert!(matches!(oversized, InteractionIdObservation::Done));
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
                ..ObservedUsage::default()
            })
        );

        let sse = b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":13,\"output_tokens\":1}}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"service_tier\":\"priority\",\"usage\":{\"output_tokens\":9,\"input_tokens_details\":{\"cached_tokens\":3},\"output_tokens_details\":{\"reasoning_tokens\":4},\"image_units\":2,\"audio_units\":5,\"video_units\":1,\"details\":{\"cost_in_usd_ticks\":42}}}}\n\n";
        assert_eq!(
            extract_observed_usage(sse),
            Some(ObservedUsage {
                input_tokens: Some(13),
                output_tokens: Some(9),
                total_tokens: Some(22),
                cost_in_usd_ticks: Some(42),
                reasoning_tokens: Some(4),
                cache_tokens: Some(3),
                image_units: Some(2),
                audio_units: Some(5),
                video_units: Some(1),
                service_tier: Some("priority".to_owned()),
            })
        );
        let generated_usage_shape = br#"{"response":{"output":[{"content":{"usage":{"input_tokens":999,"details":{"cost_in_usd_ticks":999}},"service_tier":"generated-secret"}}]}}"#;
        assert_eq!(extract_observed_usage(generated_usage_shape), None);
        let repeated_envelope = br#"{"response":{"response":{"service_tier":"generated","usage":{"input_tokens":999,"details":{"cost_in_usd_ticks":999}}}}}"#;
        assert_eq!(extract_observed_usage(repeated_envelope), None);

        let mut websocket_usage = None;
        merge_observed_usage(
            &mut websocket_usage,
            ObservedUsage {
                input_tokens: Some(13),
                ..ObservedUsage::default()
            },
        );
        merge_observed_usage(
            &mut websocket_usage,
            ObservedUsage {
                output_tokens: Some(9),
                ..ObservedUsage::default()
            },
        );
        assert_eq!(
            websocket_usage.as_ref().expect("merged usage").input_tokens,
            Some(13)
        );
        assert_eq!(
            websocket_usage
                .as_ref()
                .expect("merged usage")
                .output_tokens,
            Some(9)
        );
    }

    #[test]
    fn request_completion_persists_full_usage_ledger_record() {
        let store = Arc::new(pooler_store::MemoryStore::new());
        let lifecycle = RequestLifecycle::new(
            (store.clone(), PersistenceStatus::new(true)),
            "request-id",
            Arc::from("listener"),
            "route",
            7,
            Some(9),
            None,
        );
        {
            let mut state = lifecycle.state.lock().expect("lifecycle state");
            state.public_model = Some("public-model".to_owned());
            state.upstream_model = Some("upstream-model".to_owned());
            state.provider = Some("provider".to_owned());
            state.account_pseudonym = Some("account-pseudo".to_owned());
            state.ttft_ms = Some(12);
        }
        lifecycle.complete_with_usage(
            CompletionClass::Success,
            Some(200),
            Some(&ObservedUsage {
                input_tokens: Some(11),
                output_tokens: Some(7),
                reasoning_tokens: Some(3),
                cache_tokens: Some(2),
                image_units: Some(1),
                audio_units: Some(4),
                video_units: Some(1),
                service_tier: Some("priority".to_owned()),
                total_tokens: Some(18),
                cost_in_usd_ticks: Some(42),
            }),
        );
        let records = store.usage_records().expect("usage records");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.request_id, "request-id");
        assert_eq!(record.public_model.as_deref(), Some("public-model"));
        assert_eq!(record.upstream_model.as_deref(), Some("upstream-model"));
        assert_eq!(record.provider.as_deref(), Some("provider"));
        assert_eq!(record.account_pseudonym.as_deref(), Some("account-pseudo"));
        assert_eq!(record.reasoning_tokens, Some(3));
        assert_eq!(record.cache_tokens, Some(2));
        assert_eq!(record.ttft_ms, Some(12));
        assert_eq!(record.cost_in_usd_ticks, Some(42));
        assert_eq!(record.cost_provenance, CostProvenance::ProviderReported);
        assert_eq!(record.configuration_generation, 7);
        assert_eq!(record.catalog_generation, Some(9));
    }

    #[test]
    fn failed_store_writes_update_persistence_status() {
        let store: Arc<dyn Store> = Arc::new(
            pooler_store::SqliteStore::open_in_memory().expect("unencrypted SQLite store"),
        );
        let persistence = PersistenceStatus::new(true);
        let lifecycle = RequestLifecycle::new(
            (store, persistence.clone()),
            "request-id",
            Arc::from("listener"),
            "route",
            1,
            None,
            None,
        );
        lifecycle.complete_with_usage(CompletionClass::Success, Some(200), None);

        let status = persistence.json();
        assert_eq!(status["complete"], false);
        assert!(status["request_events"]["lost_writes"]
            .as_u64()
            .is_some_and(|lost| lost >= 1));
        assert_eq!(status["request_events"]["last_failure_class"], "encryption");
        assert_eq!(status["usage_records"]["lost_writes"], 1);
        assert_eq!(status["usage_records"]["last_failure_class"], "encryption");
    }

    #[test]
    fn request_completion_estimates_cost_only_from_a_versioned_operator_price_book() {
        let config = compile_yaml(
            "usage-price-book.yaml",
            r#"
version: 2
upstreams: {provider: {url: http://127.0.0.1:8319}}
usage_price_book:
  version: operator-2026-08-22
  entries:
    - provider: provider
      model: upstream-model
      input_per_million_usd_ticks: 2000000
      image_per_unit_usd_ticks: 5
"#,
        )
        .expect("compiled price book");
        let price_book = Arc::new(config.usage_price_book().expect("price book plan").clone());
        let store = Arc::new(pooler_store::MemoryStore::new());
        let lifecycle = RequestLifecycle::new(
            (store.clone(), PersistenceStatus::new(true)),
            "request-id",
            Arc::from("listener"),
            "route",
            1,
            None,
            Some(price_book),
        );
        {
            let mut state = lifecycle.state.lock().expect("lifecycle state");
            state.provider = Some("provider".to_owned());
            state.upstream_model = Some("upstream-model".to_owned());
        }
        lifecycle.complete_with_usage(
            CompletionClass::Success,
            Some(200),
            Some(&ObservedUsage {
                input_tokens: Some(3),
                image_units: Some(2),
                ..ObservedUsage::default()
            }),
        );
        let records = store.usage_records().expect("usage records");
        assert_eq!(records[0].cost_in_usd_ticks, Some(16));
        assert_eq!(
            records[0].cost_provenance,
            CostProvenance::OperatorEstimated
        );
        assert_eq!(
            records[0].price_book_version.as_deref(),
            Some("operator-2026-08-22")
        );
    }

    #[test]
    fn remaining_high_regression_provider_dispatch_parses_mixed_quota_dimensions() {
        let config = compile_yaml(
            "provider-quota-dispatch.yaml",
            r#"
version: 2
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
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:8319/base?tenant=pooler}}
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
        assert_eq!(
            uri,
            "http://127.0.0.1:8319/v1/infer?tenant=pooler&stream=true"
        );
    }

    #[test]
    fn websocket_uri_merges_base_and_downstream_queries() {
        let config = compile_yaml(
            "websocket-query.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: ws://127.0.0.1:8319/base?tenant=pooler}}
routes:
  - id: route
    listen: local
    match: {path: /request, websocket: true}
    target: {provider: local, upstream_path: /v1/socket}
    ingress: {mode: opaque}
    response: {mode: opaque}
"#,
        )
        .expect("WebSocket query config");
        let uri = websocket_uri(
            &config.upstreams()["local"],
            &config.routes()[0],
            &"/request?stream=true".parse().unwrap(),
        )
        .expect("WebSocket URI");
        assert_eq!(
            uri,
            "ws://127.0.0.1:8319/v1/socket?tenant=pooler&stream=true"
        );
    }

    #[test]
    fn codex_models_rewrite_includes_the_required_client_version() {
        let config = compile_yaml(
            "codex-models.yaml",
            r#"
version: 2
upstreams: {subscription: {known_provider: openai, native: {kind: codex}}}
"#,
        )
        .expect("Codex config");
        let upstream = &config.upstreams()["subscription"];
        let downstream: Uri = "/v1/models".parse().expect("downstream URI");
        let upstream_uri: Uri = "https://chatgpt.com/v1/models"
            .parse()
            .expect("upstream URI");
        let rewritten = rewrite_native_upstream_uri(upstream, &downstream, None, upstream_uri)
            .expect("rewritten Codex URI");
        assert_eq!(
            rewritten,
            "https://chatgpt.com/backend-api/codex/models?client_version=99.99.99"
        );
    }

    #[test]
    fn codex_responses_normalization_matches_subscription_constraints() {
        let input = Bytes::from_static(
            br#"{"model":"gpt-5.4","stream":false,"store":true,"parallel_tool_calls":false,"include":["file_search_call.results"],"max_output_tokens":4096,"temperature":0.2,"service_tier":"standard","truncation":"auto","prompt_cache_retention":"24h","user":"owner","input":[{"type":"message","role":"system","content":[{"type":"input_text","text":"hello","prompt_cache_breakpoint":{"type":"ephemeral"}}]}]}"#,
        );

        let output = normalize_codex_responses_request(&input).expect("Codex request");
        let value: serde_json::Value = serde_json::from_slice(&output).expect("normalized JSON");

        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
        assert_eq!(value["parallel_tool_calls"], true);
        assert_eq!(
            value["include"],
            serde_json::json!(["reasoning.encrypted_content"])
        );
        assert_eq!(value["input"][0]["role"], "developer");
        assert!(value["input"][0]["content"][0]
            .get("prompt_cache_breakpoint")
            .is_none());
        for field in [
            "max_output_tokens",
            "temperature",
            "service_tier",
            "truncation",
            "prompt_cache_retention",
            "safety_identifier",
            "user",
        ] {
            assert!(value.get(field).is_none(), "{field} must be removed");
        }
    }

    #[test]
    fn vertex_stream_rewrite_restores_provider_sse_query_after_query_merge() {
        let config = compile_yaml(
            "vertex-query.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  vertex:
    url: https://vertex.example/base?key=server-key
    native: {kind: vertex, project: test-project, location: us-central1}
routes:
  - id: route
    listen: local
    match: {method: POST, path: /v1beta/models/gemini-2.5-pro:streamGenerateContent}
    target: vertex
"#,
        )
        .expect("Vertex query config");
        let route = &config.routes()[0];
        let upstream = &config.upstreams()["vertex"];
        let downstream: Uri =
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=json&trace=alias"
                .parse()
                .expect("downstream URI");
        let uri = upstream_uri(upstream, route, &downstream).expect("upstream URI");
        let rewritten =
            rewrite_native_upstream_uri(upstream, &downstream, Some("gemini-2.5-pro"), uri)
                .expect("rewritten Vertex URI");
        assert_eq!(
            rewritten,
            "https://vertex.example/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:streamGenerateContent?key=server-key&trace=alias&alt=sse"
        );
    }

    #[test]
    fn opaque_tunnels_preserve_caller_authorization_without_pooler_credentials() {
        let config = compile_yaml(
            "opaque-auth.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  tunnel: {url: http://127.0.0.1:8319}
  authenticated:
    url: http://127.0.0.1:8320
    auth: {kind: bearer_secret, secret: env:POOLER_TEST_KEY}
routes:
  - id: tunnel
    listen: local
    match: {path: /tunnel}
    target: tunnel
    ingress: {mode: opaque}
    response: {mode: opaque}
  - id: authenticated
    listen: local
    match: {path: /authenticated}
    target: authenticated
    ingress: {mode: opaque}
    response: {mode: opaque}
  - id: downstream-authenticated
    listen: local
    match: {path: /downstream-authenticated}
    downstream_auth: {secret: env:POOLER_DOWNSTREAM_KEY}
    target: tunnel
    ingress: {mode: opaque}
    response: {mode: opaque}
"#,
        )
        .expect("opaque auth config");
        let coordinator = PoolingCoordinator::new(&config).expect("pooling coordinator");
        let tunnel = config.route("tunnel").expect("tunnel route");
        let authenticated = config.route("authenticated").expect("authenticated route");
        let downstream_authenticated = config
            .route("downstream-authenticated")
            .expect("downstream-authenticated route");
        let tunnel_selection = coordinator
            .select(
                &config,
                tunnel,
                None,
                &HeaderMap::new(),
                1,
                StdInstant::now(),
            )
            .expect("tunnel selection");
        let authenticated_selection = coordinator
            .select(
                &config,
                authenticated,
                None,
                &HeaderMap::new(),
                1,
                StdInstant::now(),
            )
            .expect("authenticated selection");
        let mut caller_headers = HeaderMap::new();
        caller_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-token"),
        );
        caller_headers.insert("x-api-key", HeaderValue::from_static("caller-api-key"));
        caller_headers.insert(
            "x-goog-api-key",
            HeaderValue::from_static("caller-google-key"),
        );
        strip_caller_credentials_when_authenticating(
            &mut caller_headers,
            false,
            &tunnel_selection,
            &config.upstreams()[tunnel.target().upstream()],
        );
        assert_eq!(
            caller_headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer caller-token"))
        );
        assert_eq!(
            caller_headers.get("x-api-key"),
            Some(&HeaderValue::from_static("caller-api-key"))
        );
        assert_eq!(
            caller_headers.get("x-goog-api-key"),
            Some(&HeaderValue::from_static("caller-google-key"))
        );

        strip_caller_credentials_when_authenticating(
            &mut caller_headers,
            false,
            &authenticated_selection,
            &config.upstreams()[authenticated.target().upstream()],
        );
        assert!(!caller_headers.contains_key(header::AUTHORIZATION));
        assert!(!caller_headers.contains_key("x-api-key"));
        assert!(!caller_headers.contains_key("x-goog-api-key"));

        let mut downstream_headers = HeaderMap::new();
        downstream_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer pooler-downstream-token"),
        );
        strip_downstream_authorization(downstream_authenticated, &mut downstream_headers);
        assert!(!downstream_headers.contains_key(header::AUTHORIZATION));
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

        let mut usage_state = WebSocketMessageState::default();
        let usage_start = RawWebSocketFrame {
            bytes: Vec::new(),
            payload: br#"{"usage":{"input_tokens":"#.to_vec(),
            fin: false,
            opcode: 1,
            payload_len: 25,
        };
        assert_eq!(
            validate_websocket_message(&usage_start, &mut usage_state, 128)
                .expect("usage fragment"),
            None
        );
        let usage_end = RawWebSocketFrame {
            bytes: Vec::new(),
            payload: b"13}}".to_vec(),
            fin: true,
            opcode: 0,
            payload_len: 4,
        };
        let complete = validate_websocket_message(&usage_end, &mut usage_state, 128)
            .expect("complete usage fragment")
            .expect("complete text");
        assert_eq!(
            extract_observed_usage(&complete)
                .expect("fragmented usage")
                .input_tokens,
            Some(13)
        );

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
        let resources = RuntimeResources::new();
        let cleanup = ResponseDeadline::new();
        let mut body = DeadlineBody::new(
            body,
            Instant::now() + Duration::from_millis(1),
            cleanup.clone(),
            resources.clone(),
        );
        let frame = body.frame().await.expect("timeout frame");
        assert_eq!(
            frame.expect_err("deadline should fail").to_string(),
            "upstream response exceeded its request timeout"
        );
        assert!(cleanup.is_elapsed());
        drop(body);
        tokio::time::timeout(Duration::from_secs(1), async {
            while resources.snapshot().tasks != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deadline timer task exits");
    }

    #[tokio::test]
    async fn response_deadline_releases_unpolled_body_and_attached_guard_once() {
        let body_drops = Arc::new(AtomicUsize::new(0));
        let guard_drops = Arc::new(AtomicUsize::new(0));
        let resources = RuntimeResources::new();
        let cleanup = ResponseDeadline::new();
        let _attached = cleanup.attach_cleanup({
            let guard_drops = Arc::clone(&guard_drops);
            move || drop(DropCounter(guard_drops))
        });
        let body = DeadlineBody::new(
            DropTrackedPendingBody(Arc::clone(&body_drops)),
            Instant::now() + Duration::from_millis(10),
            cleanup.clone(),
            resources.clone(),
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if body_drops.load(Ordering::Acquire) == 1
                    && guard_drops.load(Ordering::Acquire) == 1
                    && resources.snapshot().tasks == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned deadline releases without a downstream body poll");
        assert!(cleanup.is_elapsed());

        drop(body);
        assert_eq!(body_drops.load(Ordering::Acquire), 1);
        assert_eq!(guard_drops.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn response_deadline_preserves_frames_before_completion() {
        let resources = RuntimeResources::new();
        let cleanup = ResponseDeadline::new();
        let body = Full::new(Bytes::from_static(b"unchanged"))
            .map_err(|never: Infallible| match never {})
            .boxed();
        let body = DeadlineBody::new(
            body,
            Instant::now() + Duration::from_secs(1),
            cleanup.clone(),
            resources.clone(),
        );
        let bytes = body.collect().await.expect("body completes").to_bytes();
        assert_eq!(bytes, Bytes::from_static(b"unchanged"));
        assert!(!cleanup.is_elapsed());
        tokio::time::timeout(Duration::from_secs(1), async {
            while resources.snapshot().tasks != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed body aborts its deadline timer");
    }

    #[test]
    fn connect_and_request_timeouts_are_independent() {
        let config = compile_yaml(
            "timeout.yaml",
            r#"
version: 2
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
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn explicitly_managed_websocket_null_timeout_has_no_hidden_hard_deadline() {
        let config = compile_yaml(
            "managed-websocket-timeout.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: ws://127.0.0.1:8319}}
routes:
  - id: route
    listen: local
    match: {path: /socket, websocket: true}
    limits: {request_timeout: null, connect_timeout: null}
    target: local
    ingress: {mode: opaque}
    response: {mode: opaque}
"#,
        )
        .expect("managed WebSocket timeout config");
        let route = &config.routes()[0];
        let upstream = &config.upstreams()["local"];
        assert_eq!(request_timeout(route.limits(), upstream), None);
        assert_eq!(
            websocket_hard_deadline(StdInstant::now(), route.limits(), upstream),
            None
        );
        assert_eq!(
            connect_timeout(route.limits(), upstream),
            DEFAULT_CONNECT_TIMEOUT
        );
        assert_eq!(
            effective_request_timeout(route.limits(), upstream),
            DEFAULT_REQUEST_TIMEOUT,
        );
    }

    #[test]
    fn patch_buffer_uses_shortest_selectable_provider_timeout() {
        let config = compile_yaml(
            "selection-timeout.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  fallback:
    transport: {kind: http, base_url: http://127.0.0.1:8319, request_timeout: 10s}
  selected:
    transport: {kind: http, base_url: http://127.0.0.1:8320, request_timeout: 1s}
models:
  - id: public
    targets: [{id: public-selected-target, provider: selected, account: selected-account, priority: 1, upstream_model: private, capabilities: [text], codecs: [], wire_family: openai}]
accounts:
  selected-account: {provider: selected, secret: env:POOLER_SELECTED}
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

    #[tokio::test]
    async fn local_errors_use_the_openai_json_contract() {
        let response = error_response(ProxyError::RequestBodyTooLarge);
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("bounded error body")
            .to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).expect("OpenAI error JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "error": {
                    "message": "request too large",
                    "type": "invalid_request_error",
                    "param": null,
                    "code": "request_too_large",
                }
            })
        );

        let response = unauthorized_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer"))
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("bounded authentication body")
            .to_bytes();
        let value: serde_json::Value =
            serde_json::from_slice(&body).expect("OpenAI authentication error JSON");
        assert_eq!(value["error"]["type"], "authentication_error");
        assert_eq!(value["error"]["code"], "invalid_api_key");

        let response = error_response(ProxyError::Timeout);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("bounded upstream error body")
            .to_bytes();
        let value: serde_json::Value =
            serde_json::from_slice(&body).expect("OpenAI upstream error JSON");
        assert_eq!(value["error"]["type"], "server_error");
        assert_eq!(value["error"]["code"], "upstream_timeout");
    }
}
