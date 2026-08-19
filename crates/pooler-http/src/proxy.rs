//! Opaque HTTP forwarding for compiled custom routes.
//!
//! The proxy deliberately keeps the request and response bodies as Hyper
//! streams.  It only inspects the dimensions required to select a route and
//! never parses or rewrites an opaque payload.

use std::{
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
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
    CompiledConfig, RouteMatchError, RoutePlan, RouteRequest, SecretRef, UpstreamPlan,
};
use pooler_core::{BodyMode, RouteLimits};
use thiserror::Error;
use tokio::time::{self, Instant, Sleep};
use zeroize::Zeroizing;

use crate::{
    extract_bearer_token, strip_hop_by_hop_headers, DrainController, DrainGuard, DrainedBody,
    LimitedBody,
};

/// The erased body type used by responses returned from [`HttpProxy`].
pub type ProxyBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// A boxed body error. Hyper and body-limit errors are both preserved as the
/// source error behind this boundary.
pub type BoxError = Box<dyn Error + Send + Sync>;

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
    /// The upstream request failed before a response was received.
    #[error("upstream request failed: {0}")]
    Upstream(#[source] BoxError),
    /// The upstream did not produce response headers before the deadline.
    #[error("upstream request timed out")]
    Timeout,
}

/// A compiled route table and shared Hyper client for one listener.
#[derive(Clone)]
pub struct HttpProxy {
    config: Arc<CompiledConfig>,
    listener: Arc<str>,
    client: UpstreamClient,
    drain: DrainController,
}

impl std::fmt::Debug for HttpProxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("listener", &self.listener)
            .field("draining", &self.drain.is_draining())
            .field("active", &self.drain.active())
            .finish_non_exhaustive()
    }
}

impl HttpProxy {
    /// Construct a proxy for one compiled listener.
    pub fn new(
        config: Arc<CompiledConfig>,
        listener: impl Into<Arc<str>>,
    ) -> Result<Self, ProxyError> {
        let listener = listener.into();
        if let Some(route) = config.routes().iter().find(|route| {
            route.listener() == listener.as_ref()
                && (route.ingress().mode() != BodyMode::Opaque
                    || route.response().mode() != BodyMode::Opaque)
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
        })
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

        if let Err(status) = self.validate_request(route, &request) {
            drop(guard);
            return status;
        }

        if let Err(error) = verify_downstream_auth(route, request.headers()) {
            drop(guard);
            return match error {
                DownstreamAuthError::MissingOrInvalid => unauthorized_response(),
                DownstreamAuthError::SecretUnavailable => plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "authentication unavailable",
                ),
            };
        }
        let result = self.forward(route, request, guard).await;
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
                    "upstream request failed"
                );
                error_response(error)
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
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let upstream = self
            .config
            .upstreams()
            .get(route.target().upstream())
            .ok_or_else(|| ProxyError::MissingUpstream {
                route: route.id().to_owned(),
                upstream: route.target().upstream().to_owned(),
            })?;
        let uri = upstream_uri(upstream, route, request.uri())?;
        let method = request.method().clone();
        let version = request.version();
        let limits = route.limits();
        let mut headers = request.headers().clone();
        strip_hop_by_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::AUTHORIZATION);
        apply_upstream_auth(&mut headers, upstream)?;
        let header_count = u32::try_from(headers.len()).unwrap_or(u32::MAX);
        limits
            .check_headers(header_count, header_bytes(&headers))
            .map_err(|_| ProxyError::InvalidLimits("upstream headers exceed limits".to_owned()))?;

        let body = LimitedBody::new(
            request.into_body(),
            bounded_usize(limits.max_request_body_bytes),
        )
        .map_err(box_error)
        .boxed();
        let mut builder = Request::builder().method(method).uri(uri).version(version);
        *builder.headers_mut().expect("request builder headers") = headers;
        let upstream_request = builder.body(body)?;

        let started = Instant::now();
        let request_deadline = started + request_timeout(limits, upstream);
        let header_deadline = (started + connect_timeout(limits, upstream)).min(request_deadline);
        let cancellation = guard.cancellation_token();
        let response = tokio::select! {
            result = time::timeout_at(header_deadline, self.client.request(upstream_request)) => {
                result.map_err(|_| ProxyError::Timeout)?.map_err(|error| ProxyError::Upstream(Box::new(error)))?
            }
            () = cancellation.cancelled() => {
                return Err(ProxyError::Timeout);
            }
        };

        limits
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
            .is_some_and(|length| limits.check_response_body(length).is_err())
        {
            return Err(ProxyError::InvalidLimits(
                "upstream response body exceeds limits".to_owned(),
            ));
        }

        let (parts, body) = response.into_parts();
        let mut response_headers = parts.headers;
        strip_hop_by_hop_headers(&mut response_headers);
        let body = LimitedBody::new(body, bounded_usize(limits.max_response_body_bytes))
            .map_err(box_error)
            .boxed();
        let body = DeadlineBody::new(body, request_deadline).boxed();
        let body = DrainedBody::new(body, guard).boxed();
        let mut response = Response::new(body);
        *response.status_mut() = parts.status;
        *response.version_mut() = parts.version;
        *response.headers_mut() = response_headers;
        Ok(response)
    }
}

fn upstream_uri(
    upstream: &UpstreamPlan,
    route: &RoutePlan,
    downstream: &Uri,
) -> Result<Uri, ProxyError> {
    let mut url = upstream.url().clone();
    let path = route.target().path().unwrap_or_else(|| downstream.path());
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
        SecretRef::Keyring { .. } | SecretRef::External(_) => {
            return Err(ProxyError::SecretUnavailable)
        }
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
    let status = match error {
        ProxyError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        ProxyError::UnsupportedAuth | ProxyError::SecretUnavailable => StatusCode::BAD_GATEWAY,
        ProxyError::MissingUpstream { .. }
        | ProxyError::InvalidUri
        | ProxyError::InvalidLimits(_)
        | ProxyError::RequestBuild(_)
        | ProxyError::Upstream(_)
        | ProxyError::UnsupportedBodyMode { .. } => StatusCode::BAD_GATEWAY,
        ProxyError::TlsClient(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    plain_response(status, "upstream request failed")
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
}
