use std::sync::Arc;

use http::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_TYPE, HOST, UPGRADE};
use http::{uri::Authority, Method, Request};
use thiserror::Error;

use crate::{CompiledConfig, PathPattern, RoutePlan};

/// Request metadata used for deterministic route selection.
///
/// The body is intentionally not part of this value.  Route selection only
/// needs transport metadata, and keeping it separate lets callers match before
/// they start buffering or decoding a body.
#[derive(Clone, Debug)]
pub struct RouteRequest {
    listener: Arc<str>,
    method: Method,
    path: Arc<str>,
    host: Option<Arc<str>>,
    headers: HeaderMap,
    content_type: Option<Arc<str>>,
    websocket: Option<bool>,
}

impl RouteRequest {
    /// Create a request with the listener, method, and URI path.
    #[must_use]
    pub fn new(listener: impl Into<Arc<str>>, method: Method, path: impl Into<Arc<str>>) -> Self {
        Self {
            listener: listener.into(),
            method,
            path: path.into(),
            host: None,
            headers: HeaderMap::new(),
            content_type: None,
            websocket: None,
        }
    }

    /// Create a request from an HTTP request's route-relevant metadata.
    #[must_use]
    pub fn from_http<B>(listener: impl Into<Arc<str>>, request: &Request<B>) -> Self {
        Self {
            listener: listener.into(),
            method: request.method().clone(),
            path: Arc::from(request.uri().path()),
            host: request
                .uri()
                .authority()
                .map(|authority| Arc::from(authority.as_str())),
            headers: request.headers().clone(),
            content_type: None,
            websocket: None,
        }
    }

    /// Set an explicit host value.  Without this value, the `Host` header is
    /// used when present.
    #[must_use]
    pub fn with_host(mut self, host: impl Into<Arc<str>>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Replace the request headers used by route matching.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Add one request header using its validated HTTP representation.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Set an explicit content type.  Without this value, the `Content-Type`
    /// header is used when present.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<Arc<str>>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set whether the request is a WebSocket upgrade.
    #[must_use]
    pub fn with_websocket(mut self, websocket: bool) -> Self {
        self.websocket = Some(websocket);
        self
    }

    /// Listener ID supplied by the accepting listener.
    #[must_use]
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// HTTP method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Request path.  Query text, when supplied by a caller, is ignored by
    /// route matching.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Explicit host, if one was supplied.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Request headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Explicit content type, if one was supplied.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Explicit WebSocket state, if one was supplied.
    #[must_use]
    pub const fn websocket(&self) -> Option<bool> {
        self.websocket
    }
}

/// Failure returned when no compiled route can accept a request.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RouteMatchError {
    /// No route matched the listener and non-method request dimensions.
    #[error("no route matches listener `{listener}` and path `{path}`")]
    NoMatch { listener: String, path: String },
    /// At least one route matched the listener and request dimensions but not
    /// the HTTP method.
    #[error("method `{method}` is not allowed for listener `{listener}` and path `{path}`")]
    MethodNotAllowed {
        listener: String,
        method: String,
        path: String,
    },
    /// At least one route matched the listener, path, and method but not the
    /// request content type.
    #[error(
        "content type `{content_type}` is not allowed for listener `{listener}` and path `{path}`"
    )]
    ContentTypeNotAllowed {
        listener: String,
        content_type: String,
        path: String,
    },
}

impl CompiledConfig {
    /// Select the first route matching a request's listener, method, host,
    /// path, headers, content type, and WebSocket state.
    ///
    /// Routes are already sorted by their compiled precedence, so evaluating
    /// them in order makes the result deterministic without another route
    /// table or a second precedence implementation.
    pub fn match_route_request<'a>(
        &'a self,
        request: &RouteRequest,
    ) -> Result<&'a RoutePlan, RouteMatchError> {
        let path = route_path(request.path());
        let method = request.method().as_str().to_ascii_uppercase();
        let content_type = request_content_type(request);
        let websocket = request_websocket(request);
        let mut structural_match = false;
        let mut method_match = false;
        for route in self.routes() {
            if route.listener() != request.listener()
                || !path_matches(route.matcher().path(), path)
                || !host_matches(route.matcher().host(), request.host(), request.headers())
                || !headers_match(route.matcher().headers(), request.headers())
                || !websocket_matches(route.matcher().websocket(), websocket)
            {
                continue;
            }
            structural_match = true;
            if !method_matches_route(route, &method) {
                continue;
            }
            method_match = true;
            if content_type_matches(route.matcher().content_types(), content_type.as_deref()) {
                return Ok(route);
            }
        }

        if !structural_match {
            return Err(RouteMatchError::NoMatch {
                listener: request.listener().to_owned(),
                path: path.to_owned(),
            });
        }
        if !method_match {
            return Err(RouteMatchError::MethodNotAllowed {
                listener: request.listener().to_owned(),
                method,
                path: path.to_owned(),
            });
        }

        Err(RouteMatchError::ContentTypeNotAllowed {
            listener: request.listener().to_owned(),
            content_type: content_type.unwrap_or_default(),
            path: path.to_owned(),
        })
    }
}

fn route_path(path: &str) -> &str {
    path.split_once('?').map_or(path, |(path, _)| path)
}

fn path_matches(pattern: &PathPattern, path: &str) -> bool {
    match pattern {
        PathPattern::Exact(expected) => expected.as_ref() == path,
        PathPattern::Template(template) => template_matches(template, path),
        PathPattern::Prefix(prefix) => prefix_matches(prefix, path),
        PathPattern::Any => true,
    }
}

pub(crate) fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" || path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path.strip_prefix(prefix)
        .is_some_and(|remaining| remaining.starts_with('/'))
}

pub(crate) fn template_matches(template: &str, path: &str) -> bool {
    template.split('/').count() == path.split('/').count()
        && template
            .split('/')
            .zip(path.split('/'))
            .all(
                |(template_segment, path_segment)| match is_template_segment(template_segment) {
                    true => !path_segment.is_empty(),
                    false => template_segment == path_segment,
                },
            )
}

fn is_template_segment(segment: &str) -> bool {
    segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2
}

fn host_matches(expected: Option<&str>, explicit: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let actual = explicit.or_else(|| header_text(headers, HOST));
    let Some((expected_host, expected_port)) = normalize_authority(expected) else {
        return false;
    };
    actual
        .and_then(normalize_authority)
        .is_some_and(|(actual_host, actual_port)| {
            actual_host == expected_host
                && expected_port.is_none_or(|port| actual_port == Some(port))
        })
}

fn headers_match(
    expected_headers: &std::collections::BTreeMap<Arc<str>, Arc<str>>,
    headers: &HeaderMap,
) -> bool {
    expected_headers.iter().all(|(name, expected)| {
        headers.get_all(name.as_ref()).iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.trim() == expected.as_ref())
        })
    })
}

fn method_matches_route(route: &RoutePlan, method: &str) -> bool {
    route.matcher().methods().is_empty()
        || route
            .matcher()
            .methods()
            .iter()
            .any(|expected| expected.as_ref() == method)
}

fn content_type_matches(expected: &[Arc<str>], actual: Option<&str>) -> bool {
    if expected.is_empty() {
        return true;
    }
    let Some(actual) = actual.map(normalize_content_type) else {
        return false;
    };
    expected
        .iter()
        .map(|value| normalize_content_type(value))
        .any(|value| value == actual || media_type_wildcard_matches(&value, &actual))
}

fn request_content_type(request: &RouteRequest) -> Option<String> {
    request
        .content_type()
        .or_else(|| header_text(request.headers(), CONTENT_TYPE))
        .map(normalize_content_type)
}

fn normalize_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn media_type_wildcard_matches(expected: &str, actual: &str) -> bool {
    expected == "*/*"
        || expected.strip_suffix("/*").is_some_and(|prefix| {
            actual.starts_with(prefix) && actual.as_bytes().get(prefix.len()) == Some(&b'/')
        })
}

fn websocket_matches(expected: Option<bool>, actual: bool) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

fn request_websocket(request: &RouteRequest) -> bool {
    request
        .websocket()
        .unwrap_or_else(|| request_websocket_headers(request.headers()))
}

fn request_websocket_headers(headers: &HeaderMap) -> bool {
    let upgrade =
        header_text(headers, UPGRADE).is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = header_text(headers, CONNECTION).map(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
    });
    upgrade && connection.unwrap_or(true)
}

fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

pub(crate) fn normalize_authority(value: &str) -> Option<(String, Option<u16>)> {
    let authority = value.trim().parse::<Authority>().ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    Some((host, authority.port_u16()))
}

pub(crate) fn canonical_authority(value: &str) -> Option<String> {
    let (host, port) = normalize_authority(value)?;
    Some(port.map_or(host.clone(), |port| format!("{host}:{port}")))
}

#[cfg(test)]
mod tests {
    use http::header::{HeaderName, HeaderValue};

    use super::*;
    use crate::compile_yaml;

    fn config() -> CompiledConfig {
        compile_yaml(
            "routes.yaml",
            r#"
version: 2
listeners:
  shared: {bind: 127.0.0.1:8400}
  other: {bind: 127.0.0.1:8401}
upstreams:
  local: {url: http://127.0.0.1:8319}
  websocket: {url: ws://127.0.0.1:8320}
routes:
  - id: prefix
    listen: shared
    match: {methods: [POST], path_prefix: /v1}
    target: local
  - id: template
    listen: shared
    match: {methods: [POST], path_template: '/v1/{model}'}
    target: local
  - id: exact
    listen: shared
    match: {methods: [POST], path: /v1/fixed}
    target: local
  - id: exact-header
    listen: shared
    match: {methods: [POST], path: /v1/fixed, headers: {x-tenant: acme}}
    target: local
  - id: other-listener
    listen: other
    match: {methods: [POST], path: /v1/fixed}
    target: local
  - id: content
    listen: shared
    match: {methods: [POST], path: /content, content_types: [application/json]}
    target: local
  - id: gated
    listen: shared
    match:
      methods: [POST]
      path: /gated
      host: api.example.test
      headers: {x-tenant: acme}
      content_types: [application/json]
      websocket: true
    target: websocket
  - id: method
    listen: shared
    match: {methods: [POST], path: /method}
    target: local
"#,
        )
        .expect("route config")
    }

    #[test]
    fn matches_shared_listener_layouts_by_path_precedence() {
        let compiled = config();
        let with_tenant = RouteRequest::new("shared", Method::POST, "/v1/fixed").with_header(
            HeaderName::from_static("x-tenant"),
            HeaderValue::from_static("acme"),
        );
        assert_eq!(
            compiled
                .match_route_request(&with_tenant)
                .expect("route")
                .id(),
            "exact-header"
        );

        let exact = RouteRequest::new("shared", Method::POST, "/v1/fixed");
        assert_eq!(
            compiled.match_route_request(&exact).expect("route").id(),
            "exact"
        );

        let template = RouteRequest::new("shared", Method::POST, "/v1/other");
        assert_eq!(
            compiled.match_route_request(&template).expect("route").id(),
            "template"
        );

        let prefix = RouteRequest::new("shared", Method::POST, "/v1/other/more");
        assert_eq!(
            compiled.match_route_request(&prefix).expect("route").id(),
            "prefix"
        );

        let other_listener = RouteRequest::new("other", Method::POST, "/v1/fixed");
        assert_eq!(
            compiled
                .match_route_request(&other_listener)
                .expect("route")
                .id(),
            "other-listener"
        );
    }

    #[test]
    fn returns_typed_method_content_and_no_match_errors() {
        let compiled = config();
        let method = compiled
            .match_route_request(&RouteRequest::new("shared", Method::GET, "/method"))
            .expect_err("method mismatch");
        assert!(matches!(method, RouteMatchError::MethodNotAllowed { .. }));

        let content = compiled
            .match_route_request(
                &RouteRequest::new("shared", Method::POST, "/content")
                    .with_content_type("text/plain"),
            )
            .expect_err("content mismatch");
        assert!(matches!(
            content,
            RouteMatchError::ContentTypeNotAllowed { .. }
        ));

        let no_match = compiled
            .match_route_request(&RouteRequest::new("shared", Method::POST, "/missing"))
            .expect_err("missing route");
        assert!(matches!(no_match, RouteMatchError::NoMatch { .. }));
    }

    #[test]
    fn matches_host_headers_content_type_and_websocket_from_http_headers() {
        let mut request = RouteRequest::new("shared", Method::POST, "/gated")
            .with_header(HOST, HeaderValue::from_static("API.EXAMPLE.TEST.:8400"))
            .with_header(
                HeaderName::from_static("x-tenant"),
                HeaderValue::from_static("acme"),
            )
            .with_header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            )
            .with_header(UPGRADE, HeaderValue::from_static("websocket"))
            .with_header(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        assert_eq!(
            config().match_route_request(&request).expect("route").id(),
            "gated"
        );

        request = request.with_websocket(false);
        let error = config()
            .match_route_request(&request)
            .expect_err("not websocket");
        assert!(matches!(error, RouteMatchError::NoMatch { .. }));
    }

    #[test]
    fn prefix_and_template_match_path_segments_without_query_text() {
        let compiled = config();
        let query = RouteRequest::new("shared", Method::POST, "/v1/other?debug=true");
        assert_eq!(
            compiled.match_route_request(&query).expect("route").id(),
            "template"
        );

        let near_prefix = RouteRequest::new("shared", Method::POST, "/v10/other");
        assert!(matches!(
            compiled.match_route_request(&near_prefix),
            Err(RouteMatchError::NoMatch { .. })
        ));
    }

    #[test]
    fn matches_media_type_wildcards() {
        let compiled = compile_yaml(
            "wildcard.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:8400}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: wildcard
    listen: local
    match: {method: POST, path: /content, content_types: ['application/*']}
    target: local
  - id: any
    listen: local
    match: {method: POST, path: /any, content_types: ['*/*']}
    target: local
"#,
        )
        .expect("wildcard config");
        assert_eq!(
            compiled
                .match_route_request(
                    &RouteRequest::new("local", Method::POST, "/content")
                        .with_content_type("application/json; charset=utf-8"),
                )
                .expect("application wildcard")
                .id(),
            "wildcard"
        );
        assert_eq!(
            compiled
                .match_route_request(
                    &RouteRequest::new("local", Method::POST, "/any")
                        .with_content_type("text/plain"),
                )
                .expect("global wildcard")
                .id(),
            "any"
        );
    }

    #[test]
    fn matcher_does_not_treat_subtype_specific_wildcards_as_matches() {
        assert!(!media_type_wildcard_matches("*/json", "application/json"));
        assert!(!media_type_wildcard_matches("*/json", "text/json"));
        assert!(media_type_wildcard_matches(
            "application/*",
            "application/json"
        ));
        assert!(media_type_wildcard_matches("*/*", "text/plain"));
    }
}
