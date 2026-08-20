//! HTTP runtime seam for same-wire Gemini GenerateContent routes.

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{uri::PathAndQuery, HeaderMap, HeaderValue, Uri};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use pooler_config::RoutePlan;
use pooler_http::{
    BoxError, ProxyBody, SelectionContext, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody, SemanticResponseHint, SemanticResponseMode, SseEncoder, SseEvent,
    SseLimits, SseParser,
};
use pooler_protocol::{LossPolicy, StreamEvent};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    parse_gemini_path, GeminiEventDecoder, GeminiEventEncoder, GeminiGenerateContentCodec,
    GeminiMethod, GEMINI_JSON_CONTENT_TYPE, GEMINI_SSE_QUERY,
};

/// Semantic decoder for a Gemini GenerateContent request body.
pub const GEMINI_REQUEST_DECODER: &str = "decode.gemini.generate_content";
/// Semantic decoder for Gemini GenerateContent response objects or chunks.
pub const GEMINI_RESPONSE_DECODER: &str = "decode.gemini.generate_content.response";
/// Semantic encoder for Gemini GenerateContent response objects or chunks.
pub const GEMINI_RESPONSE_ENCODER: &str = "encode.gemini.generate_content.response";

/// Same-wire Gemini REST semantic adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeminiSemanticAdapter;

impl SemanticAdapter for GeminiSemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        route_accepts_only_post(route)
            && route.ingress().mode() == pooler_core::BodyMode::Semantic
            && route.ingress().decoder() == Some(GEMINI_REQUEST_DECODER)
            && route.response().mode() == pooler_core::BodyMode::Semantic
            && route.response().decoder() == Some(GEMINI_RESPONSE_DECODER)
            && route.response().encoder() == Some(GEMINI_RESPONSE_ENCODER)
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        let path = route_path(route)?;
        encode_request_for_path(route, path, body)
    }

    fn encode_request_with_uri(
        &self,
        route: &RoutePlan,
        uri: &Uri,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        let path = request_path(uri)?;
        encode_request_for_path(route, path, body)
    }

    fn selection_context_with_uri(
        &self,
        route: &RoutePlan,
        uri: &Uri,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        let path = request_path(uri)?;
        selection_context_for_path(route, path, body)
    }

    fn model_in_request_body(&self, _route: &RoutePlan) -> bool {
        false
    }

    fn rewrite_upstream_uri(
        &self,
        _route: &RoutePlan,
        downstream_uri: &Uri,
        upstream_model: Option<&str>,
        upstream_uri: Uri,
    ) -> Result<Uri, BoxError> {
        rewrite_gemini_uri(downstream_uri, upstream_model, upstream_uri)
            .map_err(|error| Box::new(error) as BoxError)
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        let path = route_path(route)?;
        selection_context_for_path(route, path, body)
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let method = route_method(route)
            .ok_or_else(|| Box::new(GeminiRuntimeError::UnsupportedRoute) as BoxError)?;
        decode_response_for_method(route, body, method, cancellation)
    }

    fn decode_response_with_hint(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let method = match hint.mode {
            SemanticResponseMode::Json => GeminiMethod::GenerateContent,
            SemanticResponseMode::ServerSentEvents => GeminiMethod::StreamGenerateContent,
            SemanticResponseMode::AdapterDefault => route_method(route)
                .ok_or_else(|| Box::new(GeminiRuntimeError::UnsupportedRoute) as BoxError)?,
        };
        decode_response_for_method(route, body, method, cancellation)
    }
}

fn encode_request_for_path(
    route: &RoutePlan,
    path: crate::GeminiPath<'_>,
    body: &[u8],
) -> Result<SemanticRequestBody, BoxError> {
    let decoded = GeminiGenerateContentCodec::decode_request_with_report(body, path.model)
        .map_err(|error| Box::new(error) as BoxError)?;
    decoded
        .report
        .validate(route.loss_policy())
        .map_err(|error| Box::new(error) as BoxError)?;
    let encoded = GeminiGenerateContentCodec::encode_request(&decoded.request, route.loss_policy())
        .map_err(|error| Box::new(error) as BoxError)?;
    if encoded.model != path.model {
        return Err(Box::new(GeminiRuntimeError::ModelChanged));
    }
    Ok(SemanticRequestBody {
        body: encoded.body,
        content_type: HeaderValue::from_static(GEMINI_JSON_CONTENT_TYPE),
        response_hint: SemanticResponseHint {
            mode: match path.method {
                GeminiMethod::GenerateContent => SemanticResponseMode::Json,
                GeminiMethod::StreamGenerateContent => SemanticResponseMode::ServerSentEvents,
            },
            requested_model: Some(path.model.to_owned()),
        },
    })
}

fn selection_context_for_path(
    route: &RoutePlan,
    path: crate::GeminiPath<'_>,
    body: &[u8],
) -> Result<SelectionContext, BoxError> {
    let decoded = GeminiGenerateContentCodec::decode_request_with_report(body, path.model)
        .map_err(|error| Box::new(error) as BoxError)?;
    decoded
        .report
        .validate(route.loss_policy())
        .map_err(|error| Box::new(error) as BoxError)?;
    let mut context = SelectionContext::from_semantic_request(&decoded.request);
    if path.method.is_streaming() {
        context.require(pooler_core::Capability::Streaming);
    }
    context.with_codec(GEMINI_REQUEST_DECODER);
    Ok(context)
}

fn decode_response_for_method(
    route: &RoutePlan,
    body: ProxyBody,
    method: GeminiMethod,
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    let limits = SseLimits::new(
        usize_limit(route.limits().max_frame_bytes),
        usize_limit(route.limits().max_event_bytes),
    );
    let stream = GeminiResponseBody::new(
        body,
        method,
        route.loss_policy(),
        limits,
        usize_limit(route.limits().max_response_body_bytes),
        usize_limit(u64::from(route.limits().max_queue_items)),
        usize_limit(route.limits().max_queue_bytes),
        cancellation,
    );
    Ok(SemanticResponseBody {
        body: stream.boxed(),
        content_type: match method {
            GeminiMethod::GenerateContent => HeaderValue::from_static(GEMINI_JSON_CONTENT_TYPE),
            GeminiMethod::StreamGenerateContent => HeaderValue::from_static("text/event-stream"),
        },
    })
}

fn route_method(route: &RoutePlan) -> Option<GeminiMethod> {
    if !route_accepts_only_post(route) {
        return None;
    }
    parse_gemini_path(route.matcher().path().value()).map(|path| path.method)
}

fn route_accepts_only_post(route: &RoutePlan) -> bool {
    route.matcher().methods().len() == 1 && route.matcher().methods()[0].as_ref() == "POST"
}

fn route_path(route: &RoutePlan) -> Result<crate::GeminiPath<'_>, BoxError> {
    checked_gemini_path(route.matcher().path().value())
        .ok_or_else(|| Box::new(GeminiRuntimeError::UnsupportedRoute) as BoxError)
}

fn request_path(uri: &Uri) -> Result<crate::GeminiPath<'_>, BoxError> {
    checked_gemini_path(uri.path())
        .ok_or_else(|| Box::new(GeminiRuntimeError::UnsupportedRoute) as BoxError)
}

fn checked_gemini_path(path: &str) -> Option<crate::GeminiPath<'_>> {
    if !path.starts_with("/v1/models/") && !path.starts_with("/v1beta/models/") {
        return None;
    }
    parse_gemini_path(path)
}

fn rewrite_gemini_uri(
    downstream_uri: &Uri,
    upstream_model: Option<&str>,
    upstream_uri: Uri,
) -> Result<Uri, GeminiRuntimeError> {
    let path =
        checked_gemini_path(downstream_uri.path()).ok_or(GeminiRuntimeError::UnsupportedRoute)?;
    let model = upstream_model.unwrap_or(path.model);
    if !valid_model_segment(model) {
        return Err(GeminiRuntimeError::InvalidModel);
    }
    let prefix = if downstream_uri.path().starts_with("/v1beta/models/") {
        "/v1beta/models/"
    } else {
        "/v1/models/"
    };
    let action = match path.method {
        GeminiMethod::GenerateContent => crate::GENERATE_CONTENT_ACTION,
        GeminiMethod::StreamGenerateContent => crate::STREAM_GENERATE_CONTENT_ACTION,
    };
    let mut query = upstream_uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|part| !part.is_empty() && part.split('=').next() != Some("alt"))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if path.method.is_streaming() {
        query.push(GEMINI_SSE_QUERY.to_owned());
    }
    let mut path_and_query = format!("{prefix}{model}:{action}");
    if !query.is_empty() {
        path_and_query.push('?');
        path_and_query.push_str(&query.join("&"));
    }
    let mut parts = upstream_uri.into_parts();
    parts.path_and_query = Some(
        path_and_query
            .parse::<PathAndQuery>()
            .map_err(|_| GeminiRuntimeError::InvalidUpstreamUri)?,
    );
    Uri::from_parts(parts).map_err(|_| GeminiRuntimeError::InvalidUpstreamUri)
}

fn valid_model_segment(model: &str) -> bool {
    !model.is_empty()
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

struct GeminiResponseBody {
    inner: Pin<Box<ProxyBody>>,
    method: GeminiMethod,
    parser: SseParser,
    decoder: GeminiEventDecoder,
    encoder: GeminiEventEncoder,
    policy: LossPolicy,
    limits: SseLimits,
    unary: Vec<u8>,
    max_unary_bytes: usize,
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    max_queue_items: usize,
    max_queue_bytes: usize,
    cancellation: CancellationToken,
    ended: bool,
    error: Option<BoxError>,
}

impl GeminiResponseBody {
    #[allow(clippy::too_many_arguments)]
    fn new(
        body: ProxyBody,
        method: GeminiMethod,
        policy: LossPolicy,
        limits: SseLimits,
        max_unary_bytes: usize,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner: Box::pin(body),
            method,
            parser: SseParser::with_limits(limits),
            decoder: GeminiEventDecoder::new(),
            encoder: GeminiEventEncoder::new(),
            policy,
            limits,
            unary: Vec::new(),
            max_unary_bytes,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_queue_items,
            max_queue_bytes,
            cancellation,
            ended: false,
            error: None,
        }
    }

    fn process_data(&mut self, data: &[u8]) -> Result<(), BoxError> {
        match self.method {
            GeminiMethod::GenerateContent => {
                let observed = self.unary.len().saturating_add(data.len());
                if observed > self.max_unary_bytes {
                    return Err(Box::new(GeminiRuntimeError::UnaryBodyTooLarge));
                }
                self.unary.extend_from_slice(data);
            }
            GeminiMethod::StreamGenerateContent => {
                for event in self
                    .parser
                    .feed(data)
                    .map_err(|error| Box::new(error) as BoxError)?
                {
                    self.process_sse_event(&event)?;
                }
            }
        }
        Ok(())
    }

    fn process_sse_event(&mut self, event: &SseEvent) -> Result<(), BoxError> {
        if event.is_done() {
            return Err(Box::new(GeminiRuntimeError::UnexpectedDone));
        }
        let semantic = self
            .decoder
            .decode_chunk(event.data.as_bytes())
            .map_err(|error| Box::new(error) as BoxError)?;
        self.encode_stream_events(&semantic)
    }

    fn encode_stream_events(&mut self, events: &[StreamEvent]) -> Result<(), BoxError> {
        let sse = SseEncoder::with_limits(self.limits);
        for event in events {
            let Some(encoded) = self
                .encoder
                .encode_event(event, self.policy)
                .map_err(|error| Box::new(error) as BoxError)?
            else {
                continue;
            };
            let data = String::from_utf8(encoded.body)
                .map_err(|_| Box::new(GeminiRuntimeError::InvalidJsonUtf8) as BoxError)?;
            self.enqueue(Bytes::from(
                sse.encode(&SseEvent::new(data))
                    .map_err(|error| Box::new(error) as BoxError)?,
            ))?;
        }
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        match self.method {
            GeminiMethod::GenerateContent => {
                let semantic = GeminiGenerateContentCodec::decode_response(&self.unary)
                    .map_err(|error| Box::new(error) as BoxError)?;
                let encoded = GeminiGenerateContentCodec::encode_response(&semantic, self.policy)
                    .map_err(|error| Box::new(error) as BoxError)?;
                self.enqueue(Bytes::from(encoded.body))?;
            }
            GeminiMethod::StreamGenerateContent => {
                for event in self
                    .parser
                    .finish()
                    .map_err(|error| Box::new(error) as BoxError)?
                {
                    self.process_sse_event(&event)?;
                }
                let semantic = self
                    .decoder
                    .finish()
                    .map_err(|error| Box::new(error) as BoxError)?;
                self.encode_stream_events(&semantic)?;
            }
        }
        self.ended = true;
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let items = self.queue.len().saturating_add(1);
        let byte_count = self.queued_bytes.saturating_add(bytes.len());
        if items > self.max_queue_items || byte_count > self.max_queue_bytes {
            return Err(Box::new(GeminiRuntimeError::QueueLimit {
                items,
                bytes: byte_count,
            }));
        }
        self.queued_bytes = byte_count;
        self.queue.push_back(bytes);
        Ok(())
    }

    fn set_error(&mut self, error: BoxError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

impl Body for GeminiResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.cancellation.is_cancelled() {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(GeminiRuntimeError::Cancelled))));
        }
        if let Some(bytes) = this.queue.pop_front() {
            this.queued_bytes = this.queued_bytes.saturating_sub(bytes.len());
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(error) = this.error.take() {
            this.ended = true;
            return Poll::Ready(Some(Err(error)));
        }
        if this.ended {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if let Err(error) = this.finish_upstream() {
                    this.set_error(error);
                }
                Pin::new(this).poll_frame(context)
            }
            Poll::Ready(Some(Err(error))) => {
                this.set_error(error);
                Pin::new(this).poll_frame(context)
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    if let Err(error) = this.process_data(&data) {
                        this.set_error(error);
                    }
                    Pin::new(this).poll_frame(context)
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(_) => Pin::new(this).poll_frame(context),
                    Err(_) => {
                        this.set_error(Box::new(GeminiRuntimeError::InvalidFrame));
                        Pin::new(this).poll_frame(context)
                    }
                },
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.queue.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

#[derive(Debug, Error)]
enum GeminiRuntimeError {
    #[error("route or request is not a supported POST Gemini GenerateContent path")]
    UnsupportedRoute,
    #[error("Gemini model is not a valid URL path segment")]
    InvalidModel,
    #[error("Gemini upstream URI could not be constructed")]
    InvalidUpstreamUri,
    #[error("Gemini model changed while encoding the same-wire request")]
    ModelChanged,
    #[error("Gemini unary response exceeded its configured body limit")]
    UnaryBodyTooLarge,
    #[error("Gemini stream unexpectedly contained an OpenAI [DONE] marker")]
    UnexpectedDone,
    #[error("Gemini response JSON was not UTF-8")]
    InvalidJsonUtf8,
    #[error("Gemini semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("Gemini semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("Gemini semantic response canceled")]
    Cancelled,
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_preserves_merged_query_and_normalizes_streaming_alt() {
        let downstream: Uri =
            "/v1beta/models/client-model:streamGenerateContent?trace=abc&alt=json"
                .parse()
                .expect("downstream URI");
        let upstream: Uri =
            "https://generativelanguage.googleapis.com/v1beta/models/client-model:streamGenerateContent?trace=abc&alt=json&key=server-key"
                .parse()
                .expect("upstream URI");

        let rewritten = rewrite_gemini_uri(&downstream, Some("upstream-model"), upstream)
            .expect("rewritten URI");

        assert_eq!(rewritten.host(), Some("generativelanguage.googleapis.com"));
        assert_eq!(
            rewritten.path(),
            "/v1beta/models/upstream-model:streamGenerateContent"
        );
        let query = rewritten.query().expect("query");
        assert!(query.split('&').any(|part| part == "trace=abc"));
        assert!(query.split('&').any(|part| part == "key=server-key"));
        assert_eq!(
            query
                .split('&')
                .filter(|part| part.split('=').next() == Some("alt"))
                .collect::<Vec<_>>(),
            vec![GEMINI_SSE_QUERY]
        );
    }
}
