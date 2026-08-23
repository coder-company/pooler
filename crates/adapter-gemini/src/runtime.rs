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
use serde_json::Value;
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
        let semantic_ingress = route.ingress().mode() == pooler_core::BodyMode::Semantic
            && route.ingress().decoder() == Some(GEMINI_REQUEST_DECODER);
        let supported_response = route.response().mode() == pooler_core::BodyMode::Opaque
            || (route.response().mode() == pooler_core::BodyMode::Semantic
                && route.response().decoder() == Some(GEMINI_RESPONSE_DECODER)
                && route.response().encoder() == Some(GEMINI_RESPONSE_ENCODER));
        semantic_ingress && supported_response
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

    fn model_in_request_body(&self, route: &RoutePlan) -> bool {
        route.matcher().path().value().contains("/interactions")
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
    let (body, mode) = match path.method {
        GeminiMethod::GenerateContent | GeminiMethod::StreamGenerateContent => {
            let model = path.model.ok_or(GeminiRuntimeError::UnsupportedRoute)?;
            let decoded = GeminiGenerateContentCodec::decode_request_with_report(body, model)
                .map_err(|error| Box::new(error) as BoxError)?;
            decoded
                .report
                .validate(route.loss_policy())
                .map_err(|error| Box::new(error) as BoxError)?;
            let encoded =
                GeminiGenerateContentCodec::encode_request(&decoded.request, route.loss_policy())
                    .map_err(|error| Box::new(error) as BoxError)?;
            if encoded.model != model {
                return Err(Box::new(GeminiRuntimeError::ModelChanged));
            }
            let mode = if path.method.is_streaming() {
                SemanticResponseMode::ServerSentEvents
            } else {
                SemanticResponseMode::Json
            };
            (encoded.body, mode)
        }
        GeminiMethod::CountTokens | GeminiMethod::CreateInteraction => {
            require_json_object(body)?;
            (body.to_vec(), SemanticResponseMode::AdapterDefault)
        }
        GeminiMethod::GetModel
        | GeminiMethod::Interaction
        | GeminiMethod::CancelInteraction
        | GeminiMethod::ListModels => {
            if !body.is_empty() {
                return Err(Box::new(GeminiRuntimeError::UnexpectedRequestBody));
            }
            (Vec::new(), SemanticResponseMode::AdapterDefault)
        }
    };
    Ok(SemanticRequestBody {
        body,
        content_type: HeaderValue::from_static(GEMINI_JSON_CONTENT_TYPE),
        response_hint: SemanticResponseHint {
            mode,
            requested_model: path.model.map(ToOwned::to_owned),
            ..SemanticResponseHint::default()
        },
    })
}

fn selection_context_for_path(
    route: &RoutePlan,
    path: crate::GeminiPath<'_>,
    body: &[u8],
) -> Result<SelectionContext, BoxError> {
    let mut context = match path.method {
        GeminiMethod::GenerateContent | GeminiMethod::StreamGenerateContent => {
            let model = path.model.ok_or(GeminiRuntimeError::UnsupportedRoute)?;
            let decoded = GeminiGenerateContentCodec::decode_request_with_report(body, model)
                .map_err(|error| Box::new(error) as BoxError)?;
            decoded
                .report
                .validate(route.loss_policy())
                .map_err(|error| Box::new(error) as BoxError)?;
            let mut context = SelectionContext::from_semantic_request(&decoded.request);
            context.with_codec(GEMINI_REQUEST_DECODER);
            context
        }
        GeminiMethod::CountTokens => count_tokens_selection_context(
            route,
            path.model.ok_or(GeminiRuntimeError::UnsupportedRoute)?,
            body,
        )?,
        GeminiMethod::GetModel => {
            if !body.is_empty() {
                return Err(Box::new(GeminiRuntimeError::UnexpectedRequestBody));
            }
            let mut context = SelectionContext::default();
            context.with_model(path.model.ok_or(GeminiRuntimeError::UnsupportedRoute)?);
            context.require(pooler_core::Capability::Text);
            context
        }
        GeminiMethod::CreateInteraction => interaction_selection_context(body)?,
        GeminiMethod::Interaction | GeminiMethod::CancelInteraction => {
            if !body.is_empty() {
                return Err(Box::new(GeminiRuntimeError::UnexpectedRequestBody));
            }
            let mut context = SelectionContext::default();
            if let Some(interaction_id) = path.interaction_id {
                context.with_affinity_value("gemini.interaction_id", interaction_id);
            }
            context
        }
        GeminiMethod::ListModels => SelectionContext::default(),
    };
    if path.method.is_streaming() {
        context.require(pooler_core::Capability::Streaming);
    }
    Ok(context)
}

fn count_tokens_selection_context(
    route: &RoutePlan,
    model: &str,
    body: &[u8],
) -> Result<SelectionContext, BoxError> {
    let value = require_json_object(body)?;
    let request_body = if let Some(request) = value.get("generateContentRequest") {
        serde_json::to_vec(request).map_err(|error| Box::new(error) as BoxError)?
    } else if value.contains_key("contents") {
        body.to_vec()
    } else {
        return Err(Box::new(GeminiRuntimeError::MissingCountTokensInput));
    };
    let decoded = GeminiGenerateContentCodec::decode_request_with_report(&request_body, model)
        .map_err(|error| Box::new(error) as BoxError)?;
    decoded
        .report
        .validate(route.loss_policy())
        .map_err(|error| Box::new(error) as BoxError)?;
    Ok(SelectionContext::from_semantic_request(&decoded.request))
}

fn interaction_selection_context(body: &[u8]) -> Result<SelectionContext, BoxError> {
    let value = require_json_object(body)?;
    if !value.contains_key("input") {
        return Err(Box::new(GeminiRuntimeError::MissingInteractionInput));
    }
    let mut context = SelectionContext::default();
    let model = match value.get("model") {
        None => None,
        Some(Value::String(model)) if model.trim().is_empty() => None,
        Some(Value::String(model)) => Some(normalize_model_resource_name(model)),
        Some(_) => return Err(Box::new(GeminiRuntimeError::InvalidInteractionModel)),
    };
    let agent = match value.get("agent") {
        None => None,
        Some(Value::String(agent)) if agent.trim().is_empty() => None,
        Some(Value::String(agent)) => Some(agent.as_str()),
        Some(_) => return Err(Box::new(GeminiRuntimeError::InvalidInteractionAgent)),
    };
    match (model, agent) {
        (Some(model), None) => {
            context.with_model(model);
            context.require_known_model();
        }
        (None, Some(_agent)) => {}
        (Some(_), Some(_)) => return Err(Box::new(GeminiRuntimeError::MultipleInteractionTargets)),
        (None, None) => return Err(Box::new(GeminiRuntimeError::MissingInteractionTarget)),
    }
    context.require(pooler_core::Capability::Text);
    if let Some(stream) = value.get("stream") {
        if stream
            .as_bool()
            .ok_or(GeminiRuntimeError::InvalidInteractionStream)?
        {
            context.require(pooler_core::Capability::Streaming);
        }
    }
    if let Some(tools) = value.get("tools") {
        let tools = tools
            .as_array()
            .ok_or(GeminiRuntimeError::InvalidInteractionTools)?;
        if !tools.is_empty() {
            context.require(pooler_core::Capability::Tools);
            context.require(pooler_core::Capability::FunctionCalling);
        }
    }
    if let Some(previous) = value.get("previous_interaction_id") {
        let previous = previous
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(GeminiRuntimeError::InvalidPreviousInteractionId)?;
        context.with_affinity_value("gemini.interaction_id", previous);
    }
    Ok(context)
}

fn normalize_model_resource_name(model: &str) -> &str {
    model
        .trim()
        .strip_prefix("models/")
        .filter(|model| !model.is_empty())
        .unwrap_or(model.trim())
}

fn require_json_object(body: &[u8]) -> Result<serde_json::Map<String, Value>, BoxError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| Box::new(GeminiRuntimeError::InvalidRequestJson) as BoxError)?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(Box::new(GeminiRuntimeError::InvalidRequestObject)),
    }
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
            _ => return Err(Box::new(GeminiRuntimeError::UnsupportedRoute)),
        },
    })
}

fn route_method(route: &RoutePlan) -> Option<GeminiMethod> {
    if route.matcher().methods().len() != 1 || route.matcher().methods()[0].as_ref() != "POST" {
        return None;
    }
    parse_gemini_path(route.matcher().path().value())
        .map(|path| path.method)
        .filter(|method| {
            matches!(
                method,
                GeminiMethod::GenerateContent | GeminiMethod::StreamGenerateContent
            )
        })
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
    parse_gemini_path(path)
}

fn rewrite_gemini_uri(
    downstream_uri: &Uri,
    upstream_model: Option<&str>,
    upstream_uri: Uri,
) -> Result<Uri, GeminiRuntimeError> {
    let path =
        checked_gemini_path(downstream_uri.path()).ok_or(GeminiRuntimeError::UnsupportedRoute)?;
    if path.model.is_none() {
        return Ok(upstream_uri);
    }
    let model = upstream_model
        .or(path.model)
        .ok_or(GeminiRuntimeError::InvalidModel)?;
    if !valid_model_segment(model) {
        return Err(GeminiRuntimeError::InvalidModel);
    }
    let mut query = upstream_uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|part| {
            !part.is_empty()
                && (!path.method.is_streaming() || part.split('=').next() != Some("alt"))
        })
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if path.method.is_streaming() {
        query.push(GEMINI_SSE_QUERY.to_owned());
    }
    let suffix = match path.method {
        GeminiMethod::GetModel => String::new(),
        GeminiMethod::GenerateContent => format!(":{}", crate::GENERATE_CONTENT_ACTION),
        GeminiMethod::StreamGenerateContent => {
            format!(":{}", crate::STREAM_GENERATE_CONTENT_ACTION)
        }
        GeminiMethod::CountTokens => format!(":{}", crate::COUNT_TOKENS_ACTION),
        _ => return Err(GeminiRuntimeError::UnsupportedRoute),
    };
    let mut path_and_query = format!("/{}/models/{model}{suffix}", path.api_version);
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
    !matches!(model, "" | "." | "..")
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
            _ => return Err(Box::new(GeminiRuntimeError::UnsupportedRoute)),
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
            _ => return Err(Box::new(GeminiRuntimeError::UnsupportedRoute)),
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
    #[error("route or request is not a supported Gemini path")]
    UnsupportedRoute,
    #[error("Gemini model is not a valid URL path segment")]
    InvalidModel,
    #[error("Gemini request body is not valid JSON")]
    InvalidRequestJson,
    #[error("Gemini request body must be a JSON object")]
    InvalidRequestObject,
    #[error("Gemini operation does not accept a request body")]
    UnexpectedRequestBody,
    #[error("Gemini CountTokens request requires `contents` or `generateContentRequest`")]
    MissingCountTokensInput,
    #[error("Gemini Interaction request requires `input`")]
    MissingInteractionInput,
    #[error("Gemini Interaction model must be a non-empty string")]
    InvalidInteractionModel,
    #[error("Gemini Interaction agent must be a non-empty string")]
    InvalidInteractionAgent,
    #[error("Gemini Interaction stream must be a boolean")]
    InvalidInteractionStream,
    #[error("Gemini Interaction tools must be an array")]
    InvalidInteractionTools,
    #[error("Gemini previous_interaction_id must be a non-empty string")]
    InvalidPreviousInteractionId,
    #[error("Gemini Interaction requires either `model` or `agent`")]
    MissingInteractionTarget,
    #[error("Gemini Interaction requires exactly one of `model` or `agent`")]
    MultipleInteractionTargets,
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

    #[test]
    fn rewrite_changes_count_tokens_model_without_changing_query() {
        let downstream: Uri = "/v1beta/models/public:countTokens?trace=abc&alt=json"
            .parse()
            .expect("downstream URI");
        let upstream: Uri =
            "https://generativelanguage.googleapis.com/v1beta/models/public:countTokens?trace=abc&alt=json&key=server-key"
                .parse()
                .expect("upstream URI");

        let rewritten =
            rewrite_gemini_uri(&downstream, Some("private"), upstream).expect("rewritten URI");

        assert_eq!(
            rewritten.path_and_query().expect("path and query").as_str(),
            "/v1beta/models/private:countTokens?trace=abc&alt=json&key=server-key"
        );
    }

    #[test]
    fn rewrite_rejects_dot_segment_upstream_aliases() {
        let downstream: Uri = "/v1beta/models/public:countTokens"
            .parse()
            .expect("downstream URI");
        let upstream: Uri =
            "https://generativelanguage.googleapis.com/v1beta/models/public:countTokens"
                .parse()
                .expect("upstream URI");

        for model in [".", ".."] {
            assert!(
                rewrite_gemini_uri(&downstream, Some(model), upstream.clone()).is_err(),
                "accepted dot-segment alias {model}"
            );
        }
    }

    #[test]
    fn rewrite_preserves_interaction_resource_and_query() {
        let downstream: Uri = "/v1beta/interactions/int_123?stream=true&last_event_id=evt_2"
            .parse()
            .expect("downstream URI");
        let upstream: Uri =
            "https://generativelanguage.googleapis.com/v1beta/interactions/int_123?stream=true&last_event_id=evt_2&key=server-key"
                .parse()
                .expect("upstream URI");

        let rewritten =
            rewrite_gemini_uri(&downstream, None, upstream.clone()).expect("rewritten URI");

        assert_eq!(rewritten, upstream);
    }

    #[test]
    fn interaction_selection_extracts_model_capabilities_and_affinity() {
        let context = interaction_selection_context(
            br#"{"model":"public","input":"hi","stream":true,"tools":[{"type":"function"}],"previous_interaction_id":"int_123"}"#,
        )
        .expect("interaction context");

        assert_eq!(context.model(), Some("public"));
        assert!(context
            .required_capabilities()
            .contains(pooler_core::Capability::Text));
        assert!(context
            .required_capabilities()
            .contains(pooler_core::Capability::Streaming));
        assert!(context
            .required_capabilities()
            .contains(pooler_core::Capability::Tools));
        assert!(context
            .required_capabilities()
            .contains(pooler_core::Capability::FunctionCalling));
        assert_eq!(
            context.affinity_value("gemini.interaction_id"),
            Some("int_123")
        );

        let without_tools =
            interaction_selection_context(br#"{"model":"public","input":"hi","tools":[]}"#)
                .expect("empty tools array");
        assert!(!without_tools
            .required_capabilities()
            .contains(pooler_core::Capability::Tools));
        assert!(
            interaction_selection_context(br#"{"model":"public","input":"hi","tools":null}"#)
                .is_err()
        );

        let prefixed = interaction_selection_context(br#"{"model":"models/public","input":"hi"}"#)
            .expect("prefixed interaction model");
        assert_eq!(prefixed.model(), Some("public"));
        assert!(interaction_selection_context(
            br#"{"model":"public","agent":"agent","input":"hi"}"#,
        )
        .is_err());
        assert!(
            interaction_selection_context(br#"{"model":"","agent":"agent","input":"hi"}"#).is_ok()
        );
    }
}
