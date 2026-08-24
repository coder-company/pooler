#![forbid(unsafe_code)]
#![doc = "Generic semantic HTTP adapter for OpenAI Responses and Chat wires.

Any compatible client can use these routes. Product-specific clients are
compatibility consumers, not architectural adapters. The Factory LanguageModel
protocol remains isolated in `adapter-factory`."]

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use pooler_config::RoutePlan;
use pooler_http::{
    BoxError, ProxyBody, SelectionContext, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody, SemanticResponseHint, SemanticResponseMode, SemanticWebSocketTransport,
    SseEncoder, SseEvent, SseLimits, SseParser,
};
use pooler_protocol::{
    ExtensionKey, LossPolicy, OpenAiChatCodec, OpenAiChatEventDecoder, OpenAiChatEventEncoder,
    OpenAiResponsesCodec, OpenAiResponsesEventDecoder, OpenAiResponsesEventEncoder,
    SemanticRequest, StreamEvent, OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION,
    OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION,
};
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Semantic decoder for an OpenAI Responses request.
pub const OPENAI_RESPONSES_REQUEST_DECODER: &str = "decode.openai.responses";
/// Semantic request encoder implied by a Responses upstream.
pub const OPENAI_RESPONSES_REQUEST_ENCODER: &str = "encode.openai.responses";
/// Semantic decoder for named OpenAI Responses SSE events.
pub const OPENAI_RESPONSES_EVENT_DECODER: &str = "decode.openai.responses.events";
/// Semantic encoder for named OpenAI Responses SSE events.
pub const OPENAI_RESPONSES_EVENT_ENCODER: &str = "encode.openai.responses.events";
/// Semantic decoder for an OpenAI Chat Completions request.
pub const OPENAI_CHAT_REQUEST_DECODER: &str = "decode.openai.chat";
/// Semantic request encoder implied by a Chat Completions upstream.
pub const OPENAI_CHAT_REQUEST_ENCODER: &str = "encode.openai.chat";
/// Semantic decoder for OpenAI Chat Completions SSE data chunks.
pub const OPENAI_CHAT_EVENT_DECODER: &str = "decode.openai.chat.events";
/// Semantic encoder for OpenAI Chat Completions SSE data chunks.
pub const OPENAI_CHAT_EVENT_ENCODER: &str = "encode.openai.chat.events";

/// Runtime adapter for OpenAI Responses and compatible Chat routes.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenAiSemanticAdapter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestWire {
    Responses,
    Chat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventWire {
    Responses,
    Chat,
}

impl SemanticAdapter for OpenAiSemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        route_wires(route).is_some()
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        let (request_wire, upstream_wire) = route_wires(route)
            .ok_or_else(|| Box::new(OpenAiAdapterError::UnsupportedRoute) as BoxError)?;
        let request = decode_request(request_wire, body, route.loss_policy())?;
        let streaming = request_streaming(&request);
        if !streaming
            && matches!(
                (request_wire, upstream_wire),
                (RequestWire::Responses, EventWire::Chat)
            )
        {
            return Err(Box::new(OpenAiAdapterError::UnaryCrossProtocolUnsupported));
        }
        let encoded = encode_upstream_request(upstream_wire, &request, route.loss_policy())?;
        let response_mode = if streaming {
            SemanticResponseMode::ServerSentEvents
        } else {
            SemanticResponseMode::Json
        };
        Ok(SemanticRequestBody {
            body: encoded,
            content_type: HeaderValue::from_static("application/json"),
            response_hint: SemanticResponseHint {
                mode: response_mode,
                requested_model: Some(request.model.clone()),
                ..SemanticResponseHint::default()
            },
        })
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        let (request_wire, _) = route_wires(route)
            .ok_or_else(|| Box::new(OpenAiAdapterError::UnsupportedRoute) as BoxError)?;
        let request = decode_request(request_wire, body, route.loss_policy())?;
        let mut context = SelectionContext::from_semantic_request(&request);
        if request_streaming(&request) {
            context.require(pooler_core::Capability::Streaming);
        }
        if let Some(codec) = route.ingress().decoder() {
            context.with_codec(codec);
        }
        Ok(context)
    }

    fn websocket_transport(&self, route: &RoutePlan) -> Option<SemanticWebSocketTransport> {
        matches!(
            route_wires(route),
            Some((RequestWire::Responses, EventWire::Responses))
        )
        .then_some(SemanticWebSocketTransport::OpenAiResponses)
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let (request_wire, upstream_wire) = route_wires(route)
            .ok_or_else(|| Box::new(OpenAiAdapterError::UnsupportedRoute) as BoxError)?;
        let downstream_wire = match request_wire {
            RequestWire::Responses => EventWire::Responses,
            RequestWire::Chat => EventWire::Chat,
        };
        let limits = SseLimits::new(
            usize_limit(route.limits().max_frame_bytes),
            usize_limit(route.limits().max_event_bytes),
        );
        let max_queue_items = usize_limit(u64::from(route.limits().max_queue_items));
        let max_queue_bytes = usize_limit(route.limits().max_queue_bytes);
        let stream =
            if upstream_wire == EventWire::Responses && downstream_wire == EventWire::Responses {
                OpenAiResponseBody::responses_passthrough(
                    body,
                    limits,
                    max_queue_items,
                    max_queue_bytes,
                    cancellation,
                )
            } else {
                OpenAiResponseBody::transform(
                    body,
                    upstream_wire,
                    downstream_wire,
                    route.loss_policy(),
                    limits,
                    max_queue_items,
                    max_queue_bytes,
                    cancellation,
                )
            };
        Ok(SemanticResponseBody {
            body: stream.boxed(),
            content_type: HeaderValue::from_static("text/event-stream"),
        })
    }

    fn decode_response_with_hint(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        if hint.mode != SemanticResponseMode::Json {
            return self.decode_response(route, body, cancellation);
        }
        let (_, upstream_wire) = route_wires(route)
            .ok_or_else(|| Box::new(OpenAiAdapterError::UnsupportedRoute) as BoxError)?;
        if upstream_wire == EventWire::Chat {
            return Err(Box::new(OpenAiAdapterError::UnaryCrossProtocolUnsupported));
        }
        let limit = usize_limit(route.limits().max_response_body_bytes);
        let unary = if hint.upstream_mode == SemanticResponseMode::ServerSentEvents {
            let limits = SseLimits::new(
                usize_limit(route.limits().max_frame_bytes),
                usize_limit(route.limits().max_event_bytes),
            );
            OpenAiStreamingUnaryResponseBody::new(
                body,
                upstream_wire,
                route.loss_policy(),
                limits,
                limit,
                cancellation,
            )
            .boxed()
        } else {
            OpenAiUnaryResponseBody::new(body, limit, cancellation).boxed()
        };
        Ok(SemanticResponseBody {
            body: unary,
            content_type: HeaderValue::from_static("application/json"),
        })
    }
}

fn route_wires(route: &RoutePlan) -> Option<(RequestWire, EventWire)> {
    if route.ingress().mode() != pooler_core::BodyMode::Semantic
        || route.response().mode() != pooler_core::BodyMode::Semantic
    {
        return None;
    }
    let request = match route.ingress().decoder()? {
        OPENAI_RESPONSES_REQUEST_DECODER => RequestWire::Responses,
        OPENAI_CHAT_REQUEST_DECODER => RequestWire::Chat,
        _ => return None,
    };
    let expected_request_encoder = match request {
        RequestWire::Responses => OPENAI_RESPONSES_REQUEST_ENCODER,
        RequestWire::Chat => OPENAI_CHAT_REQUEST_ENCODER,
    };
    if route
        .ingress()
        .encoder()
        .is_some_and(|encoder| encoder != expected_request_encoder)
    {
        return None;
    }
    let upstream = match route.response().decoder()? {
        OPENAI_RESPONSES_EVENT_DECODER => EventWire::Responses,
        OPENAI_CHAT_EVENT_DECODER => EventWire::Chat,
        _ => return None,
    };
    let expected_encoder = match request {
        RequestWire::Responses => OPENAI_RESPONSES_EVENT_ENCODER,
        RequestWire::Chat => OPENAI_CHAT_EVENT_ENCODER,
    };
    (route.response().encoder() == Some(expected_encoder)).then_some((request, upstream))
}

fn decode_request(
    wire: RequestWire,
    body: &[u8],
    policy: LossPolicy,
) -> Result<SemanticRequest, BoxError> {
    match wire {
        RequestWire::Responses => {
            let decoded = OpenAiResponsesCodec::decode_request_with_report(body)
                .map_err(|error| Box::new(error) as BoxError)?;
            decoded
                .report
                .validate(policy)
                .map_err(|error| Box::new(error) as BoxError)?;
            Ok(decoded.request)
        }
        RequestWire::Chat => {
            require_streaming(body)?;
            let decoded = OpenAiChatCodec::decode_request_with_report(body)
                .map_err(|error| Box::new(error) as BoxError)?;
            decoded
                .report
                .validate(policy)
                .map_err(|error| Box::new(error) as BoxError)?;
            Ok(decoded.request)
        }
    }
}

fn require_streaming(body: &[u8]) -> Result<(), BoxError> {
    let value: Value = serde_json::from_slice(body)?;
    let stream = value
        .as_object()
        .and_then(|object| object.get("stream"))
        .and_then(Value::as_bool);
    match stream {
        Some(true) => Ok(()),
        Some(false) | None => Err(Box::new(OpenAiAdapterError::StreamingRequired)),
    }
}

fn request_streaming(request: &SemanticRequest) -> bool {
    for key in [
        OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION,
        OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION,
    ] {
        let Ok(key) = ExtensionKey::parse(key) else {
            continue;
        };
        let Some(extension) = request.extensions.get(&key) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(extension.as_bytes()) else {
            continue;
        };
        if let Some(stream) = value.get("stream").and_then(Value::as_bool) {
            return stream;
        }
    }
    false
}

fn encode_upstream_request(
    wire: EventWire,
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<Vec<u8>, BoxError> {
    let stream = request_streaming(request);
    let (request, passthrough) = prepare_request_for_wire(wire, request, policy)?;
    let body = match wire {
        EventWire::Responses => {
            OpenAiResponsesCodec::encode_request(&request, policy)
                .map_err(|error| Box::new(error) as BoxError)?
                .body
        }
        EventWire::Chat => {
            OpenAiChatCodec::encode_request(&request, policy)
                .map_err(|error| Box::new(error) as BoxError)?
                .body
        }
    };
    let mut value: Value = serde_json::from_slice(&body)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Box::new(OpenAiAdapterError::EncodedRequestNotObject) as BoxError)?;
    for (key, value) in passthrough {
        object.entry(key).or_insert(value);
    }
    object.insert("stream".to_owned(), Value::Bool(stream));
    match wire {
        EventWire::Responses => {
            object.entry("store").or_insert(Value::Bool(false));
        }
        EventWire::Chat => {
            if stream {
                object.insert(
                    "stream_options".to_owned(),
                    serde_json::json!({"include_usage":true}),
                );
            } else {
                object.remove("stream_options");
            }
        }
    }
    serde_json::to_vec(&value).map_err(|error| Box::new(error) as BoxError)
}

fn prepare_request_for_wire(
    wire: EventWire,
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<(SemanticRequest, serde_json::Map<String, Value>), BoxError> {
    let mut request = request.clone();
    let foreign_extension = match wire {
        EventWire::Responses => OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION,
        EventWire::Chat => OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION,
    };
    let key =
        ExtensionKey::parse(foreign_extension).map_err(|error| Box::new(error) as BoxError)?;
    let Some(extension) = request.extensions.remove(&key) else {
        return Ok((request, serde_json::Map::new()));
    };
    let value: Value = serde_json::from_slice(extension.as_bytes())?;
    let fields = value
        .as_object()
        .ok_or_else(|| Box::new(OpenAiAdapterError::InvalidTransportExtension) as BoxError)?;
    let mut passthrough = serde_json::Map::new();
    for (field, value) in fields {
        match field.as_str() {
            "stream_options" => {}
            "stream" => {
                passthrough.insert(field.clone(), value.clone());
            }
            "store" | "parallel_tool_calls" | "prompt_cache_key" => {
                passthrough.insert(field.clone(), value.clone());
            }
            _ if policy.allows_degradation() => {}
            _ => {
                return Err(Box::new(OpenAiAdapterError::UnsupportedCrossProtocolField(
                    field.clone(),
                )));
            }
        }
    }
    Ok((request, passthrough))
}

#[derive(Debug, Error)]
enum OpenAiAdapterError {
    #[error("route is not a supported OpenAI semantic route")]
    UnsupportedRoute,
    #[error("OpenAI Chat semantic routes require stream=true")]
    StreamingRequired,
    #[error("encoded OpenAI request is not a JSON object")]
    EncodedRequestNotObject,
    #[error("OpenAI transport extension is not a JSON object")]
    InvalidTransportExtension,
    #[error("OpenAI field `{0}` cannot be preserved across Responses and Chat")]
    UnsupportedCrossProtocolField(String),
    #[error("unary Responses-to-Chat translation is not supported")]
    UnaryCrossProtocolUnsupported,
}

enum UpstreamDecoder {
    Responses(OpenAiResponsesEventDecoder),
    Chat(OpenAiChatEventDecoder),
}

impl UpstreamDecoder {
    fn new(wire: EventWire) -> Self {
        match wire {
            EventWire::Responses => Self::Responses(OpenAiResponsesEventDecoder::new()),
            EventWire::Chat => Self::Chat(OpenAiChatEventDecoder::new()),
        }
    }

    fn decode(&mut self, event: &SseEvent) -> Result<Vec<StreamEvent>, BoxError> {
        match self {
            Self::Responses(decoder) => decoder
                .decode_event(event.event.as_deref(), event.data.as_bytes())
                .map_err(|error| Box::new(error) as BoxError),
            Self::Chat(decoder) => decoder
                .decode_data(event.data.as_bytes())
                .map_err(|error| Box::new(error) as BoxError),
        }
    }

    fn finish(&mut self) -> Result<Vec<StreamEvent>, BoxError> {
        match self {
            Self::Responses(decoder) => decoder
                .finish()
                .map_err(|error| Box::new(error) as BoxError),
            Self::Chat(decoder) => decoder
                .finish()
                .map_err(|error| Box::new(error) as BoxError),
        }
    }
}

enum DownstreamEncoder {
    Responses(Box<OpenAiResponsesEventEncoder>),
    Chat(OpenAiChatEventEncoder),
}

impl DownstreamEncoder {
    fn new(wire: EventWire) -> Self {
        match wire {
            EventWire::Responses => Self::Responses(Box::new(OpenAiResponsesEventEncoder::new())),
            EventWire::Chat => Self::Chat(OpenAiChatEventEncoder::new()),
        }
    }

    fn encode(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
        limits: SseLimits,
    ) -> Result<Vec<Bytes>, BoxError> {
        let encoder = SseEncoder::with_limits(limits);
        match self {
            Self::Responses(responses) => responses
                .encode_event(event, policy)
                .map_err(|error| Box::new(error) as BoxError)?
                .into_iter()
                .map(|encoded| {
                    encoder
                        .encode(
                            &SseEvent::new(String::from_utf8(encoded.body).map_err(|_| {
                                Box::new(OpenAiStreamError::InvalidJsonUtf8) as BoxError
                            })?)
                            .with_event(encoded.event),
                        )
                        .map(Bytes::from)
                        .map_err(|error| Box::new(error) as BoxError)
                })
                .collect(),
            Self::Chat(chat) => {
                let mut output = Vec::new();
                if let Some(encoded) = chat
                    .encode_event(event, policy)
                    .map_err(|error| Box::new(error) as BoxError)?
                {
                    output.push(Bytes::from(
                        encoder
                            .encode(&SseEvent::new(String::from_utf8(encoded.body).map_err(
                                |_| Box::new(OpenAiStreamError::InvalidJsonUtf8) as BoxError,
                            )?))
                            .map_err(|error| Box::new(error) as BoxError)?,
                    ));
                }
                if event.kind.is_terminal() {
                    output.push(Bytes::from(
                        encoder
                            .encode(&SseEvent::new("[DONE]"))
                            .map_err(|error| Box::new(error) as BoxError)?,
                    ));
                }
                Ok(output)
            }
        }
    }
}

struct OpenAiUnaryResponseBody {
    inner: Pin<Box<ProxyBody>>,
    limit: usize,
    cancellation_wait: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    buffer: Vec<u8>,
    output: Option<Bytes>,
    ended: bool,
    error: Option<BoxError>,
}

impl OpenAiUnaryResponseBody {
    fn new(body: ProxyBody, limit: usize, cancellation: CancellationToken) -> Self {
        let cancellation_wait = Box::pin(cancellation.cancelled_owned());
        Self {
            inner: Box::pin(body),
            limit,
            cancellation_wait,
            buffer: Vec::new(),
            output: None,
            ended: false,
            error: None,
        }
    }

    fn finish(&mut self) -> Result<(), BoxError> {
        let value: Value = serde_json::from_slice(&self.buffer)
            .map_err(|_| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
        if !value.is_object() {
            return Err(Box::new(OpenAiStreamError::InvalidJsonResponse));
        }
        let output = self.buffer.clone();
        if output.len() > self.limit {
            return Err(Box::new(OpenAiStreamError::UnaryBodyTooLarge {
                observed: output.len(),
                limit: self.limit,
            }));
        }
        self.output = Some(Bytes::from(output));
        self.ended = true;
        Ok(())
    }
}

impl Body for OpenAiUnaryResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.cancellation_wait.as_mut().poll(context).is_ready() {
                this.ended = true;
                return Poll::Ready(Some(Err(Box::new(OpenAiStreamError::Cancelled))));
            }
            if let Some(output) = this.output.take() {
                return Poll::Ready(Some(Ok(Frame::data(output))));
            }
            if let Some(error) = this.error.take() {
                this.ended = true;
                return Poll::Ready(Some(Err(error)));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            match this.inner.as_mut().poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    if let Err(error) = this.finish() {
                        this.error = Some(error);
                    }
                }
                Poll::Ready(Some(Err(error))) => this.error = Some(error),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        let observed = this.buffer.len().saturating_add(data.len());
                        if observed > this.limit {
                            this.error = Some(Box::new(OpenAiStreamError::UnaryBodyTooLarge {
                                observed,
                                limit: this.limit,
                            }));
                        } else {
                            this.buffer.extend_from_slice(&data);
                        }
                    }
                    Err(frame) => {
                        if frame.into_trailers().is_err() {
                            this.error = Some(Box::new(OpenAiStreamError::InvalidFrame));
                        }
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.output.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

struct OpenAiStreamingUnaryResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    decoder: UpstreamDecoder,
    encoder: Box<OpenAiResponsesEventEncoder>,
    policy: LossPolicy,
    limit: usize,
    observed_bytes: usize,
    cancellation_wait: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    encoded_terminal: Option<Vec<u8>>,
    raw_terminal_response: Option<Value>,
    raw_output_items: BTreeMap<u64, Value>,
    raw_output_items_fallback: Vec<Value>,
    output: Option<Bytes>,
    ended: bool,
    error: Option<BoxError>,
}

impl OpenAiStreamingUnaryResponseBody {
    fn new(
        body: ProxyBody,
        upstream: EventWire,
        policy: LossPolicy,
        limits: SseLimits,
        limit: usize,
        cancellation: CancellationToken,
    ) -> Self {
        let cancellation_wait = Box::pin(cancellation.cancelled_owned());
        Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(limits),
            decoder: UpstreamDecoder::new(upstream),
            encoder: Box::new(OpenAiResponsesEventEncoder::new()),
            policy,
            limit,
            observed_bytes: 0,
            cancellation_wait,
            encoded_terminal: None,
            raw_terminal_response: None,
            raw_output_items: BTreeMap::new(),
            raw_output_items_fallback: Vec::new(),
            output: None,
            ended: false,
            error: None,
        }
    }

    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        self.observed_bytes = self.observed_bytes.saturating_add(chunk.len());
        if self.observed_bytes > self.limit {
            return Err(Box::new(OpenAiStreamError::UnaryBodyTooLarge {
                observed: self.observed_bytes,
                limit: self.limit,
            }));
        }
        for event in self
            .parser
            .feed(chunk)
            .map_err(|error| Box::new(error) as BoxError)?
        {
            self.process_event(&event)?;
        }
        Ok(())
    }

    fn process_event(&mut self, event: &SseEvent) -> Result<(), BoxError> {
        let projection = semantic_validation_projection(event);
        let semantic = self.decoder.decode(projection.as_ref().unwrap_or(event))?;
        self.observe_raw_event(event)?;
        for semantic in semantic {
            self.process_semantic(&semantic)?;
        }
        Ok(())
    }

    fn observe_raw_event(&mut self, event: &SseEvent) -> Result<(), BoxError> {
        if event.data == "[DONE]" {
            return Ok(());
        }
        let value: Value = serde_json::from_slice(event.data.as_bytes())
            .map_err(|_| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
        let object = value
            .as_object()
            .ok_or_else(|| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
        match object.get("type").and_then(Value::as_str) {
            Some("response.output_item.done") => {
                let item = object
                    .get("item")
                    .filter(|item| item.is_object())
                    .cloned()
                    .ok_or_else(|| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
                if let Some(index) = object.get("output_index").and_then(Value::as_u64) {
                    self.raw_output_items.insert(index, item);
                } else {
                    self.raw_output_items_fallback.push(item);
                }
            }
            Some("response.completed" | "response.incomplete" | "response.failed") => {
                let response = object
                    .get("response")
                    .filter(|response| response.is_object())
                    .cloned()
                    .ok_or_else(|| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
                if self.raw_terminal_response.replace(response).is_some() {
                    return Err(Box::new(OpenAiStreamError::MultipleUnaryTerminals));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn process_semantic(&mut self, event: &StreamEvent) -> Result<(), BoxError> {
        for encoded in self
            .encoder
            .encode_event(event, self.policy)
            .map_err(|error| Box::new(error) as BoxError)?
        {
            if is_terminal_response_event(&encoded.event)
                && self.encoded_terminal.replace(encoded.body).is_some()
            {
                return Err(Box::new(OpenAiStreamError::MultipleUnaryTerminals));
            }
        }
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        for event in self
            .parser
            .finish()
            .map_err(|error| Box::new(error) as BoxError)?
        {
            self.process_event(&event)?;
        }
        for semantic in self.decoder.finish()? {
            self.process_semantic(&semantic)?;
        }
        let mut response = if let Some(response) = self.raw_terminal_response.take() {
            response
        } else {
            let terminal = self
                .encoded_terminal
                .take()
                .ok_or_else(|| Box::new(OpenAiStreamError::MissingUnaryTerminal) as BoxError)?;
            let terminal: Value = serde_json::from_slice(&terminal)
                .map_err(|_| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
            terminal
                .get("response")
                .cloned()
                .ok_or_else(|| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?
        };
        hydrate_raw_terminal_output(
            &mut response,
            &self.raw_output_items,
            &self.raw_output_items_fallback,
        )?;
        let output = serde_json::to_vec(&response)?;
        if output.len() > self.limit {
            return Err(Box::new(OpenAiStreamError::UnaryBodyTooLarge {
                observed: output.len(),
                limit: self.limit,
            }));
        }
        self.output = Some(Bytes::from(output));
        self.ended = true;
        Ok(())
    }
}

fn semantic_validation_projection(event: &SseEvent) -> Option<SseEvent> {
    let mut value: Value = serde_json::from_slice(event.data.as_bytes()).ok()?;
    let object = value.as_object_mut()?;
    if object.get("type").and_then(Value::as_str) != Some("response.output_item.done")
        || object.get("output_index").and_then(Value::as_u64).is_none()
    {
        return None;
    }
    let item = object.get_mut("item")?.as_object_mut()?;
    if item.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    let mut changed = false;
    for part in item.get_mut("content")?.as_array_mut()? {
        let Some(annotations) = part
            .as_object_mut()
            .and_then(|part| part.get_mut("annotations"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        if !annotations.is_empty() {
            annotations.clear();
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    Some(SseEvent {
        event: event.event.clone(),
        data: serde_json::to_string(&value).ok()?,
        id: event.id.clone(),
    })
}

fn hydrate_raw_terminal_output(
    response: &mut Value,
    indexed: &BTreeMap<u64, Value>,
    fallback: &[Value],
) -> Result<(), BoxError> {
    let object = response
        .as_object_mut()
        .ok_or_else(|| Box::new(OpenAiStreamError::InvalidJsonResponse) as BoxError)?;
    if let Some(output) = object.get_mut("output").and_then(Value::as_array_mut) {
        if !output.is_empty() {
            for (index, item) in output.iter_mut().enumerate() {
                let Some(index) = u64::try_from(index).ok() else {
                    continue;
                };
                let Some(raw_item) = indexed.get(&index) else {
                    continue;
                };
                let has_id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| !id.trim().is_empty());
                if !has_id {
                    let id = raw_item
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.trim().is_empty());
                    if let (Some(item), Some(id)) = (item.as_object_mut(), id) {
                        item.insert("id".to_owned(), Value::String(id.to_owned()));
                    }
                }
                preserve_raw_item_annotations(item, raw_item)?;
            }
            return Ok(());
        }
    }
    if indexed.is_empty() && fallback.is_empty() {
        return Ok(());
    }
    let output = indexed
        .values()
        .cloned()
        .chain(fallback.iter().cloned())
        .collect();
    object.insert("output".to_owned(), Value::Array(output));
    Ok(())
}

fn preserve_raw_item_annotations(output: &mut Value, raw: &Value) -> Result<(), BoxError> {
    let Some(raw_content) = raw.get("content").and_then(Value::as_array) else {
        return Ok(());
    };
    let annotated = raw_content
        .iter()
        .enumerate()
        .filter_map(|(index, part)| {
            part.get("annotations")
                .and_then(Value::as_array)
                .filter(|annotations| !annotations.is_empty())
                .map(|annotations| (index, annotations.clone()))
        })
        .collect::<Vec<_>>();
    if annotated.is_empty() {
        return Ok(());
    }
    let output_content = output
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Box::new(OpenAiStreamError::RawAnnotationMismatch) as BoxError)?;
    for (index, annotations) in annotated {
        let part = output_content
            .get_mut(index)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| Box::new(OpenAiStreamError::RawAnnotationMismatch) as BoxError)?;
        part.insert("annotations".to_owned(), Value::Array(annotations));
    }
    Ok(())
}

impl Body for OpenAiStreamingUnaryResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.cancellation_wait.as_mut().poll(context).is_ready() {
                this.ended = true;
                return Poll::Ready(Some(Err(Box::new(OpenAiStreamError::Cancelled))));
            }
            if let Some(output) = this.output.take() {
                return Poll::Ready(Some(Ok(Frame::data(output))));
            }
            if let Some(error) = this.error.take() {
                this.ended = true;
                return Poll::Ready(Some(Err(error)));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            match this.inner.as_mut().poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    if let Err(error) = this.finish_upstream() {
                        this.error = Some(error);
                    }
                }
                Poll::Ready(Some(Err(error))) => this.error = Some(error),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if let Err(error) = this.process_chunk(&data) {
                            this.error = Some(error);
                        }
                    }
                    Err(frame) => {
                        if frame.into_trailers().is_err() {
                            this.error = Some(Box::new(OpenAiStreamError::InvalidFrame));
                        }
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.output.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

fn is_terminal_response_event(event: &str) -> bool {
    matches!(
        event,
        "response.completed" | "response.incomplete" | "response.failed"
    )
}

enum OpenAiResponsePipeline {
    ResponsesPassthrough(Box<OpenAiResponsesEventDecoder>),
    Transform {
        decoder: Box<UpstreamDecoder>,
        encoder: Box<DownstreamEncoder>,
        policy: LossPolicy,
    },
}

impl OpenAiResponsePipeline {
    fn process_event(
        &mut self,
        event: &SseEvent,
        limits: SseLimits,
    ) -> Result<Vec<Bytes>, BoxError> {
        match self {
            Self::ResponsesPassthrough(decoder) => {
                let projection = semantic_validation_projection(event);
                let validation = projection.as_ref().unwrap_or(event);
                decoder
                    .decode_event(validation.event.as_deref(), validation.data.as_bytes())
                    .map_err(|error| Box::new(error) as BoxError)?;
                let encoded = SseEncoder::with_limits(limits)
                    .encode(event)
                    .map_err(|error| Box::new(error) as BoxError)?;
                Ok(vec![Bytes::from(encoded)])
            }
            Self::Transform {
                decoder,
                encoder,
                policy,
            } => {
                let mut output = Vec::new();
                for semantic in decoder.decode(event)? {
                    output.extend(encoder.encode(&semantic, *policy, limits)?);
                }
                Ok(output)
            }
        }
    }

    fn finish(&mut self, limits: SseLimits) -> Result<Vec<Bytes>, BoxError> {
        match self {
            Self::ResponsesPassthrough(decoder) => {
                decoder
                    .finish()
                    .map_err(|error| Box::new(error) as BoxError)?;
                Ok(Vec::new())
            }
            Self::Transform {
                decoder,
                encoder,
                policy,
            } => {
                let mut output = Vec::new();
                for semantic in decoder.finish()? {
                    output.extend(encoder.encode(&semantic, *policy, limits)?);
                }
                Ok(output)
            }
        }
    }
}

struct OpenAiResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    pipeline: OpenAiResponsePipeline,
    limits: SseLimits,
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    max_queue_items: usize,
    max_queue_bytes: usize,
    cancellation_wait: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    ended: bool,
    error: Option<BoxError>,
}

impl OpenAiResponseBody {
    fn responses_passthrough(
        body: ProxyBody,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self::new(
            body,
            OpenAiResponsePipeline::ResponsesPassthrough(Box::new(
                OpenAiResponsesEventDecoder::new(),
            )),
            limits,
            max_queue_items,
            max_queue_bytes,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transform(
        body: ProxyBody,
        upstream: EventWire,
        downstream: EventWire,
        policy: LossPolicy,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self::new(
            body,
            OpenAiResponsePipeline::Transform {
                decoder: Box::new(UpstreamDecoder::new(upstream)),
                encoder: Box::new(DownstreamEncoder::new(downstream)),
                policy,
            },
            limits,
            max_queue_items,
            max_queue_bytes,
            cancellation,
        )
    }

    fn new(
        body: ProxyBody,
        pipeline: OpenAiResponsePipeline,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        let cancellation_wait = Box::pin(cancellation.cancelled_owned());
        Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(limits),
            pipeline,
            limits,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_queue_items,
            max_queue_bytes,
            cancellation_wait,
            ended: false,
            error: None,
        }
    }

    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        for event in self
            .parser
            .feed(chunk)
            .map_err(|error| Box::new(error) as BoxError)?
        {
            self.process_event(&event)?;
        }
        Ok(())
    }

    fn process_event(&mut self, event: &SseEvent) -> Result<(), BoxError> {
        for encoded in self.pipeline.process_event(event, self.limits)? {
            self.enqueue(encoded)?;
        }
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        for event in self
            .parser
            .finish()
            .map_err(|error| Box::new(error) as BoxError)?
        {
            self.process_event(&event)?;
        }
        for encoded in self.pipeline.finish(self.limits)? {
            self.enqueue(encoded)?;
        }
        self.ended = true;
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let items = self.queue.len().saturating_add(1);
        let bytes_total = self.queued_bytes.saturating_add(bytes.len());
        if items > self.max_queue_items || bytes_total > self.max_queue_bytes {
            return Err(Box::new(OpenAiStreamError::QueueLimit {
                items,
                bytes: bytes_total,
            }));
        }
        self.queued_bytes = bytes_total;
        self.queue.push_back(bytes);
        Ok(())
    }

    fn set_error(&mut self, error: BoxError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

impl Body for OpenAiResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.cancellation_wait.as_mut().poll(context).is_ready() {
                this.ended = true;
                return Poll::Ready(Some(Err(Box::new(OpenAiStreamError::Cancelled))));
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
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    if let Err(error) = this.finish_upstream() {
                        this.set_error(error);
                    }
                }
                Poll::Ready(Some(Err(error))) => this.set_error(error),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if let Err(error) = this.process_chunk(&data) {
                            this.set_error(error);
                        }
                    }
                    Err(frame) => {
                        if frame.into_trailers().is_err() {
                            this.set_error(Box::new(OpenAiStreamError::InvalidFrame));
                        }
                    }
                },
            }
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
enum OpenAiStreamError {
    #[error("OpenAI semantic response JSON was not UTF-8")]
    InvalidJsonUtf8,
    #[error("OpenAI semantic response was not a JSON object")]
    InvalidJsonResponse,
    #[error("OpenAI semantic response did not contain a terminal event")]
    MissingUnaryTerminal,
    #[error("OpenAI semantic response contained more than one terminal event")]
    MultipleUnaryTerminals,
    #[error("terminal output cannot preserve raw response annotations")]
    RawAnnotationMismatch,
    #[error("OpenAI unary semantic response exceeded {observed} bytes (limit {limit})")]
    UnaryBodyTooLarge { observed: usize, limit: usize },
    #[error("OpenAI semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("OpenAI semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("OpenAI semantic response canceled")]
    Cancelled,
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use http_body::{Body, Frame, SizeHint};
    use http_body_util::{BodyExt, Full};
    use pooler_config::Config;
    use pooler_http::{SemanticAdapter, SemanticResponseHint, SemanticResponseMode, SseParser};
    use serde_json::{json, Value};
    use tokio_util::sync::CancellationToken;

    use super::{
        hydrate_raw_terminal_output, OpenAiSemanticAdapter, OPENAI_CHAT_EVENT_DECODER,
        OPENAI_CHAT_EVENT_ENCODER, OPENAI_CHAT_REQUEST_DECODER, OPENAI_CHAT_REQUEST_ENCODER,
        OPENAI_RESPONSES_EVENT_DECODER, OPENAI_RESPONSES_EVENT_ENCODER,
        OPENAI_RESPONSES_REQUEST_DECODER, OPENAI_RESPONSES_REQUEST_ENCODER,
    };

    struct ImmediatelyReadyFrames {
        frames: VecDeque<Bytes>,
    }

    impl Body for ImmediatelyReadyFrames {
        type Data = Bytes;
        type Error = pooler_http::BoxError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frames.pop_front().map(|bytes| Ok(Frame::data(bytes))))
        }

        fn is_end_stream(&self) -> bool {
            self.frames.is_empty()
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::new()
        }
    }

    fn route(ingress: &str, decoder: &str, encoder: &str) -> pooler_config::RoutePlan {
        route_with_response_limit(ingress, decoder, encoder, None)
    }

    fn route_with_response_limit(
        ingress: &str,
        decoder: &str,
        encoder: &str,
        max_response_body_bytes: Option<usize>,
    ) -> pooler_config::RoutePlan {
        let limits = max_response_body_bytes
            .map(|value| format!("    limits: {{max_response_body_bytes: {value}}}\n"))
            .unwrap_or_default();
        let source = format!(
            "version: 2\nlisteners: {{openai: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://127.0.0.1:9}}}}\nroutes:\n  - id: openai\n    listen: openai\n    match: {{method: POST, path: /v1/responses}}\n    ingress: {{mode: semantic, decoder: {ingress}}}\n    target: {{provider: local, path: /v1/responses}}\n{limits}    response: {{mode: semantic, decoder: {decoder}, encoder: {encoder}}}\n    loss_policy: reject\n"
        );
        Config::from_yaml("openai.yaml", &source)
            .expect("config parses")
            .compile()
            .expect("config compiles")
            .routes()[0]
            .clone()
    }

    fn route_with_request_encoder(
        ingress: &str,
        request_encoder: &str,
        decoder: &str,
        encoder: &str,
    ) -> pooler_config::RoutePlan {
        let source = format!(
            "version: 2\nlisteners: {{openai: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://127.0.0.1:9}}}}\nroutes:\n  - id: openai\n    listen: openai\n    match: {{method: POST, path: /v1/responses}}\n    ingress: {{mode: semantic, decoder: {ingress}, encoder: {request_encoder}}}\n    target: {{provider: local, path: /v1/responses}}\n    response: {{mode: semantic, decoder: {decoder}, encoder: {encoder}}}\n    loss_policy: reject\n"
        );
        Config::from_yaml("openai-request-encoder.yaml", &source)
            .expect("config parses")
            .compile()
            .expect("config compiles")
            .routes()[0]
            .clone()
    }

    async fn reduce_responses_sse_to_unary(events: &[Value]) -> Value {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let source = events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect::<String>();
        let body = Full::new(Bytes::from(source))
            .map_err(|never| match never {})
            .boxed();
        let response = OpenAiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    upstream_mode: SemanticResponseMode::ServerSentEvents,
                    requested_model: Some("openai-model".to_owned()),
                },
                CancellationToken::new(),
            )
            .expect("streaming unary transformer");
        let bytes = response
            .body
            .collect()
            .await
            .expect("streaming unary body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("streaming unary JSON")
    }

    #[test]
    fn supports_responses_and_chat_without_factory_route_identity() {
        let adapter = OpenAiSemanticAdapter;
        assert!(adapter.supports(&route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        )));
        assert!(adapter.supports(&route(
            OPENAI_CHAT_REQUEST_DECODER,
            OPENAI_CHAT_EVENT_DECODER,
            OPENAI_CHAT_EVENT_ENCODER,
        )));
        assert!(adapter.supports(&route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_CHAT_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        )));
        assert!(!adapter.supports(&route(
            "decode.factory.language_model",
            OPENAI_CHAT_EVENT_DECODER,
            "encode.factory.events",
        )));
        assert!(adapter.supports(&route_with_request_encoder(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_REQUEST_ENCODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        )));
        assert!(!adapter.supports(&route_with_request_encoder(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_CHAT_REQUEST_ENCODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        )));
    }

    #[test]
    fn installed_openai_shape_encodes_as_streaming_responses() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let request = json!({
            "model":"openai-model",
            "input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],
            "tools":[{
                "type":"function","name":"Read","description":"read",
                "parameters":{"type":"object","properties":{},"additionalProperties":false},
                "strict":false
            }],
            "tool_choice":"auto",
            "parallel_tool_calls":true,
            "reasoning":{"effort":"low","summary":"auto"},
            "include":["reasoning.encrypted_content"],
            "store":false,
            "stream":true
        });
        let encoded = OpenAiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                &serde_json::to_vec(&request).expect("request JSON"),
            )
            .expect("OpenAI request encodes");
        assert_eq!(
            encoded.content_type,
            HeaderValue::from_static("application/json")
        );
        let value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
        assert_eq!(value["include"][0], "reasoning.encrypted_content");
        assert_eq!(value["tools"][0]["name"], "Read");
    }

    #[test]
    fn responses_tool_follow_up_converts_to_chat_messages() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_CHAT_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let request = json!({
            "model":"openai-model",
            "input":[
                {"role":"user","content":[{"type":"input_text","text":"read"}]},
                {"type":"function_call","call_id":"call_1","name":"Read","arguments":"{}"},
                {"type":"function_call_output","call_id":"call_1","output":"done"}
            ],
            "stream":true,
            "store":false
        });
        let encoded = OpenAiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                &serde_json::to_vec(&request).expect("request JSON"),
            )
            .expect("cross-protocol request encodes");
        let value: Value = serde_json::from_slice(&encoded.body).expect("encoded Chat JSON");
        assert_eq!(value["stream"], true);
        assert_eq!(value["stream_options"]["include_usage"], true);
        assert_eq!(value["messages"][1]["tool_calls"][0]["id"], "call_1");
        assert_eq!(value["messages"][2]["tool_call_id"], "call_1");
    }

    #[tokio::test]
    async fn chat_stream_translates_to_responses_named_events() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_CHAT_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let source = concat!(
            "data: {\"id\":\"chat_1\",\"model\":\"model-a\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat_1\",\"model\":\"model-a\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"DROID_OK\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat_1\",\"model\":\"model-a\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n",
            "data: [DONE]\n\n"
        );
        let body = Full::new(Bytes::from_static(source.as_bytes()))
            .map_err(|never| match never {})
            .boxed();
        let response = OpenAiSemanticAdapter
            .decode_response(&route, body, CancellationToken::new())
            .expect("response transformer");
        let bytes = response
            .body
            .collect()
            .await
            .expect("translated body")
            .to_bytes();
        let mut parser = SseParser::new();
        let mut events = parser.feed(&bytes).expect("Responses SSE parses");
        events.extend(parser.finish().expect("complete Responses SSE"));
        assert!(events.iter().any(|event| {
            event.event.as_deref() == Some("response.output_text.delta")
                && event.data.contains("DROID_OK")
        }));
        assert!(events
            .iter()
            .any(|event| event.event.as_deref() == Some("response.completed")));
        assert!(!events.iter().any(|event| event.data == "[DONE]"));
    }

    #[test]
    fn accepts_non_streaming_requests_and_selects_json_response() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let request = json!({"model":"openai-model","input":"hello","stream":false});
        let encoded = OpenAiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                &serde_json::to_vec(&request).expect("request JSON"),
            )
            .expect("non-streaming route encodes");
        let value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
        assert_eq!(value["stream"], false);
        assert_eq!(encoded.response_hint.mode, SemanticResponseMode::Json);
        assert_eq!(
            encoded.response_hint.requested_model.as_deref(),
            Some("openai-model")
        );
    }

    #[test]
    fn unary_responses_to_chat_is_rejected_before_upstream() {
        let reject = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_CHAT_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let request = json!({"model":"openai-model","input":"hello","stream":false});
        let body = serde_json::to_vec(&request).expect("request JSON");
        let error = OpenAiSemanticAdapter
            .encode_request(&reject, &HeaderMap::new(), &body)
            .expect_err("unary cross-protocol route must fail before upstream");
        assert!(error.to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn responses_unary_preserves_native_json_response() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let source = json!({
            "id":"resp_1",
            "object":"response",
            "status":"completed",
            "model":"openai-model",
            "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"DROID_JSON_OK","annotations":[]}]}],
            "usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}
        });
        let source_bytes = serde_json::to_vec(&source).expect("source JSON");
        let body = Full::new(Bytes::from(source_bytes.clone()))
            .map_err(|never| match never {})
            .boxed();
        let response = OpenAiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    requested_model: Some("openai-model".to_owned()),
                    ..SemanticResponseHint::default()
                },
                CancellationToken::new(),
            )
            .expect("unary response transformer");
        assert_eq!(
            response.content_type,
            HeaderValue::from_static("application/json")
        );
        let bytes = response
            .body
            .collect()
            .await
            .expect("translated body")
            .to_bytes();
        assert_eq!(bytes.as_ref(), source_bytes.as_slice());
    }

    #[tokio::test]
    async fn streaming_unary_waits_for_terminal_and_honors_limits_and_cancellation() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let incomplete = concat!(
            "data: {\"type\":\"response.created\",\"response\":{",
            "\"id\":\"resp_incomplete\",\"model\":\"openai-model\",",
            "\"status\":\"in_progress\"}}\n\n"
        );
        let body = Full::new(Bytes::from_static(incomplete.as_bytes()))
            .map_err(|never| match never {})
            .boxed();
        let response = OpenAiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    upstream_mode: SemanticResponseMode::ServerSentEvents,
                    requested_model: Some("openai-model".to_owned()),
                },
                CancellationToken::new(),
            )
            .expect("streaming unary transformer");
        let error = response
            .body
            .collect()
            .await
            .expect_err("incomplete SSE must not emit unary JSON");
        assert!(error.to_string().contains("without response.completed"));

        let limited_route = route_with_response_limit(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
            Some(32),
        );
        let body = Full::new(Bytes::from_static(incomplete.as_bytes()))
            .map_err(|never| match never {})
            .boxed();
        let response = OpenAiSemanticAdapter
            .decode_response_with_hint(
                &limited_route,
                body,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    upstream_mode: SemanticResponseMode::ServerSentEvents,
                    requested_model: Some("openai-model".to_owned()),
                },
                CancellationToken::new(),
            )
            .expect("limited streaming unary transformer");
        let error = response
            .body
            .collect()
            .await
            .expect_err("streaming unary input must obey the response limit");
        assert!(error.to_string().contains("exceeded"));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let body = Full::new(Bytes::from_static(incomplete.as_bytes()))
            .map_err(|never| match never {})
            .boxed();
        let response = OpenAiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    upstream_mode: SemanticResponseMode::ServerSentEvents,
                    requested_model: Some("openai-model".to_owned()),
                },
                cancellation,
            )
            .expect("cancelable streaming unary transformer");
        let error = response
            .body
            .collect()
            .await
            .expect_err("canceled streaming unary response must fail");
        assert!(error.to_string().contains("canceled"));
    }

    #[test]
    fn raw_terminal_hydration_preserves_fields_and_restores_missing_item_ids() {
        let mut response = json!({
            "id":"resp_exact",
            "created_at":1_777_777_777,
            "service_tier":"priority",
            "reasoning":{"effort":"none","summary":"auto"},
            "tools":[{"type":"function","name":"lookup"}],
            "metadata":{"trace_id":"trace_exact"},
            "output":[{"type":"function_call","call_id":"call_exact","name":"lookup","arguments":"{}"}]
        });
        let indexed = std::collections::BTreeMap::from([(
            0,
            json!({
                "id":"fc_exact","type":"function_call","call_id":"call_exact",
                "name":"lookup","arguments":"{}"
            }),
        )]);
        hydrate_raw_terminal_output(&mut response, &indexed, &[]).expect("raw terminal hydrates");
        assert_eq!(response["output"][0]["id"], "fc_exact");
        assert_eq!(response["created_at"], 1_777_777_777_u64);
        assert_eq!(response["service_tier"], "priority");
        assert_eq!(response["reasoning"]["effort"], "none");
        assert_eq!(response["tools"][0]["name"], "lookup");
        assert_eq!(response["metadata"]["trace_id"], "trace_exact");
    }

    #[tokio::test]
    async fn streaming_unary_preserves_refusal_lifecycle_and_terminal_only_output() {
        let refusal_item = json!({
            "id":"msg_refusal","type":"message","status":"completed","role":"assistant",
            "content":[{"type":"refusal","refusal":"cannot comply"}]
        });
        let refusal_terminal = json!({
            "id":"resp_refusal","object":"response","created_at":1_777_777_778_u64,
            "model":"openai-model","status":"completed","service_tier":"priority",
            "output":[],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4},
            "metadata":{"case":"refusal-lifecycle"}
        });
        let refusal = reduce_responses_sse_to_unary(&[
            json!({
                "type":"response.created",
                "response":{"id":"resp_refusal","model":"openai-model","status":"in_progress"}
            }),
            json!({
                "type":"response.output_item.added","output_index":0,
                "item":{"id":"msg_refusal","type":"message","status":"in_progress","role":"assistant","content":[]}
            }),
            json!({
                "type":"response.content_part.added","item_id":"msg_refusal",
                "output_index":0,"content_index":0,
                "part":{"type":"refusal","refusal":""}
            }),
            json!({
                "type":"response.refusal.delta","item_id":"msg_refusal",
                "output_index":0,"content_index":0,"delta":"cannot comply"
            }),
            json!({
                "type":"response.refusal.done","item_id":"msg_refusal",
                "output_index":0,"content_index":0,"refusal":"cannot comply"
            }),
            json!({
                "type":"response.content_part.done","item_id":"msg_refusal",
                "output_index":0,"content_index":0,
                "part":{"type":"refusal","refusal":"cannot comply"}
            }),
            json!({
                "type":"response.output_item.done","output_index":0,
                "item":refusal_item.clone()
            }),
            json!({"type":"response.completed","response":refusal_terminal.clone()}),
        ])
        .await;
        let mut expected_refusal = refusal_terminal;
        expected_refusal["output"] = Value::Array(vec![refusal_item]);
        assert_eq!(refusal, expected_refusal);

        let terminal_only = json!({
            "id":"resp_terminal_only","object":"response","created_at":1_777_777_779_u64,
            "model":"openai-model","status":"completed","service_tier":"default",
            "output":[{
                "id":"msg_terminal_only","type":"message","status":"completed",
                "role":"assistant","content":[{"type":"refusal","refusal":"terminal only"}]
            }],
            "reasoning":{"effort":"none","summary":null},
            "tools":[],"metadata":{"case":"terminal-only"}
        });
        let terminal = reduce_responses_sse_to_unary(&[
            json!({
                "type":"response.created",
                "response":{"id":"resp_terminal_only","model":"openai-model","status":"in_progress"}
            }),
            json!({"type":"response.completed","response":terminal_only.clone()}),
        ])
        .await;
        assert_eq!(terminal, terminal_only);
    }

    #[tokio::test]
    async fn streaming_unary_handles_many_immediately_ready_frames_without_recursion() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let terminal = json!({
            "id":"resp_many_frames","object":"response","created_at":1_777_777_780_u64,
            "model":"openai-model","status":"completed","output":[],
            "metadata":{"case":"many-ready-frames"}
        });
        let source = [
            json!({
                "type":"response.created",
                "response":{"id":"resp_many_frames","model":"openai-model","status":"in_progress"}
            }),
            json!({"type":"response.completed","response":terminal.clone()}),
        ]
        .into_iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect::<String>();
        let mut frames = std::iter::repeat_n(Bytes::from_static(b": keepalive\n\n"), 20_000)
            .collect::<VecDeque<_>>();
        frames.extend(source.bytes().map(|byte| Bytes::copy_from_slice(&[byte])));
        let body = ImmediatelyReadyFrames { frames }.boxed();
        let response = OpenAiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    upstream_mode: SemanticResponseMode::ServerSentEvents,
                    requested_model: Some("openai-model".to_owned()),
                },
                CancellationToken::new(),
            )
            .expect("many-frame streaming unary transformer");
        let bytes = response
            .body
            .collect()
            .await
            .expect("many-frame streaming unary response")
            .to_bytes();
        let actual: Value = serde_json::from_slice(&bytes).expect("many-frame unary JSON");
        assert_eq!(actual, terminal);
    }
}
