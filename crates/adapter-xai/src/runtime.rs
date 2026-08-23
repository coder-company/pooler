//! HTTP runtime seam for xAI Chat Completions and Responses routes.

use std::{
    collections::VecDeque,
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
    EncodedResponsesEvent, ExtensionKey, LossPolicy, OpenAiResponsesCodec,
    OpenAiResponsesEventDecoder, OpenAiResponsesEventEncoder, SemanticRequest, StreamEvent,
    StreamEventKind, Usage, OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION,
    OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION,
};
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    XaiChatEventDecoder, XaiChatEventEncoder, XaiRealtimeEventDecoder, XaiRestAdapter,
    XaiRestEndpoint, XaiRestTransport,
};

/// Semantic decoder for an xAI Chat Completions request.
pub const XAI_CHAT_REQUEST_DECODER: &str = "decode.xai.chat";
/// Semantic encoder for an xAI Chat Completions request.
pub const XAI_CHAT_REQUEST_ENCODER: &str = "encode.xai.chat";
/// Semantic decoder for xAI Chat Completions SSE data chunks.
pub const XAI_CHAT_EVENT_DECODER: &str = "decode.xai.chat.events";
/// Semantic encoder for xAI Chat Completions SSE data chunks.
pub const XAI_CHAT_EVENT_ENCODER: &str = "encode.xai.chat.events";
/// Semantic decoder for an xAI Responses request.
pub const XAI_RESPONSES_REQUEST_DECODER: &str = "decode.xai.responses";
/// Semantic encoder for an xAI Responses request.
pub const XAI_RESPONSES_REQUEST_ENCODER: &str = "encode.xai.responses";
/// Semantic decoder for named xAI Responses SSE events.
pub const XAI_RESPONSES_EVENT_DECODER: &str = "decode.xai.responses.events";
/// Semantic encoder for named xAI Responses SSE events.
pub const XAI_RESPONSES_EVENT_ENCODER: &str = "encode.xai.responses.events";

/// Runtime adapter for xAI's REST endpoints.
///
/// Streaming requests use the semantic SSE pipeline; unary requests retain
/// the provider's bounded JSON response representation.
///
/// Long-lived xAI Responses WebSocket routes intentionally remain opaque.
/// Their messages are independently bounded by the route and can be checked
/// with [`crate::XaiRealtimeRequestCodec`] and
/// [`crate::XaiRealtimeEventDecoder`] without collapsing a multi-turn socket
/// into the single-request HTTP semantic lifecycle.
#[derive(Clone, Copy, Debug, Default)]
pub struct XaiSemanticAdapter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestWire {
    Chat,
    Responses,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventWire {
    Chat,
    Responses,
}

impl SemanticAdapter for XaiSemanticAdapter {
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
            .ok_or_else(|| Box::new(XaiRuntimeError::UnsupportedRoute) as BoxError)?;
        let (request, streaming) = decode_request(request_wire, body, route.loss_policy())?;
        let downstream_wire = match request_wire {
            RequestWire::Chat => EventWire::Chat,
            RequestWire::Responses => EventWire::Responses,
        };
        if !streaming && downstream_wire != upstream_wire {
            return Err(Box::new(XaiRuntimeError::UnaryCrossProtocolUnsupported {
                downstream: downstream_wire,
                upstream: upstream_wire,
            }));
        }
        let body =
            encode_upstream_request(upstream_wire, &request, streaming, route.loss_policy())?;
        Ok(SemanticRequestBody {
            body,
            content_type: HeaderValue::from_static("application/json"),
            response_hint: SemanticResponseHint {
                mode: if streaming {
                    SemanticResponseMode::ServerSentEvents
                } else {
                    SemanticResponseMode::Json
                },
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
            .ok_or_else(|| Box::new(XaiRuntimeError::UnsupportedRoute) as BoxError)?;
        let (request, streaming) = decode_request(request_wire, body, route.loss_policy())?;
        let mut context = SelectionContext::from_semantic_request(&request);
        if streaming {
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
        .then_some(SemanticWebSocketTransport::XaiResponses)
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let (request_wire, upstream_wire) = route_wires(route)
            .ok_or_else(|| Box::new(XaiRuntimeError::UnsupportedRoute) as BoxError)?;
        let downstream_wire = match request_wire {
            RequestWire::Chat => EventWire::Chat,
            RequestWire::Responses => EventWire::Responses,
        };
        decode_response_for_mode(
            route,
            body,
            upstream_wire,
            downstream_wire,
            SemanticResponseMode::ServerSentEvents,
            cancellation,
        )
    }

    fn decode_response_with_hint(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let (request_wire, upstream_wire) = route_wires(route)
            .ok_or_else(|| Box::new(XaiRuntimeError::UnsupportedRoute) as BoxError)?;
        let downstream_wire = match request_wire {
            RequestWire::Chat => EventWire::Chat,
            RequestWire::Responses => EventWire::Responses,
        };
        decode_response_for_mode(
            route,
            body,
            upstream_wire,
            downstream_wire,
            hint.mode,
            cancellation,
        )
    }
}

fn decode_response_for_mode(
    route: &RoutePlan,
    body: ProxyBody,
    upstream_wire: EventWire,
    downstream_wire: EventWire,
    mode: SemanticResponseMode,
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    if mode == SemanticResponseMode::Json {
        if upstream_wire != downstream_wire {
            return Err(Box::new(XaiRuntimeError::UnaryCrossProtocolUnsupported {
                downstream: downstream_wire,
                upstream: upstream_wire,
            }));
        }
        return Ok(unary_response(
            route,
            body,
            upstream_wire,
            downstream_wire,
            cancellation,
        ));
    }
    let limits = SseLimits::new(
        usize_limit(route.limits().max_frame_bytes),
        usize_limit(route.limits().max_event_bytes),
    );
    let stream = XaiResponseBody::new(
        body,
        upstream_wire,
        downstream_wire,
        route.loss_policy(),
        limits,
        usize_limit(u64::from(route.limits().max_queue_items)),
        usize_limit(route.limits().max_queue_bytes),
        cancellation,
    );
    Ok(SemanticResponseBody {
        body: stream.boxed(),
        content_type: HeaderValue::from_static("text/event-stream"),
    })
}

fn route_wires(route: &RoutePlan) -> Option<(RequestWire, EventWire)> {
    if route.matcher().websocket() == Some(true)
        || route.ingress().mode() != pooler_core::BodyMode::Semantic
        || route.response().mode() != pooler_core::BodyMode::Semantic
    {
        return None;
    }
    let request = match route.ingress().decoder()? {
        XAI_CHAT_REQUEST_DECODER => RequestWire::Chat,
        XAI_RESPONSES_REQUEST_DECODER => RequestWire::Responses,
        _ => return None,
    };
    let expected_request_encoder = match request {
        RequestWire::Chat => XAI_CHAT_REQUEST_ENCODER,
        RequestWire::Responses => XAI_RESPONSES_REQUEST_ENCODER,
    };
    if route
        .ingress()
        .encoder()
        .is_some_and(|encoder| encoder != expected_request_encoder)
    {
        return None;
    }
    let upstream = match route.response().decoder()? {
        XAI_CHAT_EVENT_DECODER => EventWire::Chat,
        XAI_RESPONSES_EVENT_DECODER => EventWire::Responses,
        _ => return None,
    };
    let expected_response_encoder = match request {
        RequestWire::Chat => XAI_CHAT_EVENT_ENCODER,
        RequestWire::Responses => XAI_RESPONSES_EVENT_ENCODER,
    };
    (route.response().encoder() == Some(expected_response_encoder)).then_some((request, upstream))
}

fn decode_request(
    wire: RequestWire,
    body: &[u8],
    policy: LossPolicy,
) -> Result<(SemanticRequest, bool), BoxError> {
    match wire {
        RequestWire::Chat => {
            let decoded = XaiRestAdapter::default()
                .decode_chat_request(body, policy)
                .map_err(|error| Box::new(error) as BoxError)?;
            let streaming = request_streaming(body)?;
            Ok((decoded.request, streaming))
        }
        RequestWire::Responses => {
            let prepared = XaiRestAdapter::default()
                .prepare_request(
                    XaiRestEndpoint::Responses,
                    XaiRestTransport::Http,
                    body,
                    policy,
                )
                .map_err(|error| Box::new(error) as BoxError)?;
            let decoded = OpenAiResponsesCodec::decode_request_with_report(&prepared.body)
                .map_err(|error| Box::new(error) as BoxError)?;
            let mut report = decoded.report;
            report.merge(prepared.report);
            report
                .validate(policy)
                .map_err(|error| Box::new(error) as BoxError)?;
            Ok((decoded.request, decoded.stream))
        }
    }
}

fn request_streaming(body: &[u8]) -> Result<bool, BoxError> {
    let value: Value = serde_json::from_slice(body)?;
    Ok(value
        .as_object()
        .and_then(|object| object.get("stream"))
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn encode_upstream_request(
    wire: EventWire,
    request: &SemanticRequest,
    streaming: bool,
    policy: LossPolicy,
) -> Result<Vec<u8>, BoxError> {
    let (request, passthrough) = prepare_request_for_wire(wire, request, policy)?;
    let body = match wire {
        EventWire::Chat => {
            XaiRestAdapter::default()
                .encode_chat_request(&request, policy)
                .map_err(|error| Box::new(error) as BoxError)?
                .body
        }
        EventWire::Responses => {
            OpenAiResponsesCodec::encode_request(&request, policy)
                .map_err(|error| Box::new(error) as BoxError)?
                .body
        }
    };
    let mut value: Value = serde_json::from_slice(&body)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Box::new(XaiRuntimeError::EncodedRequestNotObject) as BoxError)?;
    for (key, value) in passthrough {
        object.entry(key).or_insert(value);
    }
    object.insert("stream".to_owned(), Value::Bool(streaming));
    match wire {
        EventWire::Chat => {
            if streaming {
                object.insert(
                    "stream_options".to_owned(),
                    serde_json::json!({"include_usage": true}),
                );
            } else {
                object.remove("stream_options");
            }
        }
        EventWire::Responses => {
            object.entry("store").or_insert(Value::Bool(false));
        }
    }
    let body = serde_json::to_vec(&value)?;
    XaiRestAdapter::default()
        .prepare_request(
            match wire {
                EventWire::Chat => XaiRestEndpoint::ChatCompletions,
                EventWire::Responses => XaiRestEndpoint::Responses,
            },
            XaiRestTransport::Http,
            &body,
            policy,
        )
        .map(|prepared| prepared.body)
        .map_err(|error| Box::new(error) as BoxError)
}

fn prepare_request_for_wire(
    wire: EventWire,
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<(SemanticRequest, serde_json::Map<String, Value>), BoxError> {
    let mut request = request.clone();
    let foreign_extension = match wire {
        EventWire::Chat => OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION,
        EventWire::Responses => OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION,
    };
    let key =
        ExtensionKey::parse(foreign_extension).map_err(|error| Box::new(error) as BoxError)?;
    let Some(extension) = request.extensions.remove(&key) else {
        return Ok((request, serde_json::Map::new()));
    };
    let value: Value = serde_json::from_slice(extension.as_bytes())?;
    let fields = value
        .as_object()
        .ok_or_else(|| Box::new(XaiRuntimeError::InvalidTransportExtension) as BoxError)?;
    let mut passthrough = serde_json::Map::new();
    for (field, value) in fields {
        match field.as_str() {
            "stream" | "stream_options" => {}
            "store" | "parallel_tool_calls" | "prompt_cache_key" => {
                passthrough.insert(field.clone(), value.clone());
            }
            _ if policy.allows_degradation() => {}
            _ => {
                return Err(Box::new(XaiRuntimeError::UnsupportedCrossProtocolField(
                    field.clone(),
                )));
            }
        }
    }
    Ok((request, passthrough))
}

#[derive(Debug, Error)]
enum XaiRuntimeError {
    #[error("route is not a supported xAI REST semantic route")]
    UnsupportedRoute,
    #[error(
        "xAI unary REST responses cannot translate between {downstream:?} and {upstream:?} wires"
    )]
    UnaryCrossProtocolUnsupported {
        downstream: EventWire,
        upstream: EventWire,
    },
    #[error("encoded xAI request is not a JSON object")]
    EncodedRequestNotObject,
    #[error("xAI transport extension is not a JSON object")]
    InvalidTransportExtension,
    #[error("xAI unary response JSON must be an object")]
    UnaryResponseNotObject,
    #[error("xAI field `{0}` cannot be preserved across Responses and Chat")]
    UnsupportedCrossProtocolField(String),
}

enum UpstreamDecoder {
    Chat(XaiChatEventDecoder),
    Responses(XaiResponsesEventDecoder),
}

impl UpstreamDecoder {
    fn new(wire: EventWire) -> Self {
        match wire {
            EventWire::Chat => Self::Chat(XaiChatEventDecoder::new()),
            EventWire::Responses => Self::Responses(XaiResponsesEventDecoder::new()),
        }
    }

    fn decode(&mut self, event: &SseEvent) -> Result<Vec<StreamEvent>, BoxError> {
        match self {
            Self::Chat(decoder) => decoder
                .decode_data(event.data.as_bytes())
                .map_err(|error| Box::new(error) as BoxError),
            Self::Responses(decoder) => decoder.decode(event),
        }
    }

    fn finish(&mut self) -> Result<Vec<StreamEvent>, BoxError> {
        match self {
            Self::Chat(decoder) => decoder
                .finish()
                .map_err(|error| Box::new(error) as BoxError),
            Self::Responses(decoder) => decoder.finish(),
        }
    }
}

/// xAI Responses REST uses the ordinary Responses event vocabulary. The xAI
/// decoder validates provider sequencing, connection lifecycle, and bounds;
/// the shared decoder supplies the canonical semantic mapping used by the
/// matching encoder. This avoids treating redundant wire lifecycle objects as
/// semantic opaque payloads while still rejecting unknown event types.
struct XaiResponsesEventDecoder {
    contract: XaiRealtimeEventDecoder,
    semantic: OpenAiResponsesEventDecoder,
}

impl XaiResponsesEventDecoder {
    fn new() -> Self {
        Self {
            contract: XaiRealtimeEventDecoder::default(),
            semantic: OpenAiResponsesEventDecoder::new(),
        }
    }

    fn decode(&mut self, event: &SseEvent) -> Result<Vec<StreamEvent>, BoxError> {
        let validated = self
            .contract
            .decode_message(event.data.as_bytes())
            .map_err(|error| Box::new(error) as BoxError)?;
        let provider_usage = validated
            .semantic_events
            .iter()
            .find_map(|event| match &event.kind {
                StreamEventKind::Usage { usage }
                | StreamEventKind::Completion {
                    usage: Some(usage), ..
                } => Some(usage.clone()),
                _ => None,
            });
        let mut semantic = self
            .semantic
            .decode_event(event.event.as_deref(), event.data.as_bytes())
            .map_err(|error| Box::new(error) as BoxError)?;
        if let Some(provider_usage) = provider_usage {
            for event in &mut semantic {
                match &mut event.kind {
                    StreamEventKind::Usage { usage }
                    | StreamEventKind::Completion {
                        usage: Some(usage), ..
                    } => usage.clone_from(&provider_usage),
                    _ => {}
                }
            }
        }
        Ok(semantic)
    }

    fn finish(&mut self) -> Result<Vec<StreamEvent>, BoxError> {
        self.contract
            .finish()
            .map_err(|error| Box::new(error) as BoxError)?;
        self.semantic
            .finish()
            .map_err(|error| Box::new(error) as BoxError)
    }
}

enum DownstreamEncoder {
    Chat(XaiChatEventEncoder),
    Responses(Box<XaiResponsesEventEncoder>),
}

impl DownstreamEncoder {
    fn new(wire: EventWire) -> Self {
        match wire {
            EventWire::Chat => Self::Chat(XaiChatEventEncoder::new()),
            EventWire::Responses => Self::Responses(Box::new(XaiResponsesEventEncoder::new())),
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
            Self::Chat(chat) => {
                let mut output = Vec::new();
                if let Some(encoded) = chat
                    .encode_event(event, policy)
                    .map_err(|error| Box::new(error) as BoxError)?
                {
                    output.push(Bytes::from(
                        encoder
                            .encode(&SseEvent::new(String::from_utf8(encoded.body).map_err(
                                |_| Box::new(XaiStreamError::InvalidJsonUtf8) as BoxError,
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
            Self::Responses(responses) => responses
                .encode_event(event, policy)
                .map_err(|error| Box::new(error) as BoxError)?
                .into_iter()
                .map(|encoded| {
                    encoder
                        .encode(
                            &SseEvent::new(String::from_utf8(encoded.body).map_err(|_| {
                                Box::new(XaiStreamError::InvalidJsonUtf8) as BoxError
                            })?)
                            .with_event(encoded.event),
                        )
                        .map(Bytes::from)
                        .map_err(|error| Box::new(error) as BoxError)
                })
                .collect(),
        }
    }
}

struct XaiResponsesEventEncoder {
    inner: OpenAiResponsesEventEncoder,
}

impl XaiResponsesEventEncoder {
    fn new() -> Self {
        Self {
            inner: OpenAiResponsesEventEncoder::new(),
        }
    }

    fn encode_event(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<Vec<EncodedResponsesEvent>, pooler_protocol::OpenAiResponsesError> {
        let mut encoded = self.inner.encode_event(event, policy)?;
        let StreamEventKind::Completion {
            usage: Some(usage), ..
        } = &event.kind
        else {
            return Ok(encoded);
        };
        for event in &mut encoded {
            enrich_xai_responses_usage(event, usage)?;
        }
        Ok(encoded)
    }
}

fn enrich_xai_responses_usage(
    event: &mut EncodedResponsesEvent,
    usage: &Usage,
) -> Result<(), pooler_protocol::OpenAiResponsesError> {
    if !usage.details.contains_key("cost_in_usd_ticks")
        && !usage.details.contains_key("num_sources_used")
    {
        return Ok(());
    }
    let mut value: Value = serde_json::from_slice(&event.body)?;
    let Some(encoded_usage) = value
        .get_mut("response")
        .and_then(|response| response.get_mut("usage"))
        .and_then(Value::as_object_mut)
    else {
        return Ok(());
    };
    for field in ["cost_in_usd_ticks", "num_sources_used"] {
        if let Some(value) = usage.details.get(field).copied() {
            encoded_usage.insert(field.to_owned(), Value::from(value));
        }
    }
    event.body = serde_json::to_vec(&value)?;
    Ok(())
}

struct XaiResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    decoder: UpstreamDecoder,
    encoder: DownstreamEncoder,
    policy: LossPolicy,
    limits: SseLimits,
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    max_queue_items: usize,
    max_queue_bytes: usize,
    cancellation: CancellationToken,
    ended: bool,
    error: Option<BoxError>,
}

impl XaiResponseBody {
    #[allow(clippy::too_many_arguments)]
    fn new(
        body: ProxyBody,
        upstream: EventWire,
        downstream: EventWire,
        policy: LossPolicy,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(limits),
            decoder: UpstreamDecoder::new(upstream),
            encoder: DownstreamEncoder::new(downstream),
            policy,
            limits,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_queue_items,
            max_queue_bytes,
            cancellation,
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
        for semantic in self.decoder.decode(event)? {
            for encoded in self.encoder.encode(&semantic, self.policy, self.limits)? {
                self.enqueue(encoded)?;
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
            for encoded in self.encoder.encode(&semantic, self.policy, self.limits)? {
                self.enqueue(encoded)?;
            }
        }
        self.ended = true;
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let items = self.queue.len().saturating_add(1);
        let bytes_total = self.queued_bytes.saturating_add(bytes.len());
        if items > self.max_queue_items || bytes_total > self.max_queue_bytes {
            return Err(Box::new(XaiStreamError::QueueLimit {
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

impl Body for XaiResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.cancellation.is_cancelled() {
                this.ended = true;
                return Poll::Ready(Some(Err(Box::new(XaiStreamError::Cancelled))));
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
                    Err(frame) => match frame.into_trailers() {
                        Ok(_) => {}
                        Err(_) => this.set_error(Box::new(XaiStreamError::InvalidFrame)),
                    },
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
enum XaiStreamError {
    #[error("xAI semantic response JSON was not UTF-8")]
    InvalidJsonUtf8,
    #[error("xAI unary response is too large: {observed} bytes exceeds limit {limit}")]
    UnaryTooLarge { observed: usize, limit: usize },
    #[error("xAI semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("xAI semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("xAI semantic response was canceled")]
    Cancelled,
}

fn unary_response(
    route: &RoutePlan,
    body: ProxyBody,
    upstream: EventWire,
    downstream: EventWire,
    cancellation: CancellationToken,
) -> SemanticResponseBody {
    let body = XaiUnaryResponseBody::new(
        body,
        upstream,
        downstream,
        usize_limit(route.limits().max_response_body_bytes),
        cancellation,
    );
    SemanticResponseBody {
        body: body.boxed(),
        content_type: HeaderValue::from_static("application/json"),
    }
}

/// Bounded xAI unary response forwarding.
///
/// Same-wire xAI Chat and Responses responses already use the downstream
/// protocol's complete JSON representation. We still parse the body before
/// forwarding it so malformed or non-object provider output cannot be
/// presented as a successful semantic response. Cross-wire unary conversion
/// is rejected by [`XaiSemanticAdapter`] until a complete response codec can
/// account for provider-specific fields without silently dropping them.
struct XaiUnaryResponseBody {
    inner: Pin<Box<ProxyBody>>,
    upstream: EventWire,
    downstream: EventWire,
    buffer: Vec<u8>,
    limit: usize,
    cancellation: CancellationToken,
    output: Option<Bytes>,
    ended: bool,
    error: Option<BoxError>,
}

impl XaiUnaryResponseBody {
    fn new(
        body: ProxyBody,
        upstream: EventWire,
        downstream: EventWire,
        limit: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner: Box::pin(body),
            upstream,
            downstream,
            buffer: Vec::new(),
            limit,
            cancellation,
            output: None,
            ended: false,
            error: None,
        }
    }

    fn finish(&mut self) -> Result<(), BoxError> {
        if self.upstream != self.downstream {
            return Err(Box::new(XaiRuntimeError::UnaryCrossProtocolUnsupported {
                downstream: self.downstream,
                upstream: self.upstream,
            }));
        }
        let value: Value = serde_json::from_slice(&self.buffer)?;
        if !value.is_object() {
            return Err(Box::new(XaiRuntimeError::UnaryResponseNotObject));
        }
        self.output = Some(Bytes::from(std::mem::take(&mut self.buffer)));
        self.ended = true;
        Ok(())
    }
}

impl Body for XaiUnaryResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.cancellation.is_cancelled() {
                this.ended = true;
                return Poll::Ready(Some(Err(Box::new(XaiStreamError::Cancelled))));
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
                            this.error = Some(Box::new(XaiStreamError::UnaryTooLarge {
                                observed,
                                limit: this.limit,
                            }));
                        } else {
                            this.buffer.extend_from_slice(&data);
                        }
                    }
                    Err(frame) => match frame.into_trailers() {
                        Ok(_) => {}
                        Err(_) => this.error = Some(Box::new(XaiStreamError::InvalidFrame)),
                    },
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

fn usize_limit(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
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
    use pooler_config::{compile_yaml, RoutePlan};
    use pooler_http::{BoxError, ProxyBody, SemanticAdapter, SseParser};
    use serde_json::Value;
    use tokio_util::sync::CancellationToken;

    use super::{XaiSemanticAdapter, XAI_CHAT_REQUEST_DECODER, XAI_RESPONSES_REQUEST_DECODER};

    struct ImmediateFrames {
        frames: VecDeque<Bytes>,
    }

    impl Body for ImmediateFrames {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(
                self.as_mut()
                    .get_mut()
                    .frames
                    .pop_front()
                    .map(|data| Ok(Frame::data(data))),
            )
        }

        fn is_end_stream(&self) -> bool {
            self.frames.is_empty()
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::new()
        }
    }

    fn immediate_frames(frames: impl IntoIterator<Item = Bytes>) -> ProxyBody {
        ImmediateFrames {
            frames: frames.into_iter().collect(),
        }
        .boxed()
    }

    fn route(decoder: &str, response_decoder: &str, response_encoder: &str) -> RoutePlan {
        compile_yaml(
            "xai-runtime.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:1}}}}\nupstreams: {{xai: {{url: https://api.x.ai}}}}\nroutes:\n  - id: xai\n    listen: local\n    match: {{method: POST, path: /v1/responses}}\n    ingress: {{mode: semantic, decoder: {decoder}}}\n    target: {{provider: xai}}\n    response: {{mode: semantic, decoder: {response_decoder}, encoder: {response_encoder}}}\n    loss_policy: reject\n"
            ),
        )
        .expect("xAI config")
        .route("xai")
        .expect("xAI route")
        .clone()
    }

    #[tokio::test]
    async fn response_bodies_handle_many_immediately_ready_frames_without_recursion() {
        const READY_FRAMES: usize = 100_000;

        let route = route(
            XAI_CHAT_REQUEST_DECODER,
            super::XAI_CHAT_EVENT_DECODER,
            super::XAI_CHAT_EVENT_ENCODER,
        );
        let mut streaming_chunks = Vec::with_capacity(READY_FRAMES + 2);
        streaming_chunks.extend(std::iter::repeat_n(
            Bytes::from_static(b": keepalive\n\n"),
            READY_FRAMES,
        ));
        streaming_chunks.push(Bytes::from_static(
            br#"data: {"id":"chat-1","model":"grok-4.6","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

"#,
        ));
        streaming_chunks.push(Bytes::from_static(b"data: [DONE]\n\n"));
        let streaming = immediate_frames(streaming_chunks);
        let response = XaiSemanticAdapter
            .decode_response(&route, streaming, CancellationToken::new())
            .expect("xAI streaming response transformer");
        let bytes = response
            .body
            .collect()
            .await
            .expect("many ready streaming frames")
            .to_bytes();
        assert!(
            !bytes.is_empty(),
            "the terminal Chat stream should produce output"
        );

        let mut unary_chunks = Vec::with_capacity(READY_FRAMES + 2);
        unary_chunks.push(Bytes::from_static(b"{"));
        unary_chunks.extend(std::iter::repeat_n(Bytes::from_static(b" "), READY_FRAMES));
        unary_chunks.push(Bytes::from_static(b"}"));
        let response = XaiSemanticAdapter
            .decode_response_with_hint(
                &route,
                immediate_frames(unary_chunks),
                &HeaderMap::new(),
                &pooler_http::SemanticResponseHint {
                    mode: pooler_http::SemanticResponseMode::Json,
                    ..pooler_http::SemanticResponseHint::default()
                },
                CancellationToken::new(),
            )
            .expect("xAI unary response transformer");
        let bytes = response
            .body
            .collect()
            .await
            .expect("many ready unary frames")
            .to_bytes();
        assert_eq!(bytes.len(), READY_FRAMES + 2);
        assert_eq!(bytes.first(), Some(&b'{'));
        assert_eq!(bytes.last(), Some(&b'}'));
    }

    #[test]
    fn recognizes_chat_and_responses_components() {
        let chat = route(
            XAI_CHAT_REQUEST_DECODER,
            super::XAI_CHAT_EVENT_DECODER,
            super::XAI_CHAT_EVENT_ENCODER,
        );
        let responses = route(
            XAI_RESPONSES_REQUEST_DECODER,
            super::XAI_RESPONSES_EVENT_DECODER,
            super::XAI_RESPONSES_EVENT_ENCODER,
        );
        assert!(XaiSemanticAdapter.supports(&chat));
        assert!(XaiSemanticAdapter.supports(&responses));
    }

    #[test]
    fn validates_xai_request_and_forces_upstream_streaming_controls() {
        let route = route(
            XAI_RESPONSES_REQUEST_DECODER,
            super::XAI_RESPONSES_EVENT_DECODER,
            super::XAI_RESPONSES_EVENT_ENCODER,
        );
        let encoded = XaiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                br#"{"model":"grok-4.6","input":"hello","stream":true}"#,
            )
            .expect("xAI request");
        let body: Value = serde_json::from_slice(&encoded.body).expect("request JSON");
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
    }

    #[test]
    fn non_streaming_chat_request_uses_json_mode_and_preserves_false() {
        let route = route(
            XAI_CHAT_REQUEST_DECODER,
            super::XAI_CHAT_EVENT_DECODER,
            super::XAI_CHAT_EVENT_ENCODER,
        );
        let encoded = XaiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                br#"{"model":"grok-4.6","messages":[{"role":"user","content":"hello"}],"stream":false}"#,
            )
            .expect("non-streaming request");
        let body: Value = serde_json::from_slice(&encoded.body).expect("request JSON");
        assert_eq!(body["stream"], false);
        assert!(body.get("stream_options").is_none());
        assert_eq!(
            encoded.response_hint.mode,
            pooler_http::SemanticResponseMode::Json
        );

        let context = XaiSemanticAdapter
            .selection_context(
                &route,
                &HeaderMap::new(),
                br#"{"model":"grok-4.6","messages":[{"role":"user","content":"hello"}],"stream":false}"#,
            )
            .expect("selection context");
        assert!(!context
            .required_capabilities()
            .contains(pooler_core::Capability::Streaming));
    }

    #[tokio::test]
    async fn non_streaming_chat_response_is_bounded_json_not_sse() {
        let route = route(
            XAI_CHAT_REQUEST_DECODER,
            super::XAI_CHAT_EVENT_DECODER,
            super::XAI_CHAT_EVENT_ENCODER,
        );
        let response_body = br#"{"id":"chat-1","object":"chat.completion","model":"grok-4.6","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        let body = Full::new(Bytes::from_static(response_body))
            .map_err(|never| match never {})
            .boxed();
        let response = XaiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &pooler_http::SemanticResponseHint {
                    mode: pooler_http::SemanticResponseMode::Json,
                    ..pooler_http::SemanticResponseHint::default()
                },
                CancellationToken::new(),
            )
            .expect("xAI unary response transformer");
        assert_eq!(
            response.content_type,
            HeaderValue::from_static("application/json")
        );
        let bytes = response
            .body
            .collect()
            .await
            .expect("translated xAI JSON")
            .to_bytes();
        assert_eq!(bytes.as_ref(), response_body);
    }

    #[test]
    fn non_streaming_responses_request_uses_json_mode_and_preserves_false() {
        let route = route(
            XAI_RESPONSES_REQUEST_DECODER,
            super::XAI_RESPONSES_EVENT_DECODER,
            super::XAI_RESPONSES_EVENT_ENCODER,
        );
        let encoded = XaiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                br#"{"model":"grok-4.6","input":"hello","stream":false,"store":false}"#,
            )
            .expect("non-streaming Responses request");
        let body: Value = serde_json::from_slice(&encoded.body).expect("request JSON");
        assert_eq!(body["stream"], false);
        assert_eq!(body["store"], false);
        assert_eq!(
            encoded.response_hint.mode,
            pooler_http::SemanticResponseMode::Json
        );
    }

    #[test]
    fn rejects_non_streaming_cross_wire_translation_before_upstream() {
        let route = route(
            XAI_CHAT_REQUEST_DECODER,
            super::XAI_RESPONSES_EVENT_DECODER,
            super::XAI_CHAT_EVENT_ENCODER,
        );
        let error = XaiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                br#"{"model":"grok-4.6","messages":[{"role":"user","content":"hello"}],"stream":false}"#,
            )
            .expect_err("cross-wire unary request");
        assert!(error
            .to_string()
            .contains("cannot translate between Chat and Responses wires"));
    }

    #[tokio::test]
    async fn non_streaming_responses_response_is_bounded_json_not_sse() {
        let route = route(
            XAI_RESPONSES_REQUEST_DECODER,
            super::XAI_RESPONSES_EVENT_DECODER,
            super::XAI_RESPONSES_EVENT_ENCODER,
        );
        let response_body = br#"{"id":"resp-1","object":"response","status":"completed","model":"grok-4.6","output":[{"id":"msg-1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#;
        let body = Full::new(Bytes::from_static(response_body))
            .map_err(|never| match never {})
            .boxed();
        let response = XaiSemanticAdapter
            .decode_response_with_hint(
                &route,
                body,
                &HeaderMap::new(),
                &pooler_http::SemanticResponseHint {
                    mode: pooler_http::SemanticResponseMode::Json,
                    ..pooler_http::SemanticResponseHint::default()
                },
                CancellationToken::new(),
            )
            .expect("xAI unary Responses transformer");
        assert_eq!(
            response.content_type,
            HeaderValue::from_static("application/json")
        );
        let bytes = response
            .body
            .collect()
            .await
            .expect("translated xAI Responses JSON")
            .to_bytes();
        assert_eq!(bytes.as_ref(), response_body);
    }

    #[tokio::test]
    async fn responses_rest_stream_uses_xai_lifecycle_and_usage_contract() {
        let route = route(
            XAI_RESPONSES_REQUEST_DECODER,
            super::XAI_RESPONSES_EVENT_DECODER,
            super::XAI_RESPONSES_EVENT_ENCODER,
        );
        let source = include_str!("../../../fixtures/xai/responses-websocket-text.jsonl")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let value: Value = serde_json::from_str(line).expect("xAI fixture JSON");
                let event = value["type"].as_str().expect("xAI fixture type");
                format!("event: {event}\ndata: {line}\n\n")
            })
            .collect::<String>();
        let body = Full::new(Bytes::from(source))
            .map_err(|never| match never {})
            .boxed();
        let response = XaiSemanticAdapter
            .decode_response(&route, body, CancellationToken::new())
            .expect("xAI response transformer");
        let bytes = response
            .body
            .collect()
            .await
            .expect("translated xAI body")
            .to_bytes();
        let mut parser = SseParser::new();
        let mut events = parser.feed(&bytes).expect("xAI Responses SSE parses");
        events.extend(parser.finish().expect("complete xAI Responses SSE"));
        let completed = events
            .iter()
            .find(|event| event.event.as_deref() == Some("response.completed"))
            .expect("xAI Responses completion");
        let completed: Value = serde_json::from_str(&completed.data).expect("xAI completion JSON");
        assert_eq!(completed["response"]["usage"]["cost_in_usd_ticks"], 42);
        assert_eq!(completed["response"]["usage"]["num_sources_used"], 1);
    }
}
