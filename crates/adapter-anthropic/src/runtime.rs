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
    SemanticResponseBody, SemanticResponseHint, SemanticResponseMode, SemanticWire, SseEvent,
    SseLimits, SseParser,
};
use pooler_protocol::{
    ExtensionKey, LossPolicy, OpenAiChatCodec, OpenAiChatEventDecoder, OpenAiResponsesCodec,
    OpenAiResponsesEventDecoder, StreamError, StreamEvent, StreamEventKind,
};
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    AnthropicEventDecoder, AnthropicEventEncoder, AnthropicMessageCodec, AnthropicMessagesCodec,
    DECODE_ANTHROPIC_EVENTS, DECODE_ANTHROPIC_MESSAGES, ENCODE_ANTHROPIC_EVENTS,
    ENCODE_ANTHROPIC_MESSAGES,
};

/// Semantic adapter for Anthropic Messages requests and named SSE responses.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnthropicSemanticAdapter;

impl SemanticAdapter for AnthropicSemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        route.ingress().mode() == pooler_core::BodyMode::Semantic
            && route.ingress().decoder() == Some(DECODE_ANTHROPIC_MESSAGES)
            && matches!(
                route.ingress().encoder(),
                None | Some(ENCODE_ANTHROPIC_MESSAGES)
            )
            && route.response().mode() == pooler_core::BodyMode::Semantic
            && route.response().decoder() == Some(DECODE_ANTHROPIC_EVENTS)
            && route.response().encoder() == Some(ENCODE_ANTHROPIC_EVENTS)
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        let decoded = AnthropicMessagesCodec::decode_request_with_report(body)
            .map_err(|error| Box::new(error) as BoxError)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(|error| Box::new(error) as BoxError)?;
        let encoded = AnthropicMessagesCodec::encode_request(&decoded.request, route.loss_policy())
            .map_err(|error| Box::new(error) as BoxError)?;
        let value: Value =
            serde_json::from_slice(&encoded.body).map_err(|error| Box::new(error) as BoxError)?;
        let object = value
            .as_object()
            .ok_or(AnthropicRuntimeError::EncodedRequestNotObject)?;
        let response_mode = if object
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            SemanticResponseMode::ServerSentEvents
        } else {
            SemanticResponseMode::Json
        };
        Ok(SemanticRequestBody {
            body: serde_json::to_vec(&value).map_err(|error| Box::new(error) as BoxError)?,
            content_type: HeaderValue::from_static("application/json"),
            response_hint: SemanticResponseHint {
                mode: response_mode,
                requested_model: Some(decoded.request.model.clone()),
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
        let decoded = AnthropicMessagesCodec::decode_request_with_report(body)
            .map_err(|error| Box::new(error) as BoxError)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(|error| Box::new(error) as BoxError)?;
        let mut context = SelectionContext::from_semantic_request(&decoded.request);
        if request_has_server_tools(body)? {
            context.require(pooler_core::Capability::Tools);
            context.require(pooler_core::Capability::FunctionCalling);
        }
        if request_streaming(body)? {
            context.require(pooler_core::Capability::Streaming);
        }
        if let Some(user_id) = decoded.request.metadata.get("user_id") {
            context.with_affinity_value("anthropic.metadata.user_id", user_id);
        }
        Ok(context)
    }

    fn reencode_request_for_wire(
        &self,
        route: &RoutePlan,
        body: &[u8],
        wire: SemanticWire,
    ) -> Result<Vec<u8>, BoxError> {
        if wire == SemanticWire::AnthropicMessages {
            return Ok(body.to_vec());
        }
        let decoded = AnthropicMessagesCodec::decode_request_with_report(body)
            .map_err(|error| Box::new(error) as BoxError)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(|error| Box::new(error) as BoxError)?;
        let mut request = decoded.request;
        let stream = take_anthropic_stream(&mut request)?;
        match wire {
            SemanticWire::OpenAiResponses => {
                OpenAiResponsesCodec::encode_request(&request, route.loss_policy())
                    .map_err(|error| Box::new(error) as BoxError)
                    .and_then(|encoded| set_openai_stream(encoded.body, stream))
            }
            SemanticWire::OpenAiChat => {
                OpenAiChatCodec::encode_request(&request, route.loss_policy())
                    .map_err(|error| Box::new(error) as BoxError)
                    .and_then(|encoded| set_openai_stream(encoded.body, stream))
            }
            SemanticWire::AnthropicMessages => unreachable!(),
            SemanticWire::GeminiGenerateContent => {
                Err(Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire))
            }
        }
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        streaming_response(route, body, SemanticWire::AnthropicMessages, cancellation)
    }

    fn decode_response_with_hint(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let upstream_wire = hint
            .upstream_wire
            .unwrap_or(SemanticWire::AnthropicMessages);
        match hint.mode {
            SemanticResponseMode::Json
                if hint.upstream_mode == SemanticResponseMode::ServerSentEvents
                    || upstream_wire != SemanticWire::AnthropicMessages =>
            {
                transcoded_unary_response(
                    route,
                    body,
                    upstream_wire,
                    hint.upstream_mode,
                    cancellation,
                )
            }
            SemanticResponseMode::Json => unary_response(route, body, cancellation),
            SemanticResponseMode::AdapterDefault | SemanticResponseMode::ServerSentEvents => {
                streaming_response(route, body, upstream_wire, cancellation)
            }
        }
    }
}

fn take_anthropic_stream(request: &mut pooler_protocol::SemanticRequest) -> Result<bool, BoxError> {
    let key = ExtensionKey::parse("anthropic.messages.stream")
        .map_err(|error| Box::new(error) as BoxError)?;
    let Some(extension) = request.extensions.remove(&key) else {
        return Ok(false);
    };
    serde_json::from_slice::<Value>(extension.as_bytes())?
        .as_bool()
        .ok_or_else(|| Box::new(AnthropicRuntimeError::EncodedRequestNotObject) as BoxError)
}

fn set_openai_stream(body: Vec<u8>, stream: bool) -> Result<Vec<u8>, BoxError> {
    let mut value: Value =
        serde_json::from_slice(&body).map_err(|error| Box::new(error) as BoxError)?;
    value
        .as_object_mut()
        .ok_or_else(|| Box::new(AnthropicRuntimeError::EncodedRequestNotObject) as BoxError)?
        .insert("stream".to_owned(), Value::Bool(stream));
    serde_json::to_vec(&value).map_err(|error| Box::new(error) as BoxError)
}

fn request_has_server_tools(body: &[u8]) -> Result<bool, BoxError> {
    let value: Value = serde_json::from_slice(body).map_err(|error| Box::new(error) as BoxError)?;
    Ok(value
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| {
            tools.iter().any(|tool| {
                tool.as_object()
                    .is_some_and(|tool| tool.contains_key("type"))
            })
        }))
}

fn request_streaming(body: &[u8]) -> Result<bool, BoxError> {
    let value: Value = serde_json::from_slice(body).map_err(|error| Box::new(error) as BoxError)?;
    Ok(value
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn streaming_response(
    route: &RoutePlan,
    body: ProxyBody,
    upstream_wire: SemanticWire,
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    let limits = SseLimits::new(
        usize_limit(route.limits().max_frame_bytes),
        usize_limit(route.limits().max_event_bytes),
    );
    let body = AnthropicResponseBody::new(
        body,
        upstream_wire,
        route.loss_policy(),
        limits,
        usize_limit(u64::from(route.limits().max_queue_items)),
        usize_limit(route.limits().max_queue_bytes),
        cancellation,
    )?;
    Ok(SemanticResponseBody {
        body: body.boxed(),
        content_type: HeaderValue::from_static("text/event-stream"),
    })
}

fn unary_response(
    route: &RoutePlan,
    body: ProxyBody,
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    let body = AnthropicUnaryResponseBody::new(
        body,
        route.loss_policy(),
        usize_limit(route.limits().max_response_body_bytes),
        cancellation,
    );
    Ok(SemanticResponseBody {
        body: body.boxed(),
        content_type: HeaderValue::from_static("application/json"),
    })
}

fn transcoded_unary_response(
    route: &RoutePlan,
    body: ProxyBody,
    upstream_wire: SemanticWire,
    upstream_mode: SemanticResponseMode,
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    let body = TranscodedAnthropicUnaryBody::new(
        body,
        upstream_wire,
        upstream_mode,
        route.loss_policy(),
        SseLimits::new(
            usize_limit(route.limits().max_frame_bytes),
            usize_limit(route.limits().max_event_bytes),
        ),
        usize_limit(route.limits().max_response_body_bytes),
        cancellation,
    )?;
    Ok(SemanticResponseBody {
        body: body.boxed(),
        content_type: HeaderValue::from_static("application/json"),
    })
}

#[derive(Debug, Error)]
enum AnthropicRuntimeError {
    #[error("encoded Anthropic Messages request was not an object")]
    EncodedRequestNotObject,
    #[error("selected upstream wire cannot be translated to Anthropic Messages")]
    UnsupportedUpstreamWire,
    #[error("Anthropic upstream SSE ended before message_stop or error")]
    MissingTerminal,
    #[error("Anthropic semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("Anthropic semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("Anthropic semantic response was canceled")]
    Cancelled,
    #[error("Anthropic unary response is too large: {observed} bytes exceeds limit {limit}")]
    UnaryTooLarge { observed: usize, limit: usize },
}

struct AnthropicUnaryResponseBody {
    inner: Pin<Box<ProxyBody>>,
    buffer: Vec<u8>,
    limit: usize,
    policy: LossPolicy,
    cancellation: CancellationToken,
    output: Option<Bytes>,
    ended: bool,
    error: Option<BoxError>,
}

impl AnthropicUnaryResponseBody {
    fn new(
        body: ProxyBody,
        policy: LossPolicy,
        limit: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner: Box::pin(body),
            buffer: Vec::new(),
            limit,
            policy,
            cancellation,
            output: None,
            ended: false,
            error: None,
        }
    }

    fn finish(&mut self) -> Result<(), BoxError> {
        let decoded = AnthropicMessageCodec::decode_response(&self.buffer)
            .map_err(|error| Box::new(error) as BoxError)?;
        decoded
            .report
            .validate(self.policy)
            .map_err(|error| Box::new(error) as BoxError)?;
        let encoded = AnthropicMessageCodec::encode_response(&decoded.events, self.policy)
            .map_err(|error| Box::new(error) as BoxError)?;
        self.output = Some(Bytes::from(encoded.body));
        self.ended = true;
        Ok(())
    }
}

impl Body for AnthropicUnaryResponseBody {
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
                return Poll::Ready(Some(Err(Box::new(AnthropicRuntimeError::Cancelled))));
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
                            this.error = Some(Box::new(AnthropicRuntimeError::UnaryTooLarge {
                                observed,
                                limit: this.limit,
                            }));
                        } else {
                            this.buffer.extend_from_slice(&data);
                        }
                    }
                    Err(frame) => {
                        if frame.into_trailers().is_err() {
                            this.error = Some(Box::new(AnthropicRuntimeError::InvalidFrame));
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

struct TranscodedAnthropicUnaryBody {
    inner: Pin<Box<ProxyBody>>,
    decoder: UpstreamEventDecoder,
    upstream_wire: SemanticWire,
    upstream_mode: SemanticResponseMode,
    policy: LossPolicy,
    limits: SseLimits,
    limit: usize,
    cancellation_wait: Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
    buffer: Vec<u8>,
    output: Option<Bytes>,
    ended: bool,
    error: Option<BoxError>,
}

impl TranscodedAnthropicUnaryBody {
    fn new(
        body: ProxyBody,
        upstream_wire: SemanticWire,
        upstream_mode: SemanticResponseMode,
        policy: LossPolicy,
        limits: SseLimits,
        limit: usize,
        cancellation: CancellationToken,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            inner: Box::pin(body),
            decoder: UpstreamEventDecoder::new(upstream_wire)?,
            upstream_wire,
            upstream_mode,
            policy,
            limits,
            limit,
            cancellation_wait: Box::pin(cancellation.cancelled_owned()),
            buffer: Vec::new(),
            output: None,
            ended: false,
            error: None,
        })
    }

    fn finish(&mut self) -> Result<(), BoxError> {
        let events = if self.upstream_mode == SemanticResponseMode::ServerSentEvents {
            let mut parser = SseParser::with_limits(self.limits);
            let mut events = Vec::new();
            for event in parser
                .feed(&self.buffer)
                .map_err(|error| Box::new(error) as BoxError)?
                .into_iter()
                .chain(
                    parser
                        .finish()
                        .map_err(|error| Box::new(error) as BoxError)?,
                )
            {
                events.extend(self.decoder.decode(&event)?);
            }
            events.extend(self.decoder.finish()?);
            events
        } else if self.upstream_wire == SemanticWire::OpenAiChat {
            decode_openai_chat_unary(&self.buffer)?
        } else {
            return Err(Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire));
        };
        let encoded = AnthropicMessageCodec::encode_response(&events, self.policy)
            .map_err(|error| Box::new(error) as BoxError)?;
        if encoded.body.len() > self.limit {
            return Err(Box::new(AnthropicRuntimeError::UnaryTooLarge {
                observed: encoded.body.len(),
                limit: self.limit,
            }));
        }
        self.output = Some(Bytes::from(encoded.body));
        self.ended = true;
        Ok(())
    }
}

fn decode_openai_chat_unary(input: &[u8]) -> Result<Vec<StreamEvent>, BoxError> {
    let mut value: Value =
        serde_json::from_slice(input).map_err(|error| Box::new(error) as BoxError)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire) as BoxError)?;
    let choices = object
        .get_mut("choices")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire) as BoxError)?;
    if choices.len() != 1 {
        return Err(Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire));
    }
    let choice = choices[0]
        .as_object_mut()
        .ok_or_else(|| Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire) as BoxError)?;
    let message = choice
        .remove("message")
        .ok_or_else(|| Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire) as BoxError)?;
    choice.insert("delta".to_owned(), message);
    let mut decoder = OpenAiChatEventDecoder::new();
    let mut events = decoder
        .decode_chunk(&serde_json::to_vec(&value).map_err(|error| Box::new(error) as BoxError)?)
        .map_err(|error| Box::new(error) as BoxError)?;
    events.extend(
        decoder
            .finish()
            .map_err(|error| Box::new(error) as BoxError)?,
    );
    Ok(events)
}

impl Body for TranscodedAnthropicUnaryBody {
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
                return Poll::Ready(Some(Err(Box::new(AnthropicRuntimeError::Cancelled))));
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
                            this.error = Some(Box::new(AnthropicRuntimeError::UnaryTooLarge {
                                observed,
                                limit: this.limit,
                            }));
                        } else {
                            this.buffer.extend_from_slice(&data);
                        }
                    }
                    Err(frame) => {
                        if frame.into_trailers().is_err() {
                            this.error = Some(Box::new(AnthropicRuntimeError::InvalidFrame));
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

enum UpstreamEventDecoder {
    Anthropic(AnthropicEventDecoder),
    OpenAiResponses(OpenAiResponsesEventDecoder),
    OpenAiChat(OpenAiChatEventDecoder),
}

impl UpstreamEventDecoder {
    fn new(wire: SemanticWire) -> Result<Self, BoxError> {
        match wire {
            SemanticWire::AnthropicMessages => Ok(Self::Anthropic(AnthropicEventDecoder::new())),
            SemanticWire::OpenAiResponses => {
                Ok(Self::OpenAiResponses(OpenAiResponsesEventDecoder::new()))
            }
            SemanticWire::OpenAiChat => Ok(Self::OpenAiChat(OpenAiChatEventDecoder::new())),
            SemanticWire::GeminiGenerateContent => {
                Err(Box::new(AnthropicRuntimeError::UnsupportedUpstreamWire))
            }
        }
    }

    fn decode(&mut self, event: &SseEvent) -> Result<Vec<StreamEvent>, BoxError> {
        match self {
            Self::Anthropic(decoder) => decoder
                .decode_sse_event(event)
                .map_err(|error| Box::new(error) as BoxError),
            Self::OpenAiResponses(decoder) => decoder
                .decode_event(event.event.as_deref(), event.data.as_bytes())
                .map_err(|error| Box::new(error) as BoxError),
            Self::OpenAiChat(decoder) => decoder
                .decode_data(event.data.as_bytes())
                .map_err(|error| Box::new(error) as BoxError),
        }
    }

    fn finish(&mut self) -> Result<Vec<StreamEvent>, BoxError> {
        match self {
            Self::Anthropic(decoder) if decoder.is_finished() => Ok(Vec::new()),
            Self::Anthropic(_) => Err(Box::new(AnthropicRuntimeError::MissingTerminal)),
            Self::OpenAiResponses(decoder) => decoder
                .finish()
                .map_err(|error| Box::new(error) as BoxError),
            Self::OpenAiChat(decoder) => decoder
                .finish()
                .map_err(|error| Box::new(error) as BoxError),
        }
    }
}

struct AnthropicResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    limits: SseLimits,
    decoder: UpstreamEventDecoder,
    encoder: AnthropicEventEncoder,
    policy: LossPolicy,
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    max_queue_items: usize,
    max_queue_bytes: usize,
    cancellation: CancellationToken,
    ended: bool,
    error: Option<BoxError>,
}

impl AnthropicResponseBody {
    fn new(
        body: ProxyBody,
        upstream_wire: SemanticWire,
        policy: LossPolicy,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(limits),
            limits,
            decoder: UpstreamEventDecoder::new(upstream_wire)?,
            encoder: AnthropicEventEncoder::new(),
            policy,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_queue_items,
            max_queue_bytes,
            cancellation,
            ended: false,
            error: None,
        })
    }

    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        for event in self
            .parser
            .feed(chunk)
            .map_err(|error| Box::new(error) as BoxError)?
        {
            let semantic = self.decoder.decode(&event)?;
            for semantic_event in semantic {
                let encoded = self
                    .encoder
                    .encode_event_with_limits(&semantic_event, self.policy, self.limits)
                    .map_err(|error| Box::new(error) as BoxError)?;
                if !encoded.body.is_empty() {
                    self.enqueue(Bytes::from(encoded.body))?;
                }
            }
        }
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        let events = self
            .parser
            .finish()
            .map_err(|error| Box::new(error) as BoxError)?;
        for event in events {
            let semantic = self.decoder.decode(&event)?;
            for semantic_event in semantic {
                let encoded = self
                    .encoder
                    .encode_event_with_limits(&semantic_event, self.policy, self.limits)
                    .map_err(|error| Box::new(error) as BoxError)?;
                if !encoded.body.is_empty() {
                    self.enqueue(Bytes::from(encoded.body))?;
                }
            }
        }
        for semantic_event in self.decoder.finish()? {
            let encoded = self
                .encoder
                .encode_event_with_limits(&semantic_event, self.policy, self.limits)
                .map_err(|error| Box::new(error) as BoxError)?;
            if !encoded.body.is_empty() {
                self.enqueue(Bytes::from(encoded.body))?;
            }
        }
        self.ended = true;
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let items = self.queue.len().saturating_add(1);
        let byte_count = self.queued_bytes.saturating_add(bytes.len());
        if items > self.max_queue_items || byte_count > self.max_queue_bytes {
            return Err(Box::new(AnthropicRuntimeError::QueueLimit {
                items,
                bytes: byte_count,
            }));
        }
        self.queued_bytes = byte_count;
        self.queue.push_back(bytes);
        Ok(())
    }

    fn set_error(&mut self, error: BoxError) {
        if self.error.is_some() {
            return;
        }
        let failure = StreamEvent::new(
            0,
            StreamEventKind::Failure {
                error: StreamError::new(
                    "invalid_upstream_stream",
                    "the upstream Anthropic stream could not be converted",
                ),
            },
        );
        let terminal = AnthropicEventEncoder::new()
            .encode_event_with_limits(&failure, LossPolicy::Reject, self.limits)
            .ok()
            .and_then(|encoded| self.enqueue(Bytes::from(encoded.body)).ok())
            .is_some();
        if terminal {
            self.ended = true;
        } else {
            self.error = Some(error);
        }
    }
}

impl Body for AnthropicResponseBody {
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
                return Poll::Ready(Some(Err(Box::new(AnthropicRuntimeError::Cancelled))));
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
                            this.set_error(Box::new(AnthropicRuntimeError::InvalidFrame));
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

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::HeaderMap;
    use http_body_util::{BodyExt, Full};
    use pooler_http::{SemanticAdapter, SemanticResponseHint, SemanticResponseMode, SemanticWire};
    use serde_json::{json, Value};
    use tokio_util::sync::CancellationToken;

    use super::AnthropicSemanticAdapter;

    fn route() -> pooler_config::RoutePlan {
        let source = r#"
version: 2
listeners: {droid: {bind: "127.0.0.1:18474"}}
upstreams: {anthropic: {url: "http://127.0.0.1:18983"}}
routes:
  - id: droid-anthropic
    listen: droid
    match: {methods: [POST], path: /v1/messages}
    ingress:
      mode: semantic
      decoder: decode.anthropic.messages
      encoder: encode.anthropic.messages
    target: {provider: anthropic, path: /v1/messages}
    response:
      mode: semantic
      decoder: decode.anthropic.messages.events
      encoder: encode.anthropic.messages.events
    loss_policy: reject
"#;
        pooler_config::compile_yaml("anthropic-route.yaml", source)
            .expect("config")
            .routes()
            .first()
            .expect("route")
            .clone()
    }

    #[test]
    fn semantic_adapter_round_trips_request_through_model() {
        let route = route();
        assert!(AnthropicSemanticAdapter.supports(&route));
        let body = br#"{
          "model":"claude-test","max_tokens":2048,"stream":true,
          "thinking":{"type":"enabled","budget_tokens":1024},
          "messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]
        }"#;
        let encoded = AnthropicSemanticAdapter
            .encode_request(&route, &HeaderMap::new(), body)
            .expect("request");
        assert_eq!(
            encoded.response_hint.mode,
            SemanticResponseMode::ServerSentEvents
        );
        let value: Value = serde_json::from_slice(&encoded.body).expect("json");
        assert_eq!(value["model"], "claude-test");
        assert_eq!(value["stream"], true);
        assert_eq!(value["thinking"]["budget_tokens"], 1024);
        assert_eq!(
            value["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        let selection = AnthropicSemanticAdapter
            .selection_context(&route, &HeaderMap::new(), body)
            .expect("selection");
        assert!(selection
            .required_capabilities()
            .contains(pooler_core::Capability::Streaming));
    }

    #[test]
    fn server_tool_only_requests_require_tool_capabilities_for_routing() {
        let route = route();
        let body = br#"{
          "model":"claude-test","max_tokens":256,
          "tools":[{"type":"web_search_20250305","name":"web_search"}],
          "messages":[{"role":"user","content":"find it"}]
        }"#;
        let selection = AnthropicSemanticAdapter
            .selection_context(&route, &HeaderMap::new(), body)
            .expect("selection");
        assert!(selection
            .required_capabilities()
            .contains(pooler_core::Capability::Tools));
        assert!(selection
            .required_capabilities()
            .contains(pooler_core::Capability::FunctionCalling));
    }

    #[test]
    fn semantic_adapter_preserves_unary_cache_warmup_request_mode() {
        let route = route();
        let body = br#"{
          "model":"claude-test","max_tokens":0,"stream":false,
          "system":[{"type":"text","text":"cache","cache_control":{"type":"ephemeral"}}],
          "messages":[{"role":"user","content":"warm cache"}]
        }"#;
        let encoded = AnthropicSemanticAdapter
            .encode_request(&route, &HeaderMap::new(), body)
            .expect("request");
        assert_eq!(encoded.response_hint.mode, SemanticResponseMode::Json);
        assert_eq!(
            encoded.response_hint.requested_model.as_deref(),
            Some("claude-test")
        );
        let value: Value = serde_json::from_slice(&encoded.body).expect("json");
        assert_eq!(value["max_tokens"], 0);
        assert_eq!(value["stream"], false);
        let selection = AnthropicSemanticAdapter
            .selection_context(&route, &HeaderMap::new(), body)
            .expect("selection");
        assert!(!selection
            .required_capabilities()
            .contains(pooler_core::Capability::Streaming));
    }

    #[tokio::test]
    async fn semantic_adapter_streams_named_sse_and_usage() {
        let route = route();
        let source = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-test\",\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        let upstream = Full::new(Bytes::from_static(source.as_bytes()))
            .map_err(|never| match never {})
            .boxed();
        let response = AnthropicSemanticAdapter
            .decode_response(&route, upstream, CancellationToken::new())
            .expect("response");
        let bytes = response.body.collect().await.expect("collect").to_bytes();
        let text = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(text.contains("event:message_start"));
        assert!(text.contains("text_delta"));
        assert!(text.contains("\"input_tokens\":5"));
        assert!(text.contains("event:message_stop"));
    }

    #[tokio::test]
    async fn semantic_adapter_returns_bounded_unary_json_with_json_content_type() {
        let route = route();
        let source = br#"{
          "id":"msg_warm","type":"message","role":"assistant","model":"claude-test",
          "content":[],"stop_reason":"max_tokens","stop_sequence":null,
          "usage":{"input_tokens":20,"output_tokens":0,"cache_creation_input_tokens":20},
          "service_tier":"standard"
        }"#;
        let upstream = Full::new(Bytes::from_static(source))
            .map_err(|never| match never {})
            .boxed();
        let response = AnthropicSemanticAdapter
            .decode_response_with_hint(
                &route,
                upstream,
                &HeaderMap::new(),
                &pooler_http::SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    requested_model: Some("claude-test".to_owned()),
                    ..pooler_http::SemanticResponseHint::default()
                },
                CancellationToken::new(),
            )
            .expect("response");
        assert_eq!(response.content_type, "application/json");
        let bytes = response.body.collect().await.expect("collect").to_bytes();
        let value: Value = serde_json::from_slice(&bytes).expect("unary JSON");
        assert_eq!(value["id"], "msg_warm");
        assert_eq!(value["content"], serde_json::json!([]));
        assert_eq!(value["stop_reason"], "max_tokens");
        assert_eq!(value["usage"]["cache_creation_input_tokens"], 20);
        assert_eq!(value["service_tier"], "standard");
    }

    #[tokio::test]
    async fn unary_messages_round_trips_through_streaming_responses() {
        let route = route();
        let request = json!({
            "model":"gpt-test",
            "max_tokens":64,
            "messages":[{"role":"user","content":"hello"}]
        });
        let encoded = AnthropicSemanticAdapter
            .reencode_request_for_wire(
                &route,
                &serde_json::to_vec(&request).expect("Messages request JSON"),
                SemanticWire::OpenAiResponses,
            )
            .expect("Messages request converts to Responses");
        let encoded: Value = serde_json::from_slice(&encoded).expect("Responses request JSON");
        assert_eq!(encoded["model"], "gpt-test");
        assert_eq!(encoded["input"][0]["role"], "user");

        let events = [
            json!({
                "type":"response.created",
                "response":{"id":"resp_messages","model":"gpt-test","status":"in_progress"}
            }),
            json!({
                "type":"response.output_item.added","output_index":0,
                "item":{"id":"msg_messages","type":"message","status":"in_progress","role":"assistant","content":[]}
            }),
            json!({
                "type":"response.content_part.added","item_id":"msg_messages",
                "output_index":0,"content_index":0,
                "part":{"type":"output_text","text":"","annotations":[]}
            }),
            json!({
                "type":"response.output_text.delta","item_id":"msg_messages",
                "output_index":0,"content_index":0,"delta":"POOLER_MESSAGES_OK"
            }),
            json!({
                "type":"response.output_item.done","output_index":0,
                "item":{"id":"msg_messages","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"POOLER_MESSAGES_OK","annotations":[]}]}
            }),
            json!({
                "type":"response.completed",
                "response":{"id":"resp_messages","model":"gpt-test","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}
            }),
        ];
        let source = events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect::<String>();
        let upstream = Full::new(Bytes::from(source))
            .map_err(|never| match never {})
            .boxed();
        let response = AnthropicSemanticAdapter
            .decode_response_with_hint(
                &route,
                upstream,
                &HeaderMap::new(),
                &SemanticResponseHint {
                    mode: SemanticResponseMode::Json,
                    upstream_mode: SemanticResponseMode::ServerSentEvents,
                    upstream_wire: Some(SemanticWire::OpenAiResponses),
                    requested_model: Some("gpt-test".to_owned()),
                },
                CancellationToken::new(),
            )
            .expect("Responses stream converts to unary Messages");
        let body: Value = serde_json::from_slice(
            &response
                .body
                .collect()
                .await
                .expect("Messages body")
                .to_bytes(),
        )
        .expect("Messages JSON");
        assert_eq!(body["type"], "message");
        assert_eq!(body["content"][0]["text"], "POOLER_MESSAGES_OK");
        assert_eq!(body["stop_reason"], "end_turn");
        assert_eq!(body["usage"]["input_tokens"], 3);
    }
}
