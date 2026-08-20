#![forbid(unsafe_code)]
#![doc = "Semantic HTTP adapter for Factory Droid's OpenAI-compatible wires.

Factory Droid is a separate product from Factory's `fx` CLI. Droid custom
models marked as `openai` use the OpenAI Responses endpoint in the installed
0.149.0 client. This adapter also supports streaming Chat Completions routes
for OpenAI-compatible providers without routing either wire through the
Factory LanguageModel adapter."]

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
    SemanticResponseBody, SemanticWebSocketTransport, SseEncoder, SseEvent, SseLimits, SseParser,
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

/// Runtime adapter for Droid's OpenAI Responses and compatible Chat routes.
#[derive(Clone, Copy, Debug, Default)]
pub struct DroidOpenAiSemanticAdapter;

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

impl SemanticAdapter for DroidOpenAiSemanticAdapter {
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
            .ok_or_else(|| Box::new(DroidAdapterError::UnsupportedRoute) as BoxError)?;
        let request = decode_request(request_wire, body, route.loss_policy())?;
        let encoded = encode_upstream_request(upstream_wire, &request, route.loss_policy())?;
        Ok(SemanticRequestBody {
            body: encoded,
            content_type: HeaderValue::from_static("application/json"),
            response_hint: pooler_http::SemanticResponseHint::default(),
        })
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        let (request_wire, _) = route_wires(route)
            .ok_or_else(|| Box::new(DroidAdapterError::UnsupportedRoute) as BoxError)?;
        let request = decode_request(request_wire, body, route.loss_policy())?;
        let mut context = SelectionContext::from_semantic_request(&request);
        context.require(pooler_core::Capability::Streaming);
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
            .ok_or_else(|| Box::new(DroidAdapterError::UnsupportedRoute) as BoxError)?;
        let downstream_wire = match request_wire {
            RequestWire::Responses => EventWire::Responses,
            RequestWire::Chat => EventWire::Chat,
        };
        let limits = SseLimits::new(
            usize_limit(route.limits().max_frame_bytes),
            usize_limit(route.limits().max_event_bytes),
        );
        let stream = DroidResponseBody::new(
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
            if !decoded.stream {
                return Err(Box::new(DroidAdapterError::StreamingRequired));
            }
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
        Some(false) | None => Err(Box::new(DroidAdapterError::StreamingRequired)),
    }
}

fn encode_upstream_request(
    wire: EventWire,
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<Vec<u8>, BoxError> {
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
        .ok_or_else(|| Box::new(DroidAdapterError::EncodedRequestNotObject) as BoxError)?;
    for (key, value) in passthrough {
        object.entry(key).or_insert(value);
    }
    object.insert("stream".to_owned(), Value::Bool(true));
    match wire {
        EventWire::Responses => {
            object.entry("store").or_insert(Value::Bool(false));
        }
        EventWire::Chat => {
            object.insert(
                "stream_options".to_owned(),
                serde_json::json!({"include_usage":true}),
            );
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
        .ok_or_else(|| Box::new(DroidAdapterError::InvalidTransportExtension) as BoxError)?;
    let mut passthrough = serde_json::Map::new();
    for (field, value) in fields {
        match field.as_str() {
            "stream" | "stream_options" => {}
            "store" | "parallel_tool_calls" | "prompt_cache_key" => {
                passthrough.insert(field.clone(), value.clone());
            }
            _ if policy.allows_degradation() => {}
            _ => {
                return Err(Box::new(DroidAdapterError::UnsupportedCrossProtocolField(
                    field.clone(),
                )));
            }
        }
    }
    Ok((request, passthrough))
}

#[derive(Debug, Error)]
enum DroidAdapterError {
    #[error("route is not a supported Droid OpenAI semantic route")]
    UnsupportedRoute,
    #[error("Droid OpenAI semantic routes require stream=true")]
    StreamingRequired,
    #[error("encoded OpenAI request is not a JSON object")]
    EncodedRequestNotObject,
    #[error("OpenAI transport extension is not a JSON object")]
    InvalidTransportExtension,
    #[error("OpenAI field `{0}` cannot be preserved across Responses and Chat")]
    UnsupportedCrossProtocolField(String),
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
                                Box::new(DroidStreamError::InvalidJsonUtf8) as BoxError
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
                                |_| Box::new(DroidStreamError::InvalidJsonUtf8) as BoxError,
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

struct DroidResponseBody {
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

impl DroidResponseBody {
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
            return Err(Box::new(DroidStreamError::QueueLimit {
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

impl Body for DroidResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.cancellation.is_cancelled() {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(DroidStreamError::Cancelled))));
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
                    if let Err(error) = this.process_chunk(&data) {
                        this.set_error(error);
                    }
                    Pin::new(this).poll_frame(context)
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(_) => Pin::new(this).poll_frame(context),
                    Err(_) => {
                        this.set_error(Box::new(DroidStreamError::InvalidFrame));
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
enum DroidStreamError {
    #[error("Droid semantic response JSON was not UTF-8")]
    InvalidJsonUtf8,
    #[error("Droid semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("Droid semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("Droid semantic response canceled")]
    Cancelled,
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use http_body_util::{BodyExt, Full};
    use pooler_config::Config;
    use pooler_http::{SemanticAdapter, SseParser};
    use serde_json::{json, Value};
    use tokio_util::sync::CancellationToken;

    use super::{
        DroidOpenAiSemanticAdapter, OPENAI_CHAT_EVENT_DECODER, OPENAI_CHAT_EVENT_ENCODER,
        OPENAI_CHAT_REQUEST_DECODER, OPENAI_RESPONSES_EVENT_DECODER,
        OPENAI_RESPONSES_EVENT_ENCODER, OPENAI_RESPONSES_REQUEST_DECODER,
    };

    fn route(ingress: &str, decoder: &str, encoder: &str) -> pooler_config::RoutePlan {
        let source = format!(
            "version: 1\nlisteners: {{droid: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://127.0.0.1:9}}}}\nroutes:\n  - id: droid\n    listen: droid\n    match: {{method: POST, path: /v1/responses}}\n    ingress: {{mode: semantic, decoder: {ingress}}}\n    target: {{provider: local, path: /v1/responses}}\n    response: {{mode: semantic, decoder: {decoder}, encoder: {encoder}}}\n    loss_policy: reject\n"
        );
        Config::from_yaml("droid.yaml", &source)
            .expect("config parses")
            .compile()
            .expect("config compiles")
            .routes()[0]
            .clone()
    }

    #[test]
    fn supports_responses_and_chat_without_factory_route_identity() {
        let adapter = DroidOpenAiSemanticAdapter;
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
    }

    #[test]
    fn installed_droid_shape_encodes_as_streaming_responses() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let request = json!({
            "model":"droid-model",
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
        let encoded = DroidOpenAiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                &serde_json::to_vec(&request).expect("request JSON"),
            )
            .expect("Droid request encodes");
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
            "model":"droid-model",
            "input":[
                {"role":"user","content":[{"type":"input_text","text":"read"}]},
                {"type":"function_call","call_id":"call_1","name":"Read","arguments":"{}"},
                {"type":"function_call_output","call_id":"call_1","output":"done"}
            ],
            "stream":true,
            "store":false
        });
        let encoded = DroidOpenAiSemanticAdapter
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
        let response = DroidOpenAiSemanticAdapter
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
    fn rejects_non_streaming_requests_before_upstream() {
        let route = route(
            OPENAI_RESPONSES_REQUEST_DECODER,
            OPENAI_RESPONSES_EVENT_DECODER,
            OPENAI_RESPONSES_EVENT_ENCODER,
        );
        let request = json!({"model":"droid-model","input":"hello","stream":false});
        let error = DroidOpenAiSemanticAdapter
            .encode_request(
                &route,
                &HeaderMap::new(),
                &serde_json::to_vec(&request).expect("request JSON"),
            )
            .expect_err("non-streaming route is rejected");
        assert!(error.to_string().contains("stream=true"));
    }
}
