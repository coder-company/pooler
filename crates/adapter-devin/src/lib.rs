//! Devin/Cascade semantic and ConnectRPC codecs.
//!
//! The wire schema is intentionally limited to the protobuf messages used by
//! the installed local bridge: auth metadata, model discovery, and streamed
//! chat.  The source and field numbers are documented in [`proto`].  Unknown
//! required provider semantics are rejected or reported through
//! [`pooler_protocol::ConversionReport`] rather than silently discarded.

#![forbid(unsafe_code)]

mod chat;
pub mod connect;
pub mod metadata;
pub mod proto;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use pooler_config::RoutePlan;
use pooler_http::{
    BoxError, ProxyBody, SelectionContext, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody, SseLimits, SseParser,
};
use pooler_protocol::{LossPolicy, OpenAiChatEventDecoder, StreamEvent};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub use chat::{
    decode_chat_message, decode_chat_request, decode_chat_response,
    decode_chat_response_with_limits, encode_chat_request, DecodedDevinChatRequest,
    DecodedDevinChatResponse, DevinChatCodecError, DevinChatEncodeOptions, DevinChatEventDecoder,
    DevinChatEventEncoder, DevinChatLimits, DevinChatResponseLimits, DevinIdentifiers,
    EncodedDevinChatRequest, EncodedDevinFrame, DEFAULT_MAX_CHAT_CONTENT_BYTES,
    DEFAULT_MAX_CHAT_MESSAGES, DEFAULT_MAX_CHAT_TOOLS, DEFAULT_MAX_RESPONSE_REASONING_BYTES,
    DEFAULT_MAX_RESPONSE_TOOL_ARGUMENT_BYTES, DEFAULT_MAX_RESPONSE_TOOL_CALLS,
    DEFAULT_MAX_TOOL_ARGUMENT_BYTES,
};
pub use connect::{
    decode_connect_frames, decode_connect_frames_with_limits, decode_proto_with_gzip_fallback,
    encode_connect_frame, encode_connect_frame_with_limits, read_connect_trailer_error,
    ConnectDecoder, ConnectError, ConnectFrame, ConnectLimits, CONNECT_COMPRESSED_FLAG,
    CONNECT_END_STREAM_FLAG, MAX_CONNECT_DECOMPRESSED_PAYLOAD, MAX_CONNECT_FRAME_PAYLOAD,
};
pub use metadata::{
    decode_auth_response, decode_model_response, encode_auth_request, encode_model_request,
    metadata, normalize_devin_session_token, normalize_models, AuthMetadata, DevinClientMetadata,
    DevinInput, DevinModel, MetadataError, DEVIN_AUTH_PATH, DEVIN_CHAT_PATH,
    DEVIN_CONNECT_CONTENT_TYPE, DEVIN_DEFAULT_STOP_PATTERNS, DEVIN_EXTENSION_VERSION,
    DEVIN_IDE_VERSION, DEVIN_MODELS_PATH, DEVIN_PROTO_CONTENT_TYPE, DEVIN_SESSION_TOKEN_PREFIX,
};

/// Semantic adapter route decoder name.
pub const DEVIN_CHAT_DECODER: &str = "decode.devin.chat";
/// Semantic adapter route encoder name.
pub const DEVIN_CONNECT_ENCODER: &str = "encode.devin.connect";
/// Upstream decoder used by the Devin semantic route.
pub const OPENAI_CHAT_EVENT_DECODER: &str = "decode.openai.chat.events";
/// Upstream request encoder used by the Devin semantic route.
pub const OPENAI_CHAT_ENCODER: &str = "encode.openai.chat";

/// Semantic adapter mounted by a Devin ConnectRPC route.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevinSemanticAdapter;

impl SemanticAdapter for DevinSemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        route.ingress().mode() == pooler_core::BodyMode::Semantic
            && route.ingress().framing() == Some("decode.connect.envelope")
            && route.ingress().decoder() == Some(DEVIN_CHAT_DECODER)
            && route.response().mode() == pooler_core::BodyMode::Semantic
            && route.response().decoder() == Some(OPENAI_CHAT_EVENT_DECODER)
            && route.response().encoder() == Some(DEVIN_CONNECT_ENCODER)
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        let limits = chat_limits(route);
        let decoded = decode_chat_request(body, limits).map_err(boxed)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(boxed)?;
        let mut upstream_request = decoded.request;
        if let Some(cascade_id) = decoded.identifiers.cascade_id {
            upstream_request
                .metadata
                .insert("devin_cascade_id".to_owned(), cascade_id);
        }
        if let Some(execution_id) = decoded.identifiers.execution_id {
            upstream_request
                .metadata
                .insert("devin_execution_id".to_owned(), execution_id);
        }
        for key in ["devin.identifiers", "devin.raw_request"] {
            if let Ok(key) = pooler_protocol::ExtensionKey::parse(key) {
                upstream_request.extensions.remove(&key);
            }
        }
        upstream_request.session_id = None;
        upstream_request.continuation_id = None;
        let encoded = pooler_protocol::OpenAiChatCodec::encode_request(
            &upstream_request,
            route.loss_policy(),
        )
        .map_err(boxed)?;
        let mut value: serde_json::Value = serde_json::from_slice(&encoded.body).map_err(boxed)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| boxed(DevinAdapterError::EncodedRequestNotObject))?;
        object.insert("stream".to_owned(), serde_json::Value::Bool(true));
        object.insert(
            "stream_options".to_owned(),
            serde_json::json!({"include_usage": true}),
        );
        Ok(SemanticRequestBody {
            body: serde_json::to_vec(&value).map_err(boxed)?,
            content_type: HeaderValue::from_static("application/json"),
        })
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        let decoded = decode_chat_request(body, chat_limits(route)).map_err(boxed)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(boxed)?;
        let mut context = SelectionContext::from_semantic_request(&decoded.request);
        context.require(pooler_core::Capability::Streaming);
        if let Some(codec) = route.ingress().decoder() {
            context.with_codec(codec);
        }
        if let Some(value) = decoded.identifiers.cascade_id.as_deref() {
            context.with_affinity_value("request.session_id", value);
            context.with_affinity_value("semantic.session_id", value);
            context.with_affinity_value("devin.conversation_id", value);
            context.with_affinity_value("devin.cascade_id", value);
        }
        if let Some(value) = decoded.identifiers.execution_id.as_deref() {
            context.with_affinity_value("devin.execution_id", value);
            context.with_affinity_value("openai.previous_response_id", value);
        }
        Ok(context)
    }

    fn sanitize_request_headers(&self, headers: &mut HeaderMap) {
        headers.remove("connect-protocol-version");
        headers.remove("connect-content-encoding");
        headers.remove("connect-accept-encoding");
        headers.remove("content-encoding");
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        self.decode_response_with_compression(route, body, false, cancellation)
    }

    fn decode_response_with_request_headers(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        self.decode_response_with_compression(
            route,
            body,
            accepts_connect_gzip(request_headers),
            cancellation,
        )
    }
}

impl DevinSemanticAdapter {
    fn decode_response_with_compression(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        compress: bool,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let sse_limits = SseLimits::new(
            usize_limit(route.limits().max_frame_bytes),
            usize_limit(route.limits().max_event_bytes),
        );
        let output = DevinResponseBody::new(
            body,
            DevinResponseOptions {
                policy: route.loss_policy(),
                compress,
                sse_limits,
                max_queue_items: usize_limit(u64::from(route.limits().max_queue_items)),
                max_queue_bytes: usize_limit(route.limits().max_queue_bytes),
                connect_limits: chat_limits(route).connect,
                response_limits: chat_limits(route).response,
                cancellation,
            },
        );
        Ok(SemanticResponseBody {
            body: output.boxed(),
            content_type: HeaderValue::from_static(DEVIN_CONNECT_CONTENT_TYPE),
        })
    }
}

/// Errors raised while adapting upstream OpenAI SSE to Devin frames.
#[derive(Debug, Error)]
enum DevinStreamError {
    /// The upstream SSE stream ended without a terminal marker.
    #[error("Devin upstream SSE ended without [DONE]")]
    MissingDone,
    /// The upstream stream sent more than one terminal marker.
    #[error("Devin upstream SSE contained duplicate [DONE] markers")]
    DuplicateDone,
    /// Output queue bounds were exceeded.
    #[error("Devin semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    /// A body frame carried neither data nor trailers.
    #[error("Devin semantic response contained an invalid body frame")]
    InvalidFrame,
    /// Downstream cancellation interrupted conversion.
    #[error("Devin semantic response canceled")]
    Cancelled,
    /// Streamed semantic state exceeded an adapter bound.
    #[error("Devin semantic response field `{field}` exceeded {limit} (observed {observed})")]
    ResponseLimit {
        /// Bounded response field.
        field: &'static str,
        /// Observed count or byte size.
        observed: usize,
        /// Configured bound.
        limit: usize,
    },
}

struct DevinResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    openai_decoder: OpenAiChatEventDecoder,
    devin_encoder: DevinChatEventEncoder,
    response_tool_ids: BTreeSet<String>,
    response_tool_argument_bytes: BTreeMap<String, usize>,
    response_reasoning_bytes: usize,
    response_limits: DevinChatResponseLimits,
    policy: LossPolicy,
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    max_queue_items: usize,
    max_queue_bytes: usize,
    cancellation: CancellationToken,
    done_seen: bool,
    terminal_emitted: bool,
    ended: bool,
    error: Option<BoxError>,
}

struct DevinResponseOptions {
    policy: LossPolicy,
    compress: bool,
    sse_limits: SseLimits,
    max_queue_items: usize,
    max_queue_bytes: usize,
    connect_limits: ConnectLimits,
    response_limits: DevinChatResponseLimits,
    cancellation: CancellationToken,
}

impl DevinResponseBody {
    fn new(body: ProxyBody, options: DevinResponseOptions) -> Self {
        Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(options.sse_limits),
            openai_decoder: OpenAiChatEventDecoder::new(),
            devin_encoder: DevinChatEventEncoder {
                compress: options.compress,
                connect_limits: options.connect_limits,
            },
            response_tool_ids: BTreeSet::new(),
            response_tool_argument_bytes: BTreeMap::new(),
            response_reasoning_bytes: 0,
            response_limits: options.response_limits,
            policy: options.policy,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_queue_items: options.max_queue_items,
            max_queue_bytes: options.max_queue_bytes,
            cancellation: options.cancellation,
            done_seen: false,
            terminal_emitted: false,
            ended: false,
            error: None,
        }
    }

    fn set_error(&mut self, error: BoxError) {
        if self.error.is_some() {
            return;
        }
        // The downstream Devin client still needs a valid terminal Connect
        // record when an upstream stream fails.  Keep this trailer
        // deliberately generic: provider error text may contain credentials
        // or other sensitive request material.
        if !self.terminal_emitted {
            let payload = serde_json::json!({
                "error": {
                    "code": "upstream_stream",
                    "message": "upstream semantic stream failed",
                }
            });
            if let Ok(payload) = serde_json::to_vec(&payload) {
                if let Ok(trailer) = encode_connect_frame_with_limits(
                    &payload,
                    false,
                    true,
                    self.devin_encoder.connect_limits,
                ) {
                    if self.enqueue(Bytes::from(trailer)).is_ok() {
                        self.terminal_emitted = true;
                        self.ended = true;
                        return;
                    }
                }
            }
        }
        self.error = Some(error);
    }

    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        let events = self.parser.feed(chunk).map_err(boxed)?;
        for event in events {
            if self.terminal_emitted {
                break;
            }
            if event.is_done() {
                if self.done_seen {
                    return Err(boxed(DevinStreamError::DuplicateDone));
                }
                self.done_seen = true;
            }
            let semantic = self
                .openai_decoder
                .decode_data(event.data.as_bytes())
                .map_err(boxed)?;
            self.encode_events(&semantic)?;
            if event.is_done() {
                let trailer = encode_connect_frame_with_limits(
                    b"{}",
                    false,
                    true,
                    self.devin_encoder.connect_limits,
                )?;
                self.enqueue(Bytes::from(trailer))?;
                self.terminal_emitted = true;
            }
        }
        Ok(())
    }

    fn encode_events(&mut self, events: &[StreamEvent]) -> Result<(), BoxError> {
        for event in events {
            self.check_response_limits(event)?;
            let encoded = self
                .devin_encoder
                .encode_event(event, self.policy)
                .map_err(boxed)?;
            if let Some(body) = encoded.body {
                self.enqueue(Bytes::from(body))?;
            }
            if matches!(
                &event.kind,
                pooler_protocol::StreamEventKind::Failure { .. }
            ) {
                self.terminal_emitted = true;
            }
        }
        Ok(())
    }

    fn check_response_limits(&mut self, event: &StreamEvent) -> Result<(), BoxError> {
        match &event.kind {
            pooler_protocol::StreamEventKind::ToolCallStart { id, .. } => {
                if self.response_tool_ids.insert(id.clone())
                    && self.response_tool_ids.len() > self.response_limits.max_tool_calls
                {
                    return Err(boxed(DevinStreamError::ResponseLimit {
                        field: "response.tool_calls",
                        observed: self.response_tool_ids.len(),
                        limit: self.response_limits.max_tool_calls,
                    }));
                }
            }
            pooler_protocol::StreamEventKind::ToolCallDelta { id, arguments } => {
                let observed = self
                    .response_tool_argument_bytes
                    .entry(id.clone())
                    .or_default()
                    .saturating_add(arguments.len());
                if observed > self.response_limits.max_tool_argument_bytes {
                    return Err(boxed(DevinStreamError::ResponseLimit {
                        field: "response.tool_call.arguments",
                        observed,
                        limit: self.response_limits.max_tool_argument_bytes,
                    }));
                }
                self.response_tool_argument_bytes
                    .insert(id.clone(), observed);
            }
            pooler_protocol::StreamEventKind::ReasoningDelta { text } => {
                let observed = self.response_reasoning_bytes.saturating_add(text.len());
                if observed > self.response_limits.max_reasoning_bytes {
                    return Err(boxed(DevinStreamError::ResponseLimit {
                        field: "response.reasoning",
                        observed,
                        limit: self.response_limits.max_reasoning_bytes,
                    }));
                }
                self.response_reasoning_bytes = observed;
            }
            pooler_protocol::StreamEventKind::ReasoningEnd { reasoning } => {
                let signature_bytes = reasoning
                    .as_ref()
                    .and_then(|value| value.signature.as_ref())
                    .map_or(0, Vec::len);
                let observed = self
                    .response_reasoning_bytes
                    .saturating_add(signature_bytes);
                if observed > self.response_limits.max_reasoning_bytes {
                    return Err(boxed(DevinStreamError::ResponseLimit {
                        field: "response.reasoning_signature",
                        observed,
                        limit: self.response_limits.max_reasoning_bytes,
                    }));
                }
                self.response_reasoning_bytes = observed;
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        if self.terminal_emitted {
            self.ended = true;
            return Ok(());
        }
        let events = self.parser.finish().map_err(boxed)?;
        for event in events {
            if self.terminal_emitted {
                break;
            }
            if event.is_done() {
                if self.done_seen {
                    return Err(boxed(DevinStreamError::DuplicateDone));
                }
                self.done_seen = true;
            }
            let semantic = self
                .openai_decoder
                .decode_data(event.data.as_bytes())
                .map_err(boxed)?;
            self.encode_events(&semantic)?;
        }
        if self.terminal_emitted {
            self.ended = true;
            return Ok(());
        }
        let terminal = self.openai_decoder.finish().map_err(boxed)?;
        self.encode_events(&terminal)?;
        if !self.done_seen {
            return Err(boxed(DevinStreamError::MissingDone));
        }
        self.ended = true;
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let items = self.queue.len().saturating_add(1);
        let total = self.queued_bytes.saturating_add(bytes.len());
        if items > self.max_queue_items || total > self.max_queue_bytes {
            return Err(boxed(DevinStreamError::QueueLimit {
                items,
                bytes: total,
            }));
        }
        self.queued_bytes = total;
        self.queue.push_back(bytes);
        Ok(())
    }
}

impl Body for DevinResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.cancellation.is_cancelled() {
            this.ended = true;
            return Poll::Ready(Some(Err(boxed(DevinStreamError::Cancelled))));
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
                    return Pin::new(this).poll_frame(context);
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
                        this.set_error(boxed(DevinStreamError::InvalidFrame));
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
enum DevinAdapterError {
    #[error("encoded OpenAI request is not an object")]
    EncodedRequestNotObject,
}

fn chat_limits(route: &RoutePlan) -> DevinChatLimits {
    let frame = usize_limit(route.limits().max_frame_bytes);
    let event = usize_limit(route.limits().max_event_bytes);
    DevinChatLimits {
        connect: ConnectLimits {
            max_frame_bytes: frame,
            max_decompressed_bytes: event,
        },
        max_content_bytes: usize_limit(route.limits().max_request_body_bytes),
        ..DevinChatLimits::default()
    }
}

fn accepts_connect_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all("connect-accept-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| {
            let mut parts = item.split(';');
            let encoding = parts.next().map(str::trim).unwrap_or_default();
            if !encoding.eq_ignore_ascii_case("gzip") {
                return false;
            }
            parts
                .filter_map(|parameter| parameter.trim().strip_prefix("q="))
                .all(|quality| {
                    quality
                        .trim()
                        .parse::<f32>()
                        .map_or(true, |value| value > 0.0)
                })
        })
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

fn boxed<E>(error: E) -> BoxError
where
    E: std::error::Error + Send + Sync + 'static,
{
    Box::new(error)
}

#[cfg(test)]
mod tests {
    use super::{
        accepts_connect_gzip, DevinResponseBody, DevinResponseOptions, DevinSemanticAdapter,
        DEVIN_CHAT_DECODER, DEVIN_CONNECT_ENCODER,
    };
    use crate::chat::{DevinChatEventEncoder, DevinChatResponseLimits, DevinIdentifiers};
    use crate::connect::{read_connect_trailer_error, ConnectDecoder, ConnectLimits};
    use crate::proto::{GetChatMessageResponse, StopReason};
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use http_body_util::{BodyExt, Full};
    use pooler_http::{BoxError, SemanticAdapter, SseLimits};
    use pooler_protocol::{FinishReason, LossPolicy, StreamEvent, StreamEventKind};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn adapter_has_stable_route_component_names() {
        assert_eq!(DEVIN_CHAT_DECODER, "decode.devin.chat");
        assert_eq!(DEVIN_CONNECT_ENCODER, "encode.devin.connect");
        let _ = DevinSemanticAdapter;
        let _ = DevinIdentifiers::default();
        let _ = GetChatMessageResponse {
            stop_reason: StopReason::StopPattern as i32,
            ..Default::default()
        };
    }

    #[test]
    fn adapter_requires_connect_framing_before_claiming_a_route() {
        let without_framing = pooler_config::compile_yaml(
            "devin-without-framing.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: devin
    listen: local
    ingress: {mode: semantic, decoder: decode.devin.chat}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}
"#,
        )
        .expect("route compiles");
        assert!(!DevinSemanticAdapter.supports(&without_framing.routes()[0]));

        let with_framing = pooler_config::compile_yaml(
            "devin-with-framing.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:8319}}
routes:
  - id: devin
    listen: local
    ingress: {mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}
"#,
        )
        .expect("route compiles");
        assert!(DevinSemanticAdapter.supports(&with_framing.routes()[0]));
    }

    #[test]
    fn response_compression_requires_an_explicit_gzip_acceptance() {
        let mut headers = HeaderMap::new();
        assert!(!accepts_connect_gzip(&headers));
        headers.insert(
            "connect-accept-encoding",
            HeaderValue::from_static("identity"),
        );
        assert!(!accepts_connect_gzip(&headers));
        headers.insert("connect-accept-encoding", HeaderValue::from_static("gzip"));
        assert!(accepts_connect_gzip(&headers));
        headers.insert(
            "connect-accept-encoding",
            HeaderValue::from_static("gzip; q=0"),
        );
        assert!(!accepts_connect_gzip(&headers));
    }

    #[test]
    fn event_encoder_rejects_unrepresentable_media_under_reject_policy() {
        let encoder = DevinChatEventEncoder::default();
        let event = StreamEvent::new(
            1,
            StreamEventKind::Media {
                media_type: "image/png".into(),
                source: pooler_protocol::MediaSource::inline([1, 2, 3]),
            },
        );
        assert!(encoder.encode_event(&event, LossPolicy::Reject).is_err());
        let _ = FinishReason::Stop;
    }

    #[test]
    fn response_metadata_is_an_explicit_implicit_wire_rule() {
        let encoder = DevinChatEventEncoder::default();
        let event = StreamEvent::new(
            1,
            StreamEventKind::response_start(Some("upstream-id".into()), Some("model".into())),
        );
        let encoded = encoder
            .encode_event(&event, LossPolicy::Reject)
            .expect("metadata rule");
        assert!(encoded.body.is_none());
        assert!(encoded
            .report
            .rules_applied
            .contains(&"devin.response_metadata_implicit".to_owned()));
    }

    #[test]
    fn failure_is_an_uncompressed_terminal_trailer_even_under_reject() {
        let encoder = DevinChatEventEncoder::default();
        let event = StreamEvent::new(
            1,
            StreamEventKind::Failure {
                error: pooler_protocol::StreamError::new("upstream", "bad gateway"),
            },
        );
        let encoded = encoder
            .encode_event(&event, LossPolicy::Reject)
            .expect("failure trailer");
        let body = encoded.body.expect("trailer");
        assert_eq!(body[0], super::CONNECT_END_STREAM_FLAG);
        let mut decoder = ConnectDecoder::with_gzip(ConnectLimits::default());
        let frames = decoder.push(&body).expect("frame");
        assert!(frames[0].is_end_stream());
        assert_eq!(
            read_connect_trailer_error(&frames[0].payload).as_deref(),
            Some("Devin stream error upstream: bad gateway")
        );
    }

    #[tokio::test]
    async fn upstream_failure_event_emits_exactly_one_terminal_trailer() {
        let upstream = Full::new(Bytes::from_static(
            br#"data: {"error":{"code":"provider","message":"bad"}}

"#,
        ))
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed();
        let response = DevinResponseBody::new(
            upstream,
            DevinResponseOptions {
                policy: LossPolicy::Reject,
                compress: false,
                sse_limits: SseLimits::default(),
                max_queue_items: 16,
                max_queue_bytes: 1024 * 1024,
                connect_limits: ConnectLimits::default(),
                response_limits: DevinChatResponseLimits::default(),
                cancellation: CancellationToken::new(),
            },
        );
        let body = response
            .collect()
            .await
            .expect("failure stream should terminate cleanly")
            .to_bytes();
        let mut decoder = ConnectDecoder::with_gzip(ConnectLimits::default());
        let frames = decoder.feed(&body).expect("terminal frame");
        decoder.finish().expect("complete frame");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].flags(), super::CONNECT_END_STREAM_FLAG);
        assert_eq!(
            read_connect_trailer_error(&frames[0].payload).as_deref(),
            Some("Devin stream error provider: bad")
        );
    }

    #[test]
    fn selection_context_uses_decoded_devin_identifiers() {
        use crate::proto::{ChatMessagePrompt, ChatMessageSource, GetChatMessageRequest};
        use prost::Message;

        let route = pooler_config::compile_yaml(
            "devin-selection.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: devin
    listen: local
    ingress: {mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}
"#,
        )
        .expect("Devin route")
        .routes()[0]
            .clone();
        let message = GetChatMessageRequest {
            chat_model_uid: "gpt-test".to_owned(),
            chat_message_prompts: vec![ChatMessagePrompt {
                source: ChatMessageSource::User as i32,
                prompt: "hello".to_owned(),
                ..Default::default()
            }],
            cascade_id: "cascade-body".to_owned(),
            execution_id: "execution-body".to_owned(),
            ..Default::default()
        };
        let body = crate::encode_connect_frame(&message.encode_to_vec(), false, false)
            .expect("Connect request");
        let context = DevinSemanticAdapter
            .selection_context(&route, &HeaderMap::new(), &body)
            .expect("selection context");
        assert_eq!(
            context.affinity_value("devin.conversation_id"),
            Some("cascade-body")
        );
        assert_eq!(
            context.affinity_value("devin.execution_id"),
            Some("execution-body")
        );
        assert_eq!(context.codec(), Some("decode.devin.chat"));
    }
}
