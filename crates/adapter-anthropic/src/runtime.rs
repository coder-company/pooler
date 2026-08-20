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
    SemanticResponseBody, SemanticResponseHint, SemanticResponseMode, SseLimits, SseParser,
};
use pooler_protocol::{LossPolicy, StreamError, StreamEvent, StreamEventKind};
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
        if request_streaming(body)? {
            context.require(pooler_core::Capability::Streaming);
        }
        context.with_codec(DECODE_ANTHROPIC_MESSAGES);
        if let Some(user_id) = decoded.request.metadata.get("user_id") {
            context.with_affinity_value("anthropic.metadata.user_id", user_id);
        }
        Ok(context)
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        streaming_response(route, body, cancellation)
    }

    fn decode_response_with_hint(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        _request_headers: &HeaderMap,
        hint: &SemanticResponseHint,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        match hint.mode {
            SemanticResponseMode::Json => unary_response(route, body, cancellation),
            SemanticResponseMode::AdapterDefault | SemanticResponseMode::ServerSentEvents => {
                streaming_response(route, body, cancellation)
            }
        }
    }
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
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    let limits = SseLimits::new(
        usize_limit(route.limits().max_frame_bytes),
        usize_limit(route.limits().max_event_bytes),
    );
    let body = AnthropicResponseBody::new(
        body,
        route.loss_policy(),
        limits,
        usize_limit(u64::from(route.limits().max_queue_items)),
        usize_limit(route.limits().max_queue_bytes),
        cancellation,
    );
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

#[derive(Debug, Error)]
enum AnthropicRuntimeError {
    #[error("encoded Anthropic Messages request was not an object")]
    EncodedRequestNotObject,
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
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if let Err(error) = this.finish() {
                    this.error = Some(error);
                }
                Pin::new(this).poll_frame(context)
            }
            Poll::Ready(Some(Err(error))) => {
                this.error = Some(error);
                Pin::new(this).poll_frame(context)
            }
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
                    Pin::new(this).poll_frame(context)
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(_) => Pin::new(this).poll_frame(context),
                    Err(_) => {
                        this.error = Some(Box::new(AnthropicRuntimeError::InvalidFrame));
                        Pin::new(this).poll_frame(context)
                    }
                },
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.output.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

struct AnthropicResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    limits: SseLimits,
    decoder: AnthropicEventDecoder,
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
        policy: LossPolicy,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(limits),
            limits,
            decoder: AnthropicEventDecoder::new(),
            encoder: AnthropicEventEncoder::new(),
            policy,
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
            let semantic = self
                .decoder
                .decode_sse_event(&event)
                .map_err(|error| Box::new(error) as BoxError)?;
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
            let semantic = self
                .decoder
                .decode_sse_event(&event)
                .map_err(|error| Box::new(error) as BoxError)?;
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
        if !self.decoder.is_finished() {
            return Err(Box::new(AnthropicRuntimeError::MissingTerminal));
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
                        this.set_error(Box::new(AnthropicRuntimeError::InvalidFrame));
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

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::HeaderMap;
    use http_body_util::{BodyExt, Full};
    use pooler_http::{SemanticAdapter, SemanticResponseMode};
    use serde_json::Value;
    use tokio_util::sync::CancellationToken;

    use super::AnthropicSemanticAdapter;

    fn route() -> pooler_config::RoutePlan {
        let source = r#"
version: 1
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
}
