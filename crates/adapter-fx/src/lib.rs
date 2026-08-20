#![forbid(unsafe_code)]
#![doc = "Native Vercel Labs fx client translation for OpenAI-compatible upstreams."]

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use adapter_factory::{
    FactoryDecodeOptions, FactoryFilePolicy, FactoryLanguageModelDecoder, GATEWAY_PROTOCOL_VERSION,
    GATEWAY_PROTOCOL_VERSION_HEADER, MODEL_ID_HEADER, SPECIFICATION_VERSION_HEADER,
    SPECIFICATION_VERSION_V3, SPECIFICATION_VERSION_V4, STREAMING_HEADER,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use pooler_config::RoutePlan;
use pooler_http::{
    BoxError, ProxyBody, SelectionContext, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody, SseEncoder, SseError, SseEvent, SseLimits, SseParser,
};
use pooler_protocol::{
    ContentPart, ConversionError, ConversionReport, Extensions, FinishReason, InputItem,
    LossPolicy, OpenAiChatEventDecoder, Role, StreamError, StreamEvent, StreamEventKind, Usage,
};
use serde_json::{Map, Value};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Decoder identifier for fx's AI LanguageModel request wire.
pub const FX_LANGUAGE_MODEL_DECODER: &str = "decode.fx.language_model";
/// Encoder identifier for fx's AI LanguageModel event stream.
pub const FX_EVENT_ENCODER: &str = "encode.fx.events";
/// Decoder identifier for an empty fx model-catalog request.
pub const FX_MODELS_REQUEST_DECODER: &str = "decode.fx.models.request";
/// Decoder identifier for an OpenAI-compatible model catalog.
pub const OPENAI_MODELS_DECODER: &str = "decode.openai.models";
/// Encoder identifier for fx's model catalog.
pub const FX_MODELS_ENCODER: &str = "encode.fx.models";
/// OpenAI Chat event decoder consumed by the fx stream adapter.
pub const OPENAI_CHAT_EVENTS_DECODER: &str = "decode.openai.chat.events";
/// Primary chat path used by fx's local gateway override.
pub const FX_LANGUAGE_MODEL_PATH: &str = "/v3/ai/language-model";
/// Model discovery path used by fx.
pub const FX_MODELS_PATH: &str = "/coding-agent/v1/models";

/// Semantic adapter for the Vercel Labs fx client.
///
/// This adapter deliberately has route component identifiers separate from
/// Factory Droid and from Pooler's legacy Factory LanguageModel adapter. It
/// accepts fx V3/V4 headers, converts requests to OpenAI Chat Completions, and
/// emits the completed `tool-call` event shape used by fx's working local
/// CLIProxy bridge.
#[derive(Clone, Copy, Debug, Default)]
pub struct FxSemanticAdapter;

impl SemanticAdapter for FxSemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        is_language_model_route(route) || is_models_route(route)
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        if is_models_route(route) {
            if !body.iter().all(u8::is_ascii_whitespace) {
                return Err(Box::new(FxAdapterError::UnexpectedModelsBody));
            }
            return Ok(SemanticRequestBody {
                body: Vec::new(),
                content_type: HeaderValue::from_static("application/json"),
            });
        }
        if !is_language_model_route(route) {
            return Err(unsupported_route(route));
        }

        let decoded = decode_language_model_request(route, headers, body)?;
        let encoded =
            pooler_protocol::OpenAiChatCodec::encode_request(&decoded.request, route.loss_policy())
                .map_err(|error| Box::new(error) as BoxError)?;
        let mut value: Value =
            serde_json::from_slice(&encoded.body).map_err(|error| Box::new(error) as BoxError)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| Box::new(FxAdapterError::EncodedRequestNotObject) as BoxError)?;
        object.insert("stream".to_owned(), Value::Bool(true));
        object.insert(
            "stream_options".to_owned(),
            serde_json::json!({"include_usage": true}),
        );
        Ok(SemanticRequestBody {
            body: serde_json::to_vec(&value).map_err(|error| Box::new(error) as BoxError)?,
            content_type: HeaderValue::from_static("application/json"),
        })
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        if is_models_route(route) {
            return Ok(SelectionContext::default());
        }
        if !is_language_model_route(route) {
            return Err(unsupported_route(route));
        }
        let decoded = decode_language_model_request(route, headers, body)?;
        let mut context = SelectionContext::from_semantic_request(&decoded.request);
        context.require(pooler_core::Capability::Streaming);
        context.with_codec(FX_LANGUAGE_MODEL_DECODER);
        add_affinity_values(body, &mut context)?;
        Ok(context)
    }

    fn sanitize_request_headers(&self, headers: &mut HeaderMap) {
        headers.remove(SPECIFICATION_VERSION_HEADER);
        headers.remove(MODEL_ID_HEADER);
        headers.remove(STREAMING_HEADER);
        headers.remove(GATEWAY_PROTOCOL_VERSION_HEADER);
    }

    fn decode_response(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        decode_response(route, body, None, cancellation)
    }

    fn decode_response_with_request_headers(
        &self,
        route: &RoutePlan,
        body: ProxyBody,
        request_headers: &HeaderMap,
        cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        let requested_model = request_headers
            .get(MODEL_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        decode_response(route, body, requested_model, cancellation)
    }
}

fn is_language_model_route(route: &RoutePlan) -> bool {
    route.ingress().mode() == pooler_core::BodyMode::Semantic
        && route.ingress().decoder() == Some(FX_LANGUAGE_MODEL_DECODER)
        && route.response().mode() == pooler_core::BodyMode::Semantic
        && route.response().decoder() == Some(OPENAI_CHAT_EVENTS_DECODER)
        && route.response().encoder() == Some(FX_EVENT_ENCODER)
}

fn is_models_route(route: &RoutePlan) -> bool {
    route.ingress().mode() == pooler_core::BodyMode::Semantic
        && route.ingress().decoder() == Some(FX_MODELS_REQUEST_DECODER)
        && route.response().mode() == pooler_core::BodyMode::Semantic
        && route.response().decoder() == Some(OPENAI_MODELS_DECODER)
        && route.response().encoder() == Some(FX_MODELS_ENCODER)
}

fn unsupported_route(route: &RoutePlan) -> BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("fx adapter does not support route `{}`", route.id()),
    ))
}

fn decode_language_model_request(
    route: &RoutePlan,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<adapter_factory::FactoryRequest, BoxError> {
    validate_fx_headers(headers).map_err(|error| Box::new(error) as BoxError)?;
    let model = request_model(headers, body).map_err(|error| Box::new(error) as BoxError)?;
    let decoder = FactoryLanguageModelDecoder::new(FactoryDecodeOptions {
        file_policy: if route.loss_policy().allows_degradation() {
            FactoryFilePolicy::Degrade
        } else {
            FactoryFilePolicy::Reject
        },
        ..FactoryDecodeOptions::default()
    });
    let mut decoded = decoder
        .decode(body, model)
        .map_err(|error| Box::new(error) as BoxError)?;
    normalize_fx_request(&mut decoded.request, &mut decoded.report)
        .map_err(|error| Box::new(error) as BoxError)?;
    decoded
        .report
        .validate(route.loss_policy())
        .map_err(|error| Box::new(error) as BoxError)?;
    Ok(decoded)
}

fn normalize_fx_request(
    request: &mut pooler_protocol::SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), FxAdapterError> {
    drop_extensions(
        "request.extensions",
        &mut request.extensions,
        report,
    );
    drop_extensions(
        "sampling.extensions",
        &mut request.sampling.extensions,
        report,
    );
    if let Some(reasoning) = &mut request.reasoning {
        drop_extensions(
            "reasoning.extensions",
            &mut reasoning.extensions,
            report,
        );
    }
    for tool in &mut request.tools {
        drop_extensions("tools[].extensions", &mut tool.extensions, report);
    }

    let mut normalized = Vec::with_capacity(request.input.len());
    for item in std::mem::take(&mut request.input) {
        let InputItem::Message(mut message) = item else {
            normalized.push(item);
            continue;
        };
        drop_extensions(
            "prompt[].providerOptions",
            &mut message.extensions,
            report,
        );
        if message.role != Role::Tool {
            for part in &mut message.content {
                if let ContentPart::ToolCall(call) = part {
                    drop_extensions(
                        "prompt[].content[].tool-call.extensions",
                        &mut call.extensions,
                        report,
                    );
                }
            }
            normalized.push(InputItem::Message(message));
            continue;
        }
        for part in message.content {
            let ContentPart::ToolResult(mut result) = part else {
                return Err(FxAdapterError::InvalidToolMessageContent);
            };
            drop_extensions(
                "prompt[].content[].tool-result.extensions",
                &mut result.extensions,
                report,
            );
            normalized.push(InputItem::ToolResult(result));
        }
    }
    request.input = normalized;
    Ok(())
}

fn drop_extensions(field: &str, extensions: &mut Extensions, report: &mut ConversionReport) {
    for extension in std::mem::take(extensions) {
        report.drop_optional(
            format!("{field}.{}", extension.key().as_str()),
            "fx provider options have no OpenAI Chat representation",
        );
    }
}

fn request_model(headers: &HeaderMap, body: &[u8]) -> Result<String, FxAdapterError> {
    if let Some(model) = headers.get(MODEL_ID_HEADER) {
        let model = model
            .to_str()
            .map_err(|_| FxAdapterError::InvalidModelHeader)?
            .trim();
        if !model.is_empty() {
            return Ok(model.to_owned());
        }
    }
    let value: Value = serde_json::from_slice(body).map_err(FxAdapterError::InvalidRequestJson)?;
    value
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_owned)
        .ok_or(FxAdapterError::MissingModel)
}

fn validate_fx_headers(headers: &HeaderMap) -> Result<(), FxAdapterError> {
    let specification = headers
        .get(SPECIFICATION_VERSION_HEADER)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| FxAdapterError::InvalidSpecificationVersion)
        })
        .transpose()?
        .map(str::trim)
        .unwrap_or(SPECIFICATION_VERSION_V3);
    if !matches!(
        specification,
        SPECIFICATION_VERSION_V3 | SPECIFICATION_VERSION_V4
    ) {
        return Err(FxAdapterError::InvalidSpecificationVersion);
    }
    if let Some(value) = headers.get(GATEWAY_PROTOCOL_VERSION_HEADER) {
        let value = value
            .to_str()
            .map_err(|_| FxAdapterError::InvalidGatewayProtocolVersion)?;
        if value.trim() != GATEWAY_PROTOCOL_VERSION || specification != SPECIFICATION_VERSION_V4 {
            return Err(FxAdapterError::InvalidGatewayProtocolVersion);
        }
    } else if specification == SPECIFICATION_VERSION_V4 {
        return Err(FxAdapterError::InvalidGatewayProtocolVersion);
    }
    if let Some(value) = headers.get(STREAMING_HEADER) {
        let value = value
            .to_str()
            .map_err(|_| FxAdapterError::InvalidStreamingHeader)?;
        if !value.eq_ignore_ascii_case("true") {
            return Err(if value.eq_ignore_ascii_case("false") {
                FxAdapterError::StreamingDisabled
            } else {
                FxAdapterError::InvalidStreamingHeader
            });
        }
    }
    Ok(())
}

fn add_affinity_values(body: &[u8], context: &mut SelectionContext) -> Result<(), BoxError> {
    let value: Value = serde_json::from_slice(body).map_err(|error| Box::new(error) as BoxError)?;
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (name, value) in object {
        let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
            continue;
        };
        match name.as_str() {
            "sessionId" | "session_id" | "conversationId" | "conversation_id" => {
                context.with_affinity_value("request.session_id", value);
                context.with_affinity_value("semantic.session_id", value);
            }
            "previousResponseId" | "previous_response_id" | "previousResponseID" => {
                context.with_affinity_value("openai.previous_response_id", value);
            }
            _ => {}
        }
    }
    Ok(())
}

fn decode_response(
    route: &RoutePlan,
    body: ProxyBody,
    requested_model: Option<String>,
    cancellation: CancellationToken,
) -> Result<SemanticResponseBody, BoxError> {
    if is_models_route(route) {
        return Ok(SemanticResponseBody {
            body: FxModelsBody::new(body, cancellation).boxed(),
            content_type: HeaderValue::from_static("application/json"),
        });
    }
    if !is_language_model_route(route) {
        return Err(unsupported_route(route));
    }
    let limits = SseLimits::new(
        usize_limit(route.limits().max_frame_bytes),
        usize_limit(route.limits().max_event_bytes),
    );
    let body = FxStreamBody::new(
        body,
        route.loss_policy(),
        limits,
        usize_limit(u64::from(route.limits().max_queue_items)),
        usize_limit(route.limits().max_queue_bytes),
        requested_model,
        cancellation,
    )?;
    Ok(SemanticResponseBody {
        body: body.boxed(),
        content_type: HeaderValue::from_static("text/event-stream"),
    })
}

#[derive(Debug, Error)]
enum FxAdapterError {
    #[error("missing {MODEL_ID_HEADER} header and request model")]
    MissingModel,
    #[error("{MODEL_ID_HEADER} header is not valid UTF-8")]
    InvalidModelHeader,
    #[error("invalid fx request JSON: {0}")]
    InvalidRequestJson(serde_json::Error),
    #[error("encoded OpenAI request is not an object")]
    EncodedRequestNotObject,
    #[error("fx specification version must be 3 or 4")]
    InvalidSpecificationVersion,
    #[error("fx Gateway protocol version must be {GATEWAY_PROTOCOL_VERSION}")]
    InvalidGatewayProtocolVersion,
    #[error("fx streaming header is not valid")]
    InvalidStreamingHeader,
    #[error("fx semantic route requires streaming=true")]
    StreamingDisabled,
    #[error("fx model discovery does not accept a request body")]
    UnexpectedModelsBody,
    #[error("fx tool messages may only contain tool-result parts")]
    InvalidToolMessageContent,
}

#[derive(Clone, Debug)]
struct PendingToolCall {
    id: String,
    name: String,
    arguments: String,
    complete: bool,
}

#[derive(Debug)]
struct FxEventEncoder {
    metadata_sent: bool,
    requested_model: Option<String>,
    tool_calls: Vec<PendingToolCall>,
    last_usage: Option<Usage>,
}

impl FxEventEncoder {
    fn new(requested_model: Option<String>) -> Self {
        Self {
            metadata_sent: false,
            requested_model,
            tool_calls: Vec::new(),
            last_usage: None,
        }
    }

    fn initial_value(&mut self) -> Option<Value> {
        let model = self.requested_model.as_ref()?;
        self.metadata_sent = true;
        Some(serde_json::json!({
            "type": "response-metadata",
            "modelId": model,
        }))
    }

    fn encode(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<Vec<Value>, FxEncodeError> {
        let mut report = ConversionReport::default();
        for (key, _) in event.extensions.iter() {
            report.drop_optional(
                format!("event.extensions.{}", key.as_str()),
                "fx's local gateway event wire has no extension field",
            );
        }
        let values = match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                if response_id.is_some() {
                    report.drop_optional(
                        "response_id",
                        "fx's local gateway metadata event has no response ID",
                    );
                }
                if self.metadata_sent {
                    Vec::new()
                } else {
                    self.metadata_sent = true;
                    let mut value = object_with_type("response-metadata");
                    if let Some(model) = self.requested_model.as_ref().or(model.as_ref()) {
                        value.insert("modelId".to_owned(), Value::String(model.clone()));
                    }
                    vec![Value::Object(value)]
                }
            }
            StreamEventKind::Metadata { values } => {
                let mut metadata = Map::new();
                metadata.insert(
                    "fx".to_owned(),
                    Value::Object(
                        values
                            .iter()
                            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                            .collect(),
                    ),
                );
                let mut value = object_with_type("response-metadata");
                value.insert("providerMetadata".to_owned(), Value::Object(metadata));
                vec![Value::Object(value)]
            }
            StreamEventKind::TextStart => {
                vec![block_value("text-start", event, None)?]
            }
            StreamEventKind::TextDelta { text } => vec![block_value(
                "text-delta",
                event,
                Some(("delta", Value::String(text.clone()))),
            )?],
            StreamEventKind::TextEnd => vec![block_value("text-end", event, None)?],
            StreamEventKind::ReasoningStart => {
                vec![block_value("reasoning-start", event, None)?]
            }
            StreamEventKind::ReasoningDelta { text } => vec![block_value(
                "reasoning-delta",
                event,
                Some(("delta", Value::String(text.clone()))),
            )?],
            StreamEventKind::ReasoningEnd { reasoning } => {
                if reasoning.is_some() {
                    report.drop_optional(
                        "reasoning.final_metadata",
                        "fx's local gateway reasoning-end event has no final metadata field",
                    );
                }
                vec![block_value("reasoning-end", event, None)?]
            }
            StreamEventKind::ToolCallStart { id, name } => {
                if self.tool_calls.iter().any(|call| call.id == *id) {
                    return Err(FxEncodeError::DuplicateToolCall(id.clone()));
                }
                self.tool_calls.push(PendingToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    arguments: String::new(),
                    complete: false,
                });
                Vec::new()
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                let call = self
                    .tool_calls
                    .iter_mut()
                    .find(|call| call.id == *id)
                    .ok_or_else(|| FxEncodeError::UnknownToolCall(id.clone()))?;
                if call.complete {
                    return Err(FxEncodeError::CompletedToolCall(id.clone()));
                }
                call.arguments.push_str(arguments);
                Vec::new()
            }
            StreamEventKind::ToolCallEnd { id } => {
                let call = self
                    .tool_calls
                    .iter_mut()
                    .find(|call| call.id == *id)
                    .ok_or_else(|| FxEncodeError::UnknownToolCall(id.clone()))?;
                if call.complete {
                    return Err(FxEncodeError::CompletedToolCall(id.clone()));
                }
                call.complete = true;
                Vec::new()
            }
            StreamEventKind::Usage { usage } => {
                self.last_usage = Some(usage.clone());
                Vec::new()
            }
            StreamEventKind::Completion {
                finish_reason,
                usage,
            } => self.encode_completion(finish_reason, usage.as_ref(), &mut report)?,
            StreamEventKind::Failure { error } => {
                vec![fx_error_value(error)]
            }
            StreamEventKind::Media { .. }
            | StreamEventKind::Refusal { .. }
            | StreamEventKind::Warning { .. }
            | StreamEventKind::Opaque { .. } => {
                return Err(FxEncodeError::UnsupportedEvent(event_name(&event.kind)))
            }
        };
        report.validate(policy)?;
        Ok(values)
    }

    fn encode_completion(
        &mut self,
        finish_reason: &FinishReason,
        usage: Option<&Usage>,
        report: &mut ConversionReport,
    ) -> Result<Vec<Value>, FxEncodeError> {
        let had_tools = !self.tool_calls.is_empty();
        if self.tool_calls.iter().any(|call| !call.complete) {
            return Err(FxEncodeError::IncompleteToolCall);
        }
        let mut values = Vec::with_capacity(self.tool_calls.len().saturating_add(1));
        for call in self.tool_calls.drain(..) {
            let input = serde_json::from_str(&call.arguments)
                .unwrap_or_else(|_| Value::String(call.arguments.clone()));
            values.push(serde_json::json!({
                "type": "tool-call",
                "toolCallId": call.id,
                "toolName": call.name,
                "input": input,
            }));
        }
        let usage = usage.cloned().or_else(|| self.last_usage.take());
        let mut finish = Map::new();
        let (unified, raw) = finish_reason_names(finish_reason, had_tools);
        finish.insert("unified".to_owned(), Value::String(unified.to_owned()));
        finish.insert("raw".to_owned(), Value::String(raw));
        let mut value = object_with_type("finish");
        value.insert("finishReason".to_owned(), Value::Object(finish));
        if let Some(usage) = usage {
            value.insert("usage".to_owned(), fx_usage(&usage, report));
        }
        values.push(Value::Object(value));
        Ok(values)
    }
}

fn finish_reason_names(reason: &FinishReason, has_tools: bool) -> (&'static str, String) {
    let raw = match reason {
        FinishReason::Stop => "stop".to_owned(),
        FinishReason::Length => "length".to_owned(),
        FinishReason::ToolCall => "tool_calls".to_owned(),
        FinishReason::ContentFilter => "content_filter".to_owned(),
        FinishReason::Error => "error".to_owned(),
        FinishReason::Other(raw) => raw.clone(),
    };
    let unified = if has_tools || matches!(reason, FinishReason::ToolCall) {
        "tool-calls"
    } else {
        match reason {
            FinishReason::Length => "length",
            FinishReason::ContentFilter => "content-filter",
            FinishReason::Error => "error",
            FinishReason::Stop | FinishReason::Other(_) => "stop",
            FinishReason::ToolCall => "tool-calls",
        }
    };
    (unified, raw)
}

fn fx_usage(usage: &Usage, report: &mut ConversionReport) -> Value {
    if usage.cached_input_tokens.is_some() {
        report.drop_optional(
            "usage.cached_input_tokens",
            "fx's bridge-compatible usage only exposes aggregate input tokens",
        );
    }
    if usage.total_tokens.is_some() {
        report.drop_optional(
            "usage.total_tokens",
            "fx's bridge-compatible usage derives no separate total field",
        );
    }
    if !usage.details.is_empty() {
        report.drop_optional(
            "usage.details",
            "fx's bridge-compatible usage has no provider detail map",
        );
    }
    let mut output = Map::new();
    output.insert("total".to_owned(), Value::from(usage.output_tokens));
    if let Some(reasoning) = usage.reasoning_tokens {
        output.insert("reasoning".to_owned(), Value::from(reasoning));
    }
    serde_json::json!({
        "inputTokens": {"total": usage.input_tokens},
        "outputTokens": Value::Object(output),
    })
}

fn fx_error_value(error: &StreamError) -> Value {
    let mut payload = Map::new();
    payload.insert("code".to_owned(), Value::String(error.code.clone()));
    payload.insert("message".to_owned(), Value::String(error.message.clone()));
    if error.retryable {
        payload.insert("retryable".to_owned(), Value::Bool(true));
    }
    if let Some(details) = &error.details {
        payload.insert("details".to_owned(), details.value().clone());
    }
    serde_json::json!({"type": "error", "error": Value::Object(payload)})
}

fn block_value(
    kind: &'static str,
    event: &StreamEvent,
    field: Option<(&'static str, Value)>,
) -> Result<Value, FxEncodeError> {
    let id = event
        .effective_block_id()
        .ok_or(FxEncodeError::MissingBlockId(kind))?;
    let mut value = object_with_type(kind);
    value.insert("id".to_owned(), Value::String(id.to_owned()));
    if let Some((name, field)) = field {
        value.insert(name.to_owned(), field);
    }
    Ok(Value::Object(value))
}

fn object_with_type(kind: &str) -> Map<String, Value> {
    let mut value = Map::new();
    value.insert("type".to_owned(), Value::String(kind.to_owned()));
    value
}

fn event_name(event: &StreamEventKind) -> &'static str {
    match event {
        StreamEventKind::Media { .. } => "media",
        StreamEventKind::Refusal { .. } => "refusal",
        StreamEventKind::Warning { .. } => "warning",
        StreamEventKind::Opaque { .. } => "opaque",
        _ => "event",
    }
}

#[derive(Debug, Error)]
enum FxEncodeError {
    #[error("cannot encode fx event JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot frame fx event as SSE: {0}")]
    Sse(#[from] SseError),
    #[error("fx event conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    #[error("fx {0} event requires a block identifier")]
    MissingBlockId(&'static str),
    #[error("fx tool call `{0}` started more than once")]
    DuplicateToolCall(String),
    #[error("fx tool event referenced unknown call `{0}`")]
    UnknownToolCall(String),
    #[error("fx tool event appeared after call `{0}` completed")]
    CompletedToolCall(String),
    #[error("fx completion arrived before every tool call completed")]
    IncompleteToolCall,
    #[error("fx bridge-compatible wire does not represent {0} events")]
    UnsupportedEvent(&'static str),
}

struct FxStreamBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    limits: SseLimits,
    decoder: OpenAiChatEventDecoder,
    encoder: FxEventEncoder,
    policy: LossPolicy,
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    max_queue_items: usize,
    max_queue_bytes: usize,
    cancellation: CancellationToken,
    done_seen: bool,
    ended: bool,
    error: Option<BoxError>,
}

impl FxStreamBody {
    #[allow(clippy::too_many_arguments)]
    fn new(
        body: ProxyBody,
        policy: LossPolicy,
        limits: SseLimits,
        max_queue_items: usize,
        max_queue_bytes: usize,
        requested_model: Option<String>,
        cancellation: CancellationToken,
    ) -> Result<Self, BoxError> {
        let mut encoder = FxEventEncoder::new(requested_model);
        let mut queue = VecDeque::new();
        let mut queued_bytes = 0usize;
        if let Some(value) = encoder.initial_value() {
            let bytes = frame_value(&value, limits)?;
            queued_bytes = bytes.len();
            queue.push_back(bytes);
        }
        if queue.len() > max_queue_items || queued_bytes > max_queue_bytes {
            return Err(Box::new(FxStreamError::QueueLimit {
                items: queue.len(),
                bytes: queued_bytes,
            }));
        }
        Ok(Self {
            inner: Box::pin(body),
            parser: SseParser::with_limits(limits),
            limits,
            decoder: OpenAiChatEventDecoder::new(),
            encoder,
            policy,
            queue,
            queued_bytes,
            max_queue_items,
            max_queue_bytes,
            cancellation,
            done_seen: false,
            ended: false,
            error: None,
        })
    }

    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        let events = self.parser.feed(chunk)?;
        for event in events {
            self.process_sse_event(&event)?;
        }
        Ok(())
    }

    fn process_sse_event(&mut self, event: &SseEvent) -> Result<(), BoxError> {
        if event.is_done() {
            if self.done_seen {
                return Err(Box::new(FxStreamError::DuplicateDone));
            }
            self.done_seen = true;
        }
        let events = self.decoder.decode_data(event.data.as_bytes())?;
        for event in events {
            let values = self.encoder.encode(&event, self.policy)?;
            for value in values {
                let bytes = frame_value(&value, self.limits)?;
                self.enqueue(bytes)?;
            }
        }
        if event.is_done() {
            self.enqueue(done_bytes(self.limits)?)?;
        }
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let items = self.queue.len().saturating_add(1);
        let byte_count = self.queued_bytes.saturating_add(bytes.len());
        if items > self.max_queue_items || byte_count > self.max_queue_bytes {
            return Err(Box::new(FxStreamError::QueueLimit {
                items,
                bytes: byte_count,
            }));
        }
        self.queued_bytes = byte_count;
        self.queue.push_back(bytes);
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        let events = self.parser.finish()?;
        for event in events {
            self.process_sse_event(&event)?;
        }
        if !self.done_seen {
            return Err(Box::new(FxStreamError::MissingDone));
        }
        self.ended = true;
        Ok(())
    }

    fn set_error(&mut self, error: BoxError) {
        if self.error.is_some() {
            return;
        }
        if !self.done_seen {
            let failure = fx_error_value(&StreamError::new(
                "invalid_upstream_stream",
                "the upstream stream could not be converted for fx",
            ));
            let terminal = frame_value(&failure, self.limits)
                .and_then(|failure| {
                    self.enqueue(failure)?;
                    self.enqueue(done_bytes(self.limits)?)
                })
                .is_ok();
            if terminal {
                self.ended = true;
                return;
            }
        }
        self.error = Some(error);
    }
}

impl Body for FxStreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.cancellation.is_cancelled() {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(FxStreamError::Cancelled))));
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
                        this.set_error(Box::new(FxStreamError::InvalidFrame));
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

fn frame_value(value: &Value, limits: SseLimits) -> Result<Bytes, BoxError> {
    let data = serde_json::to_string(value)?;
    let mut bytes = SseEncoder::with_limits(limits).encode(&SseEvent::new(data))?;
    add_data_space(&mut bytes, limits)?;
    Ok(Bytes::from(bytes))
}

fn done_bytes(limits: SseLimits) -> Result<Bytes, BoxError> {
    let mut bytes = SseEncoder::with_limits(limits).encode(&SseEvent::new("[DONE]"))?;
    add_data_space(&mut bytes, limits)?;
    Ok(Bytes::from(bytes))
}

fn add_data_space(body: &mut Vec<u8>, limits: SseLimits) -> Result<(), SseError> {
    if !body.starts_with(b"data:") || body.starts_with(b"data: ") {
        return Ok(());
    }
    let line_bytes = body
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(body.len())
        .saturating_add(1);
    if line_bytes > limits.max_line_bytes {
        return Err(SseError::LineTooLarge {
            limit: limits.max_line_bytes,
            observed: line_bytes,
        });
    }
    let event_bytes = body.len().saturating_add(1);
    if event_bytes > limits.max_event_bytes {
        return Err(SseError::EventTooLarge {
            limit: limits.max_event_bytes,
            observed: event_bytes,
        });
    }
    body.insert(5, b' ');
    Ok(())
}

#[derive(Debug, Error)]
enum FxStreamError {
    #[error("fx upstream SSE ended without [DONE]")]
    MissingDone,
    #[error("fx upstream SSE contained duplicate [DONE] markers")]
    DuplicateDone,
    #[error("fx semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("fx semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("fx semantic response canceled")]
    Cancelled,
}

struct FxModelsBody {
    inner: Pin<Box<ProxyBody>>,
    cancellation: CancellationToken,
    buffered: Vec<u8>,
    ended: bool,
}

impl FxModelsBody {
    fn new(body: ProxyBody, cancellation: CancellationToken) -> Self {
        Self {
            inner: Box::pin(body),
            cancellation,
            buffered: Vec::new(),
            ended: false,
        }
    }

    fn finish(&mut self) -> Result<Bytes, BoxError> {
        let mut value: Value = serde_json::from_slice(&self.buffered)?;
        let models = value
            .get_mut("data")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| Box::new(FxModelsError::MissingData) as BoxError)?;
        for model in models {
            let model = model
                .as_object_mut()
                .ok_or_else(|| Box::new(FxModelsError::InvalidModel) as BoxError)?;
            model.insert("type".to_owned(), Value::String("language".to_owned()));
            model.insert(
                "tags".to_owned(),
                serde_json::json!(["tool-use", "reasoning", "vision"]),
            );
            model.insert(
                "reasoning_options".to_owned(),
                serde_json::json!([{
                    "type": "effort",
                    "values": ["low", "medium", "high", "xhigh", "max", "ultra"]
                }]),
            );
        }
        Ok(Bytes::from(serde_json::to_vec(&value)?))
    }
}

impl Body for FxModelsBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        if this.cancellation.is_cancelled() {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(FxModelsError::Cancelled))));
        }
        loop {
            match this.inner.as_mut().poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.ended = true;
                    return Poll::Ready(Some(this.finish().map(Frame::data)));
                }
                Poll::Ready(Some(Err(error))) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => this.buffered.extend_from_slice(&data),
                    Err(frame) => {
                        if frame.into_trailers().is_err() {
                            this.ended = true;
                            return Poll::Ready(Some(Err(Box::new(FxModelsError::InvalidFrame))));
                        }
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

#[derive(Debug, Error)]
enum FxModelsError {
    #[error("OpenAI models response is missing a data array")]
    MissingData,
    #[error("OpenAI models response contains a non-object model")]
    InvalidModel,
    #[error("fx models response contained an invalid body frame")]
    InvalidFrame,
    #[error("fx models response canceled")]
    Cancelled,
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use pooler_protocol::StreamEvent;

    #[test]
    fn completed_tool_call_is_emitted_before_finish() {
        let mut encoder = FxEventEncoder::new(Some("gpt-test".to_owned()));
        assert!(encoder
            .encode(
                &StreamEvent::new(
                    1,
                    StreamEventKind::ToolCallStart {
                        id: "call-1".to_owned(),
                        name: "read_file".to_owned(),
                    },
                ),
                LossPolicy::Degrade,
            )
            .expect("tool start")
            .is_empty());
        assert!(encoder
            .encode(
                &StreamEvent::new(
                    2,
                    StreamEventKind::ToolCallDelta {
                        id: "call-1".to_owned(),
                        arguments: "{\"path\":\"README.md\"}".to_owned(),
                    },
                ),
                LossPolicy::Degrade,
            )
            .expect("tool delta")
            .is_empty());
        assert!(encoder
            .encode(
                &StreamEvent::new(
                    3,
                    StreamEventKind::ToolCallEnd {
                        id: "call-1".to_owned(),
                    },
                ),
                LossPolicy::Degrade,
            )
            .expect("tool end")
            .is_empty());
        let values = encoder
            .encode(
                &StreamEvent::new(
                    4,
                    StreamEventKind::completion(FinishReason::ToolCall, Some(Usage::new(10, 3))),
                ),
                LossPolicy::Degrade,
            )
            .expect("completion");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["type"], "tool-call");
        assert_eq!(values[0]["toolCallId"], "call-1");
        assert_eq!(values[0]["toolName"], "read_file");
        assert_eq!(values[0]["input"]["path"], "README.md");
        assert_eq!(values[1]["finishReason"]["unified"], "tool-calls");
        assert_eq!(values[1]["finishReason"]["raw"], "tool_calls");
    }

    #[test]
    fn reject_policy_refuses_bridge_usage_loss() {
        let mut encoder = FxEventEncoder::new(None);
        let error = encoder
            .encode(
                &StreamEvent::new(
                    1,
                    StreamEventKind::completion(FinishReason::Stop, Some(Usage::new(1, 2))),
                ),
                LossPolicy::Reject,
            )
            .expect_err("total token field is intentionally omitted");
        assert!(matches!(error, FxEncodeError::Conversion(_)));
    }
}
