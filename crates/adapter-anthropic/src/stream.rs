use std::collections::BTreeMap;

use pooler_http::{SseEncoder, SseError, SseEvent, SseLimits};
use pooler_protocol::{
    ConversionError, ConversionReport, ExtensionError, FinishReason, LossPolicy, OpaqueExtension,
    PreservedJson, PreservedJsonError, ReasoningBlock, ReplayPolicy, StreamError, StreamEvent,
    StreamEventKind, Usage,
};
use serde_json::{Map, Value};
use thiserror::Error;

const ANTHROPIC_EVENT_MEDIA_TYPE: &str = "application/vnd.anthropic.event+json";
const ANTHROPIC_CONTENT_MEDIA_TYPE: &str = "application/vnd.anthropic.content+json";
const UNARY_TEMPLATE_EXTENSION: &str = "anthropic.messages.unary_template";

/// Errors returned by Anthropic Messages stream conversion.
#[derive(Debug, Error)]
pub enum AnthropicStreamError {
    /// An SSE data field was not valid JSON.
    #[error("invalid Anthropic Messages stream JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// SSE framing failed its configured bounds.
    #[error("invalid Anthropic Messages SSE framing: {0}")]
    Sse(#[from] SseError),
    /// A required event field was absent.
    #[error("Anthropic Messages event field `{field}` is missing")]
    MissingField {
        /// Dotted event field path.
        field: String,
    },
    /// An event field had the wrong representation.
    #[error("Anthropic Messages event field `{field}` must be {expected}")]
    InvalidShape {
        /// Dotted event field path.
        field: String,
        /// Required representation.
        expected: &'static str,
    },
    /// An event violated the stream lifecycle.
    #[error("invalid Anthropic Messages stream state: {0}")]
    InvalidState(String),
    /// Provider error details could not be retained.
    #[error("invalid preserved Anthropic error JSON: {0}")]
    PreservedJson(#[from] PreservedJsonError),
    /// Provider response state could not be retained as an extension.
    #[error("invalid Anthropic response extension: {0}")]
    Extension(#[from] ExtensionError),
    /// The route's loss policy rejected an event conversion.
    #[error("Anthropic Messages event conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
}

/// One or more encoded Anthropic Messages SSE records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedAnthropicEvents {
    /// Complete SSE records, or an empty vector for a deferred usage event.
    pub body: Vec<u8>,
    /// Preserved and degraded semantic fields.
    pub report: ConversionReport,
}

/// A unary Anthropic message normalized into ordered semantic events.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedAnthropicMessage {
    /// Complete semantic response lifecycle.
    pub events: Vec<StreamEvent>,
    /// Preserved and degraded semantic fields.
    pub report: ConversionReport,
}

/// One unary Anthropic message JSON document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedAnthropicMessage {
    /// Compact UTF-8 JSON body.
    pub body: Vec<u8>,
    /// Preserved and degraded semantic fields.
    pub report: ConversionReport,
}

/// Stateless codec for non-streaming Anthropic message responses.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnthropicMessageCodec;

impl AnthropicMessageCodec {
    /// Decodes one successful unary message through semantic stream events.
    pub fn decode_response(input: &[u8]) -> Result<DecodedAnthropicMessage, AnthropicStreamError> {
        decode_unary_message(input)
    }

    /// Encodes one complete semantic response under an explicit loss policy.
    pub fn encode_response(
        events: &[StreamEvent],
        policy: LossPolicy,
    ) -> Result<EncodedAnthropicMessage, AnthropicStreamError> {
        encode_unary_message(events, policy)
    }
}

fn decode_unary_message(input: &[u8]) -> Result<DecodedAnthropicMessage, AnthropicStreamError> {
    let value: Value = serde_json::from_slice(input)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape("message", "an object"))?;
    if object.get("type").and_then(Value::as_str) == Some("error") {
        return decode_unary_error(object);
    }
    if object.get("type").and_then(Value::as_str) != Some("message") {
        return Err(AnthropicStreamError::InvalidState(
            "unary response type must be `message`".to_owned(),
        ));
    }
    if object.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err(AnthropicStreamError::InvalidState(
            "unary message role must be `assistant`".to_owned(),
        ));
    }
    let response_id = required_string(object, "id", "message.id")?.to_owned();
    let model = required_string(object, "model", "message.model")?.to_owned();
    let mut report = ConversionReport::default();
    let mut start = StreamEvent::new(
        0,
        StreamEventKind::ResponseStart {
            response_id: Some(response_id),
            model: Some(model),
        },
    );
    let template = OpaqueExtension::new(
        "anthropic.messages",
        "unary_template",
        serde_json::to_vec(&value)?,
    )?
    .with_media_type("application/json")?
    .with_replay_policy(ReplayPolicy::Never);
    report.preserve_extension(&template.key());
    start.extensions.insert(template);
    let mut events = vec![start];
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_shape("message.content", "an array"))?;
    for (index, block) in content.iter().enumerate() {
        decode_unary_content(block, index, &mut events, &mut report)?;
    }
    let mut usage = Usage::default();
    merge_usage(
        &mut usage,
        object
            .get("usage")
            .ok_or_else(|| missing("message.usage"))?,
        "message.usage",
    )?;
    let stop_reason = object
        .get("stop_reason")
        .and_then(Value::as_str)
        .map_or_else(
            || FinishReason::Other("none".to_owned()),
            decode_finish_reason,
        );
    push_unary_event(
        &mut events,
        StreamEventKind::Completion {
            finish_reason: stop_reason,
            usage: Some(usage),
        },
        None,
    );
    Ok(DecodedAnthropicMessage { events, report })
}

fn decode_unary_error(
    object: &Map<String, Value>,
) -> Result<DecodedAnthropicMessage, AnthropicStreamError> {
    let error = object
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_shape("error.error", "an object"))?;
    let code = required_string(error, "type", "error.error.type")?.to_owned();
    let message = required_string(error, "message", "error.error.message")?.to_owned();
    let retryable = matches!(
        code.as_str(),
        "api_error" | "overloaded_error" | "rate_limit_error"
    );
    let mut stream_error = StreamError::new(code, message).with_retryable(retryable);
    stream_error.details = Some(PreservedJson::from_value(Value::Object(error.clone()))?);
    Ok(DecodedAnthropicMessage {
        events: vec![StreamEvent::new(
            0,
            StreamEventKind::Failure {
                error: stream_error,
            },
        )],
        report: ConversionReport::default(),
    })
}

fn decode_unary_content(
    value: &Value,
    index: usize,
    events: &mut Vec<StreamEvent>,
    report: &mut ConversionReport,
) -> Result<(), AnthropicStreamError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape(&format!("message.content[{index}]"), "an object"))?;
    let kind = required_string(object, "type", &format!("message.content[{index}].type"))?;
    match kind {
        "text" => {
            let id = block_id("text", u64::try_from(index).unwrap_or(u64::MAX));
            push_unary_event(events, StreamEventKind::TextStart, Some(&id));
            let text = required_string(object, "text", &format!("message.content[{index}].text"))?;
            if !text.is_empty() {
                push_unary_event(
                    events,
                    StreamEventKind::TextDelta {
                        text: text.to_owned(),
                    },
                    Some(&id),
                );
            }
            push_unary_event(events, StreamEventKind::TextEnd, Some(&id));
        }
        "thinking" | "redacted_thinking" => {
            let id = block_id("thinking", u64::try_from(index).unwrap_or(u64::MAX));
            push_unary_event(events, StreamEventKind::ReasoningStart, Some(&id));
            let text = optional_string(
                object,
                "thinking",
                &format!("message.content[{index}].thinking"),
            )?
            .unwrap_or_default();
            if !text.is_empty() {
                push_unary_event(
                    events,
                    StreamEventKind::ReasoningDelta { text: text.clone() },
                    Some(&id),
                );
            }
            let reasoning = ReasoningBlock {
                text: (!text.is_empty()).then_some(text),
                signature: optional_string(
                    object,
                    "signature",
                    &format!("message.content[{index}].signature"),
                )?
                .map(String::into_bytes),
                encrypted_content: optional_string(
                    object,
                    "data",
                    &format!("message.content[{index}].data"),
                )?
                .map(String::into_bytes),
                ..ReasoningBlock::default()
            };
            push_unary_event(
                events,
                StreamEventKind::ReasoningEnd {
                    reasoning: Some(reasoning),
                },
                Some(&id),
            );
        }
        "tool_use" | "server_tool_use" => {
            let id =
                required_string(object, "id", &format!("message.content[{index}].id"))?.to_owned();
            let name = required_string(object, "name", &format!("message.content[{index}].name"))?
                .to_owned();
            push_unary_event(
                events,
                StreamEventKind::ToolCallStart {
                    id: id.clone(),
                    name,
                },
                None,
            );
            let input = object
                .get("input")
                .ok_or_else(|| missing(format!("message.content[{index}].input")))?;
            push_unary_event(
                events,
                StreamEventKind::ToolCallDelta {
                    id: id.clone(),
                    arguments: serde_json::to_string(input)?,
                },
                None,
            );
            push_unary_event(events, StreamEventKind::ToolCallEnd { id }, None);
        }
        other => {
            report.preserve_capability(format!("anthropic.messages.content.{other}"));
            push_unary_event(
                events,
                StreamEventKind::Opaque {
                    media_type: ANTHROPIC_CONTENT_MEDIA_TYPE.to_owned(),
                    data: serde_json::to_vec(value)?,
                },
                None,
            );
        }
    }
    Ok(())
}

fn push_unary_event(events: &mut Vec<StreamEvent>, kind: StreamEventKind, block_id: Option<&str>) {
    let sequence = u64::try_from(events.len()).unwrap_or(u64::MAX);
    let mut event = StreamEvent::new(sequence, kind);
    if let Some(block_id) = block_id {
        event = event.with_block_id(block_id);
    }
    events.push(event);
}

#[derive(Debug)]
enum UnaryBlock {
    Text {
        id: String,
        text: String,
    },
    Reasoning {
        id: String,
        text: String,
    },
    Tool {
        id: String,
        name: String,
        arguments: String,
    },
}

fn encode_unary_message(
    events: &[StreamEvent],
    policy: LossPolicy,
) -> Result<EncodedAnthropicMessage, AnthropicStreamError> {
    let mut report = ConversionReport::default();
    let mut template = None;
    let mut response_id = None;
    let mut model = None;
    let mut blocks = Vec::<UnaryBlock>::new();
    let mut content = Vec::new();
    let mut usage = None;
    let mut finish_reason = None;
    for event in events {
        match &event.kind {
            StreamEventKind::ResponseStart {
                response_id: id,
                model: response_model,
            } => {
                response_id = id.clone();
                model = response_model.clone();
                if let Some(extension) = event.extensions.get_str(UNARY_TEMPLATE_EXTENSION) {
                    template = Some(serde_json::from_slice::<Value>(extension.as_bytes())?);
                    report.preserve_extension(&extension.key());
                }
                report_unary_extensions(event, true, &mut report);
            }
            StreamEventKind::TextStart => {
                let id = required_block_id(event, "unary text start")?.to_owned();
                start_unary_block(
                    &mut blocks,
                    UnaryBlock::Text {
                        id,
                        text: String::new(),
                    },
                )?;
            }
            StreamEventKind::TextDelta { text } => {
                let id = required_block_id(event, "unary text delta")?;
                match unary_block_mut(&mut blocks, id)? {
                    UnaryBlock::Text { text: value, .. } => value.push_str(text),
                    _ => return Err(wrong_unary_block(id)),
                }
            }
            StreamEventKind::TextEnd => {
                let id = required_block_id(event, "unary text end")?;
                match end_unary_block(&mut blocks, id)? {
                    UnaryBlock::Text { text, .. } => {
                        content.push(serde_json::json!({"type":"text", "text":text}));
                    }
                    _ => return Err(wrong_unary_block(id)),
                }
            }
            StreamEventKind::ReasoningStart => {
                let id = required_block_id(event, "unary reasoning start")?.to_owned();
                start_unary_block(
                    &mut blocks,
                    UnaryBlock::Reasoning {
                        id,
                        text: String::new(),
                    },
                )?;
            }
            StreamEventKind::ReasoningDelta { text } => {
                let id = required_block_id(event, "unary reasoning delta")?;
                match unary_block_mut(&mut blocks, id)? {
                    UnaryBlock::Reasoning { text: value, .. } => value.push_str(text),
                    _ => return Err(wrong_unary_block(id)),
                }
            }
            StreamEventKind::ReasoningEnd { reasoning } => {
                let id = required_block_id(event, "unary reasoning end")?;
                let collected = match end_unary_block(&mut blocks, id)? {
                    UnaryBlock::Reasoning { text, .. } => text,
                    _ => return Err(wrong_unary_block(id)),
                };
                let reasoning = reasoning.as_ref();
                if let Some(encrypted) =
                    reasoning.and_then(|value| value.encrypted_content.as_ref())
                {
                    content.push(serde_json::json!({
                        "type":"redacted_thinking",
                        "data":bytes_as_string(encrypted),
                    }));
                } else {
                    let mut block = Map::from_iter([
                        ("type".to_owned(), Value::String("thinking".to_owned())),
                        (
                            "thinking".to_owned(),
                            Value::String(if collected.is_empty() {
                                reasoning
                                    .and_then(|value| value.text.clone())
                                    .unwrap_or_default()
                            } else {
                                collected
                            }),
                        ),
                    ]);
                    if let Some(signature) = reasoning.and_then(|value| value.signature.as_ref()) {
                        block.insert(
                            "signature".to_owned(),
                            Value::String(bytes_as_string(signature)),
                        );
                    }
                    content.push(Value::Object(block));
                }
            }
            StreamEventKind::ToolCallStart { id, name } => {
                start_unary_block(
                    &mut blocks,
                    UnaryBlock::Tool {
                        id: id.clone(),
                        name: name.clone(),
                        arguments: String::new(),
                    },
                )?;
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                match unary_block_mut(&mut blocks, id)? {
                    UnaryBlock::Tool {
                        arguments: value, ..
                    } => value.push_str(arguments),
                    _ => return Err(wrong_unary_block(id)),
                }
            }
            StreamEventKind::ToolCallEnd { id } => match end_unary_block(&mut blocks, id)? {
                UnaryBlock::Tool {
                    name, arguments, ..
                } => {
                    let input = if arguments.is_empty() {
                        serde_json::json!({})
                    } else {
                        serde_json::from_str(&arguments)?
                    };
                    content.push(serde_json::json!({
                        "type":"tool_use", "id":id, "name":name, "input":input
                    }));
                }
                _ => return Err(wrong_unary_block(id)),
            },
            StreamEventKind::Usage { usage: value } => usage = Some(value.clone()),
            StreamEventKind::Completion {
                finish_reason: reason,
                usage: completion_usage,
            } => {
                finish_reason = Some(reason.clone());
                if let Some(completion_usage) = completion_usage {
                    usage = Some(completion_usage.clone());
                }
            }
            StreamEventKind::Failure { error } => {
                let mut error_value = error
                    .details
                    .as_ref()
                    .and_then(|value| value.value().as_object())
                    .cloned()
                    .unwrap_or_default();
                error_value.insert("type".to_owned(), Value::String(error.code.clone()));
                error_value.insert("message".to_owned(), Value::String(error.message.clone()));
                report.validate(policy)?;
                return Ok(EncodedAnthropicMessage {
                    body: serde_json::to_vec(&serde_json::json!({
                        "type":"error", "error":error_value
                    }))?,
                    report,
                });
            }
            StreamEventKind::Opaque { media_type, data }
                if media_type == ANTHROPIC_CONTENT_MEDIA_TYPE =>
            {
                content.push(serde_json::from_slice(data)?);
            }
            StreamEventKind::Metadata { .. } | StreamEventKind::Warning { .. } => {
                report.drop_optional(
                    "unary.event",
                    "semantic event has no unary Anthropic message representation",
                );
            }
            StreamEventKind::Refusal { text } => {
                report.degrade_field(
                    "unary.refusal",
                    "Anthropic represents refusal output as text content",
                );
                content.push(serde_json::json!({"type":"text", "text":text}));
            }
            StreamEventKind::Media { .. } | StreamEventKind::Opaque { .. } => {
                report.unsupported_required(
                    "unary.event",
                    "semantic event has no unary Anthropic message representation",
                );
            }
        }
    }
    if !blocks.is_empty() {
        return Err(AnthropicStreamError::InvalidState(
            "unary response ended with open content blocks".to_owned(),
        ));
    }
    let finish_reason = finish_reason.ok_or_else(|| {
        AnthropicStreamError::InvalidState("unary response has no completion event".to_owned())
    })?;
    let usage = usage.unwrap_or_default();
    let mut object = template
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    merge_unary_content_templates(&mut content, template.as_ref());
    object.insert(
        "id".to_owned(),
        Value::String(response_id.unwrap_or_else(|| "msg_pooler".to_owned())),
    );
    object.insert("type".to_owned(), Value::String("message".to_owned()));
    object.insert("role".to_owned(), Value::String("assistant".to_owned()));
    object.insert(
        "model".to_owned(),
        Value::String(model.unwrap_or_else(|| "pooler-model".to_owned())),
    );
    object.insert("content".to_owned(), Value::Array(content));
    object.insert(
        "stop_reason".to_owned(),
        if matches!(finish_reason, FinishReason::Other(ref reason) if reason == "none") {
            Value::Null
        } else {
            Value::String(encode_finish_reason(&finish_reason))
        },
    );
    object
        .entry("stop_sequence".to_owned())
        .or_insert(Value::Null);
    object.insert(
        "usage".to_owned(),
        merge_unary_usage_template(encode_usage(&usage), template.as_ref()),
    );
    report.validate(policy)?;
    Ok(EncodedAnthropicMessage {
        body: serde_json::to_vec(&Value::Object(object))?,
        report,
    })
}

fn report_unary_extensions(
    event: &StreamEvent,
    allow_template: bool,
    report: &mut ConversionReport,
) {
    for (key, _) in &event.extensions {
        if !(allow_template && key.as_str() == UNARY_TEMPLATE_EXTENSION) {
            report.drop_optional(
                format!("event.extensions.{key}"),
                "event extension has no unary Anthropic representation",
            );
        }
    }
}

fn start_unary_block(
    blocks: &mut Vec<UnaryBlock>,
    block: UnaryBlock,
) -> Result<(), AnthropicStreamError> {
    let id = unary_block_id(&block);
    if blocks.iter().any(|block| unary_block_id(block) == id) {
        return Err(AnthropicStreamError::InvalidState(format!(
            "unary content block `{id}` started twice"
        )));
    }
    blocks.push(block);
    Ok(())
}

fn unary_block_mut<'a>(
    blocks: &'a mut [UnaryBlock],
    id: &str,
) -> Result<&'a mut UnaryBlock, AnthropicStreamError> {
    blocks
        .iter_mut()
        .find(|block| unary_block_id(block) == id)
        .ok_or_else(|| {
            AnthropicStreamError::InvalidState(format!("unary content block `{id}` is not open"))
        })
}

fn end_unary_block(
    blocks: &mut Vec<UnaryBlock>,
    id: &str,
) -> Result<UnaryBlock, AnthropicStreamError> {
    let index = blocks
        .iter()
        .position(|block| unary_block_id(block) == id)
        .ok_or_else(|| {
            AnthropicStreamError::InvalidState(format!("unary content block `{id}` is not open"))
        })?;
    Ok(blocks.remove(index))
}

fn unary_block_id(block: &UnaryBlock) -> &str {
    match block {
        UnaryBlock::Text { id, .. }
        | UnaryBlock::Reasoning { id, .. }
        | UnaryBlock::Tool { id, .. } => id,
    }
}

fn wrong_unary_block(id: &str) -> AnthropicStreamError {
    AnthropicStreamError::InvalidState(format!("unary content block `{id}` has the wrong kind"))
}

fn merge_unary_content_templates(content: &mut [Value], template: Option<&Value>) {
    let Some(template) = template
        .and_then(|value| value.get("content"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for (value, original) in content.iter_mut().zip(template) {
        let (Some(value), Some(original)) = (value.as_object_mut(), original.as_object()) else {
            continue;
        };
        if value.get("type") != original.get("type") {
            continue;
        }
        for (key, original_value) in original {
            value
                .entry(key.clone())
                .or_insert_with(|| original_value.clone());
        }
    }
}

fn merge_unary_usage_template(usage: Value, template: Option<&Value>) -> Value {
    let Some(mut usage) = usage.as_object().cloned() else {
        return usage;
    };
    if let Some(original) = template
        .and_then(|value| value.get("usage"))
        .and_then(Value::as_object)
    {
        for (key, value) in original {
            usage.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    Value::Object(usage)
}

#[derive(Debug)]
enum DecodedBlock {
    Text {
        id: String,
    },
    Reasoning {
        id: String,
        text: String,
        signature: Vec<u8>,
        encrypted_content: Option<Vec<u8>>,
    },
    Tool {
        id: String,
    },
    Opaque,
}

/// Stateful decoder for Anthropic's named SSE events.
#[derive(Debug, Default)]
pub struct AnthropicEventDecoder {
    sequence: u64,
    blocks: BTreeMap<u64, DecodedBlock>,
    usage: Usage,
    response_started: bool,
    completion_seen: bool,
    terminal: bool,
}

impl AnthropicEventDecoder {
    /// Creates an empty decoder for one response stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a `message_stop` or `error` event ended the stream.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.terminal
    }

    /// Decodes one parsed SSE record into zero or more semantic events.
    pub fn decode_sse_event(
        &mut self,
        event: &SseEvent,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        if self.terminal {
            return Err(AnthropicStreamError::InvalidState(
                "event appeared after stream termination".to_owned(),
            ));
        }
        let value: Value = serde_json::from_str(&event.data)?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid_shape("event", "an object"))?;
        let kind = required_string(object, "type", "event.type")?;
        if let Some(event_name) = event.event.as_deref() {
            if event_name != kind {
                return Err(AnthropicStreamError::InvalidState(format!(
                    "SSE event `{event_name}` carried `{kind}` data"
                )));
            }
        }
        self.decode_value(kind, object, &value)
    }

    /// Decodes one UTF-8 JSON event without SSE field framing.
    pub fn decode_data(&mut self, data: &[u8]) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        let data = std::str::from_utf8(data).map_err(|_| {
            AnthropicStreamError::InvalidState("event data was not UTF-8".to_owned())
        })?;
        self.decode_sse_event(&SseEvent::new(data))
    }

    fn decode_value(
        &mut self,
        kind: &str,
        object: &Map<String, Value>,
        raw: &Value,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        match kind {
            "message_start" => self.decode_message_start(object),
            "content_block_start" => self.decode_block_start(object),
            "content_block_delta" => self.decode_block_delta(object, raw),
            "content_block_stop" => self.decode_block_stop(object),
            "message_delta" => self.decode_message_delta(object),
            "message_stop" => self.decode_message_stop(),
            "error" => self.decode_error(object),
            "ping" => Ok(Vec::new()),
            _ => Ok(vec![self.event(StreamEventKind::Opaque {
                media_type: ANTHROPIC_EVENT_MEDIA_TYPE.to_owned(),
                data: serde_json::to_vec(raw)?,
            })]),
        }
    }

    fn decode_message_start(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        if self.response_started {
            return Err(AnthropicStreamError::InvalidState(
                "message_start appeared twice".to_owned(),
            ));
        }
        let message = object
            .get("message")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("message_start.message", "an object"))?;
        let response_id = optional_string(message, "id", "message_start.message.id")?;
        let model = optional_string(message, "model", "message_start.message.model")?;
        if let Some(usage) = message.get("usage") {
            merge_usage(&mut self.usage, usage, "message_start.message.usage")?;
        }
        self.response_started = true;
        let mut events = vec![self.event(StreamEventKind::ResponseStart { response_id, model })];
        if has_usage(&self.usage) {
            let usage = self.usage.clone();
            events.push(self.event(StreamEventKind::Usage { usage }));
        }
        Ok(events)
    }

    fn decode_block_start(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        let index = required_index(object, "content_block_start.index")?;
        if self.blocks.contains_key(&index) {
            return Err(AnthropicStreamError::InvalidState(format!(
                "content block {index} started twice"
            )));
        }
        let block = object
            .get("content_block")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("content_block_start.content_block", "an object"))?;
        let kind = required_string(block, "type", "content_block_start.content_block.type")?;
        match kind {
            "text" => {
                let id = block_id("text", index);
                self.blocks
                    .insert(index, DecodedBlock::Text { id: id.clone() });
                let mut events = vec![self.event_with_block(StreamEventKind::TextStart, &id)];
                if let Some(text) =
                    optional_string(block, "text", "content_block_start.content_block.text")?
                        .filter(|text| !text.is_empty())
                {
                    events.push(self.event_with_block(StreamEventKind::TextDelta { text }, &id));
                }
                Ok(events)
            }
            "thinking" | "redacted_thinking" => {
                let id = block_id("thinking", index);
                let text = optional_string(
                    block,
                    "thinking",
                    "content_block_start.content_block.thinking",
                )?
                .unwrap_or_default();
                let signature = optional_string(
                    block,
                    "signature",
                    "content_block_start.content_block.signature",
                )?
                .unwrap_or_default()
                .into_bytes();
                let encrypted_content =
                    optional_string(block, "data", "content_block_start.content_block.data")?
                        .map(String::into_bytes);
                self.blocks.insert(
                    index,
                    DecodedBlock::Reasoning {
                        id: id.clone(),
                        text: text.clone(),
                        signature,
                        encrypted_content,
                    },
                );
                let mut events = vec![self.event_with_block(StreamEventKind::ReasoningStart, &id)];
                if !text.is_empty() {
                    events
                        .push(self.event_with_block(StreamEventKind::ReasoningDelta { text }, &id));
                }
                Ok(events)
            }
            "tool_use" | "server_tool_use" => {
                let id = required_string(block, "id", "content_block_start.content_block.id")?
                    .to_owned();
                let name =
                    required_string(block, "name", "content_block_start.content_block.name")?
                        .to_owned();
                self.blocks
                    .insert(index, DecodedBlock::Tool { id: id.clone() });
                let mut events = vec![self.event(StreamEventKind::ToolCallStart {
                    id: id.clone(),
                    name,
                })];
                if let Some(input) = block
                    .get("input")
                    .filter(|value| value.as_object().is_none_or(|object| !object.is_empty()))
                {
                    events.push(self.event(StreamEventKind::ToolCallDelta {
                        id,
                        arguments: serde_json::to_string(input)?,
                    }));
                }
                Ok(events)
            }
            _ => {
                self.blocks.insert(index, DecodedBlock::Opaque);
                Ok(vec![self.event(StreamEventKind::Opaque {
                    media_type: ANTHROPIC_EVENT_MEDIA_TYPE.to_owned(),
                    data: serde_json::to_vec(&Value::Object(object.clone()))?,
                })])
            }
        }
    }

    fn decode_block_delta(
        &mut self,
        object: &Map<String, Value>,
        raw: &Value,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        let index = required_index(object, "content_block_delta.index")?;
        let delta = object
            .get("delta")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("content_block_delta.delta", "an object"))?;
        let kind = required_string(delta, "type", "content_block_delta.delta.type")?;
        match (self.blocks.get_mut(&index), kind) {
            (Some(DecodedBlock::Text { id }), "text_delta") => {
                let id = id.clone();
                let text =
                    required_string(delta, "text", "content_block_delta.delta.text")?.to_owned();
                Ok(vec![
                    self.event_with_block(StreamEventKind::TextDelta { text }, id)
                ])
            }
            (Some(DecodedBlock::Reasoning { id, text, .. }), "thinking_delta") => {
                let id = id.clone();
                let fragment =
                    required_string(delta, "thinking", "content_block_delta.delta.thinking")?
                        .to_owned();
                text.push_str(&fragment);
                Ok(vec![self.event_with_block(
                    StreamEventKind::ReasoningDelta { text: fragment },
                    id,
                )])
            }
            (Some(DecodedBlock::Reasoning { signature, .. }), "signature_delta") => {
                signature.extend_from_slice(
                    required_string(delta, "signature", "content_block_delta.delta.signature")?
                        .as_bytes(),
                );
                Ok(Vec::new())
            }
            (Some(DecodedBlock::Tool { id }), "input_json_delta") => {
                let id = id.clone();
                let arguments = required_string(
                    delta,
                    "partial_json",
                    "content_block_delta.delta.partial_json",
                )?
                .to_owned();
                Ok(vec![
                    self.event(StreamEventKind::ToolCallDelta { id, arguments })
                ])
            }
            (Some(DecodedBlock::Opaque), _) | (_, "citations_delta") => {
                Ok(vec![self.event(StreamEventKind::Opaque {
                    media_type: ANTHROPIC_EVENT_MEDIA_TYPE.to_owned(),
                    data: serde_json::to_vec(raw)?,
                })])
            }
            (None, _) => Err(AnthropicStreamError::InvalidState(format!(
                "delta referenced unknown content block {index}"
            ))),
            (Some(_), _) => Err(AnthropicStreamError::InvalidState(format!(
                "delta `{kind}` does not match content block {index}"
            ))),
        }
    }

    fn decode_block_stop(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        let index = required_index(object, "content_block_stop.index")?;
        let block = self.blocks.remove(&index).ok_or_else(|| {
            AnthropicStreamError::InvalidState(format!(
                "stop referenced unknown content block {index}"
            ))
        })?;
        match block {
            DecodedBlock::Text { id } => {
                Ok(vec![self.event_with_block(StreamEventKind::TextEnd, id)])
            }
            DecodedBlock::Reasoning {
                id,
                text,
                signature,
                encrypted_content,
            } => {
                let reasoning = ReasoningBlock {
                    text: (!text.is_empty()).then_some(text),
                    signature: (!signature.is_empty()).then_some(signature),
                    encrypted_content,
                    ..ReasoningBlock::default()
                };
                Ok(vec![self.event_with_block(
                    StreamEventKind::ReasoningEnd {
                        reasoning: Some(reasoning),
                    },
                    id,
                )])
            }
            DecodedBlock::Tool { id } => Ok(vec![self.event(StreamEventKind::ToolCallEnd { id })]),
            DecodedBlock::Opaque => Ok(Vec::new()),
        }
    }

    fn decode_message_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        if let Some(usage) = object.get("usage") {
            merge_usage(&mut self.usage, usage, "message_delta.usage")?;
        }
        let stop_reason = object
            .get("delta")
            .and_then(Value::as_object)
            .and_then(|delta| delta.get("stop_reason"));
        if let Some(reason) = stop_reason.filter(|value| !value.is_null()) {
            let reason = reason
                .as_str()
                .ok_or_else(|| invalid_shape("message_delta.delta.stop_reason", "a string"))?;
            self.completion_seen = true;
            let usage = self.usage.clone();
            return Ok(vec![self.event(StreamEventKind::Completion {
                finish_reason: decode_finish_reason(reason),
                usage: Some(usage),
            })]);
        }
        if object.contains_key("usage") {
            let usage = self.usage.clone();
            return Ok(vec![self.event(StreamEventKind::Usage { usage })]);
        }
        Ok(Vec::new())
    }

    fn decode_message_stop(&mut self) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        if !self.blocks.is_empty() {
            return Err(AnthropicStreamError::InvalidState(
                "message_stop appeared with open content blocks".to_owned(),
            ));
        }
        self.terminal = true;
        if self.completion_seen {
            return Ok(Vec::new());
        }
        let usage = self.usage.clone();
        Ok(vec![self.event(StreamEventKind::Completion {
            finish_reason: FinishReason::Other("message_stop".to_owned()),
            usage: Some(usage),
        })])
    }

    fn decode_error(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, AnthropicStreamError> {
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("error.error", "an object"))?;
        let code = required_string(error, "type", "error.error.type")?.to_owned();
        let message = required_string(error, "message", "error.error.message")?.to_owned();
        let retryable = matches!(
            code.as_str(),
            "api_error" | "overloaded_error" | "rate_limit_error"
        );
        let mut stream_error = StreamError::new(code, message).with_retryable(retryable);
        stream_error.details = Some(PreservedJson::from_value(Value::Object(error.clone()))?);
        self.terminal = true;
        Ok(vec![self.event(StreamEventKind::Failure {
            error: stream_error,
        })])
    }

    fn event(&mut self, kind: StreamEventKind) -> StreamEvent {
        let event = StreamEvent::new(self.sequence, kind);
        self.sequence = self.sequence.saturating_add(1);
        event
    }

    fn event_with_block(
        &mut self,
        kind: StreamEventKind,
        block_id: impl Into<String>,
    ) -> StreamEvent {
        self.event(kind).with_block_id(block_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodedBlockKind {
    Text,
    Reasoning,
    Tool,
}

#[derive(Clone, Debug)]
struct EncodedBlock {
    index: u64,
    kind: EncodedBlockKind,
}

/// Stateful encoder for semantic events into Anthropic named SSE records.
#[derive(Debug, Default)]
pub struct AnthropicEventEncoder {
    next_index: u64,
    blocks: BTreeMap<String, EncodedBlock>,
    pending_usage: Option<Usage>,
    response_started: bool,
    terminal: bool,
}

impl AnthropicEventEncoder {
    /// Creates an empty encoder for one response stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encodes one semantic event with default SSE limits.
    pub fn encode_event(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<EncodedAnthropicEvents, AnthropicStreamError> {
        self.encode_event_with_limits(event, policy, SseLimits::default())
    }

    /// Encodes one semantic event with explicit SSE limits.
    pub fn encode_event_with_limits(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
        limits: SseLimits,
    ) -> Result<EncodedAnthropicEvents, AnthropicStreamError> {
        if self.terminal {
            return Err(AnthropicStreamError::InvalidState(
                "semantic event appeared after stream termination".to_owned(),
            ));
        }
        let mut report = ConversionReport::default();
        let values = self.encode_values(event, &mut report)?;
        if !event.extensions.is_empty() {
            report.drop_optional(
                "event.extensions",
                "semantic event extensions have no Anthropic SSE representation",
            );
        }
        report.validate(policy)?;
        let encoder = SseEncoder::with_limits(limits);
        let mut body = Vec::new();
        for (name, value) in values {
            let data = serde_json::to_string(&value)?;
            body.extend(encoder.encode(&SseEvent::new(data).with_event(name))?);
        }
        Ok(EncodedAnthropicEvents { body, report })
    }

    fn encode_values(
        &mut self,
        event: &StreamEvent,
        report: &mut ConversionReport,
    ) -> Result<Vec<(&'static str, Value)>, AnthropicStreamError> {
        match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                if self.response_started {
                    return Err(AnthropicStreamError::InvalidState(
                        "semantic response started twice".to_owned(),
                    ));
                }
                self.response_started = true;
                let usage = self.pending_usage.clone().unwrap_or_default();
                Ok(vec![(
                    "message_start",
                    serde_json::json!({
                        "type":"message_start",
                        "message":{
                            "id":response_id.clone().unwrap_or_else(|| "msg_pooler".to_owned()),
                            "type":"message",
                            "role":"assistant",
                            "content":[],
                            "model":model.clone().unwrap_or_else(|| "pooler-model".to_owned()),
                            "stop_reason":Value::Null,
                            "stop_sequence":Value::Null,
                            "usage":encode_usage(&usage),
                        }
                    }),
                )])
            }
            StreamEventKind::Metadata { .. } => {
                report.drop_optional(
                    "event.metadata",
                    "Anthropic SSE has no general metadata event",
                );
                Ok(Vec::new())
            }
            StreamEventKind::TextStart => {
                let id = required_block_id(event, "text start")?;
                let index = self.start_block(id, EncodedBlockKind::Text)?;
                Ok(vec![(
                    "content_block_start",
                    serde_json::json!({
                        "type":"content_block_start",
                        "index":index,
                        "content_block":{"type":"text","text":""}
                    }),
                )])
            }
            StreamEventKind::TextDelta { text } => {
                let index = self.block_index(event, EncodedBlockKind::Text)?;
                Ok(vec![(
                    "content_block_delta",
                    serde_json::json!({
                        "type":"content_block_delta",
                        "index":index,
                        "delta":{"type":"text_delta","text":text}
                    }),
                )])
            }
            StreamEventKind::TextEnd => {
                let index = self.end_block(event, EncodedBlockKind::Text)?;
                Ok(vec![block_stop(index)])
            }
            StreamEventKind::ReasoningStart => {
                let id = required_block_id(event, "reasoning start")?;
                let index = self.start_block(id, EncodedBlockKind::Reasoning)?;
                Ok(vec![(
                    "content_block_start",
                    serde_json::json!({
                        "type":"content_block_start",
                        "index":index,
                        "content_block":{"type":"thinking","thinking":"","signature":""}
                    }),
                )])
            }
            StreamEventKind::ReasoningDelta { text } => {
                let index = self.block_index(event, EncodedBlockKind::Reasoning)?;
                Ok(vec![(
                    "content_block_delta",
                    serde_json::json!({
                        "type":"content_block_delta",
                        "index":index,
                        "delta":{"type":"thinking_delta","thinking":text}
                    }),
                )])
            }
            StreamEventKind::ReasoningEnd { reasoning } => {
                let index = self.end_block(event, EncodedBlockKind::Reasoning)?;
                let mut values = Vec::new();
                if let Some(signature) = reasoning
                    .as_ref()
                    .and_then(|reasoning| reasoning.signature.as_ref())
                {
                    values.push((
                        "content_block_delta",
                        serde_json::json!({
                            "type":"content_block_delta",
                            "index":index,
                            "delta":{
                                "type":"signature_delta",
                                "signature":bytes_as_string(signature),
                            }
                        }),
                    ));
                }
                if reasoning
                    .as_ref()
                    .and_then(|reasoning| reasoning.encrypted_content.as_ref())
                    .is_some()
                {
                    report.drop_optional(
                        "reasoning.encrypted_content",
                        "redacted thinking must be known at content-block start",
                    );
                }
                values.push(block_stop(index));
                Ok(values)
            }
            StreamEventKind::ToolCallStart { id, name } => {
                let index = self.start_block(id, EncodedBlockKind::Tool)?;
                Ok(vec![(
                    "content_block_start",
                    serde_json::json!({
                        "type":"content_block_start",
                        "index":index,
                        "content_block":{"type":"tool_use","id":id,"name":name,"input":{}}
                    }),
                )])
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                let index = self.named_block_index(id, EncodedBlockKind::Tool)?;
                Ok(vec![(
                    "content_block_delta",
                    serde_json::json!({
                        "type":"content_block_delta",
                        "index":index,
                        "delta":{"type":"input_json_delta","partial_json":arguments}
                    }),
                )])
            }
            StreamEventKind::ToolCallEnd { id } => {
                let index = self.end_named_block(id, EncodedBlockKind::Tool)?;
                Ok(vec![block_stop(index)])
            }
            StreamEventKind::Media { .. } => {
                report.unsupported_required(
                    "event.media",
                    "Anthropic Messages has no streamed media-output block",
                );
                Ok(Vec::new())
            }
            StreamEventKind::Usage { usage } => {
                self.pending_usage = Some(usage.clone());
                report.preserve_capability("usage.deferred_until_message_delta");
                Ok(Vec::new())
            }
            StreamEventKind::Refusal { text } => {
                let index = self.next_index;
                self.next_index = self.next_index.saturating_add(1);
                report.degrade_field(
                    "event.refusal",
                    "Anthropic represents refusal output as text",
                );
                Ok(vec![
                    (
                        "content_block_start",
                        serde_json::json!({
                            "type":"content_block_start",
                            "index":index,
                            "content_block":{"type":"text","text":""}
                        }),
                    ),
                    (
                        "content_block_delta",
                        serde_json::json!({
                            "type":"content_block_delta",
                            "index":index,
                            "delta":{"type":"text_delta","text":text}
                        }),
                    ),
                    block_stop(index),
                ])
            }
            StreamEventKind::Warning { .. } => {
                report.drop_optional(
                    "event.warning",
                    "Anthropic SSE has no compatibility-warning event",
                );
                Ok(Vec::new())
            }
            StreamEventKind::Completion {
                finish_reason,
                usage,
            } => {
                if !self.blocks.is_empty() {
                    return Err(AnthropicStreamError::InvalidState(
                        "completion appeared with open content blocks".to_owned(),
                    ));
                }
                let usage = usage
                    .as_ref()
                    .or(self.pending_usage.as_ref())
                    .cloned()
                    .unwrap_or_default();
                self.terminal = true;
                Ok(vec![
                    (
                        "message_delta",
                        serde_json::json!({
                            "type":"message_delta",
                            "delta":{
                                "stop_reason":encode_finish_reason(finish_reason),
                                "stop_sequence":Value::Null,
                            },
                            "usage":encode_usage(&usage),
                        }),
                    ),
                    ("message_stop", serde_json::json!({"type":"message_stop"})),
                ])
            }
            StreamEventKind::Failure { error } => {
                self.terminal = true;
                let details = error
                    .details
                    .as_ref()
                    .and_then(|value| value.value().as_object())
                    .cloned();
                let mut error_value = details.unwrap_or_default();
                error_value.insert("type".to_owned(), Value::String(error.code.clone()));
                error_value.insert("message".to_owned(), Value::String(error.message.clone()));
                Ok(vec![(
                    "error",
                    serde_json::json!({"type":"error", "error":error_value}),
                )])
            }
            StreamEventKind::Opaque { media_type, data }
                if media_type == ANTHROPIC_EVENT_MEDIA_TYPE =>
            {
                let value: Value = serde_json::from_slice(data)?;
                let name = value
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_shape("opaque.type", "a string"))?;
                let name = owned_event_name(name)?;
                report.preserve_capability("anthropic.messages.opaque_event");
                Ok(vec![(name, value)])
            }
            StreamEventKind::Opaque { .. } => {
                report.unsupported_required(
                    "event.opaque",
                    "opaque event did not originate from Anthropic Messages",
                );
                Ok(Vec::new())
            }
        }
    }

    fn start_block(
        &mut self,
        id: &str,
        kind: EncodedBlockKind,
    ) -> Result<u64, AnthropicStreamError> {
        if id.is_empty() || self.blocks.contains_key(id) {
            return Err(AnthropicStreamError::InvalidState(format!(
                "content block `{id}` has an invalid or duplicate ID"
            )));
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        self.blocks
            .insert(id.to_owned(), EncodedBlock { index, kind });
        Ok(index)
    }

    fn block_index(
        &self,
        event: &StreamEvent,
        kind: EncodedBlockKind,
    ) -> Result<u64, AnthropicStreamError> {
        let id = required_block_id(event, "content block")?;
        self.named_block_index(id, kind)
    }

    fn named_block_index(
        &self,
        id: &str,
        kind: EncodedBlockKind,
    ) -> Result<u64, AnthropicStreamError> {
        let block = self.blocks.get(id).ok_or_else(|| {
            AnthropicStreamError::InvalidState(format!("content block `{id}` is not open"))
        })?;
        if block.kind != kind {
            return Err(AnthropicStreamError::InvalidState(format!(
                "content block `{id}` has the wrong kind"
            )));
        }
        Ok(block.index)
    }

    fn end_block(
        &mut self,
        event: &StreamEvent,
        kind: EncodedBlockKind,
    ) -> Result<u64, AnthropicStreamError> {
        let id = required_block_id(event, "content block end")?.to_owned();
        self.end_named_block(&id, kind)
    }

    fn end_named_block(
        &mut self,
        id: &str,
        kind: EncodedBlockKind,
    ) -> Result<u64, AnthropicStreamError> {
        let block = self.blocks.remove(id).ok_or_else(|| {
            AnthropicStreamError::InvalidState(format!("content block `{id}` is not open"))
        })?;
        if block.kind != kind {
            return Err(AnthropicStreamError::InvalidState(format!(
                "content block `{id}` has the wrong kind"
            )));
        }
        Ok(block.index)
    }
}

fn block_stop(index: u64) -> (&'static str, Value) {
    (
        "content_block_stop",
        serde_json::json!({"type":"content_block_stop", "index":index}),
    )
}

fn required_block_id<'a>(
    event: &'a StreamEvent,
    kind: &str,
) -> Result<&'a str, AnthropicStreamError> {
    event.effective_block_id().ok_or_else(|| {
        AnthropicStreamError::InvalidState(format!("{kind} requires a stable block ID"))
    })
}

fn owned_event_name(name: &str) -> Result<&'static str, AnthropicStreamError> {
    match name {
        "message_start" => Ok("message_start"),
        "content_block_start" => Ok("content_block_start"),
        "content_block_delta" => Ok("content_block_delta"),
        "content_block_stop" => Ok("content_block_stop"),
        "message_delta" => Ok("message_delta"),
        "message_stop" => Ok("message_stop"),
        "ping" => Ok("ping"),
        "error" => Ok("error"),
        other => Err(AnthropicStreamError::InvalidState(format!(
            "unsupported opaque Anthropic event name `{other}`"
        ))),
    }
}

fn merge_usage(usage: &mut Usage, value: &Value, field: &str) -> Result<(), AnthropicStreamError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    update_usage_field(object, "input_tokens", &mut usage.input_tokens, field)?;
    update_usage_field(object, "output_tokens", &mut usage.output_tokens, field)?;
    if let Some(value) = optional_u64(object, "cache_read_input_tokens", field)? {
        usage.cached_input_tokens = Some(value);
        usage
            .details
            .insert("cache_read_input_tokens".to_owned(), value);
    }
    if let Some(value) = optional_u64(object, "cache_creation_input_tokens", field)? {
        usage
            .details
            .insert("cache_creation_input_tokens".to_owned(), value);
    }
    for (name, value) in object {
        if !matches!(
            name.as_str(),
            "input_tokens"
                | "output_tokens"
                | "cache_read_input_tokens"
                | "cache_creation_input_tokens"
        ) {
            if let Some(value) = value.as_u64() {
                usage.details.insert(name.clone(), value);
            }
        }
    }
    usage.total_tokens = Some(usage.input_tokens.saturating_add(usage.output_tokens));
    Ok(())
}

fn update_usage_field(
    object: &Map<String, Value>,
    name: &str,
    target: &mut u64,
    field: &str,
) -> Result<(), AnthropicStreamError> {
    if let Some(value) = optional_u64(object, name, field)? {
        *target = value;
    }
    Ok(())
}

fn encode_usage(usage: &Usage) -> Value {
    let mut object = Map::from_iter([
        (
            "input_tokens".to_owned(),
            Value::Number(usage.input_tokens.into()),
        ),
        (
            "output_tokens".to_owned(),
            Value::Number(usage.output_tokens.into()),
        ),
    ]);
    if let Some(cached) = usage.cached_input_tokens {
        object.insert(
            "cache_read_input_tokens".to_owned(),
            Value::Number(cached.into()),
        );
    }
    for (name, value) in &usage.details {
        object
            .entry(name.clone())
            .or_insert_with(|| Value::Number((*value).into()));
    }
    Value::Object(object)
}

fn has_usage(usage: &Usage) -> bool {
    usage.input_tokens != 0
        || usage.output_tokens != 0
        || usage.cached_input_tokens.is_some()
        || !usage.details.is_empty()
}

fn decode_finish_reason(reason: &str) -> FinishReason {
    match reason {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" | "model_context_window_exceeded" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCall,
        "refusal" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_owned()),
    }
}

fn encode_finish_reason(reason: &FinishReason) -> String {
    match reason {
        FinishReason::Stop => "end_turn".to_owned(),
        FinishReason::Length => "max_tokens".to_owned(),
        FinishReason::ToolCall => "tool_use".to_owned(),
        FinishReason::ContentFilter => "refusal".to_owned(),
        FinishReason::Error => "error".to_owned(),
        FinishReason::Other(reason) => reason.clone(),
    }
}

fn block_id(kind: &str, index: u64) -> String {
    format!("anthropic-{kind}-{index}")
}

fn required_index(object: &Map<String, Value>, field: &str) -> Result<u64, AnthropicStreamError> {
    object
        .get("index")
        .ok_or_else(|| missing(field))?
        .as_u64()
        .ok_or_else(|| invalid_shape(field, "an unsigned integer"))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, AnthropicStreamError> {
    object
        .get(key)
        .ok_or_else(|| missing(field))?
        .as_str()
        .ok_or_else(|| invalid_shape(field, "a string"))
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<String>, AnthropicStreamError> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid_shape(field, "a string"))
        })
        .transpose()
}

fn optional_u64(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<u64>, AnthropicStreamError> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| invalid_shape(&format!("{field}.{key}"), "an unsigned integer"))
        })
        .transpose()
}

fn bytes_as_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn missing(field: impl Into<String>) -> AnthropicStreamError {
    AnthropicStreamError::MissingField {
        field: field.into(),
    }
}

fn invalid_shape(field: &str, expected: &'static str) -> AnthropicStreamError {
    AnthropicStreamError::InvalidShape {
        field: field.to_owned(),
        expected,
    }
}

#[cfg(test)]
mod tests {
    use pooler_http::{SseEvent, SseParser};
    use pooler_protocol::{FinishReason, LossPolicy, StreamEvent, StreamEventKind};

    use super::{AnthropicEventDecoder, AnthropicEventEncoder, AnthropicMessageCodec};

    fn event(name: &str, data: serde_json::Value) -> SseEvent {
        SseEvent::new(serde_json::to_string(&data).expect("json")).with_event(name)
    }

    #[test]
    fn thinking_signature_tool_deltas_and_usage_round_trip() {
        let wire = [
            event(
                "message_start",
                serde_json::json!({
                    "type":"message_start",
                    "message":{"id":"msg_1","model":"claude-test","usage":{"input_tokens":9,"output_tokens":0}}
                }),
            ),
            event(
                "content_block_start",
                serde_json::json!({
                    "type":"content_block_start","index":0,
                    "content_block":{"type":"thinking","thinking":"","signature":""}
                }),
            ),
            event(
                "content_block_delta",
                serde_json::json!({
                    "type":"content_block_delta","index":0,
                    "delta":{"type":"thinking_delta","thinking":"inspect"}
                }),
            ),
            event(
                "content_block_delta",
                serde_json::json!({
                    "type":"content_block_delta","index":0,
                    "delta":{"type":"signature_delta","signature":"sig-local"}
                }),
            ),
            event(
                "content_block_stop",
                serde_json::json!({
                    "type":"content_block_stop","index":0
                }),
            ),
            event(
                "content_block_start",
                serde_json::json!({
                    "type":"content_block_start","index":1,
                    "content_block":{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}
                }),
            ),
            event(
                "content_block_delta",
                serde_json::json!({
                    "type":"content_block_delta","index":1,
                    "delta":{"type":"input_json_delta","partial_json":"{\"path\":\"README.md\"}"}
                }),
            ),
            event(
                "content_block_stop",
                serde_json::json!({
                    "type":"content_block_stop","index":1
                }),
            ),
            event(
                "message_delta",
                serde_json::json!({
                    "type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},
                    "usage":{"output_tokens":11,"cache_read_input_tokens":3}
                }),
            ),
            event("message_stop", serde_json::json!({"type":"message_stop"})),
        ];
        let mut decoder = AnthropicEventDecoder::new();
        let semantic = wire
            .iter()
            .flat_map(|event| decoder.decode_sse_event(event).expect("decode"))
            .collect::<Vec<_>>();
        assert!(decoder.is_finished());
        assert!(semantic.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::ReasoningEnd { reasoning: Some(reasoning) }
                if reasoning.signature.as_deref() == Some(b"sig-local")
        )));
        assert!(semantic.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::ToolCallDelta { id, arguments }
                if id == "toolu_1" && arguments.contains("README.md")
        )));
        assert!(semantic.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::Completion { finish_reason: FinishReason::ToolCall, usage: Some(usage) }
                if usage.input_tokens == 9
                    && usage.output_tokens == 11
                    && usage.cached_input_tokens == Some(3)
        )));

        let mut encoder = AnthropicEventEncoder::new();
        let body = semantic
            .iter()
            .flat_map(|event| {
                encoder
                    .encode_event(event, LossPolicy::Reject)
                    .expect("encode")
                    .body
            })
            .collect::<Vec<_>>();
        let mut parser = SseParser::new();
        let events = parser.feed(&body).expect("parse");
        parser.finish().expect("complete");
        assert!(events.iter().any(|event| {
            event.event.as_deref() == Some("content_block_delta")
                && event.data.contains("signature_delta")
                && event.data.contains("sig-local")
        }));
        assert_eq!(
            events.last().and_then(|event| event.event.as_deref()),
            Some("message_stop")
        );
    }

    #[test]
    fn provider_error_becomes_retryable_failure_and_encodes_back() {
        let mut decoder = AnthropicEventDecoder::new();
        let semantic = decoder
            .decode_sse_event(&event(
                "error",
                serde_json::json!({
                    "type":"error",
                    "error":{"type":"overloaded_error","message":"try later","request_id":"req_1"}
                }),
            ))
            .expect("decode");
        assert!(matches!(
            &semantic[0].kind,
            StreamEventKind::Failure { error }
                if error.code == "overloaded_error" && error.retryable
        ));
        let mut encoder = AnthropicEventEncoder::new();
        let encoded = encoder
            .encode_event(&semantic[0], LossPolicy::Reject)
            .expect("encode");
        let mut parser = SseParser::new();
        let events = parser.feed(&encoded.body).expect("parse");
        assert_eq!(events[0].event.as_deref(), Some("error"));
        assert!(events[0].data.contains("request_id"));
    }

    #[test]
    fn unary_message_round_trip_preserves_thinking_tools_usage_and_provider_fields() {
        let body = br#"{
          "id":"msg_unary","type":"message","role":"assistant","model":"claude-test",
          "content":[
            {"type":"thinking","thinking":"inspect","signature":"sig-local"},
            {"type":"tool_use","id":"toolu_1","name":"Read","input":{"path":"README.md"}},
            {"type":"text","text":"done","citations":[]}
          ],
          "stop_reason":"tool_use","stop_sequence":null,
          "usage":{"input_tokens":9,"output_tokens":11,"cache_read_input_tokens":3},
          "service_tier":"standard"
        }"#;
        let decoded = AnthropicMessageCodec::decode_response(body).expect("decode unary");
        assert!(decoded.report.is_lossless());
        assert!(decoded.events.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::ReasoningEnd { reasoning: Some(reasoning) }
                if reasoning.signature.as_deref() == Some(b"sig-local")
        )));
        assert!(decoded.events.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::ToolCallDelta { arguments, .. }
                if arguments.contains("README.md")
        )));
        let encoded = AnthropicMessageCodec::encode_response(&decoded.events, LossPolicy::Reject)
            .expect("encode unary");
        let value: serde_json::Value = serde_json::from_slice(&encoded.body).expect("json");
        assert_eq!(value["service_tier"], "standard");
        assert_eq!(value["content"][0]["signature"], "sig-local");
        assert_eq!(value["content"][1]["input"]["path"], "README.md");
        assert_eq!(value["content"][2]["citations"], serde_json::json!([]));
        assert_eq!(value["usage"]["cache_read_input_tokens"], 3);
    }

    #[test]
    fn unary_cache_warmup_response_with_empty_content_round_trips() {
        let body = br#"{
          "id":"msg_warm","type":"message","role":"assistant","model":"claude-test",
          "content":[],"stop_reason":"max_tokens","stop_sequence":null,
          "usage":{"input_tokens":20,"output_tokens":0,"cache_creation_input_tokens":20}
        }"#;
        let decoded = AnthropicMessageCodec::decode_response(body).expect("decode warmup");
        let encoded = AnthropicMessageCodec::encode_response(&decoded.events, LossPolicy::Reject)
            .expect("encode warmup");
        let value: serde_json::Value = serde_json::from_slice(&encoded.body).expect("json");
        assert_eq!(value["content"], serde_json::json!([]));
        assert_eq!(value["stop_reason"], "max_tokens");
        assert_eq!(value["usage"]["output_tokens"], 0);
        assert_eq!(value["usage"]["cache_creation_input_tokens"], 20);
    }

    #[test]
    fn unary_optional_loss_obeys_route_policy() {
        let events = vec![
            StreamEvent::new(
                0,
                StreamEventKind::ResponseStart {
                    response_id: Some("msg_1".to_owned()),
                    model: Some("claude-test".to_owned()),
                },
            ),
            StreamEvent::new(
                1,
                StreamEventKind::Metadata {
                    values: std::collections::BTreeMap::from([(
                        "trace".to_owned(),
                        "synthetic".to_owned(),
                    )]),
                },
            ),
            StreamEvent::new(
                2,
                StreamEventKind::Completion {
                    finish_reason: FinishReason::Stop,
                    usage: Some(pooler_protocol::Usage::new(1, 1)),
                },
            ),
        ];
        assert!(AnthropicMessageCodec::encode_response(&events, LossPolicy::Reject).is_err());
        let encoded = AnthropicMessageCodec::encode_response(&events, LossPolicy::Degrade)
            .expect("degrade optional metadata");
        assert_eq!(encoded.report.dropped_optional_fields, vec!["unary.event"]);
    }
}
