use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use pooler_protocol::{
    CacheHints, ContentPart, ConversionError, ConversionReport, ExtensionError, Extensions,
    InputItem, LossPolicy, MediaSource, Message, OpaqueExtension, PreservedJson,
    PreservedJsonError, ReasoningBlock, ReasoningConfig, ReasoningEffort, ReplayPolicy,
    RequestValidationError, Role, SemanticRequest, ToolCall, ToolChoice, ToolDefinition,
    ToolResult,
};
use serde_json::{Map, Number, Value};
use thiserror::Error;

const NAMESPACE: &str = "anthropic.messages";
const UNKNOWN_REQUEST_FIELDS: &str = "unknown_request_fields";
const STREAM: &str = "stream";
const THINKING: &str = "thinking";
const TOOL_CHOICE: &str = "tool_choice";
const CONTENT_EXTRAS: &str = "content_extras";
const MESSAGE_EXTRAS: &str = "message_extras";
const TOOL_EXTRAS: &str = "tool_extras";
const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_THINKING_BUDGET: u64 = 1024;

/// Errors returned by Anthropic Messages request conversion.
#[derive(Debug, Error)]
pub enum AnthropicRequestError {
    /// The body was not valid JSON.
    #[error("invalid Anthropic Messages JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A required field was absent.
    #[error("Anthropic Messages field `{field}` is missing")]
    MissingField {
        /// Dotted field path.
        field: String,
    },
    /// A field had the wrong JSON representation.
    #[error("Anthropic Messages field `{field}` must be {expected}")]
    InvalidShape {
        /// Dotted field path.
        field: String,
        /// Required representation.
        expected: &'static str,
    },
    /// A field value was not supported.
    #[error("invalid Anthropic Messages value for `{field}`: {message}")]
    InvalidValue {
        /// Dotted field path.
        field: String,
        /// Redacted explanation.
        message: String,
    },
    /// Provider extension data could not be represented.
    #[error("invalid Anthropic Messages extension: {0}")]
    Extension(#[from] ExtensionError),
    /// Preserved JSON could not be constructed.
    #[error("invalid preserved Anthropic Messages JSON: {0}")]
    PreservedJson(#[from] PreservedJsonError),
    /// The semantic request failed provider-independent validation.
    #[error("invalid semantic Anthropic request: {0}")]
    RequestValidation(#[from] RequestValidationError),
    /// The route's loss policy rejected the conversion.
    #[error("Anthropic Messages conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    /// A preserved extension tried to replace a standard field.
    #[error("Anthropic Messages extension collides with `{0}`")]
    ExtensionCollision(String),
}

/// A decoded Anthropic request and explicit conversion accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedAnthropicRequest {
    /// Provider-neutral request.
    pub request: SemanticRequest,
    /// Preserved and degraded semantic fields.
    pub report: ConversionReport,
}

/// An Anthropic Messages JSON request and conversion accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedAnthropicRequest {
    /// Compact UTF-8 JSON body.
    pub body: Vec<u8>,
    /// Preserved and degraded semantic fields.
    pub report: ConversionReport,
}

/// Stateless Anthropic Messages request codec.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnthropicMessagesCodec;

impl AnthropicMessagesCodec {
    /// Decodes a request and requires a lossless semantic representation.
    pub fn decode_request(input: &[u8]) -> Result<SemanticRequest, AnthropicRequestError> {
        let decoded = Self::decode_request_with_report(input)?;
        decoded.report.validate(LossPolicy::Reject)?;
        Ok(decoded.request)
    }

    /// Decodes a request while returning explicit conversion accounting.
    pub fn decode_request_with_report(
        input: &[u8],
    ) -> Result<DecodedAnthropicRequest, AnthropicRequestError> {
        decode_request(input)
    }

    /// Encodes a semantic request under an explicit loss policy.
    pub fn encode_request(
        request: &SemanticRequest,
        policy: LossPolicy,
    ) -> Result<EncodedAnthropicRequest, AnthropicRequestError> {
        encode_request(request, policy)
    }
}

fn decode_request(input: &[u8]) -> Result<DecodedAnthropicRequest, AnthropicRequestError> {
    let mut value: Value = serde_json::from_slice(input)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid_shape("request", "an object"))?;
    let mut report = ConversionReport::default();
    let model = take_required_string(object, "model", "model")?;
    if model.trim().is_empty() {
        return Err(invalid_value("model", "must not be empty"));
    }
    let mut request = SemanticRequest::new(model);

    if let Some(system) = object.remove("system") {
        let mut message = Message::new(Role::System);
        message.content = parse_content(
            &system,
            "system",
            &mut message.extensions,
            &mut report,
        )?;
        request.push_message(message);
    }

    let messages = object
        .remove("messages")
        .ok_or_else(|| missing("messages"))?;
    let messages = messages
        .as_array()
        .ok_or_else(|| invalid_shape("messages", "an array"))?;
    for (index, message) in messages.iter().enumerate() {
        request.push_input(InputItem::Message(parse_message(
            message,
            index,
            &mut report,
        )?));
    }

    let max_tokens = object
        .remove("max_tokens")
        .ok_or_else(|| missing("max_tokens"))?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_value("max_tokens", "must be a positive 32-bit integer"))?;
    request.sampling.max_output_tokens = Some(max_tokens);
    request.sampling.temperature = take_optional_f32(object, "temperature")?;
    request.sampling.top_p = take_optional_f32(object, "top_p")?;
    if let Some(stop) = object.remove("stop_sequences") {
        request.sampling.stop = string_array(&stop, "stop_sequences")?;
    }

    if let Some(tools) = object.remove("tools") {
        request.tools = parse_tools(&tools, &mut report)?;
    }
    if let Some(choice) = object.remove("tool_choice") {
        request.tool_choice = Some(parse_tool_choice(&choice)?);
        preserve_json(
            &mut request.extensions,
            TOOL_CHOICE,
            &choice,
            &mut report,
        )?;
    }
    if let Some(thinking) = object.remove("thinking") {
        request.reasoning = Some(parse_thinking(&thinking, &mut report)?);
    }
    if let Some(stream) = object.remove("stream") {
        if !stream.is_boolean() {
            return Err(invalid_shape("stream", "a boolean"));
        }
        preserve_json(
            &mut request.extensions,
            STREAM,
            &stream,
            &mut report,
        )?;
    }
    if let Some(metadata) = object.remove("metadata") {
        parse_metadata(&metadata, &mut request, &mut report)?;
    }
    if !object.is_empty() {
        let unknown = Value::Object(std::mem::take(object));
        preserve_json(
            &mut request.extensions,
            UNKNOWN_REQUEST_FIELDS,
            &unknown,
            &mut report,
        )?;
    }
    request.validate()?;
    Ok(DecodedAnthropicRequest { request, report })
}

fn parse_message(
    value: &Value,
    index: usize,
    report: &mut ConversionReport,
) -> Result<Message, AnthropicRequestError> {
    let field = format!("messages[{index}]");
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape(&field, "an object"))?;
    let role = match required_string(object, "role", &format!("{field}.role"))? {
        "user" => Role::User,
        "assistant" => Role::Assistant,
        other => {
            return Err(invalid_value(
                format!("{field}.role"),
                format!("unsupported role `{other}`"),
            ))
        }
    };
    let content = object
        .get("content")
        .ok_or_else(|| missing(format!("{field}.content")))?;
    let mut message = Message::new(role);
    message.content = parse_content(
        content,
        &format!("{field}.content"),
        &mut message.extensions,
        report,
    )?;
    let extras = unknown_fields(object, &["role", "content"]);
    if !extras.is_empty() {
        preserve_json(
            &mut message.extensions,
            MESSAGE_EXTRAS,
            &Value::Object(extras),
            report,
        )?;
    }
    Ok(message)
}

fn parse_content(
    value: &Value,
    field: &str,
    extensions: &mut Extensions,
    report: &mut ConversionReport,
) -> Result<Vec<ContentPart>, AnthropicRequestError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![ContentPart::text(text)]);
    }
    let values = value
        .as_array()
        .ok_or_else(|| invalid_shape(field, "a string or an array"))?;
    let mut parts = Vec::with_capacity(values.len());
    let mut extras = Vec::with_capacity(values.len());
    let mut has_extras = false;
    for (index, value) in values.iter().enumerate() {
        let part_field = format!("{field}[{index}]");
        let (part, extra) = parse_content_part(value, &part_field, report)?;
        has_extras |= !extra.is_empty();
        extras.push(Value::Object(extra));
        parts.push(part);
    }
    if has_extras {
        preserve_json(
            extensions,
            CONTENT_EXTRAS,
            &Value::Array(extras),
            report,
        )?;
    }
    Ok(parts)
}

fn parse_content_part(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
) -> Result<(ContentPart, Map<String, Value>), AnthropicRequestError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    let kind = required_string(object, "type", &format!("{field}.type"))?;
    match kind {
        "text" => Ok((
            ContentPart::text(required_string(object, "text", &format!("{field}.text"))?),
            unknown_fields(object, &["type", "text"]),
        )),
        "image" => Ok((
            parse_image(object, field)?,
            unknown_fields(object, &["type", "source"]),
        )),
        "document" => Ok((
            parse_document(object, field)?,
            unknown_fields(object, &["type", "source", "title", "context", "citations"]),
        )),
        "thinking" => {
            let signature = optional_string(object, "signature", &format!("{field}.signature"))?
                .map(String::into_bytes);
            Ok((
                ContentPart::Reasoning(ReasoningBlock {
                    text: Some(
                        required_string(object, "thinking", &format!("{field}.thinking"))?
                            .to_owned(),
                    ),
                    signature,
                    ..ReasoningBlock::default()
                }),
                unknown_fields(object, &["type", "thinking", "signature"]),
            ))
        }
        "redacted_thinking" => Ok((
            ContentPart::Reasoning(ReasoningBlock {
                encrypted_content: Some(
                    required_string(object, "data", &format!("{field}.data"))?
                        .as_bytes()
                        .to_vec(),
                ),
                ..ReasoningBlock::default()
            }),
            unknown_fields(object, &["type", "data"]),
        )),
        "tool_use" => {
            let input = object
                .get("input")
                .ok_or_else(|| missing(format!("{field}.input")))?;
            Ok((
                ContentPart::ToolCall(ToolCall::new(
                    required_string(object, "id", &format!("{field}.id"))?,
                    required_string(object, "name", &format!("{field}.name"))?,
                    PreservedJson::from_value(input.clone())?,
                )),
                unknown_fields(object, &["type", "id", "name", "input"]),
            ))
        }
        "tool_result" => {
            let content = object
                .get("content")
                .map(|content| parse_tool_result_content(content, field, report))
                .transpose()?
                .unwrap_or_default();
            Ok((
                ContentPart::ToolResult(ToolResult {
                    tool_call_id: required_string(
                        object,
                        "tool_use_id",
                        &format!("{field}.tool_use_id"),
                    )?
                    .to_owned(),
                    content,
                    is_error: optional_bool(object, "is_error", &format!("{field}.is_error"))?
                        .unwrap_or(false),
                    extensions: Extensions::default(),
                }),
                unknown_fields(object, &["type", "tool_use_id", "content", "is_error"]),
            ))
        }
        other => {
            report.preserve_capability(format!("anthropic.messages.content.{other}"));
            Ok((
                ContentPart::Provider {
                    namespace: NAMESPACE.to_owned(),
                    name: other.to_owned(),
                    data: PreservedJson::from_value(value.clone())?,
                },
                Map::new(),
            ))
        }
    }
}

fn parse_tool_result_content(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
) -> Result<Vec<ContentPart>, AnthropicRequestError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![ContentPart::text(text)]);
    }
    let values = value
        .as_array()
        .ok_or_else(|| invalid_shape(&format!("{field}.content"), "a string or an array"))?;
    values
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let part_field = format!("{field}.content[{index}]");
            let (part, extras) = parse_content_part(part, &part_field, report)?;
            if !extras.is_empty() {
                report.drop_optional(
                    format!("{part_field}.provider_fields"),
                    "nested tool-result content attributes have no semantic attachment point",
                );
            }
            Ok(part)
        })
        .collect()
}

fn parse_image(
    object: &Map<String, Value>,
    field: &str,
) -> Result<ContentPart, AnthropicRequestError> {
    let source = object
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_shape(&format!("{field}.source"), "an object"))?;
    let kind = required_string(source, "type", &format!("{field}.source.type"))?;
    match kind {
        "base64" => {
            let media_type = required_string(
                source,
                "media_type",
                &format!("{field}.source.media_type"),
            )?;
            let data = required_string(source, "data", &format!("{field}.source.data"))?;
            let bytes = BASE64.decode(data).map_err(|_| {
                invalid_value(format!("{field}.source.data"), "must be valid base64")
            })?;
            Ok(ContentPart::image(media_type, MediaSource::inline(bytes)))
        }
        "url" => Ok(ContentPart::image(
            "image/*",
            MediaSource::uri(required_string(
                source,
                "url",
                &format!("{field}.source.url"),
            )?),
        )),
        other => Err(invalid_value(
            format!("{field}.source.type"),
            format!("unsupported image source `{other}`"),
        )),
    }
}

fn parse_document(
    object: &Map<String, Value>,
    field: &str,
) -> Result<ContentPart, AnthropicRequestError> {
    let source = object
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_shape(&format!("{field}.source"), "an object"))?;
    let kind = required_string(source, "type", &format!("{field}.source.type"))?;
    let name = optional_string(object, "title", &format!("{field}.title"))?;
    match kind {
        "base64" => {
            let media_type = required_string(
                source,
                "media_type",
                &format!("{field}.source.media_type"),
            )?;
            let data = required_string(source, "data", &format!("{field}.source.data"))?;
            let bytes = BASE64.decode(data).map_err(|_| {
                invalid_value(format!("{field}.source.data"), "must be valid base64")
            })?;
            Ok(ContentPart::file(name, media_type, MediaSource::inline(bytes)))
        }
        "url" => Ok(ContentPart::file(
            name,
            "application/octet-stream",
            MediaSource::uri(required_string(
                source,
                "url",
                &format!("{field}.source.url"),
            )?),
        )),
        "text" => Ok(ContentPart::file(
            name,
            "text/plain",
            MediaSource::inline(
                required_string(source, "data", &format!("{field}.source.data"))?
                    .as_bytes()
                    .to_vec(),
            ),
        )),
        other => Err(invalid_value(
            format!("{field}.source.type"),
            format!("unsupported document source `{other}`"),
        )),
    }
}

fn parse_tools(
    value: &Value,
    report: &mut ConversionReport,
) -> Result<Vec<ToolDefinition>, AnthropicRequestError> {
    let tools = value
        .as_array()
        .ok_or_else(|| invalid_shape("tools", "an array"))?;
    tools
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let field = format!("tools[{index}]");
            let object = value
                .as_object()
                .ok_or_else(|| invalid_shape(&field, "an object"))?;
            let name = required_string(object, "name", &format!("{field}.name"))?;
            let parameters = object
                .get("input_schema")
                .map(|value| PreservedJson::from_value(value.clone()))
                .transpose()?;
            let mut tool = ToolDefinition::new(name, parameters);
            tool.description = optional_string(
                object,
                "description",
                &format!("{field}.description"),
            )?;
            let extras = unknown_fields(object, &["name", "description", "input_schema"]);
            if !extras.is_empty() {
                preserve_json(
                    &mut tool.extensions,
                    TOOL_EXTRAS,
                    &Value::Object(extras),
                    report,
                )?;
            }
            Ok(tool)
        })
        .collect()
}

fn parse_tool_choice(value: &Value) -> Result<ToolChoice, AnthropicRequestError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape("tool_choice", "an object"))?;
    match required_string(object, "type", "tool_choice.type")? {
        "auto" => Ok(ToolChoice::Auto),
        "none" => Ok(ToolChoice::None),
        "any" => Ok(ToolChoice::Required),
        "tool" => Ok(ToolChoice::Tool {
            name: required_string(object, "name", "tool_choice.name")?.to_owned(),
        }),
        other => Err(invalid_value(
            "tool_choice.type",
            format!("unsupported tool choice `{other}`"),
        )),
    }
}

fn parse_thinking(
    value: &Value,
    report: &mut ConversionReport,
) -> Result<ReasoningConfig, AnthropicRequestError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape("thinking", "an object"))?;
    let kind = required_string(object, "type", "thinking.type")?;
    if kind == "enabled" {
        object
            .get("budget_tokens")
            .and_then(Value::as_u64)
            .filter(|budget| *budget > 0)
            .ok_or_else(|| {
                invalid_value(
                    "thinking.budget_tokens",
                    "must be a positive integer when thinking is enabled",
                )
            })?;
    }
    let mut reasoning = ReasoningConfig {
        effort: Some(ReasoningEffort::Custom(kind.to_owned())),
        ..ReasoningConfig::default()
    };
    preserve_json(&mut reasoning.extensions, THINKING, value, report)?;
    Ok(reasoning)
}

fn parse_metadata(
    value: &Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), AnthropicRequestError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape("metadata", "an object"))?;
    if let Some(user_id) = optional_string(object, "user_id", "metadata.user_id")? {
        request.metadata.insert("user_id".to_owned(), user_id);
    }
    let extras = unknown_fields(object, &["user_id"]);
    if !extras.is_empty() {
        report.drop_optional(
            "metadata.provider_fields",
            "Anthropic metadata fields other than user_id have no semantic representation",
        );
    }
    Ok(())
}

fn encode_request(
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<EncodedAnthropicRequest, AnthropicRequestError> {
    request.validate()?;
    let mut report = ConversionReport::default();
    let mut object = Map::new();
    object.insert("model".to_owned(), Value::String(request.model.clone()));
    let max_tokens = request.sampling.max_output_tokens.unwrap_or_else(|| {
        report.degrade_field(
            "sampling.max_output_tokens",
            format!("Anthropic requires max_tokens; defaulted to {DEFAULT_MAX_TOKENS}"),
        );
        DEFAULT_MAX_TOKENS
    });
    object.insert(
        "max_tokens".to_owned(),
        Value::Number(Number::from(max_tokens)),
    );
    insert_optional_f32(&mut object, "temperature", request.sampling.temperature)?;
    insert_optional_f32(&mut object, "top_p", request.sampling.top_p)?;
    if !request.sampling.stop.is_empty() {
        object.insert(
            "stop_sequences".to_owned(),
            Value::Array(
                request
                    .sampling
                    .stop
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if request.sampling.seed.is_some() {
        report.drop_optional("sampling.seed", "Anthropic Messages has no seed field");
    }
    if request.sampling.presence_penalty.is_some() {
        report.drop_optional(
            "sampling.presence_penalty",
            "Anthropic Messages has no presence penalty field",
        );
    }
    if request.sampling.frequency_penalty.is_some() {
        report.drop_optional(
            "sampling.frequency_penalty",
            "Anthropic Messages has no frequency penalty field",
        );
    }

    let mut system = Vec::new();
    let mut messages = Vec::new();
    for item in &request.input {
        match item {
            InputItem::Message(message)
                if matches!(message.role, Role::System | Role::Developer) =>
            {
                if message.role == Role::Developer {
                    report.degrade_field(
                        "message.role.developer",
                        "Anthropic represents developer instructions as system content",
                    );
                }
                system.extend(encode_message_content(message, &mut report)?);
            }
            _ => messages.push(encode_input_item(item, &mut report)?),
        }
    }
    if !system.is_empty() {
        object.insert("system".to_owned(), Value::Array(system));
    }
    object.insert("messages".to_owned(), Value::Array(messages));

    if !request.tools.is_empty() {
        object.insert(
            "tools".to_owned(),
            Value::Array(
                request
                    .tools
                    .iter()
                    .map(|tool| encode_tool(tool, &mut report))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        );
    }
    if let Some(choice) = request.tool_choice.as_ref() {
        object.insert(
            "tool_choice".to_owned(),
            extension_value(&request.extensions, TOOL_CHOICE)?
                .unwrap_or_else(|| encode_tool_choice(choice)),
        );
        preserve_known_extension(&request.extensions, TOOL_CHOICE, &mut report);
    }
    if let Some(reasoning) = request.reasoning.as_ref() {
        object.insert("thinking".to_owned(), encode_thinking(reasoning, &mut report)?);
    }
    object.insert(
        "stream".to_owned(),
        extension_value(&request.extensions, STREAM)?.unwrap_or(Value::Bool(true)),
    );
    preserve_known_extension(&request.extensions, STREAM, &mut report);

    if let Some(user_id) = request.metadata.get("user_id") {
        object.insert(
            "metadata".to_owned(),
            Value::Object(Map::from_iter([(
                "user_id".to_owned(),
                Value::String(user_id.clone()),
            )])),
        );
    }
    for key in request.metadata.keys().filter(|key| key.as_str() != "user_id") {
        report.drop_optional(
            format!("metadata.{key}"),
            "Anthropic Messages only supports metadata.user_id",
        );
    }
    if request.response_format.is_some() {
        report.drop_optional(
            "response_format",
            "Anthropic Messages has no portable response-format field",
        );
    }
    if let Some(cache) = request.cache.as_ref() {
        report_cache_hints(cache, &mut report);
    }
    if request.target.is_some() {
        report.drop_optional("target", "routing metadata is not sent to Anthropic");
    }
    if request.continuation_id.is_some() {
        report.drop_optional(
            "continuation_id",
            "Anthropic Messages has no continuation identifier",
        );
    }
    if request.session_id.is_some() {
        report.drop_optional("session_id", "Anthropic Messages has no session field");
    }
    merge_unknown_request_fields(&mut object, &request.extensions, &mut report)?;
    report_unknown_extensions(
        &request.extensions,
        &[UNKNOWN_REQUEST_FIELDS, STREAM, TOOL_CHOICE],
        &mut report,
    );
    report.validate(policy)?;
    Ok(EncodedAnthropicRequest {
        body: serde_json::to_vec(&Value::Object(object))?,
        report,
    })
}

fn encode_input_item(
    item: &InputItem,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    match item {
        InputItem::Message(message) => encode_message(message, report),
        InputItem::ToolCall(call) => Ok(message_value(
            "assistant",
            vec![encode_tool_call(call, report)?],
        )),
        InputItem::ToolResult(result) => Ok(message_value(
            "user",
            vec![encode_tool_result(result, report)?],
        )),
        InputItem::Content(content) => Ok(message_value(
            "user",
            vec![encode_content_part(content, report)?],
        )),
        InputItem::Provider {
            namespace, name, ..
        } => {
            report.unsupported_required(
                format!("input.provider.{namespace}.{name}"),
                "Anthropic Messages has no generic provider item representation",
            );
            Ok(message_value("user", Vec::new()))
        }
    }
}

fn encode_message(
    message: &Message,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    let role = match message.role {
        Role::User | Role::Tool => "user",
        Role::Assistant => "assistant",
        Role::System | Role::Developer => {
            return Err(invalid_value(
                "message.role",
                "system and developer messages must be encoded in the top-level system field",
            ))
        }
    };
    if message.role == Role::Tool && message.tool_call_id.is_none() {
        return Err(invalid_value(
            "message.tool_call_id",
            "tool messages require a tool invocation ID",
        ));
    }
    let content = if message.role == Role::Tool {
        vec![encode_tool_result(
            &ToolResult {
                tool_call_id: message.tool_call_id.clone().unwrap_or_default(),
                content: message.content.clone(),
                is_error: false,
                extensions: Extensions::default(),
            },
            report,
        )?]
    } else {
        encode_message_content(message, report)?
    };
    if message.id.is_some() {
        report.drop_optional("message.id", "Anthropic Messages has no message ID input field");
    }
    if message.name.is_some() {
        report.drop_optional(
            "message.name",
            "Anthropic Messages has no message speaker-name field",
        );
    }
    if !message.metadata.is_empty() {
        report.drop_optional(
            "message.metadata",
            "Anthropic Messages has no per-message metadata field",
        );
    }
    let mut value = message_value(role, content);
    if let Some(extras) = extension_value(&message.extensions, MESSAGE_EXTRAS)? {
        merge_object(&mut value, extras, report, "message")?;
        preserve_known_extension(&message.extensions, MESSAGE_EXTRAS, report);
    }
    report_unknown_extensions(
        &message.extensions,
        &[CONTENT_EXTRAS, MESSAGE_EXTRAS],
        report,
    );
    Ok(value)
}

fn encode_message_content(
    message: &Message,
    report: &mut ConversionReport,
) -> Result<Vec<Value>, AnthropicRequestError> {
    let mut parts = message
        .content
        .iter()
        .map(|part| encode_content_part(part, report))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(Value::Array(extras)) = extension_value(&message.extensions, CONTENT_EXTRAS)? {
        for (part, extra) in parts.iter_mut().zip(extras) {
            merge_object(part, extra, report, "message.content")?;
        }
        preserve_known_extension(&message.extensions, CONTENT_EXTRAS, report);
    }
    Ok(parts)
}

fn encode_content_part(
    part: &ContentPart,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    match part {
        ContentPart::Text { text } => Ok(serde_json::json!({"type":"text", "text":text})),
        ContentPart::Image {
            media_type,
            source,
            detail,
        } => {
            if detail.is_some() {
                report.drop_optional(
                    "image.detail",
                    "Anthropic Messages has no image detail field",
                );
            }
            Ok(serde_json::json!({
                "type":"image",
                "source":encode_media_source(media_type, source, false),
            }))
        }
        ContentPart::File {
            name,
            media_type,
            source,
        } => {
            let mut object = Map::from_iter([
                ("type".to_owned(), Value::String("document".to_owned())),
                (
                    "source".to_owned(),
                    encode_media_source(media_type, source, media_type == "text/plain"),
                ),
            ]);
            if let Some(name) = name {
                object.insert("title".to_owned(), Value::String(name.clone()));
            }
            Ok(Value::Object(object))
        }
        ContentPart::Audio { .. } => {
            report.unsupported_required(
                "input.audio",
                "Anthropic Messages does not accept portable audio input",
            );
            Ok(serde_json::json!({"type":"text", "text":""}))
        }
        ContentPart::Reasoning(reasoning) => encode_reasoning_part(reasoning),
        ContentPart::ToolCall(call) => encode_tool_call(call, report),
        ContentPart::ToolResult(result) => encode_tool_result(result, report),
        ContentPart::Provider {
            namespace, data, ..
        } if namespace == NAMESPACE => {
            report.preserve_capability("anthropic.messages.provider_content");
            Ok(data.value().clone())
        }
        ContentPart::Provider {
            namespace, name, ..
        } => {
            report.unsupported_required(
                format!("content.provider.{namespace}.{name}"),
                "provider content has no Anthropic Messages representation",
            );
            Ok(serde_json::json!({"type":"text", "text":""}))
        }
    }
}

fn encode_reasoning_part(reasoning: &ReasoningBlock) -> Result<Value, AnthropicRequestError> {
    if let Some(encrypted) = reasoning.encrypted_content.as_ref() {
        return Ok(serde_json::json!({
            "type":"redacted_thinking",
            "data":bytes_as_string(encrypted),
        }));
    }
    let mut object = Map::from_iter([
        ("type".to_owned(), Value::String("thinking".to_owned())),
        (
            "thinking".to_owned(),
            Value::String(reasoning.text.clone().unwrap_or_default()),
        ),
    ]);
    if let Some(signature) = reasoning.signature.as_ref() {
        object.insert(
            "signature".to_owned(),
            Value::String(bytes_as_string(signature)),
        );
    }
    Ok(Value::Object(object))
}

fn encode_tool_call(
    call: &ToolCall,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    if !call.dependencies.is_empty() {
        report.drop_optional(
            "tool_call.dependencies",
            "Anthropic Messages has no tool dependency field",
        );
    }
    report_unknown_extensions(&call.extensions, &[], report);
    Ok(serde_json::json!({
        "type":"tool_use",
        "id":call.id,
        "name":call.name,
        "input":call.arguments.value(),
    }))
}

fn encode_tool_result(
    result: &ToolResult,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    report_unknown_extensions(&result.extensions, &[], report);
    let content = if let [ContentPart::Text { text }] = result.content.as_slice() {
        Value::String(text.clone())
    } else {
        Value::Array(
            result
                .content
                .iter()
                .map(|part| encode_content_part(part, report))
                .collect::<Result<Vec<_>, _>>()?,
        )
    };
    Ok(serde_json::json!({
        "type":"tool_result",
        "tool_use_id":result.tool_call_id,
        "content":content,
        "is_error":result.is_error,
    }))
}

fn encode_tool(
    tool: &ToolDefinition,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    let mut object = Map::new();
    object.insert("name".to_owned(), Value::String(tool.name.clone()));
    object.insert(
        "input_schema".to_owned(),
        tool.parameters
            .as_ref()
            .map_or_else(|| serde_json::json!({"type":"object"}), |value| value.value().clone()),
    );
    if let Some(description) = tool.description.as_ref() {
        object.insert(
            "description".to_owned(),
            Value::String(description.clone()),
        );
    }
    if tool.strict.is_some() {
        report.drop_optional(
            "tool.strict",
            "Anthropic Messages has no portable strict-schema field",
        );
    }
    if let Some(extras) = extension_value(&tool.extensions, TOOL_EXTRAS)? {
        merge_object_value(&mut object, extras, report, "tool")?;
        preserve_known_extension(&tool.extensions, TOOL_EXTRAS, report);
    }
    report_unknown_extensions(&tool.extensions, &[TOOL_EXTRAS], report);
    Ok(Value::Object(object))
}

fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => serde_json::json!({"type":"auto"}),
        ToolChoice::None => serde_json::json!({"type":"none"}),
        ToolChoice::Required => serde_json::json!({"type":"any"}),
        ToolChoice::Tool { name } => serde_json::json!({"type":"tool", "name":name}),
    }
}

fn encode_thinking(
    reasoning: &ReasoningConfig,
    report: &mut ConversionReport,
) -> Result<Value, AnthropicRequestError> {
    if let Some(value) = extension_value(&reasoning.extensions, THINKING)? {
        preserve_known_extension(&reasoning.extensions, THINKING, report);
        report_unknown_extensions(&reasoning.extensions, &[THINKING], report);
        return Ok(value);
    }
    let value = match reasoning.effort.as_ref() {
        Some(ReasoningEffort::Custom(value)) if value == "disabled" => {
            serde_json::json!({"type":"disabled"})
        }
        Some(ReasoningEffort::Custom(value)) if value == "adaptive" => {
            serde_json::json!({"type":"adaptive"})
        }
        Some(ReasoningEffort::Low) => thinking_with_budget(1024),
        Some(ReasoningEffort::Medium) => thinking_with_budget(4096),
        Some(ReasoningEffort::High) => thinking_with_budget(16_384),
        Some(ReasoningEffort::Max) => thinking_with_budget(32_768),
        Some(ReasoningEffort::Custom(_)) | None => {
            report.degrade_field(
                "reasoning.effort",
                format!(
                    "Anthropic requires a thinking budget; defaulted to {DEFAULT_THINKING_BUDGET}"
                ),
            );
            thinking_with_budget(DEFAULT_THINKING_BUDGET)
        }
    };
    if reasoning.include_summary {
        report.drop_optional(
            "reasoning.include_summary",
            "Anthropic thinking has no summary control",
        );
    }
    report_unknown_extensions(&reasoning.extensions, &[], report);
    Ok(value)
}

fn thinking_with_budget(budget: u64) -> Value {
    serde_json::json!({"type":"enabled", "budget_tokens":budget})
}

fn encode_media_source(media_type: &str, source: &MediaSource, text: bool) -> Value {
    match source {
        MediaSource::Uri(uri) => serde_json::json!({"type":"url", "url":uri}),
        MediaSource::Inline(bytes) if text => serde_json::json!({
            "type":"text",
            "media_type":media_type,
            "data":String::from_utf8_lossy(bytes),
        }),
        MediaSource::Inline(bytes) => serde_json::json!({
            "type":"base64",
            "media_type":media_type,
            "data":BASE64.encode(bytes),
        }),
    }
}

fn message_value(role: &str, content: Vec<Value>) -> Value {
    Value::Object(Map::from_iter([
        ("role".to_owned(), Value::String(role.to_owned())),
        ("content".to_owned(), Value::Array(content)),
    ]))
}

fn report_cache_hints(cache: &CacheHints, report: &mut ConversionReport) {
    if cache.allow_prompt_cache || cache.prefer_cache_read || cache.key.is_some() {
        report.drop_optional(
            "cache",
            "Anthropic cache controls attach to individual request blocks",
        );
    }
    report_unknown_extensions(&cache.extensions, &[], report);
}

fn parse_extension_value(
    extensions: &Extensions,
    name: &str,
) -> Result<Option<Value>, AnthropicRequestError> {
    let key = format!("{NAMESPACE}.{name}");
    extensions
        .get_str(&key)
        .map(|extension| serde_json::from_slice(extension.as_bytes()).map_err(Into::into))
        .transpose()
}

fn extension_value(
    extensions: &Extensions,
    name: &str,
) -> Result<Option<Value>, AnthropicRequestError> {
    parse_extension_value(extensions, name)
}

fn preserve_json(
    extensions: &mut Extensions,
    name: &str,
    value: &Value,
    report: &mut ConversionReport,
) -> Result<(), AnthropicRequestError> {
    let extension = OpaqueExtension::new(NAMESPACE, name, serde_json::to_vec(value)?)?
        .with_media_type("application/json")?
        .with_replay_policy(ReplayPolicy::IfSafe);
    let key = extension.key();
    extensions.insert(extension);
    report.preserve_extension(&key);
    Ok(())
}

fn preserve_known_extension(
    extensions: &Extensions,
    name: &str,
    report: &mut ConversionReport,
) {
    let key = format!("{NAMESPACE}.{name}");
    if let Some(extension) = extensions.get_str(&key) {
        report.preserve_extension(&extension.key());
    }
}

fn report_unknown_extensions(
    extensions: &Extensions,
    known_names: &[&str],
    report: &mut ConversionReport,
) {
    for (key, _) in extensions {
        let known = key.namespace.as_str() == NAMESPACE
            && known_names.contains(&key.name.as_str());
        if !known {
            report.drop_optional(
                format!("extensions.{key}"),
                "extension has no Anthropic Messages representation",
            );
        }
    }
}

fn merge_unknown_request_fields(
    object: &mut Map<String, Value>,
    extensions: &Extensions,
    report: &mut ConversionReport,
) -> Result<(), AnthropicRequestError> {
    let Some(value) = extension_value(extensions, UNKNOWN_REQUEST_FIELDS)? else {
        return Ok(());
    };
    merge_object_value(object, value, report, "request")?;
    preserve_known_extension(extensions, UNKNOWN_REQUEST_FIELDS, report);
    Ok(())
}

fn merge_object(
    target: &mut Value,
    extras: Value,
    report: &mut ConversionReport,
    field: &str,
) -> Result<(), AnthropicRequestError> {
    let target = target
        .as_object_mut()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    merge_object_value(target, extras, report, field)
}

fn merge_object_value(
    target: &mut Map<String, Value>,
    extras: Value,
    report: &mut ConversionReport,
    field: &str,
) -> Result<(), AnthropicRequestError> {
    let extras = extras
        .as_object()
        .ok_or_else(|| invalid_shape(&format!("{field}.extension"), "an object"))?;
    for (key, value) in extras {
        if target.contains_key(key) {
            return Err(AnthropicRequestError::ExtensionCollision(format!(
                "{field}.{key}"
            )));
        }
        target.insert(key.clone(), value.clone());
    }
    report.preserve_capability(format!("{field}.provider_fields"));
    Ok(())
}

fn unknown_fields(object: &Map<String, Value>, known: &[&str]) -> Map<String, Value> {
    object
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn take_required_string(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<String, AnthropicRequestError> {
    object
        .remove(key)
        .ok_or_else(|| missing(field))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_shape(field, "a string"))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, AnthropicRequestError> {
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
) -> Result<Option<String>, AnthropicRequestError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid_shape(field, "a string"))
        })
        .transpose()
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<bool>, AnthropicRequestError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid_shape(field, "a boolean"))
        })
        .transpose()
}

fn take_optional_f32(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<f32>, AnthropicRequestError> {
    object
        .remove(key)
        .map(|value| {
            let value = value
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| invalid_shape(key, "a finite number"))?;
            #[allow(clippy::cast_possible_truncation)]
            let value = value as f32;
            Ok(value)
        })
        .transpose()
}

fn insert_optional_f32(
    object: &mut Map<String, Value>,
    key: &str,
    value: Option<f32>,
) -> Result<(), AnthropicRequestError> {
    if let Some(value) = value {
        let number = Number::from_f64(f64::from(value))
            .ok_or_else(|| invalid_value(key, "must be a finite number"))?;
        object.insert(key.to_owned(), Value::Number(number));
    }
    Ok(())
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>, AnthropicRequestError> {
    value
        .as_array()
        .ok_or_else(|| invalid_shape(field, "an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                invalid_shape(&format!("{field}[{index}]"), "a string")
            })
        })
        .collect()
}

fn bytes_as_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| BASE64.encode(bytes))
}

fn missing(field: impl Into<String>) -> AnthropicRequestError {
    AnthropicRequestError::MissingField {
        field: field.into(),
    }
}

fn invalid_shape(field: &str, expected: &'static str) -> AnthropicRequestError {
    AnthropicRequestError::InvalidShape {
        field: field.to_owned(),
        expected,
    }
}

fn invalid_value(
    field: impl Into<String>,
    message: impl Into<String>,
) -> AnthropicRequestError {
    AnthropicRequestError::InvalidValue {
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use pooler_protocol::{ContentPart, InputItem, LossPolicy, ReasoningEffort, Role, ToolChoice};
    use serde_json::Value;

    use super::AnthropicMessagesCodec;

    #[test]
    fn droid_request_normalizes_thinking_tools_and_results() {
        let body = br#"{
          "model":"claude-test",
          "max_tokens":4096,
          "stream":true,
          "system":[{"type":"text","text":"Be concise","cache_control":{"type":"ephemeral"}}],
          "thinking":{"type":"enabled","budget_tokens":1024},
          "tools":[{"name":"Read","description":"Read a file","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],
          "tool_choice":{"type":"auto","disable_parallel_tool_use":true},
          "messages":[
            {"role":"assistant","content":[
              {"type":"thinking","thinking":"I should read","signature":"sig-local"},
              {"type":"tool_use","id":"toolu_1","name":"Read","input":{"path":"README.md"}}
            ]},
            {"role":"user","content":[
              {"type":"tool_result","tool_use_id":"toolu_1","content":"Pooler","is_error":false}
            ]}
          ]
        }"#;
        let decoded = AnthropicMessagesCodec::decode_request_with_report(body).expect("decode");
        assert!(decoded.report.is_lossless());
        assert_eq!(decoded.request.model, "claude-test");
        assert!(matches!(
            decoded.request.reasoning.as_ref().and_then(|value| value.effort.as_ref()),
            Some(ReasoningEffort::Custom(value)) if value == "enabled"
        ));
        assert!(matches!(decoded.request.tool_choice, Some(ToolChoice::Auto)));
        assert!(matches!(
            &decoded.request.input[0],
            InputItem::Message(message) if message.role == Role::System
        ));
        assert!(matches!(
            &decoded.request.input[1],
            InputItem::Message(message)
                if matches!(&message.content[0], ContentPart::Reasoning(reasoning)
                    if reasoning.signature.as_deref() == Some(b"sig-local"))
                && matches!(&message.content[1], ContentPart::ToolCall(call)
                    if call.id == "toolu_1" && call.name == "Read")
        ));
        assert!(matches!(
            &decoded.request.input[2],
            InputItem::Message(message)
                if matches!(&message.content[0], ContentPart::ToolResult(result)
                    if result.tool_call_id == "toolu_1" && !result.is_error)
        ));

        let encoded = AnthropicMessagesCodec::encode_request(&decoded.request, LossPolicy::Reject)
            .expect("lossless re-encode");
        let value: Value = serde_json::from_slice(&encoded.body).expect("json");
        assert_eq!(value["thinking"]["budget_tokens"], 1024);
        assert_eq!(value["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(value["tools"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(
            value["tool_choice"]["disable_parallel_tool_use"],
            true
        );
        assert_eq!(
            value["messages"][0]["content"][0]["signature"],
            "sig-local"
        );
        assert_eq!(
            value["messages"][1]["content"][0]["tool_use_id"],
            "toolu_1"
        );
    }

    #[test]
    fn missing_required_max_tokens_is_rejected() {
        let error = AnthropicMessagesCodec::decode_request(
            br#"{"model":"claude-test","messages":[{"role":"user","content":"hi"}]}"#,
        )
        .expect_err("max_tokens is required");
        assert!(error.to_string().contains("max_tokens"));
    }
}
