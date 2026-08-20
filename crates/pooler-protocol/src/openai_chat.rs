//! OpenAI Chat Completions request and chunk codecs.
//!
//! The codec owns JSON conversion only.  A caller that uses an HTTP SSE
//! transport should remove the SSE field framing before calling
//! [`OpenAiChatEventDecoder::decode_chunk`] and add that framing around chunks
//! returned by [`OpenAiChatEventEncoder::encode_event`].

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    ContentPart, ConversionError, ConversionReport, Extensions, FinishReason, InputItem,
    LossPolicy, MediaSource, Message, ModelDialect, OpaqueExtension, PreservedJson,
    ReasoningConfig, ReasoningEffort, RequestValidationError, ResponseFormat, Role,
    SemanticRequest, StreamError, StreamEvent, StreamEventKind, ToolCall, ToolChoice,
    ToolDefinition, ToolResult, Usage,
};

/// Extension carrying OpenAI Chat fields not represented by the semantic
/// request.  Its payload is a JSON object containing the original fields.
pub const OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION: &str = "openai.chat.unknown_request_fields";

const UNKNOWN_FIELDS_NAMESPACE: &str = "openai.chat";
const UNKNOWN_FIELDS_NAME: &str = "unknown_request_fields";
/// Delta fields observed carrying assistant reasoning text, in precedence
/// order.
///
/// OpenAI-compatible providers disagree on this name: OpenAI and xAI use
/// `reasoning`, DeepSeek and Fireworks use `reasoning_content`, and some
/// gateways use `reasoning_text`. Every name is accepted so an upstream absent
/// from the model catalog still streams reasoning. `reasoning_content` keeps
/// first precedence to preserve the previously observed decode order.
const REASONING_DELTA_FIELDS: [&str; 3] = ["reasoning_content", "reasoning", "reasoning_text"];

const TEXT_BLOCK_ID: &str = "text";
const REASONING_BLOCK_ID: &str = "reasoning";
const DEFAULT_RESPONSE_ID: &str = "pooler-response";

/// Errors returned by the OpenAI Chat JSON codecs.
#[derive(Debug, Error)]
pub enum OpenAiChatError {
    /// The body is not valid JSON.
    #[error("invalid OpenAI Chat JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A required JSON field is absent.
    #[error("OpenAI Chat field `{field}` is missing")]
    MissingField {
        /// JSON field path.
        field: String,
    },
    /// A JSON field has an unexpected representation.
    #[error("OpenAI Chat field `{field}` must be {expected}")]
    InvalidShape {
        /// JSON field path.
        field: String,
        /// Expected JSON representation.
        expected: &'static str,
    },
    /// A JSON field has an invalid value.
    #[error("invalid OpenAI Chat value for `{field}`: {message}")]
    InvalidValue {
        /// JSON field path.
        field: String,
        /// Redacted value explanation.
        message: String,
    },
    /// Two mutually exclusive request fields were supplied together.
    #[error("OpenAI Chat fields `{first}` and `{second}` cannot be used together")]
    ConflictingFields {
        /// First field.
        first: &'static str,
        /// Second field.
        second: &'static str,
    },
    /// A semantic request failed provider-independent validation.
    #[error("invalid semantic request: {0}")]
    RequestValidation(#[from] RequestValidationError),
    /// A preserved semantic JSON value could not be constructed.
    #[error("invalid preserved JSON: {0}")]
    PreservedJson(#[from] crate::PreservedJsonError),
    /// A conversion report was not accepted by the selected loss policy.
    #[error("OpenAI Chat conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    /// A stream chunk cannot be represented by the semantic event model.
    #[error("invalid OpenAI Chat stream: {message}")]
    InvalidStream {
        /// Redacted stream invariant explanation.
        message: String,
    },
    /// A semantic event cannot be represented by OpenAI Chat.
    #[error("OpenAI Chat cannot encode event: {message}")]
    UnsupportedEvent {
        /// Semantic event explanation.
        message: String,
    },
    /// An extension payload has an invalid shape.
    #[error("invalid OpenAI Chat extension `{key}`")]
    InvalidExtension {
        /// Extension key.
        key: String,
    },
}

/// The decoded semantic request and its conversion accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedChatRequest {
    /// Protocol-neutral request.
    pub request: SemanticRequest,
    /// Fields preserved or degraded while decoding.
    pub report: ConversionReport,
}

impl DecodedChatRequest {
    /// Returns the request and report as separate values.
    #[must_use]
    pub fn into_parts(self) -> (SemanticRequest, ConversionReport) {
        (self.request, self.report)
    }
}

/// A JSON request encoded for the OpenAI Chat Completions endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedChatRequest {
    /// UTF-8 JSON request body.
    pub body: Vec<u8>,
    /// Fields represented, preserved, or deliberately degraded.
    pub report: ConversionReport,
}

/// A single JSON Chat Completions stream chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedChatChunk {
    /// UTF-8 JSON chunk body.
    pub body: Vec<u8>,
    /// Fields represented, preserved, or deliberately degraded.
    pub report: ConversionReport,
}

/// Stateless entry points for OpenAI Chat request and event conversion.
pub struct OpenAiChatCodec;

impl OpenAiChatCodec {
    /// Decodes a request and requires a lossless semantic representation.
    pub fn decode_request(input: &[u8]) -> Result<SemanticRequest, OpenAiChatError> {
        let decoded = decode_chat_request_with_report(input)?;
        decoded.report.validate(LossPolicy::Reject)?;
        Ok(decoded.request)
    }

    /// Decodes a request and returns conversion accounting without applying a
    /// loss policy.
    pub fn decode_request_with_report(input: &[u8]) -> Result<DecodedChatRequest, OpenAiChatError> {
        decode_chat_request_with_report(input)
    }

    /// Encodes a semantic request under an explicit loss policy.
    pub fn encode_request(
        request: &SemanticRequest,
        policy: LossPolicy,
    ) -> Result<EncodedChatRequest, OpenAiChatError> {
        encode_chat_request(request, policy)
    }
}

/// Decode an OpenAI Chat request and require a lossless representation.
pub fn decode_chat_request(input: &[u8]) -> Result<SemanticRequest, OpenAiChatError> {
    OpenAiChatCodec::decode_request(input)
}

/// Decode an OpenAI Chat request and expose conversion accounting.
pub fn decode_chat_request_with_report(
    input: &[u8],
) -> Result<DecodedChatRequest, OpenAiChatError> {
    let mut value: Value = serde_json::from_slice(input)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "request".to_owned(),
            expected: "an object",
        })?;
    let mut report = ConversionReport::default();
    let model = take_string(object, "model")?.ok_or_else(|| OpenAiChatError::MissingField {
        field: "model".to_owned(),
    })?;
    if model.trim().is_empty() {
        return Err(OpenAiChatError::InvalidValue {
            field: "model".to_owned(),
            message: "must not be empty".to_owned(),
        });
    }

    let messages = object
        .remove("messages")
        .ok_or_else(|| OpenAiChatError::MissingField {
            field: "messages".to_owned(),
        })?;
    let messages = messages
        .as_array()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "messages".to_owned(),
            expected: "an array",
        })?;
    let mut request = SemanticRequest::new(model);
    for (index, message) in messages.iter().enumerate() {
        request.push_input(parse_message(message, index, &mut report)?);
    }

    if let Some(tools) = object.remove("tools") {
        request.tools = parse_tools(&tools, &mut report)?;
    }
    if let Some(tool_choice) = object.remove("tool_choice") {
        request.tool_choice = Some(parse_tool_choice(&tool_choice, &mut report)?);
    }
    parse_sampling(object, &mut request)?;
    parse_response_format(object, &mut request, &mut report)?;
    parse_reasoning(object, &mut request)?;
    parse_metadata(object, &mut request)?;

    if let Some(n) = object.remove("n") {
        let count = n.as_u64().ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "n".to_owned(),
            expected: "an unsigned integer",
        })?;
        if count != 1 {
            report.unsupported_required(
                "n",
                "the semantic event model represents one completion choice",
            );
        }
    }

    if !object.is_empty() {
        preserve_unknown_fields(&mut request, std::mem::take(object), &mut report)?;
    }
    request.validate()?;
    Ok(DecodedChatRequest { request, report })
}

/// Encode a semantic request for OpenAI Chat under `policy`.
///
/// The target model is assumed to accept every standard sampling parameter.
/// Use [`encode_chat_request_with_dialect`] when the catalog records that a
/// model rejects one.
pub fn encode_chat_request(
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<EncodedChatRequest, OpenAiChatError> {
    encode_chat_request_with_dialect(request, policy, ModelDialect::DEFAULT)
}

/// Encode a semantic request for OpenAI Chat under `policy` and `dialect`.
///
/// When `dialect` records that the target model rejects a sampling parameter
/// the caller supplied, the parameter is reported as a dropped optional field
/// rather than silently omitted. Under the default [`LossPolicy::Reject`] the
/// request then fails before upstream execution, naming the field; only
/// [`LossPolicy::Degrade`] permits the omission, and it records a warning.
pub fn encode_chat_request_with_dialect(
    request: &SemanticRequest,
    policy: LossPolicy,
    dialect: ModelDialect,
) -> Result<EncodedChatRequest, OpenAiChatError> {
    request.validate()?;
    let mut report = ConversionReport::default();
    let mut object = Map::new();
    object.insert("model".to_owned(), Value::String(request.model.clone()));

    let mut messages = Vec::new();
    for item in &request.input {
        messages.push(encode_input_item(item, &mut report)?);
    }
    if messages.is_empty() {
        report.unsupported_required("input", "OpenAI Chat requires at least one message");
    }
    object.insert("messages".to_owned(), Value::Array(messages));
    if !request.tools.is_empty() {
        object.insert(
            "tools".to_owned(),
            Value::Array(
                request
                    .tools
                    .iter()
                    .map(|definition| encode_tool_definition(definition, &mut report))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        );
    }
    if let Some(choice) = request.tool_choice.as_ref() {
        object.insert("tool_choice".to_owned(), encode_tool_choice(choice));
    }
    if request.target.is_some() {
        report.drop_optional(
            "target",
            "routing target metadata is not part of an OpenAI Chat request",
        );
    }
    if request.continuation_id.is_some() {
        report.drop_optional(
            "continuation_id",
            "OpenAI Chat has no portable continuation field",
        );
    }
    if request.session_id.is_some() {
        report.drop_optional("session_id", "OpenAI Chat has no portable session field");
    }
    encode_sampling(&request.sampling, dialect, &mut object, &mut report);
    if let Some(format) = request.response_format.as_ref() {
        object.insert("response_format".to_owned(), encode_response_format(format));
    }
    if let Some(reasoning) = request.reasoning.as_ref() {
        if let Some(effort) = reasoning.effort.as_ref() {
            object.insert(
                "reasoning_effort".to_owned(),
                Value::String(reasoning_effort_name(effort)),
            );
        }
        if reasoning.include_summary {
            report.drop_optional(
                "reasoning.include_summary",
                "OpenAI Chat has no standard reasoning summary control",
            );
        }
        report_unrepresentable_extensions(
            "reasoning.extensions",
            &reasoning.extensions,
            &mut report,
        );
    }
    if !request.metadata.is_empty() {
        object.insert(
            "metadata".to_owned(),
            Value::Object(
                request
                    .metadata
                    .iter()
                    .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                    .collect(),
            ),
        );
    }
    if request.cache.is_some() {
        report.drop_optional("cache", "OpenAI Chat has no portable prompt-cache control");
    }
    merge_unknown_fields(&mut object, &request.extensions, &mut report)?;
    report.validate(policy)?;
    Ok(EncodedChatRequest {
        body: serde_json::to_vec(&Value::Object(object))?,
        report,
    })
}

fn parse_message(
    value: &Value,
    index: usize,
    report: &mut ConversionReport,
) -> Result<InputItem, OpenAiChatError> {
    let object = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: format!("messages[{index}]"),
            expected: "an object",
        })?;
    let role = required_string(object, "role", &format!("messages[{index}].role"))?;
    let content = object.get("content").unwrap_or(&Value::Null);
    let content = parse_content(content, &format!("messages[{index}].content"), report)?;
    match role {
        "system" => {
            report_unknown_fields(
                object,
                &["role", "content", "id", "name"],
                &format!("messages[{index}]"),
                report,
            );
            Ok(InputItem::Message(Message {
                role: Role::System,
                content,
                id: optional_string(object, "id", &format!("messages[{index}].id"))?,
                name: optional_string(object, "name", &format!("messages[{index}].name"))?,
                tool_call_id: None,
                metadata: BTreeMap::new(),
                extensions: Extensions::default(),
            }))
        }
        "developer" => {
            report_unknown_fields(
                object,
                &["role", "content", "id", "name"],
                &format!("messages[{index}]"),
                report,
            );
            Ok(InputItem::Message(Message {
                role: Role::Developer,
                content,
                id: optional_string(object, "id", &format!("messages[{index}].id"))?,
                name: optional_string(object, "name", &format!("messages[{index}].name"))?,
                tool_call_id: None,
                metadata: BTreeMap::new(),
                extensions: Extensions::default(),
            }))
        }
        "user" => {
            report_unknown_fields(
                object,
                &["role", "content", "id", "name"],
                &format!("messages[{index}]"),
                report,
            );
            Ok(InputItem::Message(Message {
                role: Role::User,
                content,
                id: optional_string(object, "id", &format!("messages[{index}].id"))?,
                name: optional_string(object, "name", &format!("messages[{index}].name"))?,
                tool_call_id: None,
                metadata: BTreeMap::new(),
                extensions: Extensions::default(),
            }))
        }
        "assistant" => {
            let mut content = content;
            if let Some(tool_calls) = object.get("tool_calls") {
                let calls = tool_calls
                    .as_array()
                    .ok_or_else(|| OpenAiChatError::InvalidShape {
                        field: format!("messages[{index}].tool_calls"),
                        expected: "an array",
                    })?;
                for (call_index, call) in calls.iter().enumerate() {
                    content.push(ContentPart::ToolCall(parse_tool_call(
                        call,
                        &format!("messages[{index}].tool_calls[{call_index}]"),
                        report,
                    )?));
                }
            }
            report_unknown_fields(
                object,
                &["role", "content", "id", "name", "tool_calls"],
                &format!("messages[{index}]"),
                report,
            );
            Ok(InputItem::Message(Message {
                role: Role::Assistant,
                content,
                id: optional_string(object, "id", &format!("messages[{index}].id"))?,
                name: optional_string(object, "name", &format!("messages[{index}].name"))?,
                tool_call_id: None,
                metadata: BTreeMap::new(),
                extensions: Extensions::default(),
            }))
        }
        "tool" => {
            report_unknown_fields(
                object,
                &["role", "content", "tool_call_id"],
                &format!("messages[{index}]"),
                report,
            );
            Ok(InputItem::ToolResult(ToolResult {
                tool_call_id: required_string(
                    object,
                    "tool_call_id",
                    &format!("messages[{index}].tool_call_id"),
                )?
                .to_owned(),
                content,
                is_error: false,
                extensions: Extensions::default(),
            }))
        }
        other => Err(OpenAiChatError::InvalidValue {
            field: format!("messages[{index}].role"),
            message: format!("unsupported role `{other}`"),
        }),
    }
}

fn report_unknown_fields(
    object: &Map<String, Value>,
    known: &[&str],
    field: &str,
    report: &mut ConversionReport,
) {
    for key in object.keys() {
        if !known.contains(&key.as_str()) {
            report.drop_optional(
                format!("{field}.{key}"),
                "OpenAI Chat field is not represented by the semantic model",
            );
        }
    }
}

fn parse_content(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
) -> Result<Vec<ContentPart>, OpenAiChatError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(text) = value.as_str() {
        return Ok(vec![ContentPart::text(text)]);
    }
    let parts = value
        .as_array()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: field.to_owned(),
            expected: "a string, null, or an array",
        })?;
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| parse_content_part(part, &format!("{field}[{index}]"), report))
        .collect()
}

fn parse_content_part(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
) -> Result<ContentPart, OpenAiChatError> {
    let object = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: field.to_owned(),
            expected: "an object",
        })?;
    let kind = required_string(object, "type", &format!("{field}.type"))?;
    match kind {
        "text" => {
            report_unknown_fields(object, &["type", "text"], field, report);
            Ok(ContentPart::text(required_string(object, "text", field)?))
        }
        "image_url" => {
            report_unknown_fields(object, &["type", "image_url"], field, report);
            let image = object
                .get("image_url")
                .and_then(Value::as_object)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("{field}.image_url"),
                    expected: "an object",
                })?;
            report_unknown_fields(
                image,
                &["url", "detail"],
                &format!("{field}.image_url"),
                report,
            );
            let url = required_string(image, "url", &format!("{field}.image_url.url"))?;
            let mut part = ContentPart::image("image/*", MediaSource::uri(url));
            if let ContentPart::Image { detail, .. } = &mut part {
                *detail = optional_string(image, "detail", &format!("{field}.image_url.detail"))?;
            }
            Ok(part)
        }
        "input_audio" => {
            report_unknown_fields(object, &["type", "input_audio"], field, report);
            let audio = object
                .get("input_audio")
                .and_then(Value::as_object)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("{field}.input_audio"),
                    expected: "an object",
                })?;
            report_unknown_fields(
                audio,
                &["format", "data"],
                &format!("{field}.input_audio"),
                report,
            );
            let format = required_string(audio, "format", &format!("{field}.input_audio.format"))?;
            let data = required_string(audio, "data", &format!("{field}.input_audio.data"))?;
            Ok(ContentPart::audio(
                format!("audio/{format}"),
                MediaSource::uri(format!("data:audio/{format};base64,{data}")),
            ))
        }
        "file" => {
            report_unknown_fields(object, &["type", "file"], field, report);
            let file = object
                .get("file")
                .and_then(Value::as_object)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("{field}.file"),
                    expected: "an object",
                })?;
            report_unknown_fields(
                file,
                &["file_id", "file_data", "filename"],
                &format!("{field}.file"),
                report,
            );
            let source = file
                .get("file_id")
                .or_else(|| file.get("file_data"))
                .and_then(Value::as_str)
                .ok_or_else(|| OpenAiChatError::MissingField {
                    field: format!("{field}.file.file_id or file_data"),
                })?;
            Ok(ContentPart::file(
                optional_string(file, "filename", &format!("{field}.file.filename"))?,
                "application/octet-stream",
                MediaSource::uri(source),
            ))
        }
        "refusal" => Ok(ContentPart::Provider {
            namespace: UNKNOWN_FIELDS_NAMESPACE.to_owned(),
            name: "refusal".to_owned(),
            data: PreservedJson::from_value(value.clone())?,
        }),
        other => {
            report.preserve_capability(format!("openai.chat.content.{other}"));
            Ok(ContentPart::Provider {
                namespace: UNKNOWN_FIELDS_NAMESPACE.to_owned(),
                name: other.to_owned(),
                data: PreservedJson::from_value(value.clone())?,
            })
        }
    }
}

fn parse_tool_call(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
) -> Result<ToolCall, OpenAiChatError> {
    let object = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: field.to_owned(),
            expected: "an object",
        })?;
    report_unknown_fields(object, &["id", "type", "function"], field, report);
    let id = required_string(object, "id", &format!("{field}.id"))?;
    let function = object
        .get("function")
        .and_then(Value::as_object)
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: format!("{field}.function"),
            expected: "an object",
        })?;
    report_unknown_fields(
        function,
        &["name", "arguments"],
        &format!("{field}.function"),
        report,
    );
    let name = required_string(function, "name", &format!("{field}.function.name"))?;
    let arguments = required_string(
        function,
        "arguments",
        &format!("{field}.function.arguments"),
    )?;
    let arguments =
        PreservedJson::from_str(arguments).map_err(|error| OpenAiChatError::InvalidValue {
            field: format!("{field}.function.arguments"),
            message: error.to_string(),
        })?;
    Ok(ToolCall::new(id, name, arguments))
}

fn parse_tools(
    value: &Value,
    report: &mut ConversionReport,
) -> Result<Vec<ToolDefinition>, OpenAiChatError> {
    let tools = value
        .as_array()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "tools".to_owned(),
            expected: "an array",
        })?;
    tools
        .iter()
        .enumerate()
        .map(|(index, tool)| {
            let field = format!("tools[{index}]");
            let object = tool
                .as_object()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: field.clone(),
                    expected: "an object",
                })?;
            report_unknown_fields(object, &["type", "function"], &field, report);
            let tool_type = optional_string(object, "type", &format!("{field}.type"))?;
            if tool_type.as_deref().is_some_and(|kind| kind != "function") {
                return Err(OpenAiChatError::InvalidValue {
                    field: format!("{field}.type"),
                    message: "only function tools are supported".to_owned(),
                });
            }
            let function = object
                .get("function")
                .and_then(Value::as_object)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("{field}.function"),
                    expected: "an object",
                })?;
            report_unknown_fields(
                function,
                &["name", "parameters", "description", "strict"],
                &format!("{field}.function"),
                report,
            );
            let name = required_string(function, "name", &format!("{field}.function.name"))?;
            let parameters = function
                .get("parameters")
                .map(|value| PreservedJson::from_value(value.clone()))
                .transpose()?;
            let mut definition = ToolDefinition::new(name, parameters);
            definition.description = optional_string(
                function,
                "description",
                &format!("{field}.function.description"),
            )?;
            definition.strict =
                optional_bool(function, "strict", &format!("{field}.function.strict"))?;
            Ok(definition)
        })
        .collect()
}

fn parse_tool_choice(
    value: &Value,
    report: &mut ConversionReport,
) -> Result<ToolChoice, OpenAiChatError> {
    if let Some(choice) = value.as_str() {
        return match choice {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" => Ok(ToolChoice::Required),
            _ => Err(OpenAiChatError::InvalidValue {
                field: "tool_choice".to_owned(),
                message: "expected auto, none, or required".to_owned(),
            }),
        };
    }
    let object = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "tool_choice".to_owned(),
            expected: "a string or object",
        })?;
    report_unknown_fields(object, &["type", "function"], "tool_choice", report);
    let kind = optional_string(object, "type", "tool_choice.type")?;
    if kind.as_deref() != Some("function") {
        return Err(OpenAiChatError::InvalidValue {
            field: "tool_choice.type".to_owned(),
            message: "only function tool choices are supported".to_owned(),
        });
    }
    let function = object
        .get("function")
        .and_then(Value::as_object)
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "tool_choice.function".to_owned(),
            expected: "an object",
        })?;
    report_unknown_fields(function, &["name"], "tool_choice.function", report);
    Ok(ToolChoice::Tool {
        name: required_string(function, "name", "tool_choice.function.name")?.to_owned(),
    })
}

fn parse_sampling(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), OpenAiChatError> {
    request.sampling.temperature = take_f32(object, "temperature")?;
    request.sampling.top_p = take_f32(object, "top_p")?;
    if let Some(max_tokens) = object.remove("max_tokens") {
        request.sampling.max_output_tokens = Some(as_u32(max_tokens, "max_tokens")?);
    }
    if let Some(max_completion_tokens) = object.remove("max_completion_tokens") {
        if request.sampling.max_output_tokens.is_some() {
            return Err(OpenAiChatError::ConflictingFields {
                first: "max_tokens",
                second: "max_completion_tokens",
            });
        }
        request.sampling.max_output_tokens =
            Some(as_u32(max_completion_tokens, "max_completion_tokens")?);
    }
    if let Some(stop) = object.remove("stop") {
        request.sampling.stop = if let Some(value) = stop.as_str() {
            vec![value.to_owned()]
        } else {
            stop.as_array()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: "stop".to_owned(),
                    expected: "a string or array of strings",
                })?
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                        OpenAiChatError::InvalidShape {
                            field: format!("stop[{index}]"),
                            expected: "a string",
                        }
                    })
                })
                .collect::<Result<_, _>>()?
        };
    }
    request.sampling.seed = take_u64(object, "seed")?;
    request.sampling.presence_penalty = take_f32(object, "presence_penalty")?;
    request.sampling.frequency_penalty = take_f32(object, "frequency_penalty")?;
    Ok(())
}

fn parse_response_format(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), OpenAiChatError> {
    let Some(value) = object.remove("response_format") else {
        return Ok(());
    };
    let value = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "response_format".to_owned(),
            expected: "an object",
        })?;
    report_unknown_fields(value, &["type", "json_schema"], "response_format", report);
    let kind = required_string(value, "type", "response_format.type")?;
    request.response_format = Some(match kind {
        "text" => ResponseFormat::Text,
        "json_object" => ResponseFormat::JsonObject,
        "json_schema" => {
            let schema = value
                .get("json_schema")
                .and_then(Value::as_object)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: "response_format.json_schema".to_owned(),
                    expected: "an object",
                })?;
            report_unknown_fields(
                schema,
                &["name", "schema", "strict"],
                "response_format.json_schema",
                report,
            );
            ResponseFormat::JsonSchema {
                name: required_string(schema, "name", "response_format.json_schema.name")?
                    .to_owned(),
                schema: schema
                    .get("schema")
                    .map(|schema| PreservedJson::from_value(schema.clone()))
                    .transpose()?
                    .ok_or_else(|| OpenAiChatError::MissingField {
                        field: "response_format.json_schema.schema".to_owned(),
                    })?,
                strict: optional_bool(schema, "strict", "response_format.json_schema.strict")?
                    .unwrap_or(false),
            }
        }
        other => {
            return Err(OpenAiChatError::InvalidValue {
                field: "response_format.type".to_owned(),
                message: format!("unsupported type `{other}`"),
            })
        }
    });
    Ok(())
}

fn parse_reasoning(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), OpenAiChatError> {
    let Some(value) = object.remove("reasoning_effort") else {
        return Ok(());
    };
    let value = value
        .as_str()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "reasoning_effort".to_owned(),
            expected: "a string",
        })?;
    request.reasoning = Some(ReasoningConfig {
        effort: Some(match value {
            "low" => ReasoningEffort::Low,
            "medium" => ReasoningEffort::Medium,
            "high" => ReasoningEffort::High,
            "max" => ReasoningEffort::Max,
            other => ReasoningEffort::Custom(other.to_owned()),
        }),
        include_summary: false,
        extensions: Extensions::default(),
    });
    Ok(())
}

fn parse_metadata(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), OpenAiChatError> {
    let Some(value) = object.remove("metadata") else {
        return Ok(());
    };
    let metadata = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "metadata".to_owned(),
            expected: "an object",
        })?;
    request.metadata = metadata
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("metadata.{key}"),
                    expected: "a string",
                })
        })
        .collect::<Result<_, _>>()?;
    Ok(())
}

fn preserve_unknown_fields(
    request: &mut SemanticRequest,
    fields: Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), OpenAiChatError> {
    let bytes = serde_json::to_vec(&Value::Object(fields))?;
    let extension = OpaqueExtension::new(UNKNOWN_FIELDS_NAMESPACE, UNKNOWN_FIELDS_NAME, bytes)
        .map_err(|_| OpenAiChatError::InvalidExtension {
            key: OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION.to_owned(),
        })?
        .with_media_type("application/json")
        .map_err(|_| OpenAiChatError::InvalidExtension {
            key: OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION.to_owned(),
        })?;
    report.preserve_extension(&extension.key());
    request.extensions.insert(extension);
    Ok(())
}

fn merge_unknown_fields(
    object: &mut Map<String, Value>,
    extensions: &Extensions,
    report: &mut ConversionReport,
) -> Result<(), OpenAiChatError> {
    for (key, extension) in extensions {
        if key.as_str() != OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION {
            report.unsupported_required(
                format!("extension.{key}"),
                "OpenAI Chat cannot serialize this semantic extension",
            );
            continue;
        }
        let value: Value = serde_json::from_slice(extension.as_bytes())?;
        let fields = value
            .as_object()
            .ok_or_else(|| OpenAiChatError::InvalidExtension { key: key.as_str() })?;
        let mut inserted = false;
        for (field, value) in fields {
            if object.contains_key(field) {
                report.drop_optional(
                    format!("{key}.{field}"),
                    format!("canonical field `{field}` wins over preserved field"),
                );
                continue;
            }
            object.insert(field.clone(), value.clone());
            inserted = true;
        }
        if inserted {
            report.preserve_capability(key.as_str());
        }
    }
    Ok(())
}

fn encode_input_item(
    item: &InputItem,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    match item {
        InputItem::Message(message) => encode_message(message, report),
        InputItem::ToolCall(call) => Ok(encode_tool_call_message(call, report)?),
        InputItem::ToolResult(result) => encode_tool_result_message(result, report),
        InputItem::Content(content) => Ok(Value::Object(json_message(
            "user",
            vec![encode_content_part(content, report)?],
            None,
            None,
        ))),
        InputItem::Provider {
            namespace,
            name,
            data: _,
        } => {
            report.unsupported_required(
                format!("input.provider.{namespace}.{name}"),
                "OpenAI Chat has no generic provider item representation",
            );
            Ok(Value::Object(json_message("user", Vec::new(), None, None)))
        }
    }
}

fn encode_message(
    message: &Message,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    if !message.metadata.is_empty() {
        report.drop_optional(
            "message.metadata",
            "OpenAI Chat has no per-message metadata field",
        );
    }
    report_unrepresentable_extensions("message.extensions", &message.extensions, report);
    if message.role != Role::Tool && message.tool_call_id.is_some() {
        report.unsupported_required(
            "message.tool_call_id",
            "OpenAI Chat only accepts tool_call_id on tool messages",
        );
    }
    if message.role == Role::Tool {
        return encode_tool_result_message(
            &ToolResult {
                tool_call_id: message.tool_call_id.clone().ok_or_else(|| {
                    OpenAiChatError::InvalidValue {
                        field: "message.tool_call_id".to_owned(),
                        message: "tool messages require an invocation ID".to_owned(),
                    }
                })?,
                content: message.content.clone(),
                is_error: false,
                extensions: Extensions::default(),
            },
            report,
        );
    }
    let mut content = Vec::new();
    let mut tool_calls = Vec::new();
    for part in &message.content {
        match part {
            ContentPart::ToolCall(call) => tool_calls.push(encode_tool_call(call, report)?),
            ContentPart::ToolResult(_result) => {
                report.unsupported_required(
                    "message.content.tool_result",
                    "tool results must be standalone tool messages in OpenAI Chat",
                );
            }
            _ => content.push(encode_content_part(part, report)?),
        }
    }
    let mut object = match message.role {
        Role::System => json_message(
            "system",
            content,
            message.name.as_deref(),
            message.id.as_deref(),
        ),
        Role::Developer => json_message(
            "developer",
            content,
            message.name.as_deref(),
            message.id.as_deref(),
        ),
        Role::User => json_message(
            "user",
            content,
            message.name.as_deref(),
            message.id.as_deref(),
        ),
        Role::Assistant => json_message(
            "assistant",
            content,
            message.name.as_deref(),
            message.id.as_deref(),
        ),
        Role::Tool => unreachable!("tool messages handled above"),
    };
    if !tool_calls.is_empty() {
        object.insert("tool_calls".to_owned(), Value::Array(tool_calls));
    }
    Ok(Value::Object(object))
}

fn encode_tool_call_message(
    call: &ToolCall,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    let mut object = json_message("assistant", Vec::new(), None, None);
    object.insert(
        "tool_calls".to_owned(),
        Value::Array(vec![encode_tool_call(call, report)?]),
    );
    Ok(Value::Object(object))
}

fn encode_tool_result_message(
    result: &ToolResult,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    report_unrepresentable_extensions("tool_result.extensions", &result.extensions, report);
    if result.is_error {
        report.drop_optional(
            "tool_result.is_error",
            "OpenAI Chat has no standard tool-result error flag",
        );
    }
    let mut object = json_message("tool", Vec::new(), None, None);
    object.insert(
        "tool_call_id".to_owned(),
        Value::String(result.tool_call_id.clone()),
    );
    let content = if result.content.len() == 1 {
        match &result.content[0] {
            ContentPart::Text { text } => Value::String(text.clone()),
            part => Value::Array(vec![encode_content_part(part, report)?]),
        }
    } else {
        Value::Array(
            result
                .content
                .iter()
                .map(|part| encode_content_part(part, report))
                .collect::<Result<Vec<_>, _>>()?,
        )
    };
    object.insert("content".to_owned(), content);
    Ok(Value::Object(object))
}

fn json_message(
    role: &str,
    content: Vec<Value>,
    name: Option<&str>,
    id: Option<&str>,
) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("role".to_owned(), Value::String(role.to_owned()));
    if content.is_empty() {
        object.insert("content".to_owned(), Value::Null);
    } else if content.len() == 1 {
        if let Value::Object(part) = &content[0] {
            if part.get("type") == Some(&Value::String("text".to_owned())) {
                if let Some(text) = part.get("text") {
                    object.insert("content".to_owned(), text.clone());
                }
            }
        }
        if !object.contains_key("content") {
            object.insert("content".to_owned(), Value::Array(content));
        }
    } else {
        object.insert("content".to_owned(), Value::Array(content));
    }
    if let Some(name) = name {
        object.insert("name".to_owned(), Value::String(name.to_owned()));
    }
    if let Some(id) = id {
        object.insert("id".to_owned(), Value::String(id.to_owned()));
    }
    object
}

fn encode_content_part(
    part: &ContentPart,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    match part {
        ContentPart::Text { text } => Ok(serde_json::json!({"type":"text", "text":text})),
        ContentPart::Image {
            media_type,
            source,
            detail,
        } => {
            let url = encode_media_source(media_type, source);
            let mut image = Map::new();
            image.insert("url".to_owned(), Value::String(url));
            if let Some(detail) = detail {
                image.insert("detail".to_owned(), Value::String(detail.clone()));
            }
            Ok(Value::Object(Map::from_iter([
                ("type".to_owned(), Value::String("image_url".to_owned())),
                ("image_url".to_owned(), Value::Object(image)),
            ])))
        }
        ContentPart::File {
            name,
            media_type: _,
            source,
        } => {
            let mut file = Map::new();
            match source {
                MediaSource::Uri(uri) => {
                    if uri.starts_with("data:") {
                        file.insert("file_data".to_owned(), Value::String(uri.clone()));
                    } else {
                        file.insert("file_id".to_owned(), Value::String(uri.clone()));
                    }
                }
                MediaSource::Inline(_) => {
                    report.unsupported_required(
                        "input.file",
                        "inline files need a provider file ID or data URI",
                    );
                }
            }
            if let Some(name) = name {
                file.insert("filename".to_owned(), Value::String(name.clone()));
            }
            Ok(Value::Object(Map::from_iter([
                ("type".to_owned(), Value::String("file".to_owned())),
                ("file".to_owned(), Value::Object(file)),
            ])))
        }
        ContentPart::Audio { media_type, source } => {
            let (format, data) = match source {
                MediaSource::Uri(uri) if uri.starts_with("data:audio/") => {
                    let format = uri
                        .strip_prefix("data:audio/")
                        .and_then(|value| value.split_once(";base64,"))
                        .map(|(format, data)| (format.to_owned(), data.to_owned()));
                    format.ok_or_else(|| OpenAiChatError::InvalidValue {
                        field: "input_audio".to_owned(),
                        message: "audio data URI must use ;base64".to_owned(),
                    })?
                }
                MediaSource::Uri(uri) => {
                    report.unsupported_required(
                        "input.audio",
                        "OpenAI Chat audio input requires a base64 data URI",
                    );
                    (
                        media_type.trim_start_matches("audio/").to_owned(),
                        uri.clone(),
                    )
                }
                MediaSource::Inline(bytes) => (
                    media_type.trim_start_matches("audio/").to_owned(),
                    encode_base64(bytes),
                ),
            };
            Ok(serde_json::json!({
                "type":"input_audio",
                "input_audio":{"format":format,"data":data}
            }))
        }
        ContentPart::Reasoning(_reasoning) => {
            report.drop_optional(
                "message.reasoning",
                "OpenAI Chat has no standard reasoning input part",
            );
            Ok(serde_json::json!({"type":"text", "text":""}))
        }
        ContentPart::ToolCall(_) | ContentPart::ToolResult(_) => {
            Err(OpenAiChatError::UnsupportedEvent {
                message: "tool content must be encoded by its message owner".to_owned(),
            })
        }
        ContentPart::Provider {
            namespace,
            name,
            data,
        } if namespace == UNKNOWN_FIELDS_NAMESPACE => {
            report.preserve_capability(format!("openai.chat.content.{name}"));
            Ok(data.value().clone())
        }
        ContentPart::Provider {
            namespace, name, ..
        } => {
            report.unsupported_required(
                format!("content.provider.{namespace}.{name}"),
                "provider content has no OpenAI Chat representation",
            );
            Ok(serde_json::json!({"type":"text", "text":""}))
        }
    }
}

fn encode_media_source(media_type: &str, source: &MediaSource) -> String {
    match source {
        MediaSource::Uri(uri) => uri.clone(),
        MediaSource::Inline(bytes) => {
            format!("data:{media_type};base64,{}", encode_base64(bytes))
        }
    }
}

fn report_unrepresentable_extensions(
    field: &str,
    extensions: &Extensions,
    report: &mut ConversionReport,
) {
    if !extensions.is_empty() {
        report.unsupported_required(
            field,
            "OpenAI Chat has no representation for this provider-specific state",
        );
    }
}

fn encode_tool_call(
    call: &ToolCall,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    if !call.dependencies.is_empty() {
        report.unsupported_required(
            "tool_call.dependencies",
            "OpenAI Chat has no tool-call dependency representation",
        );
    }
    report_unrepresentable_extensions("tool_call.extensions", &call.extensions, report);
    Ok(serde_json::json!({
        "id":call.id,
        "type":"function",
        "function":{
            "name":call.name,
            "arguments":String::from_utf8_lossy(&call.arguments.to_bytes())
        }
    }))
}

fn encode_tool_definition(
    definition: &ToolDefinition,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiChatError> {
    report_unrepresentable_extensions("tool_definition.extensions", &definition.extensions, report);
    let mut function = Map::new();
    function.insert("name".to_owned(), Value::String(definition.name.clone()));
    if let Some(description) = &definition.description {
        function.insert("description".to_owned(), Value::String(description.clone()));
    }
    if let Some(parameters) = &definition.parameters {
        function.insert("parameters".to_owned(), parameters.value().clone());
    }
    if let Some(strict) = definition.strict {
        function.insert("strict".to_owned(), Value::Bool(strict));
    }
    Ok(Value::Object(Map::from_iter([
        ("type".to_owned(), Value::String("function".to_owned())),
        ("function".to_owned(), Value::Object(function)),
    ])))
}

fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => Value::String("auto".to_owned()),
        ToolChoice::None => Value::String("none".to_owned()),
        ToolChoice::Required => Value::String("required".to_owned()),
        ToolChoice::Tool { name } => serde_json::json!({
            "type":"function",
            "function":{"name":name}
        }),
    }
}

fn encode_sampling(
    sampling: &crate::SamplingParameters,
    dialect: ModelDialect,
    object: &mut Map<String, Value>,
    report: &mut ConversionReport,
) {
    report_unrepresentable_extensions("sampling.extensions", &sampling.extensions, report);
    if let Some(value) = sampling.temperature {
        if dialect.temperature.is_accepted() {
            object.insert("temperature".to_owned(), serde_json::json!(value));
        } else {
            report.drop_optional(
                "sampling.temperature",
                "the target model rejects the temperature parameter",
            );
        }
    }
    if let Some(value) = sampling.top_p {
        object.insert("top_p".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = sampling.max_output_tokens {
        object.insert("max_tokens".to_owned(), serde_json::json!(value));
    }
    if !sampling.stop.is_empty() {
        object.insert(
            "stop".to_owned(),
            if sampling.stop.len() == 1 {
                Value::String(sampling.stop[0].clone())
            } else {
                Value::Array(sampling.stop.iter().cloned().map(Value::String).collect())
            },
        );
    }
    if let Some(value) = sampling.seed {
        object.insert("seed".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = sampling.presence_penalty {
        object.insert("presence_penalty".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = sampling.frequency_penalty {
        object.insert("frequency_penalty".to_owned(), serde_json::json!(value));
    }
}

fn encode_response_format(format: &ResponseFormat) -> Value {
    match format {
        ResponseFormat::Text => serde_json::json!({"type":"text"}),
        ResponseFormat::JsonObject => serde_json::json!({"type":"json_object"}),
        ResponseFormat::JsonSchema {
            name,
            schema,
            strict,
        } => serde_json::json!({
            "type":"json_schema",
            "json_schema":{"name":name,"schema":schema.value(),"strict":strict}
        }),
    }
}

fn reasoning_effort_name(effort: &ReasoningEffort) -> String {
    match effort {
        ReasoningEffort::Low => "low".to_owned(),
        ReasoningEffort::Medium => "medium".to_owned(),
        ReasoningEffort::High => "high".to_owned(),
        ReasoningEffort::Max => "max".to_owned(),
        ReasoningEffort::Custom(value) => value.clone(),
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, OpenAiChatError> {
    object
        .get(key)
        .ok_or_else(|| OpenAiChatError::MissingField {
            field: field.to_owned(),
        })?
        .as_str()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: field.to_owned(),
            expected: "a string",
        })
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<String>, OpenAiChatError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: field.to_owned(),
                    expected: "a string",
                })
        })
        .transpose()
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<bool>, OpenAiChatError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: field.to_owned(),
                    expected: "a boolean",
                })
        })
        .transpose()
}

fn take_string(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<String>, OpenAiChatError> {
    object
        .remove(key)
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: key.to_owned(),
                    expected: "a string",
                })
        })
        .transpose()
}

fn take_f32(object: &mut Map<String, Value>, key: &str) -> Result<Option<f32>, OpenAiChatError> {
    object
        .remove(key)
        .map(|value| {
            let value = value
                .as_f64()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: key.to_owned(),
                    expected: "a number",
                })?;
            if !value.is_finite() || value < f32::MIN as f64 || value > f32::MAX as f64 {
                return Err(OpenAiChatError::InvalidValue {
                    field: key.to_owned(),
                    message: "number is outside the supported range".to_owned(),
                });
            }
            Ok(value as f32)
        })
        .transpose()
}

fn take_u64(object: &mut Map<String, Value>, key: &str) -> Result<Option<u64>, OpenAiChatError> {
    object
        .remove(key)
        .map(|value| {
            value.as_u64().ok_or_else(|| OpenAiChatError::InvalidShape {
                field: key.to_owned(),
                expected: "an unsigned integer",
            })
        })
        .transpose()
}

fn as_u32(value: Value, field: &str) -> Result<u32, OpenAiChatError> {
    let value = value
        .as_u64()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: field.to_owned(),
            expected: "an unsigned integer",
        })?;
    u32::try_from(value).map_err(|_| OpenAiChatError::InvalidValue {
        field: field.to_owned(),
        message: "number is too large".to_owned(),
    })
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

/// Stateful decoder for OpenAI Chat Completions JSON chunks.
#[derive(Clone, Debug, Default)]
pub struct OpenAiChatEventDecoder {
    next_sequence: u64,
    response_id: Option<String>,
    model: Option<String>,
    response_started: bool,
    text_open: bool,
    reasoning_open: bool,
    tools: BTreeMap<usize, DecodedToolCall>,
    pending_finish: Option<FinishReason>,
    pending_usage: Option<Usage>,
    completed: bool,
}

#[derive(Clone, Debug)]
struct DecodedToolCall {
    id: String,
}

impl OpenAiChatEventDecoder {
    /// Creates an empty decoder for one response stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes one JSON chunk and returns ordered semantic events.
    pub fn decode_chunk(&mut self, input: &[u8]) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        if self.completed {
            return Err(OpenAiChatError::InvalidStream {
                message: "chunk appeared after completion".to_owned(),
            });
        }
        let value: Value = serde_json::from_slice(input)?;
        let object = value
            .as_object()
            .ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "chunk".to_owned(),
                expected: "an object",
            })?;
        if let Some(error) = object.get("error") {
            return self.decode_error(error);
        }
        let id = optional_string(object, "id", "id")?;
        let model = optional_string(object, "model", "model")?;
        let mut events = Vec::new();
        if let Some(id) = id {
            if let Some(previous) = &self.response_id {
                if previous != &id {
                    return Err(OpenAiChatError::InvalidStream {
                        message: "response ID changed within one stream".to_owned(),
                    });
                }
            } else {
                self.response_id = Some(id);
            }
        }
        if let Some(model) = model {
            if let Some(previous) = &self.model {
                if previous != &model {
                    return Err(OpenAiChatError::InvalidStream {
                        message: "model changed within one stream".to_owned(),
                    });
                }
            } else {
                self.model = Some(model);
            }
        }
        if !self.response_started {
            events.push(self.event(
                StreamEventKind::response_start(self.response_id.clone(), self.model.clone()),
                None,
            ));
            self.response_started = true;
        }

        if let Some(fingerprint) = object.get("system_fingerprint").and_then(Value::as_str) {
            events.push(self.event(
                StreamEventKind::Metadata {
                    values: BTreeMap::from([(
                        String::from("system_fingerprint"),
                        fingerprint.to_owned(),
                    )]),
                },
                None,
            ));
        }

        let usage = object
            .get("usage")
            .filter(|usage| !usage.is_null())
            .map(parse_usage)
            .transpose()?;

        let choices = object
            .get("choices")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| OpenAiChatError::InvalidShape {
                        field: "choices".to_owned(),
                        expected: "an array",
                    })
            })
            .transpose()?
            .map_or(&[][..], |choices| choices.as_slice());
        if choices.len() > 1 {
            return Err(OpenAiChatError::InvalidStream {
                message: "semantic events support one completion choice".to_owned(),
            });
        }
        if self.pending_finish.is_some() && !choices.is_empty() {
            return Err(OpenAiChatError::InvalidStream {
                message: "chunk appeared after finish_reason and before [DONE]".to_owned(),
            });
        }
        if let Some(choice) = choices.first() {
            events.extend(self.decode_choice(choice)?);
        }
        if let Some(usage) = usage {
            self.pending_usage = Some(usage.clone());
            if self.pending_finish.is_some() {
                events.extend(self.complete_pending());
            } else {
                events.push(self.event(StreamEventKind::Usage { usage }, None));
            }
        }
        Ok(events)
    }

    /// Decodes an SSE data payload, including the OpenAI `[DONE]` sentinel.
    pub fn decode_data(&mut self, data: &[u8]) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        if data == b"[DONE]" {
            return self.finish();
        }
        self.decode_chunk(data)
    }

    /// Finishes a stream after its final Chat chunk.
    ///
    /// OpenAI normally includes a non-null `finish_reason` before `[DONE]`.
    /// The decoder therefore rejects a sentinel without a completion event
    /// instead of inventing a successful terminal state.
    pub fn finish(&mut self) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        if self.completed {
            return Ok(Vec::new());
        }
        if self.pending_finish.is_none() {
            return Err(OpenAiChatError::InvalidStream {
                message: "stream ended without a finish_reason".to_owned(),
            });
        }
        Ok(self.complete_pending())
    }

    fn decode_error(&mut self, value: &Value) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        let object = value
            .as_object()
            .ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "error".to_owned(),
                expected: "an object",
            })?;
        let message = required_string(object, "message", "error.message")?;
        let code = object
            .get("code")
            .and_then(Value::as_str)
            .or_else(|| object.get("type").and_then(Value::as_str))
            .unwrap_or("openai_error");
        self.completed = true;
        Ok(vec![self.event(
            StreamEventKind::Failure {
                error: StreamError::new(code, message),
            },
            None,
        )])
    }

    fn decode_choice(&mut self, value: &Value) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        let object = value
            .as_object()
            .ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "choices[0]".to_owned(),
                expected: "an object",
            })?;
        if let Some(index) = object.get("index") {
            let index = index
                .as_u64()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: "choices[0].index".to_owned(),
                    expected: "an unsigned integer",
                })?;
            if index != 0 {
                return Err(OpenAiChatError::InvalidStream {
                    message: "semantic events support only choice index zero".to_owned(),
                });
            }
        }
        let delta = object
            .get("delta")
            .and_then(Value::as_object)
            .ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "choices[0].delta".to_owned(),
                expected: "an object",
            })?;
        let mut events = Vec::new();
        if let Some(role) = delta.get("role") {
            let role = role.as_str().ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "choices[0].delta.role".to_owned(),
                expected: "a string",
            })?;
            if role != "assistant" {
                return Err(OpenAiChatError::InvalidStream {
                    message: format!("unsupported assistant delta role `{role}`"),
                });
            }
        }
        // A null value means this delta carries no reasoning, matching how
        // `content` is treated below.
        let reasoning = REASONING_DELTA_FIELDS.iter().find_map(|field| {
            delta
                .get(*field)
                .filter(|value| !value.is_null())
                .map(|value| (*field, value))
        });
        if let Some((field, value)) = reasoning {
            let reasoning = value
                .as_str()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("choices[0].delta.{field}"),
                    expected: "a string or null",
                })?;
            if !reasoning.is_empty() {
                if !self.reasoning_open {
                    events.push(
                        self.event(StreamEventKind::ReasoningStart, Some(REASONING_BLOCK_ID)),
                    );
                    self.reasoning_open = true;
                }
                events.push(self.event(
                    StreamEventKind::reasoning_delta(reasoning),
                    Some(REASONING_BLOCK_ID),
                ));
            }
        }
        if let Some(content) = delta.get("content") {
            if !content.is_null() {
                let content = content
                    .as_str()
                    .ok_or_else(|| OpenAiChatError::InvalidShape {
                        field: "choices[0].delta.content".to_owned(),
                        expected: "a string or null",
                    })?;
                if !content.is_empty() {
                    if self.reasoning_open {
                        events.push(self.event(
                            StreamEventKind::ReasoningEnd { reasoning: None },
                            Some(REASONING_BLOCK_ID),
                        ));
                        self.reasoning_open = false;
                    }
                    if !self.text_open {
                        events.push(self.event(StreamEventKind::TextStart, Some(TEXT_BLOCK_ID)));
                        self.text_open = true;
                    }
                    events.push(
                        self.event(StreamEventKind::text_delta(content), Some(TEXT_BLOCK_ID)),
                    );
                }
            }
        }
        if let Some(refusal) = delta.get("refusal") {
            if !refusal.is_null() {
                let refusal = refusal
                    .as_str()
                    .ok_or_else(|| OpenAiChatError::InvalidShape {
                        field: "choices[0].delta.refusal".to_owned(),
                        expected: "a string or null",
                    })?;
                if !refusal.is_empty() {
                    events.push(self.event(
                        StreamEventKind::Refusal {
                            text: refusal.to_owned(),
                        },
                        None,
                    ));
                }
            }
        }
        if let Some(tool_calls) = delta.get("tool_calls") {
            events.extend(self.decode_tool_calls(tool_calls)?);
        }
        if let Some(finish_reason) = object.get("finish_reason") {
            if !finish_reason.is_null() {
                let finish_reason =
                    finish_reason
                        .as_str()
                        .ok_or_else(|| OpenAiChatError::InvalidShape {
                            field: "choices[0].finish_reason".to_owned(),
                            expected: "a string or null",
                        })?;
                if self.pending_finish.is_some() {
                    return Err(OpenAiChatError::InvalidStream {
                        message: "finish_reason appeared more than once".to_owned(),
                    });
                }
                events.extend(self.close_blocks());
                self.pending_finish = Some(parse_finish_reason(finish_reason));
            }
        }
        Ok(events)
    }

    fn complete_pending(&mut self) -> Vec<StreamEvent> {
        let Some(finish_reason) = self.pending_finish.take() else {
            return Vec::new();
        };
        let usage = self.pending_usage.take();
        self.completed = true;
        vec![self.event(StreamEventKind::completion(finish_reason, usage), None)]
    }

    fn decode_tool_calls(&mut self, value: &Value) -> Result<Vec<StreamEvent>, OpenAiChatError> {
        let calls = value
            .as_array()
            .ok_or_else(|| OpenAiChatError::InvalidShape {
                field: "choices[0].delta.tool_calls".to_owned(),
                expected: "an array",
            })?;
        let mut events = Vec::new();
        for (position, value) in calls.iter().enumerate() {
            let object = value
                .as_object()
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("choices[0].delta.tool_calls[{position}]"),
                    expected: "an object",
                })?;
            let index = object
                .get("index")
                .and_then(Value::as_u64)
                .map(|index| index as usize)
                .unwrap_or(position);
            let function = object
                .get("function")
                .and_then(Value::as_object)
                .ok_or_else(|| OpenAiChatError::InvalidShape {
                    field: format!("choices[0].delta.tool_calls[{position}].function"),
                    expected: "an object",
                })?;
            if let Some(kind) = object.get("type").and_then(Value::as_str) {
                if kind != "function" {
                    return Err(OpenAiChatError::InvalidStream {
                        message: format!("unsupported tool call type `{kind}`"),
                    });
                }
            }
            let arguments = function
                .get("arguments")
                .map(|value| {
                    value.as_str().ok_or_else(|| OpenAiChatError::InvalidShape {
                        field: format!(
                            "choices[0].delta.tool_calls[{position}].function.arguments"
                        ),
                        expected: "a string",
                    })
                })
                .transpose()?
                .unwrap_or("");
            let Some(existing) = self.tools.get(&index) else {
                let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                    OpenAiChatError::InvalidStream {
                        message: format!("tool call {index} started without an ID"),
                    }
                })?;
                let name = function
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| OpenAiChatError::InvalidStream {
                        message: format!("tool call {index} started without a name"),
                    })?;
                self.tools
                    .insert(index, DecodedToolCall { id: id.to_owned() });
                events.push(self.event(
                    StreamEventKind::ToolCallStart {
                        id: id.to_owned(),
                        name: name.to_owned(),
                    },
                    Some(id),
                ));
                if !arguments.is_empty() {
                    events.push(self.event(
                        StreamEventKind::ToolCallDelta {
                            id: id.to_owned(),
                            arguments: arguments.to_owned(),
                        },
                        Some(id),
                    ));
                }
                continue;
            };
            let existing_id = existing.id.clone();
            if let Some(id) = object.get("id").and_then(Value::as_str) {
                if id != existing_id {
                    return Err(OpenAiChatError::InvalidStream {
                        message: format!("tool call {index} changed IDs"),
                    });
                }
            }
            if !arguments.is_empty() {
                events.push(self.event(
                    StreamEventKind::ToolCallDelta {
                        id: existing_id.clone(),
                        arguments: arguments.to_owned(),
                    },
                    Some(&existing_id),
                ));
            }
        }
        Ok(events)
    }

    fn close_blocks(&mut self) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        if self.reasoning_open {
            events.push(self.event(
                StreamEventKind::ReasoningEnd { reasoning: None },
                Some(REASONING_BLOCK_ID),
            ));
            self.reasoning_open = false;
        }
        if self.text_open {
            events.push(self.event(StreamEventKind::TextEnd, Some(TEXT_BLOCK_ID)));
            self.text_open = false;
        }
        let tools = std::mem::take(&mut self.tools);
        for (_, tool) in tools {
            events.push(self.event(
                StreamEventKind::ToolCallEnd {
                    id: tool.id.clone(),
                },
                Some(&tool.id),
            ));
        }
        events
    }

    fn event(&mut self, kind: StreamEventKind, block_id: Option<&str>) -> StreamEvent {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event = StreamEvent::new(self.next_sequence, kind);
        match block_id {
            Some(block_id) => event.with_block_id(block_id),
            None => event,
        }
    }
}

/// Stateful encoder for OpenAI Chat Completions JSON chunks.
#[derive(Clone, Debug)]
pub struct OpenAiChatEventEncoder {
    response_id: String,
    model: String,
    response_started: bool,
    completed: bool,
    tool_indices: BTreeMap<String, usize>,
    next_tool_index: usize,
}

impl Default for OpenAiChatEventEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiChatEventEncoder {
    /// Creates an encoder with deterministic fallback response metadata.
    #[must_use]
    pub fn new() -> Self {
        Self {
            response_id: DEFAULT_RESPONSE_ID.to_owned(),
            model: String::new(),
            response_started: false,
            completed: false,
            tool_indices: BTreeMap::new(),
            next_tool_index: 0,
        }
    }

    /// Encodes one semantic event.  Lifecycle-only events return `None`.
    pub fn encode_event(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<Option<EncodedChatChunk>, OpenAiChatError> {
        if self.completed {
            return Err(OpenAiChatError::UnsupportedEvent {
                message: "event appeared after completion".to_owned(),
            });
        }
        let mut report = ConversionReport::default();
        let mut object = self.base_chunk();
        let mut choices = Vec::new();
        let mut usage = None;
        match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                if self.response_started {
                    return Err(OpenAiChatError::UnsupportedEvent {
                        message: "response start appeared more than once".to_owned(),
                    });
                }
                if let Some(response_id) = response_id {
                    self.response_id = response_id.clone();
                }
                if let Some(model) = model {
                    self.model = model.clone();
                }
                object = self.base_chunk();
                choices.push(choice(serde_json::json!({"role":"assistant"}), Value::Null));
                self.response_started = true;
            }
            StreamEventKind::TextDelta { text } => {
                choices.push(choice(serde_json::json!({"content":text}), Value::Null));
            }
            StreamEventKind::ToolCallStart { id, name } => {
                let index = self.tool_index(id);
                choices.push(choice(
                    serde_json::json!({
                        "tool_calls":[{"index":index,"id":id,"type":"function","function":{"name":name}}]
                    }),
                    Value::Null,
                ));
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                let index = *self.tool_indices.get(id).ok_or_else(|| {
                    OpenAiChatError::UnsupportedEvent {
                        message: format!("tool call `{id}` has no start event"),
                    }
                })?;
                choices.push(choice(
                    serde_json::json!({
                        "tool_calls":[{"index":index,"function":{"arguments":arguments}}]
                    }),
                    Value::Null,
                ));
            }
            StreamEventKind::Refusal { text } => {
                choices.push(choice(serde_json::json!({"refusal":text}), Value::Null));
            }
            StreamEventKind::Usage { usage: value } => {
                usage = Some(encode_usage(value));
                object.insert("choices".to_owned(), Value::Array(Vec::new()));
            }
            StreamEventKind::Completion {
                finish_reason,
                usage: value,
            } => {
                let reason = encode_finish_reason(finish_reason);
                choices.push(choice(Value::Object(Map::new()), Value::String(reason)));
                if let Some(value) = value {
                    usage = Some(encode_usage(value));
                }
                self.completed = true;
            }
            StreamEventKind::Failure { error } => {
                let body = serde_json::json!({
                    "error":{"message":error.message,"type":error.code}
                });
                report.apply_rule("openai.chat.error");
                report.validate(policy)?;
                return Ok(Some(EncodedChatChunk {
                    body: serde_json::to_vec(&body)?,
                    report,
                }));
            }
            StreamEventKind::ReasoningStart
            | StreamEventKind::ReasoningDelta { .. }
            | StreamEventKind::ReasoningEnd { .. } => {
                report.drop_optional(
                    "reasoning",
                    "OpenAI Chat has no standard reasoning stream field",
                );
            }
            StreamEventKind::TextStart
            | StreamEventKind::TextEnd
            | StreamEventKind::ToolCallEnd { .. } => return Ok(None),
            StreamEventKind::Metadata { .. }
            | StreamEventKind::Media { .. }
            | StreamEventKind::Warning { .. }
            | StreamEventKind::Opaque { .. } => {
                report.drop_optional("event", "OpenAI Chat has no representation for this event");
            }
        }
        report.validate(policy)?;
        if choices.is_empty() && usage.is_none() {
            return Ok(None);
        }
        if !choices.is_empty() {
            object.insert("choices".to_owned(), Value::Array(choices));
        }
        if let Some(usage) = usage {
            object.insert("usage".to_owned(), usage);
        }
        Ok(Some(EncodedChatChunk {
            body: serde_json::to_vec(&Value::Object(object))?,
            report,
        }))
    }

    fn base_chunk(&self) -> Map<String, Value> {
        Map::from_iter([
            ("id".to_owned(), Value::String(self.response_id.clone())),
            (
                "object".to_owned(),
                Value::String("chat.completion.chunk".to_owned()),
            ),
            ("created".to_owned(), Value::Number(0.into())),
            ("model".to_owned(), Value::String(self.model.clone())),
        ])
    }

    fn tool_index(&mut self, id: &str) -> usize {
        if let Some(index) = self.tool_indices.get(id) {
            return *index;
        }
        let index = self.next_tool_index;
        self.next_tool_index += 1;
        self.tool_indices.insert(id.to_owned(), index);
        index
    }
}

fn choice(delta: Value, finish_reason: Value) -> Value {
    serde_json::json!({"index":0,"delta":delta,"finish_reason":finish_reason})
}

fn parse_finish_reason(value: &str) -> FinishReason {
    match value {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" | "function_call" => FinishReason::ToolCall,
        "content_filter" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_owned()),
    }
}

fn encode_finish_reason(reason: &FinishReason) -> String {
    match reason {
        FinishReason::Stop => "stop".to_owned(),
        FinishReason::Length => "length".to_owned(),
        FinishReason::ToolCall => "tool_calls".to_owned(),
        FinishReason::ContentFilter => "content_filter".to_owned(),
        FinishReason::Error => "error".to_owned(),
        FinishReason::Other(value) => value.clone(),
    }
}

fn parse_usage(value: &Value) -> Result<Usage, OpenAiChatError> {
    let object = value
        .as_object()
        .ok_or_else(|| OpenAiChatError::InvalidShape {
            field: "usage".to_owned(),
            expected: "an object",
        })?;
    let input_tokens = usage_count(object, "prompt_tokens")?.unwrap_or(0);
    let output_tokens = usage_count(object, "completion_tokens")?.unwrap_or(0);
    let mut usage = Usage {
        input_tokens,
        output_tokens,
        reasoning_tokens: None,
        cached_input_tokens: None,
        total_tokens: usage_count(object, "total_tokens")?,
        details: BTreeMap::new(),
    };
    if let Some(details) = object
        .get("completion_tokens_details")
        .and_then(Value::as_object)
    {
        usage.reasoning_tokens = usage_count(details, "reasoning_tokens")?;
    }
    if let Some(details) = object
        .get("prompt_tokens_details")
        .and_then(Value::as_object)
    {
        usage.cached_input_tokens = usage_count(details, "cached_tokens")?;
    }
    Ok(usage)
}

fn usage_count(object: &Map<String, Value>, field: &str) -> Result<Option<u64>, OpenAiChatError> {
    object
        .get(field)
        .map(|value| {
            value.as_u64().ok_or_else(|| OpenAiChatError::InvalidShape {
                field: format!("usage.{field}"),
                expected: "an unsigned integer",
            })
        })
        .transpose()
}

fn encode_usage(usage: &Usage) -> Value {
    let total_tokens = usage
        .total_tokens
        .unwrap_or_else(|| usage.input_tokens.saturating_add(usage.output_tokens));
    let mut value = serde_json::json!({
        "prompt_tokens":usage.input_tokens,
        "completion_tokens":usage.output_tokens,
        "total_tokens":total_tokens
    });
    if let Some(reasoning_tokens) = usage.reasoning_tokens {
        value["completion_tokens_details"] =
            serde_json::json!({"reasoning_tokens":reasoning_tokens});
    }
    if let Some(cached_tokens) = usage.cached_input_tokens {
        value["prompt_tokens_details"] = serde_json::json!({"cached_tokens":cached_tokens});
    }
    value
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        decode_chat_request, decode_chat_request_with_report, encode_chat_request,
        encode_chat_request_with_dialect, OpenAiChatError, OpenAiChatEventDecoder,
        OpenAiChatEventEncoder,
    };
    use crate::{
        ContentPart, FinishReason, InputItem, LossPolicy, Message, ModelDialect, OpaqueExtension,
        ReasoningConfig, ReasoningEffort, Role, SemanticRequest, StreamEvent, StreamEventKind,
        StreamValidator, TargetMetadata, ToolCall, ToolDefinition, ToolResult, Usage,
    };

    #[test]
    fn request_codec_preserves_standard_fields_and_unknown_fields() {
        let input = br#"{
          "model":"gpt-test",
          "messages":[
            {"role":"system","content":"be concise"},
            {"role":"user","content":[{"type":"text","text":"hello"},{"type":"image_url","image_url":{"url":"https://example.test/image.png","detail":"low"}}]},
            {"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"city\":\"Paris\"}"}}]},
            {"role":"tool","tool_call_id":"call-1","content":"sunny"}
          ],
          "tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"},"strict":true}}],
          "reasoning_effort":"high",
          "temperature":0.25,
          "stream":true
        }"#;

        let decoded = decode_chat_request_with_report(input).expect("request");
        assert!(decoded.report.is_lossless());
        assert_eq!(decoded.request.model, "gpt-test");
        assert_eq!(decoded.request.input.len(), 4);
        assert_eq!(decoded.request.tools[0].name, "lookup");
        assert_eq!(
            decoded
                .request
                .extensions
                .get_str("openai.chat.unknown_request_fields")
                .expect("stream extension")
                .as_bytes(),
            br#"{"stream":true}"#
        );

        let encoded = encode_chat_request(&decoded.request, LossPolicy::Reject).expect("encode");
        let value: Value = serde_json::from_slice(&encoded.body).expect("JSON");
        assert_eq!(value["model"], "gpt-test");
        assert_eq!(value["messages"][2]["tool_calls"][0]["id"], "call-1");
        assert_eq!(value["stream"], true);
        assert!(encoded.report.is_lossless());
        let strict = decode_chat_request(&encoded.body).expect("strict decode");
        assert_eq!(strict.model, decoded.request.model);
    }

    #[test]
    fn request_codec_rejects_multiple_choices_before_execution() {
        let input = br#"{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"n":2}"#;
        let error = decode_chat_request(input).expect_err("multiple choices");
        assert!(matches!(error, OpenAiChatError::Conversion(_)));
    }

    fn reasoning_text_from_delta(delta: &str) -> Vec<String> {
        let chunk = format!(
            r#"{{"id":"chat-1","model":"gpt-test","choices":[{{"index":0,"delta":{delta},"finish_reason":null}}]}}"#
        );
        let mut decoder = OpenAiChatEventDecoder::new();
        decoder
            .decode_chunk(chunk.as_bytes())
            .expect("decode reasoning delta")
            .into_iter()
            .filter_map(|event| match event.kind {
                StreamEventKind::ReasoningDelta { text } => Some(text),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn decoder_accepts_every_observed_reasoning_field_name() {
        for field in ["reasoning", "reasoning_content", "reasoning_text"] {
            let delta = format!(r#"{{"role":"assistant","{field}":"thinking"}}"#);
            assert_eq!(
                reasoning_text_from_delta(&delta),
                vec!["thinking".to_owned()],
                "provider field `{field}` must stream reasoning"
            );
        }
    }

    #[test]
    fn decoder_treats_a_null_reasoning_field_as_absent() {
        // A bare null previously reached `as_str` and failed as InvalidShape,
        // because only the `reasoning_content` branch filtered nulls.
        assert!(reasoning_text_from_delta(r#"{"role":"assistant","reasoning":null}"#).is_empty());
        assert!(
            reasoning_text_from_delta(r#"{"role":"assistant","reasoning_text":null}"#).is_empty()
        );
    }

    #[test]
    fn decoder_reports_the_offending_reasoning_field_by_name() {
        let chunk = br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","reasoning":42},"finish_reason":null}]}"#;
        let error = OpenAiChatEventDecoder::new()
            .decode_chunk(chunk)
            .expect_err("a non-string reasoning value is invalid");
        let OpenAiChatError::InvalidShape { field, .. } = error else {
            panic!("expected an invalid-shape error");
        };
        assert_eq!(field, "choices[0].delta.reasoning");
    }

    fn request_with_temperature() -> SemanticRequest {
        let input =
            br#"{"model":"o-test","messages":[{"role":"user","content":"hi"}],"temperature":0.25}"#;
        decode_chat_request_with_report(input)
            .expect("request")
            .request
    }

    #[test]
    fn default_dialect_forwards_temperature_upstream() {
        let encoded = encode_chat_request(&request_with_temperature(), LossPolicy::Reject)
            .expect("default dialect encodes");
        let value: Value = serde_json::from_slice(&encoded.body).expect("JSON");
        assert_eq!(value["temperature"], 0.25);
        assert!(encoded.report.is_lossless());
    }

    #[test]
    fn rejecting_dialect_fails_before_upstream_under_the_default_policy() {
        let error = encode_chat_request_with_dialect(
            &request_with_temperature(),
            LossPolicy::Reject,
            ModelDialect::new().rejecting_temperature(),
        )
        .expect_err("temperature must not reach a model that rejects it");
        let OpenAiChatError::Conversion(conversion) = error else {
            panic!("expected a conversion error naming the dropped field");
        };
        assert_eq!(conversion.policy, LossPolicy::Reject);
        assert!(conversion
            .disallowed_losses
            .iter()
            .any(|field| field == "sampling.temperature"));
    }

    #[test]
    fn rejecting_dialect_omits_temperature_and_records_loss_under_degrade() {
        let encoded = encode_chat_request_with_dialect(
            &request_with_temperature(),
            LossPolicy::Degrade,
            ModelDialect::new().rejecting_temperature(),
        )
        .expect("degrade permits the omission");
        let value: Value = serde_json::from_slice(&encoded.body).expect("JSON");
        assert!(
            value.get("temperature").is_none(),
            "temperature must be absent for a model that rejects it"
        );
        assert!(encoded.report.has_loss());
        assert!(encoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| field == "sampling.temperature"));
    }

    #[test]
    fn rejecting_dialect_is_lossless_when_the_caller_sent_no_temperature() {
        let input = br#"{"model":"o-test","messages":[{"role":"user","content":"hi"}]}"#;
        let request = decode_chat_request_with_report(input)
            .expect("request")
            .request;
        let encoded = encode_chat_request_with_dialect(
            &request,
            LossPolicy::Reject,
            ModelDialect::new().rejecting_temperature(),
        )
        .expect("no temperature means no loss");
        assert!(encoded.report.is_lossless());
    }

    #[test]
    fn decoder_emits_valid_text_lifecycle_and_completion() {
        let mut decoder = OpenAiChatEventDecoder::new();
        let chunks = [
            br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#
                .as_slice(),
            br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}"#
                .as_slice(),
            br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}"#
                .as_slice(),
        ];
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(decoder.decode_chunk(chunk).expect("chunk"));
        }
        assert!(decoder.decode_data(b"[DONE]").expect("done").is_empty());
        let mut validator = StreamValidator::default();
        for event in &events {
            validator.accept(event).expect("valid semantic event");
        }
        assert!(validator.is_terminal());
        assert!(validator.is_drained());
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::TextDelta { ref text } if text == "hello"
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::Stop,
                usage: Some(Usage {
                    input_tokens: 2,
                    output_tokens: 1,
                    ..
                }),
                ..
            }
        )));
        assert!(!events
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::Usage { .. })));
    }

    #[test]
    fn decoder_accepts_usage_only_chunk_after_finish() {
        let mut decoder = OpenAiChatEventDecoder::new();
        decoder
            .decode_chunk(
                br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
            )
            .expect("start");
        let finish_events = decoder
            .decode_chunk(
                br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            )
            .expect("finish");
        assert!(!finish_events
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::Completion { .. })));

        let usage_events = decoder
            .decode_chunk(
                br#"{"id":"chat-1","model":"gpt-test","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}"#,
            )
            .expect("usage-only chunk");
        assert!(usage_events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::Stop,
                usage: Some(Usage {
                    input_tokens: 2,
                    output_tokens: 1,
                    ..
                }),
            }
        )));
        assert!(decoder.decode_data(b"[DONE]").expect("done").is_empty());
    }

    #[test]
    fn decoder_accepts_reasoning_alias_delta() {
        let mut decoder = OpenAiChatEventDecoder::new();
        let events = decoder
            .decode_chunk(
                br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":null,"reasoning":"checking"},"finish_reason":null}]}"#,
            )
            .expect("reasoning alias");
        assert!(events
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::ReasoningStart)));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::ReasoningDelta { ref text } if text == "checking"
        )));
    }

    #[test]
    fn decoder_preserves_tool_argument_fragments() {
        let mut decoder = OpenAiChatEventDecoder::new();
        let first = decoder
            .decode_chunk(br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"city\":"}}]},"finish_reason":null}]}"#)
            .expect("tool start");
        let second = decoder
            .decode_chunk(br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]},"finish_reason":"tool_calls"}]}"#)
            .expect("tool finish");
        let events = first.into_iter().chain(second).collect::<Vec<_>>();
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::ToolCallStart { ref id, ref name }
                if id == "call-1" && name == "lookup"
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::ToolCallDelta { ref arguments, .. }
                if arguments == "{\"city\":" || arguments == "\"Paris\"}"
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::ToolCallEnd { ref id } if id == "call-1"
        )));
    }

    #[test]
    fn encoder_accounts_for_unrepresentable_reasoning() {
        let event = StreamEvent::new(
            1,
            StreamEventKind::ReasoningDelta {
                text: "private chain".to_owned(),
            },
        )
        .with_block_id("reasoning");
        let mut encoder = OpenAiChatEventEncoder::new();
        let error = encoder
            .encode_event(&event, LossPolicy::Reject)
            .expect_err("reasoning must be rejected");
        assert!(matches!(error, OpenAiChatError::Conversion(_)));

        let encoded = encoder
            .encode_event(&event, LossPolicy::Degrade)
            .expect("degraded reasoning");
        assert!(encoded.is_none());
    }

    #[test]
    fn encoder_emits_tool_chunks_and_usage() {
        let mut request = SemanticRequest::new("gpt-test");
        request.push_message(Message::text(Role::User, "find it"));
        request.reasoning = Some(ReasoningConfig {
            effort: Some(ReasoningEffort::Low),
            ..ReasoningConfig::default()
        });
        let tool = ToolCall::new(
            "call-1",
            "lookup",
            crate::PreservedJson::from_str("{\"city\":\"Paris\"}").expect("arguments"),
        );
        assert!(request.validate().is_ok());
        let encoded_request = encode_chat_request(&request, LossPolicy::Degrade).expect("request");
        assert!(encoded_request
            .body
            .windows(5)
            .any(|window| window == b"model"));

        let mut encoder = OpenAiChatEventEncoder::new();
        let start = StreamEvent::new(
            1,
            StreamEventKind::response_start(Some("chat-1".to_owned()), Some("gpt-test".to_owned())),
        );
        assert!(encoder
            .encode_event(&start, LossPolicy::Reject)
            .expect("start")
            .is_some());
        let tool_start = StreamEvent::new(
            2,
            StreamEventKind::ToolCallStart {
                id: tool.id.clone(),
                name: tool.name.clone(),
            },
        );
        let chunk = encoder
            .encode_event(&tool_start, LossPolicy::Reject)
            .expect("tool start")
            .expect("chunk");
        let value: Value = serde_json::from_slice(&chunk.body).expect("chunk JSON");
        assert_eq!(
            value["choices"][0]["delta"]["tool_calls"][0]["id"],
            "call-1"
        );
        let usage = encoder
            .encode_event(
                &StreamEvent::new(
                    3,
                    StreamEventKind::Usage {
                        usage: Usage::new(2, 3),
                    },
                ),
                LossPolicy::Reject,
            )
            .expect("usage")
            .expect("usage chunk");
        let value: Value = serde_json::from_slice(&usage.body).expect("usage JSON");
        assert_eq!(value["usage"]["total_tokens"], 5);
    }

    #[test]
    fn request_decoder_reports_nested_unknown_fields() {
        let input = br#"{
          "model":"gpt-test",
          "messages":[
            {"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/image.png","provider_extra":true},"content_extra":true}]},
            {"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{}","provider_extra":true},"call_extra":true}],"message_extra":true}
          ],
          "tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"},"provider_extra":true},"tool_extra":true}]
        }"#;

        let decoded = decode_chat_request_with_report(input).expect("request");
        assert!(decoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| { field == "messages[0].content[0].content_extra" }));
        assert!(decoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| { field == "messages[0].content[0].image_url.provider_extra" }));
        assert!(decoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| { field == "messages[1].tool_calls[0].function.provider_extra" }));
        assert!(matches!(
            decode_chat_request(input),
            Err(OpenAiChatError::Conversion(_))
        ));
    }

    #[test]
    fn encoder_reports_extensions_that_are_not_serialized() {
        let mut request = SemanticRequest::new("gpt-test");
        request.push_message(Message::text(Role::User, "hello"));
        request.extensions.insert(
            OpaqueExtension::new("provider", "secret", br#"{"value":true}"#.to_vec())
                .expect("extension"),
        );
        let error = encode_chat_request(&request, LossPolicy::Reject)
            .expect_err("unsupported extension must not be marked preserved");
        match error {
            OpenAiChatError::Conversion(error) => assert!(error
                .unsupported_required_fields
                .iter()
                .any(|field| field == "extension.provider.secret")),
            other => panic!("unexpected error: {other:?}"),
        }

        let mut request = SemanticRequest::new("gpt-test");
        request.push_message(Message::text(Role::User, "hello"));
        request.extensions.insert(
            OpaqueExtension::new(
                "openai.chat",
                "unknown_request_fields",
                br#"{"model":"wrong","stream":true}"#.to_vec(),
            )
            .expect("extension"),
        );
        let encoded = encode_chat_request(&request, LossPolicy::Degrade).expect("degrade");
        let value: Value = serde_json::from_slice(&encoded.body).expect("JSON");
        assert_eq!(value["model"], "gpt-test");
        assert_eq!(value["stream"], true);
        assert!(encoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| { field == "openai.chat.unknown_request_fields.model" }));
        assert!(encoded.report.preserved_extensions.is_empty());
        assert!(matches!(
            encode_chat_request(&request, LossPolicy::Reject),
            Err(OpenAiChatError::Conversion(_))
        ));
    }

    #[test]
    fn encoder_rejects_unrepresented_nested_semantics() {
        let mut request = SemanticRequest::new("gpt-test");
        let mut message = Message::text(Role::User, "hello");
        message
            .metadata
            .insert("trace".to_owned(), "one".to_owned());
        message.extensions.insert(
            OpaqueExtension::new("provider", "message_state", br#"{}"#.to_vec())
                .expect("message extension"),
        );
        let mut call = ToolCall::new(
            "call-1",
            "lookup",
            crate::PreservedJson::from_str("{}").expect("arguments"),
        );
        call.dependencies.push("call-0".to_owned());
        call.extensions.insert(
            OpaqueExtension::new("provider", "tool_state", br#"{}"#.to_vec())
                .expect("tool extension"),
        );
        message.push_content(ContentPart::ToolCall(call));
        request.push_message(message);

        let mut definition = ToolDefinition::new("lookup", None);
        definition.extensions.insert(
            OpaqueExtension::new("provider", "definition_state", br#"{}"#.to_vec())
                .expect("definition extension"),
        );
        request.tools.push(definition);

        let error = encode_chat_request(&request, LossPolicy::Reject)
            .expect_err("nested semantics must not be silently discarded");
        let OpenAiChatError::Conversion(error) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert!(error
            .disallowed_losses
            .iter()
            .any(|field| field == "message.metadata"));
        assert!(error
            .unsupported_required_fields
            .iter()
            .any(|field| field == "message.extensions"));
        assert!(error
            .unsupported_required_fields
            .iter()
            .any(|field| field == "tool_call.dependencies"));
        assert!(error
            .unsupported_required_fields
            .iter()
            .any(|field| field == "tool_call.extensions"));
        assert!(error
            .unsupported_required_fields
            .iter()
            .any(|field| field == "tool_definition.extensions"));
    }

    #[test]
    fn encoder_accounts_direct_tool_result_and_control_extensions() {
        let mut request = SemanticRequest::new("gpt-test");
        let mut result = ToolResult::text("call-1", "done");
        result.is_error = true;
        result.extensions.insert(
            OpaqueExtension::new("provider", "result_state", br#"{}"#.to_vec())
                .expect("result extension"),
        );
        request.push_input(InputItem::ToolResult(result));
        request.sampling.extensions.insert(
            OpaqueExtension::new("provider", "sampling_state", br#"{}"#.to_vec())
                .expect("sampling extension"),
        );
        request.reasoning = Some(ReasoningConfig {
            effort: Some(ReasoningEffort::Low),
            extensions: {
                let mut extensions = crate::Extensions::default();
                extensions.insert(
                    OpaqueExtension::new("provider", "reasoning_state", br#"{}"#.to_vec())
                        .expect("reasoning extension"),
                );
                extensions
            },
            ..ReasoningConfig::default()
        });
        request.target = Some(TargetMetadata::default());
        request.continuation_id = Some("continuation".to_owned());
        request.session_id = Some("session".to_owned());

        let error = encode_chat_request(&request, LossPolicy::Reject)
            .expect_err("unrepresented control state must be accounted");
        let OpenAiChatError::Conversion(error) = error else {
            panic!("unexpected error: {error:?}");
        };
        for field in [
            "tool_result.extensions",
            "sampling.extensions",
            "reasoning.extensions",
        ] {
            assert!(error
                .unsupported_required_fields
                .iter()
                .any(|actual| actual == field));
        }
        for field in [
            "tool_result.is_error",
            "target",
            "continuation_id",
            "session_id",
        ] {
            assert!(error.disallowed_losses.iter().any(|actual| actual == field));
        }
    }

    #[test]
    fn decoder_reports_unrepresented_json_schema_fields() {
        let input = br#"{
          "model":"gpt-test",
          "messages":[{"role":"user","content":"hello"}],
          "response_format":{"type":"json_schema","json_schema":{"name":"answer","description":"extra context","schema":{"type":"object"},"strict":true,"provider_extra":true}}
        }"#;

        let decoded = decode_chat_request_with_report(input).expect("request");
        assert!(decoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| { field == "response_format.json_schema.description" }));
        assert!(decoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| { field == "response_format.json_schema.provider_extra" }));
        assert!(matches!(
            decode_chat_request(input),
            Err(OpenAiChatError::Conversion(_))
        ));
    }

    #[test]
    fn decoder_rejects_incomplete_done_sentinel() {
        let mut decoder = OpenAiChatEventDecoder::new();
        decoder
            .decode_chunk(br#"{"id":"chat-1","model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#)
            .expect("start");
        let error = decoder.decode_data(b"[DONE]").expect_err("missing finish");
        assert!(matches!(error, OpenAiChatError::InvalidStream { .. }));
    }
}
