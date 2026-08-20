//! OpenAI Responses request and streaming-event codecs.
//!
//! The Responses API uses typed input items and named SSE events. This module
//! translates that wire into Pooler's protocol-neutral request and event
//! model while keeping unmodeled top-level request controls in one opaque,
//! namespaced extension.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    ContentPart, ConversionError, ConversionReport, Extensions, FinishReason, InputItem,
    LossPolicy, MediaSource, Message, OpaqueExtension, PreservedJson, ReasoningBlock,
    ReasoningConfig, ReasoningEffort, RequestValidationError, ResponseFormat, Role,
    SemanticRequest, StreamError, StreamEvent, StreamEventKind, ToolCall, ToolChoice,
    ToolDefinition, ToolResult, Usage,
};

/// Extension carrying Responses request fields that are not represented by
/// the semantic request model, such as `stream`, `store`, and `include`.
pub const OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION: &str =
    "openai.responses.unknown_request_fields";
/// Extension preserving the exact Responses `reasoning.summary` mode.
pub const OPENAI_RESPONSES_REASONING_SUMMARY_EXTENSION: &str = "openai.responses.reasoning_summary";

const UNKNOWN_FIELDS_NAMESPACE: &str = "openai.responses";
const UNKNOWN_FIELDS_NAME: &str = "unknown_request_fields";
const REASONING_SUMMARY_NAME: &str = "reasoning_summary";
const DEFAULT_RESPONSE_ID: &str = "resp_pooler";
const FILE_ID_SOURCE_PREFIX: &str = "openai-file-id:";

/// Errors returned by the OpenAI Responses codecs.
#[derive(Debug, Error)]
pub enum OpenAiResponsesError {
    /// The body or event was not valid JSON.
    #[error("invalid OpenAI Responses JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A required field was absent.
    #[error("OpenAI Responses field `{field}` is missing")]
    MissingField {
        /// JSON field path.
        field: String,
    },
    /// A field had an unexpected representation.
    #[error("OpenAI Responses field `{field}` must be {expected}")]
    InvalidShape {
        /// JSON field path.
        field: String,
        /// Expected representation.
        expected: &'static str,
    },
    /// A field had an unsupported value.
    #[error("invalid OpenAI Responses value for `{field}`: {message}")]
    InvalidValue {
        /// JSON field path.
        field: String,
        /// Safe value explanation.
        message: String,
    },
    /// A semantic request failed provider-independent validation.
    #[error("invalid semantic request: {0}")]
    RequestValidation(#[from] RequestValidationError),
    /// A preserved JSON value could not be constructed.
    #[error("invalid preserved JSON: {0}")]
    PreservedJson(#[from] crate::PreservedJsonError),
    /// The selected loss policy rejected a conversion report.
    #[error("OpenAI Responses conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    /// An event violated the Responses stream lifecycle.
    #[error("invalid OpenAI Responses stream: {message}")]
    InvalidStream {
        /// Safe invariant explanation.
        message: String,
    },
    /// A semantic event has no implemented Responses representation.
    #[error("OpenAI Responses cannot encode event: {message}")]
    UnsupportedEvent {
        /// Safe event explanation.
        message: String,
    },
    /// An opaque extension had an invalid shape.
    #[error("invalid OpenAI Responses extension `{key}")]
    InvalidExtension {
        /// Extension identity.
        key: String,
    },
}

/// A decoded Responses request and its conversion accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedResponsesRequest {
    /// Protocol-neutral request.
    pub request: SemanticRequest,
    /// Fields preserved or degraded while decoding.
    pub report: ConversionReport,
    /// Whether the source requested an SSE response.
    pub stream: bool,
}

/// A JSON request encoded for the Responses endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedResponsesRequest {
    /// UTF-8 JSON body.
    pub body: Vec<u8>,
    /// Conversion accounting.
    pub report: ConversionReport,
}

/// One named Responses SSE event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedResponsesEvent {
    /// SSE `event` field.
    pub event: String,
    /// UTF-8 JSON data field.
    pub body: Vec<u8>,
    /// Conversion accounting for the source semantic event.
    pub report: ConversionReport,
}

/// Stateless entry points for OpenAI Responses request conversion.
pub struct OpenAiResponsesCodec;

impl OpenAiResponsesCodec {
    /// Decodes a request and requires a lossless semantic representation.
    pub fn decode_request(input: &[u8]) -> Result<SemanticRequest, OpenAiResponsesError> {
        let decoded = decode_responses_request_with_report(input)?;
        decoded.report.validate(LossPolicy::Reject)?;
        Ok(decoded.request)
    }

    /// Decodes a request and returns conversion accounting.
    pub fn decode_request_with_report(
        input: &[u8],
    ) -> Result<DecodedResponsesRequest, OpenAiResponsesError> {
        decode_responses_request_with_report(input)
    }

    /// Encodes a semantic request under an explicit loss policy.
    pub fn encode_request(
        request: &SemanticRequest,
        policy: LossPolicy,
    ) -> Result<EncodedResponsesRequest, OpenAiResponsesError> {
        encode_responses_request(request, policy)
    }
}

/// Decode a Responses request and require lossless semantic representation.
pub fn decode_responses_request(input: &[u8]) -> Result<SemanticRequest, OpenAiResponsesError> {
    OpenAiResponsesCodec::decode_request(input)
}

/// Decode a Responses request and expose conversion accounting.
pub fn decode_responses_request_with_report(
    input: &[u8],
) -> Result<DecodedResponsesRequest, OpenAiResponsesError> {
    let mut value: Value = serde_json::from_slice(input)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid_shape("request", "an object"))?;
    let mut report = ConversionReport::default();
    let model = take_string(object, "model")?.ok_or_else(|| missing("model"))?;
    if model.trim().is_empty() {
        return Err(invalid_value("model", "must not be empty"));
    }

    let stream = optional_bool(object, "stream", "stream")?.unwrap_or(false);
    let mut request = SemanticRequest::new(model);
    if let Some(instructions) = take_string(object, "instructions")? {
        request.push_message(Message::text(Role::System, instructions));
        report.apply_rule("openai.responses.instructions_to_system_message");
    }
    if let Some(input) = object.remove("input") {
        parse_input(input, &mut request, &mut report)?;
    }
    if let Some(tools) = object.remove("tools") {
        request.tools = parse_tools(&tools, &mut report)?;
    }
    if let Some(choice) = object.remove("tool_choice") {
        request.tool_choice = Some(parse_tool_choice(&choice)?);
    }
    parse_reasoning(object, &mut request, &mut report)?;
    parse_sampling(object, &mut request)?;
    parse_text_format(object, &mut request, &mut report)?;
    parse_metadata(object, &mut request)?;
    request.continuation_id = take_string(object, "previous_response_id")?;

    // These fields affect the Responses transport or provider execution but
    // have no portable semantic slot. Keeping them in an opaque extension is
    // lossless when a Responses encoder is selected later.
    if !object.is_empty() {
        preserve_unknown_fields(&mut request, std::mem::take(object), &mut report)?;
    }
    request.validate()?;
    Ok(DecodedResponsesRequest {
        request,
        report,
        stream,
    })
}

fn parse_input(
    value: Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), OpenAiResponsesError> {
    if let Some(text) = value.as_str() {
        request.push_message(Message::text(Role::User, text));
        return Ok(());
    }
    let items = value
        .as_array()
        .ok_or_else(|| invalid_shape("input", "a string or array"))?;
    for (index, item) in items.iter().enumerate() {
        request.push_input(parse_input_item(item, index, report)?);
    }
    Ok(())
}

fn parse_input_item(
    value: &Value,
    index: usize,
    report: &mut ConversionReport,
) -> Result<InputItem, OpenAiResponsesError> {
    let field = format!("input[{index}]");
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape(&field, "an object"))?;
    match object.get("type").and_then(Value::as_str) {
        Some("function_call") => parse_function_call(object, &field, report),
        Some("function_call_output") => parse_function_output(object, &field, report),
        Some("reasoning") => parse_reasoning_item(object, &field, report),
        Some("message") | None if object.contains_key("role") => {
            parse_message_item(object, &field, report)
        }
        Some(kind) => {
            report.preserve_capability(format!("openai.responses.input.{kind}"));
            Ok(InputItem::Provider {
                namespace: UNKNOWN_FIELDS_NAMESPACE.to_owned(),
                name: kind.to_owned(),
                data: PreservedJson::from_value(value.clone())?,
            })
        }
        None => Err(missing(format!("{field}.type or role"))),
    }
}

fn parse_message_item(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
) -> Result<InputItem, OpenAiResponsesError> {
    let role = match required_string(object, "role", &format!("{field}.role"))? {
        "system" => Role::System,
        "developer" => Role::Developer,
        "user" => Role::User,
        "assistant" => Role::Assistant,
        other => {
            return Err(invalid_value(
                format!("{field}.role"),
                format!("unsupported role `{other}`"),
            ))
        }
    };
    let content = object.get("content").unwrap_or(&Value::Null);
    let content = parse_content(content, role, &format!("{field}.content"), report)?;
    report_unknown_fields(
        object,
        &["type", "role", "content", "id", "status"],
        field,
        report,
    );
    Ok(InputItem::Message(Message {
        id: optional_string(object, "id", &format!("{field}.id"))?,
        role,
        content,
        name: None,
        tool_call_id: None,
        metadata: BTreeMap::new(),
        extensions: Extensions::default(),
    }))
}

fn parse_content(
    value: &Value,
    role: Role,
    field: &str,
    report: &mut ConversionReport,
) -> Result<Vec<ContentPart>, OpenAiResponsesError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(text) = value.as_str() {
        return Ok(vec![ContentPart::text(text)]);
    }
    value
        .as_array()
        .ok_or_else(|| invalid_shape(field, "a string, null, or array"))?
        .iter()
        .enumerate()
        .map(|(index, part)| parse_content_part(part, role, &format!("{field}[{index}]"), report))
        .collect()
}

fn parse_content_part(
    value: &Value,
    _role: Role,
    field: &str,
    report: &mut ConversionReport,
) -> Result<ContentPart, OpenAiResponsesError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    let kind = required_string(object, "type", &format!("{field}.type"))?;
    match kind {
        "input_text" | "output_text" => {
            if let Some(annotations) = object.get("annotations") {
                let annotations = annotations
                    .as_array()
                    .ok_or_else(|| invalid_shape(format!("{field}.annotations"), "an array"))?;
                if !annotations.is_empty() {
                    report.drop_optional(
                        format!("{field}.annotations"),
                        "semantic text parts do not represent OpenAI annotations",
                    );
                }
            }
            report_unknown_fields(object, &["type", "text", "annotations"], field, report);
            Ok(ContentPart::text(required_string(
                object,
                "text",
                &format!("{field}.text"),
            )?))
        }
        "input_image" => {
            report_unknown_fields(
                object,
                &["type", "image_url", "file_id", "detail"],
                field,
                report,
            );
            let source = if let Some(image_url) = object.get("image_url") {
                image_url
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| invalid_shape(format!("{field}.image_url"), "a string"))?
            } else {
                let file_id = required_string(object, "file_id", &format!("{field}.file_id"))?;
                format!("{FILE_ID_SOURCE_PREFIX}{file_id}")
            };
            let mut image = ContentPart::image("image/*", MediaSource::uri(source));
            if let ContentPart::Image { detail, .. } = &mut image {
                *detail = optional_string(object, "detail", &format!("{field}.detail"))?;
            }
            Ok(image)
        }
        "input_file" => {
            report_unknown_fields(
                object,
                &["type", "file_id", "file_url", "file_data", "filename"],
                field,
                report,
            );
            let source = object
                .get("file_id")
                .or_else(|| object.get("file_url"))
                .or_else(|| object.get("file_data"))
                .and_then(Value::as_str)
                .ok_or_else(|| missing(format!("{field}.file_id, file_url, or file_data")))?;
            Ok(ContentPart::file(
                optional_string(object, "filename", &format!("{field}.filename"))?,
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
            report.preserve_capability(format!("openai.responses.content.{other}"));
            Ok(ContentPart::Provider {
                namespace: UNKNOWN_FIELDS_NAMESPACE.to_owned(),
                name: other.to_owned(),
                data: PreservedJson::from_value(value.clone())?,
            })
        }
    }
}

fn parse_function_call(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
) -> Result<InputItem, OpenAiResponsesError> {
    report_unknown_fields(
        object,
        &["type", "id", "call_id", "name", "arguments", "status"],
        field,
        report,
    );
    let call_id = required_string(object, "call_id", &format!("{field}.call_id"))?;
    let name = required_string(object, "name", &format!("{field}.name"))?;
    let arguments = required_string(object, "arguments", &format!("{field}.arguments"))?;
    let arguments = PreservedJson::from_str(arguments)
        .map_err(|error| invalid_value(format!("{field}.arguments"), error.to_string()))?;
    Ok(InputItem::ToolCall(ToolCall::new(call_id, name, arguments)))
}

fn parse_function_output(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
) -> Result<InputItem, OpenAiResponsesError> {
    report_unknown_fields(
        object,
        &["type", "id", "call_id", "output", "status"],
        field,
        report,
    );
    let call_id = required_string(object, "call_id", &format!("{field}.call_id"))?;
    let output = object
        .get("output")
        .ok_or_else(|| missing(format!("{field}.output")))?;
    let content = if let Some(text) = output.as_str() {
        vec![ContentPart::text(text)]
    } else if output.is_array() {
        parse_content(output, Role::Tool, &format!("{field}.output"), report)?
    } else {
        vec![ContentPart::text(serde_json::to_string(output)?)]
    };
    Ok(InputItem::ToolResult(ToolResult {
        tool_call_id: call_id.to_owned(),
        content,
        is_error: false,
        extensions: Extensions::default(),
    }))
}

fn parse_reasoning_item(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
) -> Result<InputItem, OpenAiResponsesError> {
    report_unknown_fields(
        object,
        &["type", "id", "summary", "encrypted_content", "status"],
        field,
        report,
    );
    let summary = parse_summary(object.get("summary"), &format!("{field}.summary"))?;
    let encrypted_content = optional_string(
        object,
        "encrypted_content",
        &format!("{field}.encrypted_content"),
    )?
    .map(String::into_bytes);
    Ok(InputItem::Content(ContentPart::Reasoning(ReasoningBlock {
        id: optional_string(object, "id", &format!("{field}.id"))?,
        text: None,
        summary,
        encrypted_content,
        signature: None,
        extensions: Extensions::default(),
    })))
}

fn parse_summary(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<String>, OpenAiResponsesError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parts = value
        .as_array()
        .ok_or_else(|| invalid_shape(field, "an array"))?;
    let mut text = String::new();
    for (index, part) in parts.iter().enumerate() {
        let object = part
            .as_object()
            .ok_or_else(|| invalid_shape(format!("{field}[{index}]"), "an object"))?;
        let kind = required_string(object, "type", &format!("{field}[{index}].type"))?;
        if kind != "summary_text" {
            return Err(invalid_value(
                format!("{field}[{index}].type"),
                format!("unsupported summary part `{kind}`"),
            ));
        }
        text.push_str(required_string(
            object,
            "text",
            &format!("{field}[{index}].text"),
        )?);
    }
    Ok((!text.is_empty()).then_some(text))
}

fn parse_tools(
    value: &Value,
    report: &mut ConversionReport,
) -> Result<Vec<ToolDefinition>, OpenAiResponsesError> {
    value
        .as_array()
        .ok_or_else(|| invalid_shape("tools", "an array"))?
        .iter()
        .enumerate()
        .map(|(index, tool)| {
            let field = format!("tools[{index}]");
            let object = tool
                .as_object()
                .ok_or_else(|| invalid_shape(&field, "an object"))?;
            let kind = required_string(object, "type", &format!("{field}.type"))?;
            if kind != "function" {
                report.unsupported_required(
                    format!("{field}.type"),
                    "only function tools have a protocol-neutral definition",
                );
                return Ok(ToolDefinition::new(format!("unsupported_{index}"), None));
            }
            report_unknown_fields(
                object,
                &["type", "name", "description", "parameters", "strict"],
                &field,
                report,
            );
            let name = required_string(object, "name", &format!("{field}.name"))?;
            let parameters = object
                .get("parameters")
                .map(|parameters| PreservedJson::from_value(parameters.clone()))
                .transpose()?;
            let mut definition = ToolDefinition::new(name, parameters);
            definition.description =
                optional_string(object, "description", &format!("{field}.description"))?;
            definition.strict = optional_bool(object, "strict", &format!("{field}.strict"))?;
            Ok(definition)
        })
        .collect()
}

fn parse_tool_choice(value: &Value) -> Result<ToolChoice, OpenAiResponsesError> {
    if let Some(choice) = value.as_str() {
        return match choice {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" => Ok(ToolChoice::Required),
            other => Err(invalid_value(
                "tool_choice",
                format!("unsupported choice `{other}`"),
            )),
        };
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape("tool_choice", "a string or object"))?;
    if required_string(object, "type", "tool_choice.type")? != "function" {
        return Err(invalid_value(
            "tool_choice.type",
            "only function choices are supported",
        ));
    }
    Ok(ToolChoice::Tool {
        name: required_string(object, "name", "tool_choice.name")?.to_owned(),
    })
}

fn parse_reasoning(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), OpenAiResponsesError> {
    let Some(value) = object.remove("reasoning") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let reasoning = value
        .as_object()
        .ok_or_else(|| invalid_shape("reasoning", "an object"))?;
    report_unknown_fields(reasoning, &["effort", "summary"], "reasoning", report);
    let effort =
        optional_string(reasoning, "effort", "reasoning.effort")?.map(|effort| {
            match effort.as_str() {
                "low" => ReasoningEffort::Low,
                "medium" => ReasoningEffort::Medium,
                "high" => ReasoningEffort::High,
                "max" => ReasoningEffort::Max,
                other => ReasoningEffort::Custom(other.to_owned()),
            }
        });
    let summary = optional_string(reasoning, "summary", "reasoning.summary")?;
    let mut extensions = Extensions::default();
    if let Some(summary) = summary.as_deref() {
        let extension = OpaqueExtension::new(
            UNKNOWN_FIELDS_NAMESPACE,
            REASONING_SUMMARY_NAME,
            serde_json::to_vec(summary)?,
        )
        .map_err(|_| invalid_extension())?
        .with_media_type("application/json")
        .map_err(|_| invalid_extension())?;
        report.preserve_extension(&extension.key());
        extensions.insert(extension);
    }
    request.reasoning = Some(ReasoningConfig {
        effort,
        include_summary: summary.as_deref().is_some_and(|value| value != "none"),
        extensions,
    });
    Ok(())
}

fn parse_sampling(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), OpenAiResponsesError> {
    request.sampling.temperature = take_f32(object, "temperature")?;
    request.sampling.top_p = take_f32(object, "top_p")?;
    request.sampling.max_output_tokens = take_u32(object, "max_output_tokens")?;
    Ok(())
}

fn parse_text_format(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), OpenAiResponsesError> {
    let Some(value) = object.remove("text") else {
        return Ok(());
    };
    let text = value
        .as_object()
        .ok_or_else(|| invalid_shape("text", "an object"))?;
    report_unknown_fields(text, &["format"], "text", report);
    let Some(format) = text.get("format") else {
        return Ok(());
    };
    let format = format
        .as_object()
        .ok_or_else(|| invalid_shape("text.format", "an object"))?;
    let kind = required_string(format, "type", "text.format.type")?;
    request.response_format = Some(match kind {
        "text" => ResponseFormat::Text,
        "json_object" => ResponseFormat::JsonObject,
        "json_schema" => ResponseFormat::JsonSchema {
            name: required_string(format, "name", "text.format.name")?.to_owned(),
            schema: format
                .get("schema")
                .map(|schema| PreservedJson::from_value(schema.clone()))
                .transpose()?
                .ok_or_else(|| missing("text.format.schema"))?,
            strict: optional_bool(format, "strict", "text.format.strict")?.unwrap_or(false),
        },
        other => {
            return Err(invalid_value(
                "text.format.type",
                format!("unsupported type `{other}`"),
            ))
        }
    });
    Ok(())
}

fn parse_metadata(
    object: &mut Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), OpenAiResponsesError> {
    let Some(value) = object.remove("metadata") else {
        return Ok(());
    };
    let metadata = value
        .as_object()
        .ok_or_else(|| invalid_shape("metadata", "an object"))?;
    request.metadata = metadata
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| invalid_shape(format!("metadata.{key}"), "a string"))
        })
        .collect::<Result<_, _>>()?;
    Ok(())
}

/// Encode a semantic request for OpenAI Responses.
pub fn encode_responses_request(
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<EncodedResponsesRequest, OpenAiResponsesError> {
    request.validate()?;
    let mut report = ConversionReport::default();
    let mut object = preserved_unknown_fields(&request.extensions, &mut report)?;
    object.insert("model".to_owned(), Value::String(request.model.clone()));
    object.insert(
        "input".to_owned(),
        Value::Array(
            request
                .input
                .iter()
                .map(|item| encode_input_item(item, &mut report))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
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
        object.insert("tool_choice".to_owned(), encode_tool_choice(choice));
    }
    if let Some(reasoning) = request.reasoning.as_ref() {
        let mut value = Map::new();
        if let Some(effort) = reasoning.effort.as_ref() {
            value.insert(
                "effort".to_owned(),
                Value::String(reasoning_effort_name(effort)),
            );
        }
        if let Some(summary) = preserved_reasoning_summary(&reasoning.extensions, &mut report)? {
            value.insert("summary".to_owned(), Value::String(summary));
        } else if reasoning.include_summary {
            value.insert("summary".to_owned(), Value::String("auto".to_owned()));
        }
        report_reasoning_extensions(&reasoning.extensions, &mut report);
        object.insert("reasoning".to_owned(), Value::Object(value));
    }
    encode_sampling(request, &mut object, &mut report);
    if let Some(format) = request.response_format.as_ref() {
        object.insert(
            "text".to_owned(),
            serde_json::json!({"format": encode_response_format(format)}),
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
    if let Some(previous) = request.continuation_id.as_ref() {
        object.insert(
            "previous_response_id".to_owned(),
            Value::String(previous.clone()),
        );
    }
    if let Some(cache) = request.cache.as_ref() {
        if let Some(key) = cache.key.as_ref() {
            object.insert("prompt_cache_key".to_owned(), Value::String(key.clone()));
        }
        if cache.allow_prompt_cache || cache.prefer_cache_read {
            report.apply_rule("openai.responses.prompt_cache");
        }
        report_extensions("cache.extensions", &cache.extensions, &mut report);
    }
    if request.target.is_some() {
        report.drop_optional(
            "target",
            "routing target metadata is not part of a Responses request",
        );
    }
    if request.session_id.is_some() {
        report.drop_optional("session_id", "Responses has no portable session field");
    }
    report.validate(policy)?;
    Ok(EncodedResponsesRequest {
        body: serde_json::to_vec(&Value::Object(object))?,
        report,
    })
}

fn encode_input_item(
    item: &InputItem,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    match item {
        InputItem::Message(message) => encode_message(message, report),
        InputItem::ToolCall(call) => encode_tool_call(call, report),
        InputItem::ToolResult(result) => encode_tool_result(result, report),
        InputItem::Content(part) => match part {
            ContentPart::Reasoning(reasoning) => encode_reasoning_item(reasoning, report),
            _ => Ok(serde_json::json!({
                "role":"user",
                "content":[encode_content_part(part, Role::User, report)?]
            })),
        },
        InputItem::Provider {
            namespace,
            name,
            data,
        } if namespace == UNKNOWN_FIELDS_NAMESPACE => {
            report.preserve_capability(format!("openai.responses.input.{name}"));
            Ok(data.value().clone())
        }
        InputItem::Provider {
            namespace, name, ..
        } => {
            report.unsupported_required(
                format!("input.provider.{namespace}.{name}"),
                "provider item has no Responses representation",
            );
            Ok(Value::Null)
        }
    }
}

fn encode_message(
    message: &Message,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    if !message.metadata.is_empty() {
        report.drop_optional(
            "message.metadata",
            "Responses has no per-message metadata field",
        );
    }
    report_extensions("message.extensions", &message.extensions, report);
    if message.tool_call_id.is_some() {
        report.unsupported_required(
            "message.tool_call_id",
            "tool results must be standalone function_call_output items",
        );
    }
    let role = match message.role {
        Role::System => "system",
        Role::Developer => "developer",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => {
            let call_id = message.tool_call_id.as_deref().ok_or_else(|| {
                invalid_value("message.tool_call_id", "tool messages require a call ID")
            })?;
            return encode_tool_result(
                &ToolResult {
                    tool_call_id: call_id.to_owned(),
                    content: message.content.clone(),
                    is_error: false,
                    extensions: Extensions::default(),
                },
                report,
            );
        }
    };
    let mut object = Map::new();
    object.insert("role".to_owned(), Value::String(role.to_owned()));
    object.insert(
        "content".to_owned(),
        Value::Array(
            message
                .content
                .iter()
                .map(|part| encode_content_part(part, message.role, report))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    if let Some(id) = message.id.as_ref() {
        object.insert("id".to_owned(), Value::String(id.clone()));
    }
    if message.name.is_some() {
        report.drop_optional(
            "message.name",
            "Responses messages have no portable name field",
        );
    }
    Ok(Value::Object(object))
}

fn encode_content_part(
    part: &ContentPart,
    role: Role,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    match part {
        ContentPart::Text { text } => Ok(serde_json::json!({
            "type": if role == Role::Assistant {"output_text"} else {"input_text"},
            "text": text
        })),
        ContentPart::Image {
            media_type,
            source,
            detail,
        } => {
            let mut value = match source {
                MediaSource::Uri(source) if source.starts_with(FILE_ID_SOURCE_PREFIX) => {
                    let file_id = source
                        .strip_prefix(FILE_ID_SOURCE_PREFIX)
                        .expect("file ID source prefix was checked");
                    serde_json::json!({"type":"input_image","file_id":file_id})
                }
                _ => serde_json::json!({
                    "type":"input_image",
                    "image_url":encode_media_source(media_type, source)
                }),
            };
            if let Some(detail) = detail {
                value["detail"] = Value::String(detail.clone());
            }
            Ok(value)
        }
        ContentPart::File {
            name,
            media_type,
            source,
        } => {
            let mut value = Map::new();
            value.insert("type".to_owned(), Value::String("input_file".to_owned()));
            match source {
                MediaSource::Uri(uri) if uri.starts_with("file-") => {
                    value.insert("file_id".to_owned(), Value::String(uri.clone()));
                }
                MediaSource::Uri(uri)
                    if uri.starts_with("http://") || uri.starts_with("https://") =>
                {
                    value.insert("file_url".to_owned(), Value::String(uri.clone()));
                }
                _ => {
                    value.insert(
                        "file_data".to_owned(),
                        Value::String(encode_media_source(media_type, source)),
                    );
                }
            }
            if let Some(name) = name {
                value.insert("filename".to_owned(), Value::String(name.clone()));
            }
            Ok(Value::Object(value))
        }
        ContentPart::Reasoning(reasoning) => encode_reasoning_item(reasoning, report),
        ContentPart::ToolCall(call) => encode_tool_call(call, report),
        ContentPart::ToolResult(result) => encode_tool_result(result, report),
        ContentPart::Audio { .. } => {
            report.unsupported_required(
                "input.audio",
                "Responses audio input is not implemented by this codec",
            );
            Ok(Value::Null)
        }
        ContentPart::Provider {
            namespace,
            name,
            data,
        } if namespace == UNKNOWN_FIELDS_NAMESPACE => {
            report.preserve_capability(format!("openai.responses.content.{name}"));
            Ok(data.value().clone())
        }
        ContentPart::Provider {
            namespace, name, ..
        } => {
            report.unsupported_required(
                format!("content.provider.{namespace}.{name}"),
                "provider content has no Responses representation",
            );
            Ok(Value::Null)
        }
    }
}

fn encode_tool_call(
    call: &ToolCall,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    if !call.dependencies.is_empty() {
        report.unsupported_required(
            "tool_call.dependencies",
            "Responses function calls have no dependency field",
        );
    }
    report_extensions("tool_call.extensions", &call.extensions, report);
    Ok(serde_json::json!({
        "type":"function_call",
        "call_id":call.id,
        "name":call.name,
        "arguments":String::from_utf8_lossy(&call.arguments.to_bytes())
    }))
}

fn encode_tool_result(
    result: &ToolResult,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    report_extensions("tool_result.extensions", &result.extensions, report);
    if result.is_error {
        report.drop_optional(
            "tool_result.is_error",
            "Responses function_call_output has no standard error flag",
        );
    }
    let output = if result.content.len() == 1 {
        match &result.content[0] {
            ContentPart::Text { text } => Value::String(text.clone()),
            part => Value::Array(vec![encode_content_part(part, Role::Tool, report)?]),
        }
    } else {
        Value::Array(
            result
                .content
                .iter()
                .map(|part| encode_content_part(part, Role::Tool, report))
                .collect::<Result<Vec<_>, _>>()?,
        )
    };
    Ok(serde_json::json!({
        "type":"function_call_output",
        "call_id":result.tool_call_id,
        "output":output
    }))
}

fn encode_reasoning_item(
    reasoning: &ReasoningBlock,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    if reasoning.text.is_some() {
        report.drop_optional(
            "reasoning.text",
            "Responses input reasoning items accept summary or encrypted content",
        );
    }
    if reasoning.signature.is_some() {
        report.unsupported_required(
            "reasoning.signature",
            "Responses reasoning items have no signature field",
        );
    }
    report_extensions("reasoning.extensions", &reasoning.extensions, report);
    let mut value = Map::new();
    value.insert("type".to_owned(), Value::String("reasoning".to_owned()));
    if let Some(id) = reasoning.id.as_ref() {
        value.insert("id".to_owned(), Value::String(id.clone()));
    }
    value.insert(
        "summary".to_owned(),
        reasoning.summary.as_ref().map_or_else(
            || Value::Array(Vec::new()),
            |summary| {
                Value::Array(vec![serde_json::json!({
                    "type":"summary_text",
                    "text":summary
                })])
            },
        ),
    );
    if let Some(encrypted) = reasoning.encrypted_content.as_ref() {
        value.insert(
            "encrypted_content".to_owned(),
            Value::String(String::from_utf8_lossy(encrypted).into_owned()),
        );
    }
    Ok(Value::Object(value))
}

fn encode_tool(
    tool: &ToolDefinition,
    report: &mut ConversionReport,
) -> Result<Value, OpenAiResponsesError> {
    report_extensions("tool.extensions", &tool.extensions, report);
    let mut value = Map::new();
    value.insert("type".to_owned(), Value::String("function".to_owned()));
    value.insert("name".to_owned(), Value::String(tool.name.clone()));
    if let Some(description) = tool.description.as_ref() {
        value.insert("description".to_owned(), Value::String(description.clone()));
    }
    if let Some(parameters) = tool.parameters.as_ref() {
        value.insert("parameters".to_owned(), parameters.value().clone());
    }
    if let Some(strict) = tool.strict {
        value.insert("strict".to_owned(), Value::Bool(strict));
    }
    Ok(Value::Object(value))
}

fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => Value::String("auto".to_owned()),
        ToolChoice::None => Value::String("none".to_owned()),
        ToolChoice::Required => Value::String("required".to_owned()),
        ToolChoice::Tool { name } => serde_json::json!({"type":"function","name":name}),
    }
}

fn encode_sampling(
    request: &SemanticRequest,
    object: &mut Map<String, Value>,
    report: &mut ConversionReport,
) {
    let sampling = &request.sampling;
    if let Some(value) = sampling.temperature {
        object.insert("temperature".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = sampling.top_p {
        object.insert("top_p".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = sampling.max_output_tokens {
        object.insert("max_output_tokens".to_owned(), serde_json::json!(value));
    }
    if !sampling.stop.is_empty() {
        report.drop_optional("sampling.stop", "Responses has no portable stop field");
    }
    if sampling.seed.is_some() {
        report.drop_optional("sampling.seed", "Responses has no portable seed field");
    }
    if sampling.presence_penalty.is_some() {
        report.drop_optional(
            "sampling.presence_penalty",
            "Responses has no portable presence penalty field",
        );
    }
    if sampling.frequency_penalty.is_some() {
        report.drop_optional(
            "sampling.frequency_penalty",
            "Responses has no portable frequency penalty field",
        );
    }
    report_extensions("sampling.extensions", &sampling.extensions, report);
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
            "name":name,
            "schema":schema.value(),
            "strict":strict
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

fn preserve_unknown_fields(
    request: &mut SemanticRequest,
    fields: Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), OpenAiResponsesError> {
    let extension = OpaqueExtension::new(
        UNKNOWN_FIELDS_NAMESPACE,
        UNKNOWN_FIELDS_NAME,
        serde_json::to_vec(&Value::Object(fields))?,
    )
    .map_err(|_| invalid_extension())?
    .with_media_type("application/json")
    .map_err(|_| invalid_extension())?;
    report.preserve_extension(&extension.key());
    request.extensions.insert(extension);
    Ok(())
}

fn preserved_unknown_fields(
    extensions: &Extensions,
    report: &mut ConversionReport,
) -> Result<Map<String, Value>, OpenAiResponsesError> {
    let mut object = Map::new();
    for (key, extension) in extensions {
        if key.as_str() != OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION {
            report.unsupported_required(
                format!("extension.{key}"),
                "Responses cannot serialize this semantic extension",
            );
            continue;
        }
        let value: Value = serde_json::from_slice(extension.as_bytes())?;
        let fields = value.as_object().ok_or_else(invalid_extension)?;
        object.extend(fields.clone());
        report.preserve_extension(key);
    }
    Ok(object)
}

fn report_extensions(field: &str, extensions: &Extensions, report: &mut ConversionReport) {
    if !extensions.is_empty() {
        report.unsupported_required(
            field,
            "Responses has no representation for this provider-specific state",
        );
    }
}

fn preserved_reasoning_summary(
    extensions: &Extensions,
    report: &mut ConversionReport,
) -> Result<Option<String>, OpenAiResponsesError> {
    let Some(extension) = extensions.get_str(OPENAI_RESPONSES_REASONING_SUMMARY_EXTENSION) else {
        return Ok(None);
    };
    let summary: String = serde_json::from_slice(extension.as_bytes())?;
    report.preserve_extension(&extension.key());
    Ok(Some(summary))
}

fn report_reasoning_extensions(extensions: &Extensions, report: &mut ConversionReport) {
    for (key, _) in extensions {
        if key.as_str() != OPENAI_RESPONSES_REASONING_SUMMARY_EXTENSION {
            report.unsupported_required(
                format!("reasoning.extensions.{key}"),
                "Responses has no representation for this provider-specific state",
            );
        }
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
                "Responses item field is not represented by the semantic model",
            );
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

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
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

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, OpenAiResponsesError> {
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
) -> Result<Option<String>, OpenAiResponsesError> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid_shape(field, "a string or null"))
        })
        .transpose()
}

fn take_string(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<String>, OpenAiResponsesError> {
    object
        .remove(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid_shape(key, "a string or null"))
        })
        .transpose()
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<bool>, OpenAiResponsesError> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid_shape(field, "a boolean or null"))
        })
        .transpose()
}

fn take_f32(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<f32>, OpenAiResponsesError> {
    object
        .remove(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_f64()
                .map(|number| number as f32)
                .ok_or_else(|| invalid_shape(key, "a number or null"))
        })
        .transpose()
}

fn take_u32(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<u32>, OpenAiResponsesError> {
    object
        .remove(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or_else(|| invalid_shape(key, "an unsigned 32-bit integer or null"))
        })
        .transpose()
}

fn missing(field: impl Into<String>) -> OpenAiResponsesError {
    OpenAiResponsesError::MissingField {
        field: field.into(),
    }
}

fn invalid_shape(field: impl Into<String>, expected: &'static str) -> OpenAiResponsesError {
    OpenAiResponsesError::InvalidShape {
        field: field.into(),
        expected,
    }
}

fn invalid_value(field: impl Into<String>, message: impl Into<String>) -> OpenAiResponsesError {
    OpenAiResponsesError::InvalidValue {
        field: field.into(),
        message: message.into(),
    }
}

fn invalid_extension() -> OpenAiResponsesError {
    OpenAiResponsesError::InvalidExtension {
        key: OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION.to_owned(),
    }
}

#[derive(Clone, Debug, Default)]
struct DecodedReasoningItem {
    open: bool,
    summary: String,
}

#[derive(Clone, Debug)]
struct DecodedFunctionItem {
    call_id: String,
    arguments: String,
    open: bool,
}

/// Stateful decoder for named OpenAI Responses SSE events.
#[derive(Clone, Debug, Default)]
pub struct OpenAiResponsesEventDecoder {
    next_sequence: u64,
    response_id: Option<String>,
    model: Option<String>,
    response_started: bool,
    text_items: BTreeMap<String, bool>,
    reasoning_items: BTreeMap<String, DecodedReasoningItem>,
    function_items: BTreeMap<String, DecodedFunctionItem>,
    saw_tool_call: bool,
    completed: bool,
}

impl OpenAiResponsesEventDecoder {
    /// Creates an empty decoder for one response stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode one Responses event using the optional SSE event name.
    pub fn decode_event(
        &mut self,
        event_name: Option<&str>,
        input: &[u8],
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        if input == b"[DONE]" {
            if self.completed {
                return Ok(Vec::new());
            }
            return Err(OpenAiResponsesError::InvalidStream {
                message: "[DONE] appeared before a terminal Responses event".to_owned(),
            });
        }
        if self.completed {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "event appeared after completion".to_owned(),
            });
        }
        let value: Value = serde_json::from_slice(input)?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid_shape("event", "an object"))?;
        let kind = required_string(object, "type", "event.type")?;
        if event_name.is_some_and(|event_name| event_name != kind) {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "SSE event name does not match the JSON event type".to_owned(),
            });
        }
        match kind {
            "response.created" | "response.in_progress" => self.decode_response_start(object),
            "response.output_item.added" => self.decode_output_item_added(object),
            "response.content_part.added" => self.decode_content_part_added(object),
            "response.output_text.delta" => self.decode_text_delta(object),
            "response.output_text.done" => Ok(Vec::new()),
            "response.content_part.done" => self.decode_content_part_done(object),
            "response.reasoning_summary_part.added" => self.decode_reasoning_part_added(object),
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                self.decode_reasoning_delta(object)
            }
            "response.reasoning_summary_text.done"
            | "response.reasoning_text.done"
            | "response.reasoning_summary_part.done" => Ok(Vec::new()),
            "response.function_call_arguments.delta" => self.decode_function_delta(object),
            "response.function_call_arguments.done" => self.decode_function_done(object),
            "response.refusal.delta" => self.decode_refusal_delta(object),
            "response.refusal.done" => Ok(Vec::new()),
            "response.output_item.done" => self.decode_output_item_done(object),
            "response.completed" => self.decode_completed(object, false),
            "response.incomplete" => self.decode_completed(object, true),
            "response.failed" => self.decode_failed(object),
            "error" => self.decode_error(object),
            "response.queued" => Ok(Vec::new()),
            other => Err(OpenAiResponsesError::InvalidStream {
                message: format!("unsupported Responses event `{other}`"),
            }),
        }
    }

    /// Decode an event when only its JSON data field is available.
    pub fn decode_data(&mut self, input: &[u8]) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        self.decode_event(None, input)
    }

    /// Finish a Responses stream at transport EOF.
    pub fn finish(&mut self) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        if !self.completed {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "stream ended without response.completed, response.incomplete, or response.failed"
                    .to_owned(),
            });
        }
        Ok(Vec::new())
    }

    fn decode_response_start(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let response = response_object(object)?;
        self.observe_response_identity(response)?;
        if self.response_started {
            return Ok(Vec::new());
        }
        self.response_started = true;
        let response_id = self.response_id.clone();
        let model = self.model.clone();
        Ok(vec![self.event(
            StreamEventKind::response_start(response_id, model),
            None,
        )])
    }

    fn observe_response_identity(
        &mut self,
        response: &Map<String, Value>,
    ) -> Result<(), OpenAiResponsesError> {
        if let Some(id) = optional_string(response, "id", "response.id")? {
            if self
                .response_id
                .as_ref()
                .is_some_and(|previous| previous != &id)
            {
                return Err(OpenAiResponsesError::InvalidStream {
                    message: "response ID changed within one stream".to_owned(),
                });
            }
            self.response_id = Some(id);
        }
        if let Some(model) = optional_string(response, "model", "response.model")? {
            if self
                .model
                .as_ref()
                .is_some_and(|previous| previous != &model)
            {
                return Err(OpenAiResponsesError::InvalidStream {
                    message: "model changed within one stream".to_owned(),
                });
            }
            self.model = Some(model);
        }
        Ok(())
    }

    fn ensure_response_start(&mut self) -> Vec<StreamEvent> {
        if self.response_started {
            return Vec::new();
        }
        self.response_started = true;
        let response_id = self.response_id.clone();
        let model = self.model.clone();
        vec![self.event(StreamEventKind::response_start(response_id, model), None)]
    }

    fn decode_output_item_added(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item = item_object(object)?;
        let item_id = required_string(item, "id", "event.item.id")?.to_owned();
        let kind = required_string(item, "type", "event.item.type")?;
        let mut events = self.ensure_response_start();
        match kind {
            "message" => {
                self.text_items.entry(item_id).or_insert(false);
            }
            "reasoning" => {
                let state = self.reasoning_items.entry(item_id.clone()).or_default();
                if !state.open {
                    state.open = true;
                    events.push(self.event(StreamEventKind::ReasoningStart, Some(&item_id)));
                }
            }
            "function_call" => {
                let call_id = required_string(item, "call_id", "event.item.call_id")?.to_owned();
                let name = required_string(item, "name", "event.item.name")?.to_owned();
                if self.function_items.contains_key(&item_id) {
                    return Err(OpenAiResponsesError::InvalidStream {
                        message: "function-call output item started more than once".to_owned(),
                    });
                }
                self.function_items.insert(
                    item_id,
                    DecodedFunctionItem {
                        call_id: call_id.clone(),
                        arguments: String::new(),
                        open: true,
                    },
                );
                self.saw_tool_call = true;
                events.push(self.event(
                    StreamEventKind::ToolCallStart {
                        id: call_id.clone(),
                        name,
                    },
                    Some(&call_id),
                ));
            }
            _ => {}
        }
        Ok(events)
    }

    fn decode_content_part_added(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let part = object
            .get("part")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("event.part", "an object"))?;
        if required_string(part, "type", "event.part.type")? != "output_text" {
            return Ok(Vec::new());
        }
        let item_id = required_string(object, "item_id", "event.item_id")?.to_owned();
        self.open_text(&item_id)
    }

    fn open_text(&mut self, item_id: &str) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let open = self.text_items.entry(item_id.to_owned()).or_insert(false);
        if *open {
            return Ok(Vec::new());
        }
        *open = true;
        Ok(vec![self.event(StreamEventKind::TextStart, Some(item_id))])
    }

    fn decode_text_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item_id = required_string(object, "item_id", "event.item_id")?.to_owned();
        let delta = required_string(object, "delta", "event.delta")?.to_owned();
        let mut events = self.open_text(&item_id)?;
        if !delta.is_empty() {
            events.push(self.event(StreamEventKind::text_delta(delta), Some(&item_id)));
        }
        Ok(events)
    }

    fn decode_content_part_done(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let part = object
            .get("part")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("event.part", "an object"))?;
        let kind = required_string(part, "type", "event.part.type")?;
        if kind == "refusal" {
            let text = required_string(part, "refusal", "event.part.refusal")?;
            return Ok((!text.is_empty())
                .then(|| {
                    self.event(
                        StreamEventKind::Refusal {
                            text: text.to_owned(),
                        },
                        None,
                    )
                })
                .into_iter()
                .collect());
        }
        if kind != "output_text" {
            return Ok(Vec::new());
        }
        let item_id = required_string(object, "item_id", "event.item_id")?.to_owned();
        self.close_text(&item_id)
    }

    fn close_text(&mut self, item_id: &str) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let Some(open) = self.text_items.get_mut(item_id) else {
            return Ok(Vec::new());
        };
        if !*open {
            return Ok(Vec::new());
        }
        *open = false;
        Ok(vec![self.event(StreamEventKind::TextEnd, Some(item_id))])
    }

    fn decode_reasoning_part_added(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item_id = required_string(object, "item_id", "event.item_id")?.to_owned();
        self.open_reasoning(&item_id)
    }

    fn open_reasoning(&mut self, item_id: &str) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let state = self.reasoning_items.entry(item_id.to_owned()).or_default();
        if state.open {
            return Ok(Vec::new());
        }
        state.open = true;
        Ok(vec![
            self.event(StreamEventKind::ReasoningStart, Some(item_id))
        ])
    }

    fn decode_reasoning_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item_id = required_string(object, "item_id", "event.item_id")?.to_owned();
        let delta = required_string(object, "delta", "event.delta")?.to_owned();
        let mut events = self.open_reasoning(&item_id)?;
        if !delta.is_empty() {
            self.reasoning_items
                .get_mut(&item_id)
                .expect("reasoning item was opened")
                .summary
                .push_str(&delta);
            events.push(self.event(StreamEventKind::reasoning_delta(delta), Some(&item_id)));
        }
        Ok(events)
    }

    fn decode_function_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item_id = required_string(object, "item_id", "event.item_id")?;
        let delta = required_string(object, "delta", "event.delta")?.to_owned();
        let state = self.function_items.get_mut(item_id).ok_or_else(|| {
            OpenAiResponsesError::InvalidStream {
                message: "function arguments appeared before output_item.added".to_owned(),
            }
        })?;
        if !state.open {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "function arguments appeared after output_item.done".to_owned(),
            });
        }
        state.arguments.push_str(&delta);
        let call_id = state.call_id.clone();
        Ok((!delta.is_empty())
            .then(|| {
                self.event(
                    StreamEventKind::ToolCallDelta {
                        id: call_id.clone(),
                        arguments: delta,
                    },
                    Some(&call_id),
                )
            })
            .into_iter()
            .collect())
    }

    fn decode_function_done(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item_id = required_string(object, "item_id", "event.item_id")?;
        let arguments = required_string(object, "arguments", "event.arguments")?;
        let state = self.function_items.get_mut(item_id).ok_or_else(|| {
            OpenAiResponsesError::InvalidStream {
                message: "function arguments completed before output_item.added".to_owned(),
            }
        })?;
        if state.arguments.is_empty() && !arguments.is_empty() {
            state.arguments.push_str(arguments);
            let call_id = state.call_id.clone();
            return Ok(vec![self.event(
                StreamEventKind::ToolCallDelta {
                    id: call_id.clone(),
                    arguments: arguments.to_owned(),
                },
                Some(&call_id),
            )]);
        }
        if state.arguments != arguments {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "function arguments done value did not match streamed deltas".to_owned(),
            });
        }
        Ok(Vec::new())
    }

    fn decode_refusal_delta(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let delta = required_string(object, "delta", "event.delta")?;
        Ok((!delta.is_empty())
            .then(|| {
                self.event(
                    StreamEventKind::Refusal {
                        text: delta.to_owned(),
                    },
                    None,
                )
            })
            .into_iter()
            .collect())
    }

    fn decode_output_item_done(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let item = item_object(object)?;
        let item_id = required_string(item, "id", "event.item.id")?.to_owned();
        match required_string(item, "type", "event.item.type")? {
            "message" => {
                reject_nonempty_message_annotations(item)?;
                self.close_text(&item_id)
            }
            "reasoning" => self.close_reasoning(&item_id, item),
            "function_call" => self.close_function(&item_id, item),
            _ => Ok(Vec::new()),
        }
    }

    fn close_reasoning(
        &mut self,
        item_id: &str,
        item: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let streamed_summary = self
            .reasoning_items
            .get(item_id)
            .map(|state| state.summary.clone())
            .unwrap_or_default();
        let final_summary = parse_summary(item.get("summary"), "event.item.summary")?;
        if !streamed_summary.is_empty()
            && final_summary
                .as_ref()
                .is_some_and(|summary| summary != &streamed_summary)
        {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "reasoning summary did not match streamed deltas".to_owned(),
            });
        }
        let encrypted_content =
            optional_string(item, "encrypted_content", "event.item.encrypted_content")?
                .map(String::into_bytes);
        let mut events = self.open_reasoning(item_id)?;
        if let Some(state) = self.reasoning_items.get_mut(item_id) {
            state.open = false;
        }
        events.push(self.event(
            StreamEventKind::ReasoningEnd {
                reasoning: Some(
                    ReasoningBlock {
                        id: Some(item_id.to_owned()),
                        text: None,
                        summary:
                            final_summary.or_else(|| {
                                (!streamed_summary.is_empty()).then_some(streamed_summary)
                            }),
                        encrypted_content,
                        signature: None,
                        extensions: Extensions::default(),
                    },
                ),
            },
            Some(item_id),
        ));
        Ok(events)
    }

    fn close_function(
        &mut self,
        item_id: &str,
        item: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let final_arguments = required_string(item, "arguments", "event.item.arguments")?;
        let Some(state) = self.function_items.get_mut(item_id) else {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "function output item ended before it started".to_owned(),
            });
        };
        if !state.open {
            return Ok(Vec::new());
        }
        let mut delta = None;
        if state.arguments.is_empty() && !final_arguments.is_empty() {
            state.arguments.push_str(final_arguments);
            delta = Some(final_arguments.to_owned());
        } else if state.arguments != final_arguments {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "final function arguments did not match streamed deltas".to_owned(),
            });
        }
        state.open = false;
        let call_id = state.call_id.clone();
        let mut events = Vec::new();
        if let Some(arguments) = delta {
            events.push(self.event(
                StreamEventKind::ToolCallDelta {
                    id: call_id.clone(),
                    arguments,
                },
                Some(&call_id),
            ));
        }
        events.push(self.event(
            StreamEventKind::ToolCallEnd {
                id: call_id.clone(),
            },
            Some(&call_id),
        ));
        Ok(events)
    }

    fn decode_completed(
        &mut self,
        object: &Map<String, Value>,
        incomplete: bool,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let response = response_object(object)?;
        self.observe_response_identity(response)?;
        let mut events = self.ensure_response_start();
        events.extend(self.close_all_open()?);
        let usage = response
            .get("usage")
            .filter(|usage| !usage.is_null())
            .map(parse_responses_usage)
            .transpose()?;
        let finish_reason = if incomplete {
            FinishReason::Length
        } else if self.saw_tool_call {
            FinishReason::ToolCall
        } else {
            FinishReason::Stop
        };
        if let Some(usage) = usage.clone() {
            events.push(self.event(StreamEventKind::Usage { usage }, None));
        }
        events.push(self.event(StreamEventKind::completion(finish_reason, usage), None));
        self.completed = true;
        Ok(events)
    }

    fn close_all_open(&mut self) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let mut events = Vec::new();
        let text_ids = self
            .text_items
            .iter()
            .filter_map(|(id, open)| open.then_some(id.clone()))
            .collect::<Vec<_>>();
        for id in text_ids {
            events.extend(self.close_text(&id)?);
        }
        let reasoning_ids = self
            .reasoning_items
            .iter()
            .filter_map(|(id, state)| state.open.then_some(id.clone()))
            .collect::<Vec<_>>();
        for id in reasoning_ids {
            let summary = self
                .reasoning_items
                .get(&id)
                .map(|state| state.summary.clone())
                .unwrap_or_default();
            self.reasoning_items
                .get_mut(&id)
                .expect("reasoning item exists")
                .open = false;
            events.push(self.event(
                StreamEventKind::ReasoningEnd {
                    reasoning: Some(ReasoningBlock {
                        id: Some(id.clone()),
                        summary: (!summary.is_empty()).then_some(summary),
                        ..ReasoningBlock::default()
                    }),
                },
                Some(&id),
            ));
        }
        let function_ids = self
            .function_items
            .iter()
            .filter_map(|(id, state)| state.open.then_some(id.clone()))
            .collect::<Vec<_>>();
        for item_id in function_ids {
            let state = self
                .function_items
                .get_mut(&item_id)
                .expect("function item exists");
            state.open = false;
            let call_id = state.call_id.clone();
            events.push(self.event(
                StreamEventKind::ToolCallEnd {
                    id: call_id.clone(),
                },
                Some(&call_id),
            ));
        }
        Ok(events)
    }

    fn decode_failed(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let response = response_object(object)?;
        self.observe_response_identity(response)?;
        let error = response
            .get("error")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_shape("response.error", "an object"))?;
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("openai_error");
        let message = required_string(error, "message", "response.error.message")?;
        let mut events = self.ensure_response_start();
        events.push(self.event(
            StreamEventKind::Failure {
                error: StreamError::new(code, message),
            },
            None,
        ));
        self.completed = true;
        Ok(events)
    }

    fn decode_error(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Vec<StreamEvent>, OpenAiResponsesError> {
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .unwrap_or(object);
        let code = error
            .get("code")
            .or_else(|| error.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("openai_error");
        let message = required_string(error, "message", "error.message")?;
        self.completed = true;
        Ok(vec![self.event(
            StreamEventKind::Failure {
                error: StreamError::new(code, message),
            },
            None,
        )])
    }

    fn event(&mut self, kind: StreamEventKind, block_id: Option<&str>) -> StreamEvent {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event = StreamEvent::new(self.next_sequence, kind);
        block_id.map_or(event.clone(), |block_id| event.with_block_id(block_id))
    }
}

fn reject_nonempty_message_annotations(
    item: &Map<String, Value>,
) -> Result<(), OpenAiResponsesError> {
    let Some(content) = item.get("content") else {
        return Ok(());
    };
    let content = content
        .as_array()
        .ok_or_else(|| invalid_shape("event.item.content", "an array"))?;
    for (index, part) in content.iter().enumerate() {
        let Some(annotations) = part.get("annotations") else {
            continue;
        };
        let annotations = annotations.as_array().ok_or_else(|| {
            invalid_shape(
                format!("event.item.content[{index}].annotations"),
                "an array",
            )
        })?;
        if !annotations.is_empty() {
            return Err(OpenAiResponsesError::InvalidStream {
                message: "output text annotations are not represented by semantic events"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn response_object(
    event: &Map<String, Value>,
) -> Result<&Map<String, Value>, OpenAiResponsesError> {
    event
        .get("response")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_shape("event.response", "an object"))
}

fn item_object(event: &Map<String, Value>) -> Result<&Map<String, Value>, OpenAiResponsesError> {
    event
        .get("item")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_shape("event.item", "an object"))
}

fn parse_responses_usage(value: &Value) -> Result<Usage, OpenAiResponsesError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_shape("response.usage", "an object"))?;
    let input_tokens = usage_count(object, "input_tokens")?.unwrap_or(0);
    let output_tokens = usage_count(object, "output_tokens")?.unwrap_or(0);
    let reasoning_tokens = object
        .get("output_tokens_details")
        .and_then(Value::as_object)
        .map(|details| usage_count(details, "reasoning_tokens"))
        .transpose()?
        .flatten();
    let cached_input_tokens = object
        .get("input_tokens_details")
        .and_then(Value::as_object)
        .map(|details| usage_count(details, "cached_tokens"))
        .transpose()?
        .flatten();
    Ok(Usage {
        input_tokens,
        output_tokens,
        reasoning_tokens,
        cached_input_tokens,
        total_tokens: usage_count(object, "total_tokens")?,
        details: BTreeMap::new(),
    })
}

fn usage_count(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, OpenAiResponsesError> {
    object
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| invalid_shape(format!("usage.{field}"), "an unsigned integer"))
        })
        .transpose()
}

#[derive(Clone, Debug)]
struct EncodedTextItem {
    id: String,
    output_index: u64,
    text: String,
}

#[derive(Clone, Debug)]
struct EncodedReasoningItem {
    id: String,
    output_index: u64,
    summary: String,
}

#[derive(Clone, Debug)]
struct EncodedFunctionItem {
    item_id: String,
    output_index: u64,
    name: String,
    arguments: String,
}

/// Stateful encoder for named OpenAI Responses SSE events.
#[derive(Clone, Debug)]
pub struct OpenAiResponsesEventEncoder {
    response_id: String,
    model: String,
    next_sequence: u64,
    next_output_index: u64,
    response_started: bool,
    completed: bool,
    text: Option<EncodedTextItem>,
    reasoning: Option<EncodedReasoningItem>,
    functions: BTreeMap<String, EncodedFunctionItem>,
    output: Vec<Value>,
    pending_usage: Option<Usage>,
    metadata: BTreeMap<String, String>,
}

impl Default for OpenAiResponsesEventEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiResponsesEventEncoder {
    /// Creates an encoder with deterministic fallback response metadata.
    #[must_use]
    pub fn new() -> Self {
        Self {
            response_id: DEFAULT_RESPONSE_ID.to_owned(),
            model: String::new(),
            next_sequence: 0,
            next_output_index: 0,
            response_started: false,
            completed: false,
            text: None,
            reasoning: None,
            functions: BTreeMap::new(),
            output: Vec::new(),
            pending_usage: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Encode one semantic event into zero or more named Responses events.
    pub fn encode_event(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<Vec<EncodedResponsesEvent>, OpenAiResponsesError> {
        if self.completed {
            return Err(OpenAiResponsesError::UnsupportedEvent {
                message: "event appeared after completion".to_owned(),
            });
        }
        let mut report = ConversionReport::default();
        let mut values = Vec::new();
        match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                if self.response_started {
                    return Err(OpenAiResponsesError::UnsupportedEvent {
                        message: "response start appeared more than once".to_owned(),
                    });
                }
                if let Some(response_id) = response_id {
                    self.response_id = response_id.clone();
                }
                if let Some(model) = model {
                    self.model = model.clone();
                }
                self.response_started = true;
                values.push((
                    "response.created",
                    serde_json::json!({"response":self.response_value("in_progress", None, None, None)}),
                ));
                values.push((
                    "response.in_progress",
                    serde_json::json!({"response":self.response_value("in_progress", None, None, None)}),
                ));
            }
            StreamEventKind::TextStart => {
                values.extend(self.start_text(event.effective_block_id())?);
            }
            StreamEventKind::TextDelta { text } => {
                if self.text.is_none() {
                    values.extend(self.start_text(event.effective_block_id())?);
                }
                let state = self.text.as_mut().expect("text item was started");
                state.text.push_str(text);
                values.push((
                    "response.output_text.delta",
                    serde_json::json!({
                        "item_id":state.id,
                        "output_index":state.output_index,
                        "content_index":0,
                        "delta":text,
                        "logprobs":[]
                    }),
                ));
            }
            StreamEventKind::TextEnd => {
                values.extend(self.finish_text()?);
            }
            StreamEventKind::ReasoningStart => {
                values.extend(self.start_reasoning(event.effective_block_id())?);
            }
            StreamEventKind::ReasoningDelta { text } => {
                if self.reasoning.is_none() {
                    values.extend(self.start_reasoning(event.effective_block_id())?);
                }
                let state = self.reasoning.as_mut().expect("reasoning item was started");
                state.summary.push_str(text);
                values.push((
                    "response.reasoning_summary_text.delta",
                    serde_json::json!({
                        "item_id":state.id,
                        "output_index":state.output_index,
                        "summary_index":0,
                        "delta":text
                    }),
                ));
            }
            StreamEventKind::ReasoningEnd { reasoning } => {
                values.extend(self.finish_reasoning(reasoning.as_ref())?);
            }
            StreamEventKind::ToolCallStart { id, name } => {
                values.extend(self.start_function(id, name)?);
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                let state = self.functions.get_mut(id).ok_or_else(|| {
                    OpenAiResponsesError::UnsupportedEvent {
                        message: format!("tool call `{id}` has no start event"),
                    }
                })?;
                state.arguments.push_str(arguments);
                values.push((
                    "response.function_call_arguments.delta",
                    serde_json::json!({
                        "item_id":state.item_id,
                        "output_index":state.output_index,
                        "delta":arguments
                    }),
                ));
            }
            StreamEventKind::ToolCallEnd { id } => {
                values.extend(self.finish_function(id)?);
            }
            StreamEventKind::Usage { usage } => {
                self.pending_usage = Some(usage.clone());
            }
            StreamEventKind::Metadata { values: metadata } => {
                self.metadata.extend(metadata.clone());
                report.preserve_capability("response.metadata");
            }
            StreamEventKind::Refusal { text } => {
                values.extend(self.encode_refusal(text));
            }
            StreamEventKind::Completion {
                finish_reason,
                usage,
            } => {
                if self.text.is_some() || self.reasoning.is_some() || !self.functions.is_empty() {
                    return Err(OpenAiResponsesError::UnsupportedEvent {
                        message: "completion appeared before all output blocks ended".to_owned(),
                    });
                }
                let usage = usage.clone().or_else(|| self.pending_usage.clone());
                let (event_name, status, incomplete_details, error) = match finish_reason {
                    FinishReason::Length => (
                        "response.incomplete",
                        "incomplete",
                        Some(serde_json::json!({"reason":"max_output_tokens"})),
                        None,
                    ),
                    FinishReason::Error => (
                        "response.failed",
                        "failed",
                        None,
                        Some(serde_json::json!({
                            "code":"semantic_error",
                            "message":"the semantic stream ended with an error"
                        })),
                    ),
                    _ => ("response.completed", "completed", None, None),
                };
                values.push((
                    event_name,
                    serde_json::json!({
                        "response":self.response_value(
                            status,
                            error,
                            incomplete_details,
                            usage.as_ref()
                        )
                    }),
                ));
                self.completed = true;
            }
            StreamEventKind::Failure { error } => {
                values.push((
                    "response.failed",
                    serde_json::json!({
                        "response":self.response_value(
                            "failed",
                            Some(serde_json::json!({
                                "code":error.code,
                                "message":error.message
                            })),
                            None,
                            None
                        )
                    }),
                ));
                self.completed = true;
            }
            StreamEventKind::Warning { .. } => {
                report.drop_optional("warning", "Responses has no standard stream warning event");
            }
            StreamEventKind::Media { .. } => {
                report.unsupported_required(
                    "media",
                    "Responses media output events are not implemented by this codec",
                );
            }
            StreamEventKind::Opaque { .. } => {
                report.unsupported_required(
                    "opaque_event",
                    "opaque events cannot be assigned a safe Responses event type",
                );
            }
        }
        report.validate(policy)?;
        values
            .into_iter()
            .map(|(name, value)| self.finish_encoded_event(name, value, report.clone()))
            .collect()
    }

    fn start_text(
        &mut self,
        block_id: Option<&str>,
    ) -> Result<Vec<(&'static str, Value)>, OpenAiResponsesError> {
        if self.text.is_some() {
            return Err(OpenAiResponsesError::UnsupportedEvent {
                message: "text block started more than once".to_owned(),
            });
        }
        let id = block_id
            .filter(|id| !id.is_empty())
            .unwrap_or("msg_pooler")
            .to_owned();
        let output_index = self.take_output_index();
        self.text = Some(EncodedTextItem {
            id: id.clone(),
            output_index,
            text: String::new(),
        });
        Ok(vec![
            (
                "response.output_item.added",
                serde_json::json!({
                    "output_index":output_index,
                    "item":{"id":id,"type":"message","status":"in_progress","role":"assistant","content":[]}
                }),
            ),
            (
                "response.content_part.added",
                serde_json::json!({
                    "item_id":id,
                    "output_index":output_index,
                    "content_index":0,
                    "part":{"type":"output_text","text":"","annotations":[]}
                }),
            ),
        ])
    }

    fn finish_text(&mut self) -> Result<Vec<(&'static str, Value)>, OpenAiResponsesError> {
        let state = self
            .text
            .take()
            .ok_or_else(|| OpenAiResponsesError::UnsupportedEvent {
                message: "text block ended before it started".to_owned(),
            })?;
        let item = serde_json::json!({
            "id":state.id,
            "type":"message",
            "status":"completed",
            "role":"assistant",
            "content":[{"type":"output_text","text":state.text,"annotations":[]}]
        });
        self.output.push(item.clone());
        Ok(vec![
            (
                "response.output_text.done",
                serde_json::json!({
                    "item_id":state.id,
                    "output_index":state.output_index,
                    "content_index":0,
                    "text":state.text,
                    "logprobs":[]
                }),
            ),
            (
                "response.content_part.done",
                serde_json::json!({
                    "item_id":state.id,
                    "output_index":state.output_index,
                    "content_index":0,
                    "part":{"type":"output_text","text":state.text,"annotations":[]}
                }),
            ),
            (
                "response.output_item.done",
                serde_json::json!({"output_index":state.output_index,"item":item}),
            ),
        ])
    }

    fn start_reasoning(
        &mut self,
        block_id: Option<&str>,
    ) -> Result<Vec<(&'static str, Value)>, OpenAiResponsesError> {
        if self.reasoning.is_some() {
            return Err(OpenAiResponsesError::UnsupportedEvent {
                message: "reasoning block started more than once".to_owned(),
            });
        }
        let id = block_id
            .filter(|id| !id.is_empty())
            .unwrap_or("rs_pooler")
            .to_owned();
        let output_index = self.take_output_index();
        self.reasoning = Some(EncodedReasoningItem {
            id: id.clone(),
            output_index,
            summary: String::new(),
        });
        Ok(vec![
            (
                "response.output_item.added",
                serde_json::json!({
                    "output_index":output_index,
                    "item":{"id":id,"type":"reasoning","status":"in_progress","summary":[]}
                }),
            ),
            (
                "response.reasoning_summary_part.added",
                serde_json::json!({
                    "item_id":id,
                    "output_index":output_index,
                    "summary_index":0,
                    "part":{"type":"summary_text","text":""}
                }),
            ),
        ])
    }

    fn finish_reasoning(
        &mut self,
        final_reasoning: Option<&ReasoningBlock>,
    ) -> Result<Vec<(&'static str, Value)>, OpenAiResponsesError> {
        let state =
            self.reasoning
                .take()
                .ok_or_else(|| OpenAiResponsesError::UnsupportedEvent {
                    message: "reasoning block ended before it started".to_owned(),
                })?;
        let summary = final_reasoning
            .and_then(|reasoning| reasoning.summary.clone())
            .unwrap_or(state.summary);
        let mut item = serde_json::json!({
            "id":state.id,
            "type":"reasoning",
            "status":"completed",
            "summary":[{"type":"summary_text","text":summary}]
        });
        if let Some(encrypted) =
            final_reasoning.and_then(|reasoning| reasoning.encrypted_content.as_ref())
        {
            item["encrypted_content"] =
                Value::String(String::from_utf8_lossy(encrypted).into_owned());
        }
        self.output.push(item.clone());
        Ok(vec![
            (
                "response.reasoning_summary_text.done",
                serde_json::json!({
                    "item_id":state.id,
                    "output_index":state.output_index,
                    "summary_index":0,
                    "text":summary
                }),
            ),
            (
                "response.reasoning_summary_part.done",
                serde_json::json!({
                    "item_id":state.id,
                    "output_index":state.output_index,
                    "summary_index":0,
                    "part":{"type":"summary_text","text":summary}
                }),
            ),
            (
                "response.output_item.done",
                serde_json::json!({"output_index":state.output_index,"item":item}),
            ),
        ])
    }

    fn start_function(
        &mut self,
        id: &str,
        name: &str,
    ) -> Result<Vec<(&'static str, Value)>, OpenAiResponsesError> {
        if self.functions.contains_key(id) {
            return Err(OpenAiResponsesError::UnsupportedEvent {
                message: format!("tool call `{id}` started more than once"),
            });
        }
        let output_index = self.take_output_index();
        let item_id = format!("fc_{output_index}");
        self.functions.insert(
            id.to_owned(),
            EncodedFunctionItem {
                item_id: item_id.clone(),
                output_index,
                name: name.to_owned(),
                arguments: String::new(),
            },
        );
        Ok(vec![(
            "response.output_item.added",
            serde_json::json!({
                "output_index":output_index,
                "item":{
                    "id":item_id,
                    "type":"function_call",
                    "status":"in_progress",
                    "arguments":"",
                    "call_id":id,
                    "name":name
                }
            }),
        )])
    }

    fn finish_function(
        &mut self,
        id: &str,
    ) -> Result<Vec<(&'static str, Value)>, OpenAiResponsesError> {
        let state =
            self.functions
                .remove(id)
                .ok_or_else(|| OpenAiResponsesError::UnsupportedEvent {
                    message: format!("tool call `{id}` ended before it started"),
                })?;
        let item = serde_json::json!({
            "id":state.item_id,
            "type":"function_call",
            "status":"completed",
            "arguments":state.arguments,
            "call_id":id,
            "name":state.name
        });
        self.output.push(item.clone());
        Ok(vec![
            (
                "response.function_call_arguments.done",
                serde_json::json!({
                    "item_id":state.item_id,
                    "output_index":state.output_index,
                    "arguments":state.arguments
                }),
            ),
            (
                "response.output_item.done",
                serde_json::json!({"output_index":state.output_index,"item":item}),
            ),
        ])
    }

    fn encode_refusal(&mut self, text: &str) -> Vec<(&'static str, Value)> {
        let output_index = self.take_output_index();
        let item_id = format!("msg_{output_index}");
        let item = serde_json::json!({
            "id":item_id,
            "type":"message",
            "status":"completed",
            "role":"assistant",
            "content":[{"type":"refusal","refusal":text}]
        });
        self.output.push(item.clone());
        vec![
            (
                "response.output_item.added",
                serde_json::json!({
                    "output_index":output_index,
                    "item":{"id":item_id,"type":"message","status":"in_progress","role":"assistant","content":[]}
                }),
            ),
            (
                "response.content_part.added",
                serde_json::json!({
                    "item_id":item_id,
                    "output_index":output_index,
                    "content_index":0,
                    "part":{"type":"refusal","refusal":""}
                }),
            ),
            (
                "response.refusal.delta",
                serde_json::json!({
                    "item_id":item_id,
                    "output_index":output_index,
                    "content_index":0,
                    "delta":text
                }),
            ),
            (
                "response.refusal.done",
                serde_json::json!({
                    "item_id":item_id,
                    "output_index":output_index,
                    "content_index":0,
                    "refusal":text
                }),
            ),
            (
                "response.content_part.done",
                serde_json::json!({
                    "item_id":item_id,
                    "output_index":output_index,
                    "content_index":0,
                    "part":{"type":"refusal","refusal":text}
                }),
            ),
            (
                "response.output_item.done",
                serde_json::json!({"output_index":output_index,"item":item}),
            ),
        ]
    }

    fn response_value(
        &self,
        status: &str,
        error: Option<Value>,
        incomplete_details: Option<Value>,
        usage: Option<&Usage>,
    ) -> Value {
        serde_json::json!({
            "id":self.response_id,
            "object":"response",
            "created_at":0,
            "status":status,
            "error":error,
            "incomplete_details":incomplete_details,
            "instructions":null,
            "max_output_tokens":null,
            "model":self.model,
            "output":self.output,
            "parallel_tool_calls":true,
            "previous_response_id":null,
            "reasoning":{"effort":null,"summary":null},
            "store":false,
            "temperature":null,
            "text":{"format":{"type":"text"}},
            "tool_choice":"auto",
            "tools":[],
            "top_p":null,
            "truncation":"disabled",
            "usage":usage.map(encode_responses_usage),
            "metadata":self.metadata
        })
    }

    fn take_output_index(&mut self) -> u64 {
        let index = self.next_output_index;
        self.next_output_index = self.next_output_index.saturating_add(1);
        index
    }

    fn finish_encoded_event(
        &mut self,
        name: &str,
        mut value: Value,
        report: ConversionReport,
    ) -> Result<EncodedResponsesEvent, OpenAiResponsesError> {
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid_shape("encoded event", "an object"))?;
        object.insert("type".to_owned(), Value::String(name.to_owned()));
        object.insert(
            "sequence_number".to_owned(),
            Value::Number(self.next_sequence.into()),
        );
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(EncodedResponsesEvent {
            event: name.to_owned(),
            body: serde_json::to_vec(&value)?,
            report,
        })
    }
}

fn encode_responses_usage(usage: &Usage) -> Value {
    serde_json::json!({
        "input_tokens":usage.input_tokens,
        "input_tokens_details":{"cached_tokens":usage.cached_input_tokens.unwrap_or(0)},
        "output_tokens":usage.output_tokens,
        "output_tokens_details":{"reasoning_tokens":usage.reasoning_tokens.unwrap_or(0)},
        "total_tokens":usage.total_tokens.unwrap_or_else(|| usage.input_tokens.saturating_add(usage.output_tokens))
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{
        decode_responses_request_with_report, encode_responses_request, OpenAiResponsesCodec,
        OpenAiResponsesEventDecoder, OpenAiResponsesEventEncoder,
    };
    use crate::{
        FinishReason, LossPolicy, ReasoningBlock, StreamEvent, StreamEventKind, StreamValidator,
        Usage,
    };

    #[test]
    fn droid_responses_request_preserves_tools_reasoning_and_tool_follow_up() {
        let source = json!({
            "model":"droid-openai-model",
            "instructions":"system guidance",
            "input":[
                {"role":"user","content":[{"type":"input_text","text":"use the tool"}]},
                {
                    "type":"reasoning",
                    "id":"rs_1",
                    "summary":[{"type":"summary_text","text":"brief plan"}],
                    "encrypted_content":"encrypted-state"
                },
                {
                    "type":"function_call",
                    "call_id":"call_1",
                    "name":"Read",
                    "arguments":"{\"file_path\":\"/tmp/example\"}"
                },
                {
                    "type":"function_call_output",
                    "call_id":"call_1",
                    "output":"file contents"
                }
            ],
            "tools":[{
                "type":"function",
                "name":"Read",
                "description":"read a file",
                "parameters":{
                    "type":"object",
                    "properties":{"file_path":{"type":"string"}},
                    "required":["file_path"],
                    "additionalProperties":false
                },
                "strict":true
            }],
            "tool_choice":"auto",
            "parallel_tool_calls":true,
            "reasoning":{"effort":"low","summary":"auto"},
            "include":["reasoning.encrypted_content"],
            "prompt_cache_key":"cache-key",
            "store":false,
            "stream":true
        });
        let decoded = decode_responses_request_with_report(
            &serde_json::to_vec(&source).expect("request JSON"),
        )
        .expect("Droid request decodes");
        assert!(decoded.stream);
        assert!(decoded.report.is_lossless());
        assert_eq!(decoded.request.model, "droid-openai-model");
        assert_eq!(decoded.request.input.len(), 5);
        assert_eq!(decoded.request.tools[0].name, "Read");
        assert!(decoded
            .request
            .reasoning
            .as_ref()
            .is_some_and(|reasoning| reasoning.include_summary));

        let encoded = encode_responses_request(&decoded.request, LossPolicy::Reject)
            .expect("semantic request re-encodes");
        assert!(encoded.report.is_lossless());
        let value: Value = serde_json::from_slice(&encoded.body).expect("encoded request JSON");
        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
        assert_eq!(value["parallel_tool_calls"], true);
        assert_eq!(value["include"][0], "reasoning.encrypted_content");
        assert_eq!(value["reasoning"]["effort"], "low");
        assert_eq!(value["reasoning"]["summary"], "auto");
        assert!(value["input"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["type"] == "function_call_output")
        }));
    }

    #[test]
    fn remaining_high_regression_preserves_exact_reasoning_summary_modes() {
        for mode in ["auto", "concise", "detailed", "none"] {
            let source = json!({
                "model":"strict-model",
                "input":"hello",
                "reasoning":{"effort":"low","summary":mode}
            });
            let decoded = OpenAiResponsesCodec::decode_request(
                &serde_json::to_vec(&source).expect("request JSON"),
            )
            .expect("Reject decoding preserves the exact mode");
            let encoded = encode_responses_request(&decoded, LossPolicy::Reject)
                .expect("Reject encoding preserves the exact mode");
            let value: Value = serde_json::from_slice(&encoded.body).expect("encoded JSON");
            assert_eq!(value["reasoning"]["summary"], mode);
        }
    }

    #[test]
    fn reject_policy_accounts_for_unmodeled_reasoning_text_and_annotations() {
        let source = json!({
            "model":"strict-model",
            "input":[{
                "role":"assistant",
                "content":[{
                    "type":"output_text",
                    "text":"cited",
                    "annotations":[{"type":"url_citation","url":"https://example.test"}]
                }]
            }],
            "reasoning":{
                "effort":"low",
                "summary":"auto",
                "context":"preserve-this-context",
                "mode":"detailed"
            },
            "text":{"format":{"type":"text"},"verbosity":"high"},
            "stream":true
        });
        let bytes = serde_json::to_vec(&source).expect("strict request JSON");
        let decoded = decode_responses_request_with_report(&bytes).expect("request decodes");
        for field in [
            "input[0].content[0].annotations",
            "reasoning.context",
            "reasoning.mode",
            "text.verbosity",
        ] {
            assert!(
                decoded
                    .report
                    .dropped_optional_fields
                    .contains(&field.to_owned()),
                "missing loss accounting for {field}"
            );
        }
        assert!(decoded.report.validate(LossPolicy::Reject).is_err());
        assert!(decoded.report.validate(LossPolicy::Degrade).is_ok());
        assert!(OpenAiResponsesCodec::decode_request(&bytes).is_err());
    }

    #[test]
    fn empty_annotations_do_not_create_semantic_loss() {
        let source = json!({
            "model":"strict-model",
            "input":[{
                "role":"assistant",
                "content":[{"type":"output_text","text":"plain","annotations":[]}]
            }]
        });
        let decoded = decode_responses_request_with_report(
            &serde_json::to_vec(&source).expect("request JSON"),
        )
        .expect("request decodes");
        assert!(decoded.report.is_lossless());
    }

    #[test]
    fn input_image_file_id_round_trips_as_file_id() {
        let source = json!({
            "model":"vision-model",
            "input":[{
                "role":"user",
                "content":[{
                    "type":"input_image",
                    "file_id":"opaque-image-id",
                    "detail":"high"
                }]
            }]
        });
        let decoded = decode_responses_request_with_report(
            &serde_json::to_vec(&source).expect("request JSON"),
        )
        .expect("image request decodes");
        assert!(decoded.report.is_lossless());
        let encoded = encode_responses_request(&decoded.request, LossPolicy::Reject)
            .expect("image request encodes");
        let value: Value = serde_json::from_slice(&encoded.body).expect("encoded request JSON");
        let image = &value["input"][0]["content"][0];
        assert_eq!(image["file_id"], "opaque-image-id");
        assert!(image.get("image_url").is_none());
        assert_eq!(image["detail"], "high");
    }

    #[test]
    fn stream_decoder_rejects_nonempty_output_annotations() {
        let mut decoder = OpenAiResponsesEventDecoder::new();
        let added = json!({
            "type":"response.output_item.added",
            "output_index":0,
            "item":{
                "id":"msg_annotations","type":"message","status":"in_progress",
                "role":"assistant","content":[]
            }
        });
        decoder
            .decode_data(&serde_json::to_vec(&added).expect("added event JSON"))
            .expect("message starts");
        let done = json!({
            "type":"response.output_item.done",
            "output_index":0,
            "item":{
                "id":"msg_annotations","type":"message","status":"completed",
                "role":"assistant",
                "content":[{
                    "type":"output_text","text":"cited",
                    "annotations":[{"type":"url_citation","url":"https://example.test"}]
                }]
            }
        });
        let error = decoder
            .decode_data(&serde_json::to_vec(&done).expect("done event JSON"))
            .expect_err("annotations must not be silently discarded");
        assert!(error.to_string().contains("annotations"));
    }

    #[test]
    fn decoder_handles_fragment_independent_text_stream_and_usage() {
        let mut decoder = OpenAiResponsesEventDecoder::new();
        let events = [
            (
                "response.created",
                json!({
                    "type":"response.created",
                    "response":{"id":"resp_1","model":"model-a","status":"in_progress"}
                }),
            ),
            (
                "response.output_item.added",
                json!({
                    "type":"response.output_item.added",
                    "output_index":0,
                    "item":{"id":"msg_1","type":"message","status":"in_progress","role":"assistant","content":[]}
                }),
            ),
            (
                "response.content_part.added",
                json!({
                    "type":"response.content_part.added",
                    "item_id":"msg_1","output_index":0,"content_index":0,
                    "part":{"type":"output_text","text":"","annotations":[]}
                }),
            ),
            (
                "response.output_text.delta",
                json!({
                    "type":"response.output_text.delta",
                    "item_id":"msg_1","output_index":0,"content_index":0,"delta":"hello"
                }),
            ),
            (
                "response.output_item.done",
                json!({
                    "type":"response.output_item.done",
                    "output_index":0,
                    "item":{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[]}]}
                }),
            ),
            (
                "response.completed",
                json!({
                    "type":"response.completed",
                    "response":{
                        "id":"resp_1","model":"model-a","status":"completed",
                        "usage":{
                            "input_tokens":3,"input_tokens_details":{"cached_tokens":1},
                            "output_tokens":2,"output_tokens_details":{"reasoning_tokens":0},
                            "total_tokens":5
                        }
                    }
                }),
            ),
        ];
        let mut semantic = Vec::new();
        for (name, value) in events {
            semantic.extend(
                decoder
                    .decode_event(Some(name), &serde_json::to_vec(&value).expect("event JSON"))
                    .expect("event decodes"),
            );
        }
        decoder.finish().expect("terminal event was observed");
        let mut validator = StreamValidator::default();
        for event in &semantic {
            validator.accept(event).expect("valid semantic lifecycle");
        }
        assert!(semantic.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::TextDelta { text } if text == "hello"
        )));
        assert!(semantic.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::Stop,
                usage: Some(Usage {
                    input_tokens: 3,
                    output_tokens: 2,
                    cached_input_tokens: Some(1),
                    ..
                })
            }
        )));
    }

    #[test]
    fn reasoning_and_tool_events_round_trip_with_encrypted_state() {
        let source = vec![
            StreamEvent::new(
                1,
                StreamEventKind::response_start(
                    Some("resp_roundtrip".to_owned()),
                    Some("model-a".to_owned()),
                ),
            ),
            StreamEvent::new(2, StreamEventKind::ReasoningStart).with_block_id("rs_1"),
            StreamEvent::new(3, StreamEventKind::reasoning_delta("plan")).with_block_id("rs_1"),
            StreamEvent::new(
                4,
                StreamEventKind::ReasoningEnd {
                    reasoning: Some(ReasoningBlock {
                        id: Some("rs_1".to_owned()),
                        summary: Some("plan".to_owned()),
                        encrypted_content: Some(b"encrypted-state".to_vec()),
                        ..ReasoningBlock::default()
                    }),
                },
            )
            .with_block_id("rs_1"),
            StreamEvent::new(
                5,
                StreamEventKind::ToolCallStart {
                    id: "call_1".to_owned(),
                    name: "Read".to_owned(),
                },
            ),
            StreamEvent::new(
                6,
                StreamEventKind::ToolCallDelta {
                    id: "call_1".to_owned(),
                    arguments: "{\"file_path\":\"/tmp/example\"}".to_owned(),
                },
            ),
            StreamEvent::new(
                7,
                StreamEventKind::ToolCallEnd {
                    id: "call_1".to_owned(),
                },
            ),
            StreamEvent::new(
                8,
                StreamEventKind::completion(FinishReason::ToolCall, Some(Usage::new(5, 4))),
            ),
        ];

        let mut encoder = OpenAiResponsesEventEncoder::new();
        let mut decoder = OpenAiResponsesEventDecoder::new();
        let mut decoded = Vec::new();
        for event in &source {
            for encoded in encoder
                .encode_event(event, LossPolicy::Reject)
                .expect("semantic event encodes")
            {
                decoded.extend(
                    decoder
                        .decode_event(Some(&encoded.event), &encoded.body)
                        .expect("encoded event decodes"),
                );
            }
        }
        decoder.finish().expect("round-trip stream completes");
        let mut validator = StreamValidator::default();
        for event in &decoded {
            validator.accept(event).expect("valid semantic lifecycle");
        }
        assert!(decoded.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::ReasoningEnd {
                reasoning: Some(ReasoningBlock {
                    encrypted_content: Some(encrypted),
                    ..
                })
            } if encrypted == b"encrypted-state"
        )));
        assert!(decoded.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::ToolCallDelta { id, arguments }
                if id == "call_1" && arguments.contains("file_path")
        )));
        assert!(decoded.iter().any(|event| matches!(
            &event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::ToolCall,
                ..
            }
        )));
    }

    #[test]
    fn decoder_rejects_transport_eof_without_terminal_event() {
        let mut decoder = OpenAiResponsesEventDecoder::new();
        let created = json!({
            "type":"response.created",
            "response":{"id":"resp_1","model":"model-a","status":"in_progress"}
        });
        decoder
            .decode_data(&serde_json::to_vec(&created).expect("event JSON"))
            .expect("created event");
        assert!(decoder.finish().is_err());
    }
}
