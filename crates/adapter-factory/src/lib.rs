#![forbid(unsafe_code)]
#![doc = "Semantic codecs for Factory's LanguageModel V3 and V4 wires.

The request and stream-part fields shared by both specifications are translated
through Pooler's semantic model. Version-specific headers are validated at the
HTTP boundary, and unsupported required semantics remain visible through the
explicit conversion report."]

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use pooler_config::RoutePlan;
use pooler_http::{
    BoxError, ProxyBody, SelectionContext, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody, SseEncoder, SseError, SseEvent, SseLimits, SseParser,
};
use pooler_protocol::OpenAiChatEventDecoder;
use pooler_protocol::{
    ContentPart, ConversionError, ConversionReport, ExtensionKey, Extensions, FinishReason,
    InputItem, LossPolicy, MediaSource, Message, OpaqueExtension, PreservedJson, ReasoningBlock,
    ReasoningConfig, ReasoningEffort, RequestValidationError, ResponseFormat, Role,
    SemanticRequest, StreamError, StreamEvent, StreamEventKind, ToolCall, ToolChoice,
    ToolDefinition, ToolResult, Usage,
};
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Factory language-model route named by the architecture plan.
pub const FACTORY_LANGUAGE_MODEL_PATH: &str = "/v3/ai/language-model";
/// Header carrying the LanguageModel specification version.
pub const SPECIFICATION_VERSION_HEADER: &str = "ai-language-model-specification-version";
/// Header carrying the selected model identifier.
pub const MODEL_ID_HEADER: &str = "ai-language-model-id";
/// Header selecting unary or streaming model execution.
pub const STREAMING_HEADER: &str = "ai-language-model-streaming";
/// LanguageModel V3 specification version.
pub const SPECIFICATION_VERSION_V3: &str = "3";
/// LanguageModel V4 specification version used by the current Factory client.
pub const SPECIFICATION_VERSION_V4: &str = "4";
/// Header carrying the AI Gateway wire-protocol revision.
pub const GATEWAY_PROTOCOL_VERSION_HEADER: &str = "ai-gateway-protocol-version";
/// AI Gateway protocol revision used by Factory LanguageModel V4.
pub const GATEWAY_PROTOCOL_VERSION: &str = "0.0.1";

/// Semantic adapter mounted by the HTTP runtime for Factory LanguageModel V3/V4.
#[derive(Clone, Copy, Debug, Default)]
pub struct FactorySemanticAdapter;

/// Bounds applied before a Factory request is converted into semantic values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactoryDecodeLimits {
    /// Maximum serialized request body size.
    pub max_body_bytes: usize,
    /// Maximum number of prompt messages.
    pub max_prompt_messages: usize,
    /// Maximum number of content parts across the prompt.
    pub max_content_parts: usize,
    /// Maximum number of function tools.
    pub max_tools: usize,
    /// Maximum serialized tool-call input size.
    pub max_tool_arguments_bytes: usize,
}

impl Default for FactoryDecodeLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 8 * 1024 * 1024,
            max_prompt_messages: 1024,
            max_content_parts: 4096,
            max_tools: 256,
            max_tool_arguments_bytes: 1024 * 1024,
        }
    }
}

/// How non-image file prompt parts are handled by the request decoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FactoryFilePolicy {
    /// Reject files before any upstream request is made.
    #[default]
    Reject,
    /// Keep the file part and record an explicit conversion degradation.
    Degrade,
}

/// Decoder options for one Factory route.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FactoryDecodeOptions {
    /// Request and nesting bounds.
    pub limits: FactoryDecodeLimits,
    /// Policy for non-image files in prompt content.
    pub file_policy: FactoryFilePolicy,
}

/// A decoded Factory request and the accounting accumulated while converting it.
#[derive(Clone, Debug, PartialEq)]
pub struct FactoryRequest {
    /// Protocol-neutral request passed to target selection and an upstream encoder.
    pub request: SemanticRequest,
    /// Explicit preservation, degradation, and unsupported-field accounting.
    pub report: ConversionReport,
}

/// Factory LanguageModel request decoder shared by V3 and V4.
#[derive(Clone, Copy, Debug, Default)]
pub struct FactoryLanguageModelDecoder {
    options: FactoryDecodeOptions,
}

impl FactoryLanguageModelDecoder {
    /// Creates a decoder with explicit request and file bounds.
    #[must_use]
    pub const fn new(options: FactoryDecodeOptions) -> Self {
        Self { options }
    }

    /// Decodes a serialized LanguageModel V3 request using the model selected by routing.
    pub fn decode(
        &self,
        body: &[u8],
        model: impl Into<String>,
    ) -> Result<FactoryRequest, FactoryDecodeError> {
        if body.len() > self.options.limits.max_body_bytes {
            return Err(FactoryDecodeError::BodyTooLarge {
                observed: body.len(),
                limit: self.options.limits.max_body_bytes,
            });
        }
        let value: Value = serde_json::from_slice(body)?;
        self.decode_value(&value, model)
    }

    /// Decodes a parsed LanguageModel V3 request.
    pub fn decode_value(
        &self,
        value: &Value,
        model: impl Into<String>,
    ) -> Result<FactoryRequest, FactoryDecodeError> {
        let model = model.into();
        if model.trim().is_empty() {
            return Err(FactoryDecodeError::MissingModel);
        }
        let object = value.as_object().ok_or(FactoryDecodeError::RootNotObject)?;
        let mut report = ConversionReport::default();
        let mut request = SemanticRequest::new(model);
        let prompt = object
            .get("prompt")
            .ok_or(FactoryDecodeError::MissingField("prompt"))?;
        let messages = prompt.as_array().ok_or(FactoryDecodeError::InvalidField {
            field: "prompt",
            reason: "must be an array",
        })?;
        if messages.len() > self.options.limits.max_prompt_messages {
            return Err(FactoryDecodeError::LimitExceeded {
                field: "prompt",
                observed: messages.len(),
                limit: self.options.limits.max_prompt_messages,
            });
        }
        let mut content_count = 0;
        for (index, message) in messages.iter().enumerate() {
            request.push_message(decode_message(
                message,
                index,
                &mut report,
                &mut content_count,
                self.options,
            )?);
        }
        if let Some(tools) = object.get("tools") {
            decode_tools(
                tools,
                &mut request,
                &mut report,
                self.options.limits.max_tools,
            )?;
        }
        if let Some(tool_choice) = object.get("toolChoice") {
            let tool_choice = decode_tool_choice(tool_choice)?;
            if let ToolChoice::Tool { name } = &tool_choice {
                if !request.tools.iter().any(|tool| tool.name == *name) {
                    return Err(invalid_value(
                        "toolChoice.toolName",
                        "must name a declared function tool",
                    ));
                }
            }
            request.tool_choice = Some(tool_choice);
        }
        if let Some(response_format) = object.get("responseFormat") {
            request.response_format = Some(decode_response_format(
                response_format,
                &mut request.extensions,
                &mut report,
            )?);
        }
        decode_sampling(object, &mut request, &mut report)?;
        decode_reasoning(object, &mut request)?;
        preserve_provider_options(
            object.get("providerOptions"),
            &mut request.extensions,
            &mut report,
        )?;
        request
            .validate()
            .map_err(FactoryDecodeError::InvalidSemanticRequest)?;
        Ok(FactoryRequest { request, report })
    }
}

/// Errors raised while decoding a Factory request.
#[derive(Debug, Error)]
pub enum FactoryDecodeError {
    /// Request body exceeded the adapter's configured bound.
    #[error("Factory request body is too large: {observed} bytes exceeds limit {limit}")]
    BodyTooLarge { observed: usize, limit: usize },
    /// Request JSON could not be parsed.
    #[error("invalid Factory request JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// The JSON root must be an object.
    #[error("Factory request JSON must be an object")]
    RootNotObject,
    /// The route must supply a model from its configured header or fallback.
    #[error("Factory request model is missing")]
    MissingModel,
    /// A required request field was absent.
    #[error("Factory request field {0} is missing")]
    MissingField(&'static str),
    /// A known field had the wrong JSON shape.
    #[error("invalid Factory request field {field}: {reason}")]
    InvalidField {
        /// Field path in the request.
        field: &'static str,
        /// Shape error.
        reason: &'static str,
    },
    /// A configured bound was exceeded.
    #[error("Factory request field {field} has {observed} entries, limit is {limit}")]
    LimitExceeded {
        /// Field whose bound was exceeded.
        field: &'static str,
        /// Observed count.
        observed: usize,
        /// Configured bound.
        limit: usize,
    },
    /// A semantic value could not be represented safely.
    #[error("invalid Factory request field {field}: {reason}")]
    InvalidValue {
        /// Field path in the request.
        field: String,
        /// Conversion failure.
        reason: String,
    },
    /// A file was rejected before upstream execution.
    #[error("Factory file input {0} is not supported by the configured file policy")]
    UnsupportedFile(String),
    /// The resulting semantic request failed provider-independent validation.
    #[error("invalid semantic Factory request: {0}")]
    InvalidSemanticRequest(#[from] RequestValidationError),
    /// A provider-options namespace could not become a validated extension name.
    #[error("invalid Factory providerOptions namespace {0}")]
    InvalidProviderOptionsNamespace(String),
}

fn decode_message(
    value: &Value,
    index: usize,
    report: &mut ConversionReport,
    content_count: &mut usize,
    options: FactoryDecodeOptions,
) -> Result<Message, FactoryDecodeError> {
    let object = value.as_object().ok_or(FactoryDecodeError::InvalidField {
        field: "prompt",
        reason: "each message must be an object",
    })?;
    let role = match object.get("role").and_then(Value::as_str) {
        Some("system") => Role::System,
        Some("user") => Role::User,
        Some("assistant") => Role::Assistant,
        Some("tool") => Role::Tool,
        Some(_) | None => {
            return Err(FactoryDecodeError::InvalidValue {
                field: format!("prompt[{index}].role"),
                reason: "must be system, user, assistant, or tool".to_owned(),
            })
        }
    };
    let content = object
        .get("content")
        .ok_or(FactoryDecodeError::InvalidField {
            field: "prompt[].content",
            reason: "is required",
        })?;
    let mut message = Message::new(role);
    if role == Role::System {
        let text = content.as_str().ok_or(FactoryDecodeError::InvalidField {
            field: "prompt[].content",
            reason: "system content must be a string",
        })?;
        message.push_content(ContentPart::text(text));
    } else {
        let parts = content.as_array().ok_or(FactoryDecodeError::InvalidField {
            field: "prompt[].content",
            reason: "content must be an array for this role",
        })?;
        for (part_index, part) in parts.iter().enumerate() {
            *content_count = content_count.saturating_add(1);
            if *content_count > options.limits.max_content_parts {
                return Err(FactoryDecodeError::LimitExceeded {
                    field: "prompt[].content",
                    observed: *content_count,
                    limit: options.limits.max_content_parts,
                });
            }
            message.push_content(decode_content_part(
                part,
                &format!("prompt[{index}].content[{part_index}]"),
                report,
                options,
            )?);
        }
    }
    preserve_provider_options(
        object.get("providerOptions"),
        &mut message.extensions,
        report,
    )?;
    Ok(message)
}

fn decode_content_part(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
    options: FactoryDecodeOptions,
) -> Result<ContentPart, FactoryDecodeError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_value(field, "content part must be an object"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_value(field, "content part type is required"))?;
    match kind {
        "text" => {
            account_dropped_provider_options(object, field, report)?;
            Ok(ContentPart::text(string_field(object, "text", field)?))
        }
        "reasoning" => {
            let mut reasoning = ReasoningBlock {
                text: Some(string_field(object, "text", field)?.to_owned()),
                ..ReasoningBlock::default()
            };
            preserve_provider_options(
                object.get("providerOptions"),
                &mut reasoning.extensions,
                report,
            )?;
            Ok(ContentPart::Reasoning(reasoning))
        }
        "file" => decode_file_part(object, field, report, options),
        "tool-call" => {
            let id = string_field(object, "toolCallId", field)?;
            let name = string_field(object, "toolName", field)?;
            let input = object
                .get("input")
                .ok_or_else(|| invalid_value(field, "tool-call input is required"))?;
            let input = PreservedJson::from_value(input.clone())
                .map_err(|error| invalid_value(&format!("{field}.input"), error.to_string()))?;
            if input.bytes().len() > options.limits.max_tool_arguments_bytes {
                return Err(FactoryDecodeError::LimitExceeded {
                    field: "prompt[].content[].input",
                    observed: input.bytes().len(),
                    limit: options.limits.max_tool_arguments_bytes,
                });
            }
            let mut call = ToolCall::new(id, name, input);
            if let Some(provider_executed) = object.get("providerExecuted") {
                if !provider_executed.is_boolean() {
                    return Err(FactoryDecodeError::InvalidField {
                        field: "prompt[].content[].providerExecuted",
                        reason: "must be a boolean",
                    });
                }
                preserve_json_extension(
                    "factory",
                    "tool_call_provider_executed",
                    provider_executed,
                    &mut call.extensions,
                    report,
                    &format!("{field}.providerExecuted"),
                )?;
            }
            preserve_provider_options(object.get("providerOptions"), &mut call.extensions, report)?;
            Ok(ContentPart::ToolCall(call))
        }
        "tool-result" => decode_tool_result(object, field, report),
        "tool-approval-response" => preserve_provider_part(field, value, report),
        _ => preserve_provider_part(field, value, report),
    }
}

fn decode_file_part(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
    options: FactoryDecodeOptions,
) -> Result<ContentPart, FactoryDecodeError> {
    let media_type = string_field(object, "mediaType", field)?;
    let source = decode_media_source(object.get("data"), &format!("{field}.data"))?;
    if media_type.starts_with("image/") {
        if object.contains_key("filename") {
            report.drop_optional(
                format!("{field}.filename"),
                "image content has no common semantic filename field",
            );
        }
        account_dropped_provider_options(object, field, report)?;
        return Ok(ContentPart::image(media_type, source));
    }
    match options.file_policy {
        FactoryFilePolicy::Reject => Err(FactoryDecodeError::UnsupportedFile(field.to_owned())),
        FactoryFilePolicy::Degrade => {
            report.degrade_field(
                field,
                "Factory file input is retained as a generic semantic file part",
            );
            account_dropped_provider_options(object, field, report)?;
            Ok(ContentPart::file(
                object
                    .get("filename")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                media_type,
                source,
            ))
        }
    }
}

fn decode_tool_result(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
) -> Result<ContentPart, FactoryDecodeError> {
    let id = string_field(object, "toolCallId", field)?;
    let output = object
        .get("output")
        .ok_or_else(|| invalid_value(field, "tool-result output is required"))?;
    let output_type = output.get("type").and_then(Value::as_str);
    let (content, is_error) = match output_type {
        Some("text") | Some("error-text") => {
            let output = output
                .as_object()
                .ok_or_else(|| invalid_value(field, "tool-result output must be an object"))?;
            let text = string_field(output, "value", field)?;
            (
                vec![ContentPart::text(text)],
                output_type == Some("error-text"),
            )
        }
        Some("execution-denied") => (
            vec![ContentPart::text(
                output
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("tool execution denied"),
            )],
            true,
        ),
        Some("json") | Some("error-json") | Some("content") | None => {
            let data = output
                .get("value")
                .cloned()
                .unwrap_or_else(|| output.clone());
            let json = PreservedJson::from_value(data)
                .map_err(|error| invalid_value(field, error.to_string()))?;
            (
                vec![ContentPart::Provider {
                    namespace: "factory".to_owned(),
                    name: "tool_result_output".to_owned(),
                    data: json,
                }],
                output_type == Some("error-json"),
            )
        }
        Some(kind) => {
            return Err(invalid_value(
                &format!("{field}.output.type"),
                format!("unsupported tool-result output type {kind}"),
            ))
        }
    };
    let mut result = ToolResult {
        tool_call_id: id.to_owned(),
        content,
        is_error,
        extensions: Extensions::default(),
    };
    if let Some(tool_name) = object.get("toolName") {
        if !tool_name.is_string() {
            return Err(FactoryDecodeError::InvalidField {
                field: "tool-result.toolName",
                reason: "must be a string",
            });
        }
        preserve_json_extension(
            "factory",
            "tool_result_name",
            tool_name,
            &mut result.extensions,
            report,
            "tool-result.toolName",
        )?;
    }
    if let Some(output_object) = output.as_object() {
        if let Some(provider_options) = output_object.get("providerOptions") {
            if !provider_options.is_object() {
                return Err(FactoryDecodeError::InvalidField {
                    field: "tool-result.output.providerOptions",
                    reason: "must be an object",
                });
            }
            preserve_json_extension(
                "factory",
                "tool_result_output_options",
                provider_options,
                &mut result.extensions,
                report,
                "tool-result.output.providerOptions",
            )?;
        }
    }
    preserve_provider_options(
        object.get("providerOptions"),
        &mut result.extensions,
        report,
    )?;
    Ok(ContentPart::ToolResult(result))
}

fn decode_tools(
    value: &Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
    max_tools: usize,
) -> Result<(), FactoryDecodeError> {
    let tools = value.as_array().ok_or(FactoryDecodeError::InvalidField {
        field: "tools",
        reason: "must be an array",
    })?;
    if tools.len() > max_tools {
        return Err(FactoryDecodeError::LimitExceeded {
            field: "tools",
            observed: tools.len(),
            limit: max_tools,
        });
    }
    for (index, value) in tools.iter().enumerate() {
        let object = value.as_object().ok_or(FactoryDecodeError::InvalidField {
            field: "tools[]",
            reason: "each tool must be an object",
        })?;
        match object.get("type").and_then(Value::as_str) {
            Some("function") => {
                let name = string_field(object, "name", "tools[]")?;
                let schema = object
                    .get("inputSchema")
                    .ok_or_else(|| invalid_value("tools[].inputSchema", "is required"))?;
                let schema = PreservedJson::from_value(schema.clone())
                    .map_err(|error| invalid_value("tools[].inputSchema", error.to_string()))?;
                let mut tool = ToolDefinition::new(name, Some(schema));
                tool.description = object
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                tool.strict = object
                    .get("strict")
                    .map(|value| {
                        value.as_bool().ok_or(FactoryDecodeError::InvalidField {
                            field: "tools[].strict",
                            reason: "must be a boolean",
                        })
                    })
                    .transpose()?;
                if let Some(input_examples) = object.get("inputExamples") {
                    if !input_examples.is_array() {
                        return Err(FactoryDecodeError::InvalidField {
                            field: "tools[].inputExamples",
                            reason: "must be an array",
                        });
                    }
                    preserve_json_extension(
                        "factory",
                        "input_examples",
                        input_examples,
                        &mut tool.extensions,
                        report,
                        "tools[].inputExamples",
                    )?;
                }
                preserve_provider_options(
                    object.get("providerOptions"),
                    &mut tool.extensions,
                    report,
                )?;
                request.tools.push(tool);
            }
            Some("provider") => {
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                report.drop_optional(
                    format!("tools[{index}]"),
                    format!(
                        "Factory provider tool {name} has no provider-neutral OpenAI representation"
                    ),
                );
            }
            Some(_) | None => {
                return Err(invalid_value(
                    &format!("tools[{index}].type"),
                    "must be function or provider",
                ))
            }
        }
    }
    Ok(())
}

fn decode_tool_choice(value: &Value) -> Result<ToolChoice, FactoryDecodeError> {
    let object = value.as_object().ok_or(FactoryDecodeError::InvalidField {
        field: "toolChoice",
        reason: "must be an object",
    })?;
    match object.get("type").and_then(Value::as_str) {
        Some("auto") => Ok(ToolChoice::Auto),
        Some("none") => Ok(ToolChoice::None),
        Some("required") => Ok(ToolChoice::Required),
        Some("tool") => Ok(ToolChoice::Tool {
            name: string_field(object, "toolName", "toolChoice")?.to_owned(),
        }),
        Some(_) | None => Err(invalid_value(
            "toolChoice.type",
            "must be auto, none, required, or tool",
        )),
    }
}

fn decode_response_format(
    value: &Value,
    extensions: &mut Extensions,
    report: &mut ConversionReport,
) -> Result<ResponseFormat, FactoryDecodeError> {
    let object = value.as_object().ok_or(FactoryDecodeError::InvalidField {
        field: "responseFormat",
        reason: "must be an object",
    })?;
    let format = match object.get("type").and_then(Value::as_str) {
        Some("text") => ResponseFormat::Text,
        Some("json") => match object.get("schema") {
            Some(schema) => ResponseFormat::JsonSchema {
                name: object
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("output")
                    .to_owned(),
                schema: PreservedJson::from_value(schema.clone())
                    .map_err(|error| invalid_value("responseFormat.schema", error.to_string()))?,
                strict: object
                    .get("strict")
                    .map(|value| {
                        value.as_bool().ok_or(FactoryDecodeError::InvalidField {
                            field: "responseFormat.strict",
                            reason: "must be a boolean",
                        })
                    })
                    .transpose()?
                    .unwrap_or(false),
            },
            None => ResponseFormat::JsonObject,
        },
        Some(_) | None => return Err(invalid_value("responseFormat.type", "must be text or json")),
    };
    preserve_json_extension(
        "factory",
        "response_format",
        value,
        extensions,
        report,
        "responseFormat",
    )?;
    Ok(format)
}

fn decode_sampling(
    object: &Map<String, Value>,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), FactoryDecodeError> {
    request.sampling.temperature = optional_number(object, "temperature")?;
    request.sampling.top_p = optional_number(object, "topP")?;
    request.sampling.max_output_tokens = object
        .get("maxOutputTokens")
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or(FactoryDecodeError::InvalidField {
                    field: "maxOutputTokens",
                    reason: "must be a non-negative 32-bit integer",
                })
        })
        .transpose()?;
    request.sampling.stop = match object.get("stopSequences") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .ok_or(FactoryDecodeError::InvalidField {
                field: "stopSequences",
                reason: "must be an array",
            })?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(FactoryDecodeError::InvalidField {
                        field: "stopSequences[]",
                        reason: "must be a string",
                    })
            })
            .collect::<Result<_, _>>()?,
    };
    request.sampling.seed = object
        .get("seed")
        .map(|value| {
            value.as_u64().ok_or(FactoryDecodeError::InvalidField {
                field: "seed",
                reason: "must be a non-negative integer",
            })
        })
        .transpose()?;
    request.sampling.presence_penalty = optional_number(object, "presencePenalty")?;
    request.sampling.frequency_penalty = optional_number(object, "frequencyPenalty")?;
    if let Some(top_k) = object.get("topK") {
        if top_k.as_u64().is_none() {
            return Err(FactoryDecodeError::InvalidField {
                field: "topK",
                reason: "must be a non-negative integer",
            });
        }
        preserve_json_extension(
            "factory",
            "top_k",
            top_k,
            &mut request.sampling.extensions,
            report,
            "topK",
        )?;
    }
    Ok(())
}

fn decode_reasoning(
    object: &Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), FactoryDecodeError> {
    let Some(value) = object.get("reasoning") else {
        return Ok(());
    };
    let value = value.as_object().ok_or(FactoryDecodeError::InvalidField {
        field: "reasoning",
        reason: "must be an object",
    })?;
    let effort =
        value
            .get("effort")
            .and_then(Value::as_str)
            .ok_or(FactoryDecodeError::InvalidField {
                field: "reasoning.effort",
                reason: "must be a string",
            })?;
    request.reasoning = Some(ReasoningConfig {
        effort: Some(match effort {
            "low" => ReasoningEffort::Low,
            "medium" => ReasoningEffort::Medium,
            "high" => ReasoningEffort::High,
            "max" => ReasoningEffort::Max,
            other => ReasoningEffort::Custom(other.to_owned()),
        }),
        include_summary: value
            .get("includeSummary")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        extensions: Extensions::default(),
    });
    Ok(())
}

fn optional_number(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<f32>, FactoryDecodeError> {
    object
        .get(field)
        .map(|value| {
            value
                .as_f64()
                .and_then(|number| number.to_string().parse().ok())
                .ok_or(FactoryDecodeError::InvalidField {
                    field,
                    reason: "must be a finite number",
                })
        })
        .transpose()
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
    parent: &str,
) -> Result<&'a str, FactoryDecodeError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_value(&format!("{parent}.{field}"), "must be a non-empty string"))
}

fn invalid_value(field: &str, reason: impl Into<String>) -> FactoryDecodeError {
    FactoryDecodeError::InvalidValue {
        field: field.to_owned(),
        reason: reason.into(),
    }
}

fn account_dropped_provider_options(
    object: &Map<String, Value>,
    field: &str,
    report: &mut ConversionReport,
) -> Result<(), FactoryDecodeError> {
    let Some(options) = object.get("providerOptions") else {
        return Ok(());
    };
    if !options.is_object() {
        return Err(FactoryDecodeError::InvalidField {
            field: "providerOptions",
            reason: "must be an object",
        });
    }
    report.drop_optional(
        format!("{field}.providerOptions"),
        "content-part provider options have no common semantic storage",
    );
    Ok(())
}

fn decode_media_source(
    value: Option<&Value>,
    field: &str,
) -> Result<MediaSource, FactoryDecodeError> {
    let value = value.ok_or_else(|| invalid_value(field, "media data is required"))?;
    if let Some(value) = value.as_str() {
        return decode_bare_media_string(value);
    }
    if let Some(object) = value.as_object() {
        match object.get("type").and_then(Value::as_str) {
            Some("data") => {
                return decode_inline_media_data(object.get("data"), field);
            }
            Some("text") => {
                let text = object
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_value(field, "text data needs a string text"))?;
                return Ok(MediaSource::inline(text.as_bytes().to_vec()));
            }
            Some("url") => {
                return Ok(MediaSource::uri(
                    object
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid_value(field, "URL data needs a string url"))?,
                ));
            }
            Some("reference") => {
                return Err(invalid_value(
                    field,
                    "provider media references are not supported by this adapter",
                ));
            }
            Some(kind) => {
                return Err(invalid_value(
                    field,
                    format!("unsupported media data type {kind}"),
                ));
            }
            None => {}
        }
        if let Some(url) = object.get("url") {
            let url = url
                .as_str()
                .ok_or_else(|| invalid_value(field, "URL data needs a string url"))?;
            return Ok(MediaSource::uri(url));
        }
        if let Some(data) = object.get("data") {
            return decode_media_source(Some(data), field);
        }
    }
    if value.is_array() {
        return decode_inline_media_data(Some(value), field);
    }
    Err(invalid_value(
        field,
        "media data must be a string, URL object, or byte array",
    ))
}

fn decode_bare_media_string(value: &str) -> Result<MediaSource, FactoryDecodeError> {
    if looks_like_uri(value) {
        return Ok(MediaSource::uri(value));
    }
    if let Ok(bytes) = decode_base64(value) {
        return Ok(MediaSource::inline(bytes));
    }
    Ok(MediaSource::uri(value))
}

fn decode_inline_media_data(
    value: Option<&Value>,
    field: &str,
) -> Result<MediaSource, FactoryDecodeError> {
    let value = value.ok_or_else(|| invalid_value(field, "inline data is required"))?;
    if let Some(value) = value.as_str() {
        return decode_base64(value)
            .map(MediaSource::inline)
            .map_err(|error| invalid_value(field, error.to_string()));
    }
    if let Some(bytes) = value.as_array() {
        let mut inline = Vec::with_capacity(bytes.len());
        for byte in bytes {
            let Some(byte) = byte.as_u64().and_then(|byte| u8::try_from(byte).ok()) else {
                return Err(invalid_value(field, "inline data array must contain bytes"));
            };
            inline.push(byte);
        }
        return Ok(MediaSource::inline(inline));
    }
    Err(invalid_value(
        field,
        "inline data must be a base64 string or byte array",
    ))
}

fn looks_like_uri(value: &str) -> bool {
    if value.starts_with("//") {
        return true;
    }
    let Some(colon) = value.find(':') else {
        return false;
    };
    colon > 0
        && value[..colon].bytes().all(|byte| {
            byte.is_ascii_alphabetic()
                || byte.is_ascii_digit()
                || byte == b'+'
                || byte == b'-'
                || byte == b'.'
        })
        && value.as_bytes()[0].is_ascii_alphabetic()
}

fn preserve_provider_part(
    field: &str,
    value: &Value,
    report: &mut ConversionReport,
) -> Result<ContentPart, FactoryDecodeError> {
    let data = PreservedJson::from_value(value.clone())
        .map_err(|error| invalid_value(field, error.to_string()))?;
    let name = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("content_part");
    let key = ExtensionKey::new("factory", name)
        .map_err(|error| invalid_value(field, error.to_string()))?;
    report.preserve_extension(&key);
    Ok(ContentPart::provider("factory", name, data))
}

fn preserve_json_extension(
    namespace: &str,
    name: &str,
    value: &Value,
    extensions: &mut Extensions,
    report: &mut ConversionReport,
    field: &str,
) -> Result<(), FactoryDecodeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| invalid_value(field, format!("cannot preserve JSON: {error}")))?;
    let extension = OpaqueExtension::new(namespace, name, bytes)
        .map_err(|error| invalid_value(field, error.to_string()))?
        .with_media_type("application/json")
        .map_err(|error| invalid_value(field, error.to_string()))?;
    let key = extension.key();
    report.preserve_extension(&key);
    extensions.insert(extension);
    Ok(())
}

fn preserve_provider_options(
    value: Option<&Value>,
    extensions: &mut Extensions,
    report: &mut ConversionReport,
) -> Result<(), FactoryDecodeError> {
    let Some(value) = value else {
        return Ok(());
    };
    let object = value.as_object().ok_or(FactoryDecodeError::InvalidField {
        field: "providerOptions",
        reason: "must be an object",
    })?;
    for (namespace, options) in object {
        let extension = OpaqueExtension::new(
            namespace.clone(),
            "options",
            serde_json::to_vec(options)
                .map_err(|error| invalid_value("providerOptions", error.to_string()))?,
        )
        .map_err(|error| FactoryDecodeError::InvalidProviderOptionsNamespace(error.to_string()))?
        .with_media_type("application/json")
        .map_err(|error| invalid_value("providerOptions", error.to_string()))?;
        let key = extension.key();
        report.preserve_extension(&key);
        extensions.insert(extension);
    }
    Ok(())
}

/// Encodes semantic events as LanguageModel V3 JSON stream parts.
#[derive(Clone, Copy, Debug, Default)]
pub struct FactoryEventEncoder;

/// One encoded Factory event and the accounting for its conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedFactoryEvent {
    /// UTF-8 JSON or SSE bytes.
    pub body: Vec<u8>,
    /// Explicit preservation and loss accounting.
    pub report: ConversionReport,
}

impl FactoryEventEncoder {
    /// Encodes one semantic event as compact JSON without SSE framing.
    pub fn encode_json(
        &self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<EncodedFactoryEvent, FactoryEncodeError> {
        let (value, report) = self.encode_value(event, policy)?;
        let body = serde_json::to_vec(&value).map_err(FactoryEncodeError::Json)?;
        Ok(EncodedFactoryEvent { body, report })
    }

    /// Encodes one event as an SSE data record.
    pub fn encode_sse(
        &self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<EncodedFactoryEvent, FactoryEncodeError> {
        self.encode_sse_with_limits(event, policy, SseLimits::default())
    }

    /// Encodes one event as SSE with explicit transport bounds.
    pub fn encode_sse_with_limits(
        &self,
        event: &StreamEvent,
        policy: LossPolicy,
        limits: SseLimits,
    ) -> Result<EncodedFactoryEvent, FactoryEncodeError> {
        let encoded = self.encode_json(event, policy)?;
        let data =
            String::from_utf8(encoded.body).map_err(|_| FactoryEncodeError::InvalidUtf8Json)?;
        let mut body = SseEncoder::with_limits(limits)
            .encode(&SseEvent::new(data))
            .map_err(FactoryEncodeError::Sse)?;
        add_factory_data_space(&mut body, limits).map_err(FactoryEncodeError::Sse)?;
        Ok(EncodedFactoryEvent {
            body,
            report: encoded.report,
        })
    }

    fn encode_value(
        &self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<(Value, ConversionReport), FactoryEncodeError> {
        let mut report = ConversionReport::default();
        let mut part = match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                let mut value = object_with_type("response-metadata");
                insert_optional_string(&mut value, "id", response_id.as_deref());
                insert_optional_string(&mut value, "modelId", model.as_deref());
                value
            }
            StreamEventKind::Metadata { values } => {
                let mut metadata = Map::new();
                metadata.insert(
                    "factory".to_owned(),
                    Value::Object(
                        values
                            .iter()
                            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                            .collect(),
                    ),
                );
                let mut value = object_with_type("response-metadata");
                value.insert("providerMetadata".to_owned(), Value::Object(metadata));
                value
            }
            StreamEventKind::TextStart => block_value("text-start", event, None)?,
            StreamEventKind::TextDelta { text } => block_value(
                "text-delta",
                event,
                Some(("delta", Value::String(text.clone()))),
            )?,
            StreamEventKind::TextEnd => block_value("text-end", event, None)?,
            StreamEventKind::ReasoningStart => block_value("reasoning-start", event, None)?,
            StreamEventKind::ReasoningDelta { text } => block_value(
                "reasoning-delta",
                event,
                Some(("delta", Value::String(text.clone()))),
            )?,
            StreamEventKind::ReasoningEnd { reasoning } => {
                let mut value = block_value("reasoning-end", event, None)?;
                if let Some(reasoning) = reasoning {
                    value.insert(
                        "providerMetadata".to_owned(),
                        serde_json::json!({
                            "pooler": {
                                "reasoning": reasoning,
                            }
                        }),
                    );
                    report.preserve_capability("reasoning.final_metadata");
                }
                value
            }
            StreamEventKind::ToolCallStart { id, name } => {
                let mut value = object_with_type("tool-input-start");
                value.insert("id".to_owned(), Value::String(id.clone()));
                value.insert("toolName".to_owned(), Value::String(name.clone()));
                value
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                let mut value = object_with_type("tool-input-delta");
                value.insert("id".to_owned(), Value::String(id.clone()));
                value.insert("delta".to_owned(), Value::String(arguments.clone()));
                value
            }
            StreamEventKind::ToolCallEnd { id } => {
                let mut value = object_with_type("tool-input-end");
                value.insert("id".to_owned(), Value::String(id.clone()));
                value
            }
            StreamEventKind::Media { media_type, source } => {
                let mut value = object_with_type("file");
                value.insert("mediaType".to_owned(), Value::String(media_type.clone()));
                value.insert("data".to_owned(), encode_media_source(source));
                value
            }
            StreamEventKind::Usage { usage } => {
                let mut metadata = Map::new();
                metadata.insert("usage".to_owned(), encode_usage(usage, &mut report));
                let mut provider_metadata = Map::new();
                provider_metadata.insert("factory".to_owned(), Value::Object(metadata));
                let mut value = object_with_type("response-metadata");
                value.insert(
                    "providerMetadata".to_owned(),
                    Value::Object(provider_metadata),
                );
                value
            }
            StreamEventKind::Refusal { .. } => {
                return Err(FactoryEncodeError::UnsupportedEvent("refusal"))
            }
            StreamEventKind::Warning { warning } => {
                let warning = match warning.severity {
                    pooler_protocol::WarningSeverity::Info => {
                        json_warning("compatibility", warning.field.as_deref(), &warning.message)
                    }
                    pooler_protocol::WarningSeverity::Warning => {
                        json_warning("other", None, &warning.message)
                    }
                };
                let mut value = object_with_type("stream-start");
                value.insert("warnings".to_owned(), Value::Array(vec![warning]));
                value
            }
            StreamEventKind::Completion {
                finish_reason,
                usage,
            } => {
                let usage = usage.as_ref().ok_or(FactoryEncodeError::MissingUsage)?;
                let mut value = object_with_type("finish");
                value.insert("usage".to_owned(), encode_usage(usage, &mut report));
                let (unified, raw) = encode_finish_reason(finish_reason);
                let mut finish = Map::new();
                finish.insert("unified".to_owned(), Value::String(unified.to_owned()));
                if let Some(raw) = raw {
                    finish.insert("raw".to_owned(), Value::String(raw));
                    report.preserve_capability("finish_reason.raw");
                }
                value.insert("finishReason".to_owned(), Value::Object(finish));
                value
            }
            StreamEventKind::Failure { error } => {
                let mut value = object_with_type("error");
                value.insert("error".to_owned(), encode_stream_error(error));
                value
            }
            StreamEventKind::Opaque { media_type, data } => {
                let mut value = object_with_type("raw");
                value.insert(
                    "rawValue".to_owned(),
                    serde_json::json!({
                        "mediaType": media_type,
                        "data": encode_base64(data),
                    }),
                );
                report.preserve_capability("event.raw");
                value
            }
        };
        attach_extensions(&mut part, &event.extensions, &mut report)?;
        report
            .validate(policy)
            .map_err(FactoryEncodeError::Conversion)?;
        Ok((Value::Object(part), report))
    }
}

fn add_factory_data_space(body: &mut Vec<u8>, limits: SseLimits) -> Result<(), SseError> {
    if !body.starts_with(b"data:") || body.starts_with(b"data: ") {
        return Ok(());
    }
    let line_length = body
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(body.len())
        .saturating_add(1);
    if line_length > limits.max_line_bytes {
        return Err(SseError::LineTooLarge {
            limit: limits.max_line_bytes,
            observed: line_length,
        });
    }
    let event_length = body.len().saturating_add(1);
    if event_length > limits.max_event_bytes {
        return Err(SseError::EventTooLarge {
            limit: limits.max_event_bytes,
            observed: event_length,
        });
    }
    body.insert(5, b' ');
    Ok(())
}

/// Errors raised while encoding semantic events for LanguageModel V3.
#[derive(Debug, Error)]
pub enum FactoryEncodeError {
    /// Event JSON could not be serialized.
    #[error("cannot serialize Factory stream event: {0}")]
    Json(#[from] serde_json::Error),
    /// The JSON serializer returned bytes that were not UTF-8.
    #[error("Factory stream JSON was not valid UTF-8")]
    InvalidUtf8Json,
    /// SSE framing rejected the event under its configured bounds.
    #[error("cannot frame Factory stream event as SSE: {0}")]
    Sse(#[from] SseError),
    /// The selected loss policy rejected an event conversion.
    #[error("Factory stream conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    /// A block lifecycle event did not identify its block.
    #[error("Factory {0} event requires a block identifier")]
    MissingBlockId(&'static str),
    /// LanguageModel V3 has no lossless representation for this event.
    #[error("Factory LanguageModel V3 does not represent semantic {0} events")]
    UnsupportedEvent(&'static str),
    /// LanguageModel V3 requires usage on its finish part.
    #[error("Factory finish event requires token usage")]
    MissingUsage,
    /// A provider extension collided with a standard metadata field.
    #[error("Factory provider extension `{0}` collides with standard metadata")]
    ExtensionCollision(String),
}

fn normalize_tool_results(
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), FactoryAdapterError> {
    let mut normalized = Vec::with_capacity(request.input.len());
    for item in std::mem::take(&mut request.input) {
        let InputItem::Message(message) = item else {
            normalized.push(item);
            continue;
        };
        if message.role != Role::Tool {
            normalized.push(InputItem::Message(message));
            continue;
        }
        for extension in message.extensions {
            report.drop_optional(
                format!("prompt[].{}", extension.key().as_str()),
                "OpenAI Chat tool-result messages have no message-level provider options",
            );
        }
        for part in message.content {
            let ContentPart::ToolResult(result) = part else {
                return Err(FactoryAdapterError::InvalidToolMessageContent);
            };
            normalized.push(InputItem::ToolResult(result));
        }
    }
    request.input = normalized;
    Ok(())
}

impl SemanticAdapter for FactorySemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        route.ingress().mode() == pooler_core::BodyMode::Semantic
            && route.ingress().decoder() == Some("decode.factory.language_model")
            && route.response().mode() == pooler_core::BodyMode::Semantic
            && route.response().decoder() == Some("decode.openai.chat.events")
            && route.response().encoder() == Some("encode.factory.events")
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        validate_factory_headers(headers)?;
        let model = headers
            .get(MODEL_ID_HEADER)
            .ok_or(FactoryAdapterError::MissingModelHeader)?
            .to_str()
            .map_err(|_| FactoryAdapterError::InvalidModelHeader)?
            .trim();
        if model.is_empty() {
            return Err(Box::new(FactoryAdapterError::MissingModelHeader));
        }
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
        normalize_tool_results(&mut decoded.request, &mut decoded.report)
            .map_err(|error| Box::new(error) as BoxError)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(|error| Box::new(error) as BoxError)?;
        let encoded =
            pooler_protocol::OpenAiChatCodec::encode_request(&decoded.request, route.loss_policy())
                .map_err(|error| Box::new(error) as BoxError)?;
        let mut value: Value =
            serde_json::from_slice(&encoded.body).map_err(|error| Box::new(error) as BoxError)?;
        let object = value
            .as_object_mut()
            .ok_or(FactoryAdapterError::EncodedRequestNotObject)?;
        object.insert("stream".to_owned(), Value::Bool(true));
        object.insert(
            "stream_options".to_owned(),
            serde_json::json!({"include_usage": true}),
        );
        Ok(SemanticRequestBody {
            body: serde_json::to_vec(&value)?,
            content_type: HeaderValue::from_static("application/json"),
            response_hint: pooler_http::SemanticResponseHint::default(),
        })
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        validate_factory_headers(headers)?;
        let model = headers
            .get(MODEL_ID_HEADER)
            .ok_or(FactoryAdapterError::MissingModelHeader)?
            .to_str()
            .map_err(|_| FactoryAdapterError::InvalidModelHeader)?
            .trim();
        if model.is_empty() {
            return Err(Box::new(FactoryAdapterError::MissingModelHeader));
        }
        let decoder = FactoryLanguageModelDecoder::new(FactoryDecodeOptions {
            file_policy: if route.loss_policy().allows_degradation() {
                FactoryFilePolicy::Degrade
            } else {
                FactoryFilePolicy::Reject
            },
            ..FactoryDecodeOptions::default()
        });
        let decoded = decoder
            .decode(body, model)
            .map_err(|error| Box::new(error) as BoxError)?;
        decoded
            .report
            .validate(route.loss_policy())
            .map_err(|error| Box::new(error) as BoxError)?;
        let mut context = SelectionContext::from_semantic_request(&decoded.request);
        context.require(pooler_core::Capability::Streaming);
        if let Some(codec) = route.ingress().decoder() {
            context.with_codec(codec);
        }
        let value: Value = serde_json::from_slice(body)?;
        add_factory_affinity_values(&value, &mut context);
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
        let line_limit = usize_limit(route.limits().max_frame_bytes);
        let event_limit = usize_limit(route.limits().max_event_bytes);
        let limits = SseLimits::new(line_limit, event_limit);
        let stream = FactoryResponseBody::new(
            body,
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

fn add_factory_affinity_values(value: &Value, context: &mut SelectionContext) {
    let Some(object) = value.as_object() else {
        return;
    };
    for (name, value) in object {
        if let Some(value) = value.as_str().filter(|value| !value.is_empty()) {
            match name.as_str() {
                "sessionId" | "session_id" => {
                    context.with_affinity_value("request.session_id", value);
                    context.with_affinity_value("semantic.session_id", value);
                }
                "conversationId" | "conversation_id" => {
                    context.with_affinity_value("request.session_id", value);
                    context.with_affinity_value("semantic.session_id", value);
                }
                "previousResponseId" | "previous_response_id" | "previousResponseID" => {
                    context.with_affinity_value("openai.previous_response_id", value);
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Error)]
enum FactoryAdapterError {
    #[error("missing {MODEL_ID_HEADER} header")]
    MissingModelHeader,
    #[error("{MODEL_ID_HEADER} header is not valid UTF-8")]
    InvalidModelHeader,
    #[error("encoded OpenAI request is not an object")]
    EncodedRequestNotObject,
    #[error("Factory tool messages may contain only tool-result parts")]
    InvalidToolMessageContent,
    #[error("Factory specification version must be 3 or 4")]
    InvalidSpecificationVersion,
    #[error("Factory Gateway protocol version must be {GATEWAY_PROTOCOL_VERSION}")]
    InvalidGatewayProtocolVersion,
    #[error("Factory streaming header is not valid")]
    InvalidStreamingHeader,
    #[error("Factory semantic route requires streaming=true")]
    StreamingDisabled,
}

fn validate_factory_headers(headers: &HeaderMap) -> Result<(), FactoryAdapterError> {
    let specification = headers
        .get(SPECIFICATION_VERSION_HEADER)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| FactoryAdapterError::InvalidSpecificationVersion)
        })
        .transpose()?
        .map(str::trim)
        .unwrap_or(SPECIFICATION_VERSION_V3);
    if !matches!(
        specification,
        SPECIFICATION_VERSION_V3 | SPECIFICATION_VERSION_V4
    ) {
        return Err(FactoryAdapterError::InvalidSpecificationVersion);
    }
    if let Some(value) = headers.get(GATEWAY_PROTOCOL_VERSION_HEADER) {
        let value = value
            .to_str()
            .map_err(|_| FactoryAdapterError::InvalidGatewayProtocolVersion)?;
        if value.trim() != GATEWAY_PROTOCOL_VERSION || specification != SPECIFICATION_VERSION_V4 {
            return Err(FactoryAdapterError::InvalidGatewayProtocolVersion);
        }
    } else if specification == SPECIFICATION_VERSION_V4 {
        return Err(FactoryAdapterError::InvalidGatewayProtocolVersion);
    }
    if let Some(value) = headers.get(STREAMING_HEADER) {
        let value = value
            .to_str()
            .map_err(|_| FactoryAdapterError::InvalidStreamingHeader)?;
        if !value.eq_ignore_ascii_case("true") {
            if value.eq_ignore_ascii_case("false") {
                return Err(FactoryAdapterError::StreamingDisabled);
            }
            return Err(FactoryAdapterError::InvalidStreamingHeader);
        }
    }
    Ok(())
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

struct FactoryResponseBody {
    inner: Pin<Box<ProxyBody>>,
    parser: SseParser,
    limits: SseLimits,
    decoder: OpenAiChatEventDecoder,
    encoder: FactoryEventEncoder,
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

impl FactoryResponseBody {
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
            decoder: OpenAiChatEventDecoder::new(),
            encoder: FactoryEventEncoder,
            policy,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_queue_items,
            max_queue_bytes,
            cancellation,
            done_seen: false,
            ended: false,
            error: None,
        }
    }

    fn set_error(&mut self, error: BoxError) {
        if self.error.is_some() {
            return;
        }
        let mut terminal_enqueued = false;
        if !self.done_seen {
            let failure = StreamEvent::new(
                0,
                StreamEventKind::Failure {
                    error: StreamError::new(
                        "invalid_upstream_stream",
                        "the upstream semantic stream could not be converted",
                    ),
                },
            );
            if let Ok(encoded) =
                self.encoder
                    .encode_sse_with_limits(&failure, self.policy, self.limits)
            {
                if self.enqueue(Bytes::from(encoded.body)).is_ok() {
                    if let Ok(done) = self.done_bytes() {
                        terminal_enqueued = self.enqueue(done).is_ok();
                    }
                }
            }
        }
        if terminal_enqueued {
            self.ended = true;
            return;
        }
        self.error = Some(error);
    }

    fn done_bytes(&self) -> Result<Bytes, BoxError> {
        let mut done = SseEncoder::with_limits(self.limits)
            .encode(&SseEvent::new("[DONE]"))
            .map_err(|error| Box::new(error) as BoxError)?;
        add_factory_data_space(&mut done, self.limits)
            .map_err(|error| Box::new(error) as BoxError)?;
        Ok(Bytes::from(done))
    }

    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        let events = self
            .parser
            .feed(chunk)
            .map_err(|error| Box::new(error) as BoxError)?;
        for event in events {
            self.process_sse_event(&event)?;
        }
        Ok(())
    }

    fn process_sse_event(&mut self, event: &SseEvent) -> Result<(), BoxError> {
        if event.is_done() {
            if self.done_seen {
                return Err(Box::new(FactoryStreamError::DuplicateDone));
            }
            self.done_seen = true;
        }
        let events = self
            .decoder
            .decode_data(event.data.as_bytes())
            .map_err(|error| Box::new(error) as BoxError)?;
        for event in events {
            let encoded = self
                .encoder
                .encode_sse_with_limits(&event, self.policy, self.limits)
                .map_err(|error| Box::new(error) as BoxError)?;
            self.enqueue(Bytes::from(encoded.body))?;
        }
        if event.is_done() {
            let done = self.done_bytes()?;
            self.enqueue(done)?;
        }
        Ok(())
    }

    fn enqueue(&mut self, bytes: Bytes) -> Result<(), BoxError> {
        let next_items = self.queue.len().saturating_add(1);
        let next_bytes = self.queued_bytes.saturating_add(bytes.len());
        if next_items > self.max_queue_items || next_bytes > self.max_queue_bytes {
            return Err(Box::new(FactoryStreamError::QueueLimit {
                items: next_items,
                bytes: next_bytes,
            }));
        }
        self.queued_bytes = next_bytes;
        self.queue.push_back(bytes);
        Ok(())
    }

    fn finish_upstream(&mut self) -> Result<(), BoxError> {
        let events = self
            .parser
            .finish()
            .map_err(|error| Box::new(error) as BoxError)?;
        for event in events {
            self.process_sse_event(&event)?;
        }
        if !self.done_seen {
            return Err(Box::new(FactoryStreamError::MissingDone));
        }
        self.ended = true;
        Ok(())
    }
}

impl Body for FactoryResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.cancellation.is_cancelled() {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(FactoryStreamError::Cancelled))));
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
                if let Some(bytes) = this.queue.pop_front() {
                    this.queued_bytes = this.queued_bytes.saturating_sub(bytes.len());
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                } else {
                    Poll::Ready(None)
                }
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
                        this.set_error(Box::new(FactoryStreamError::InvalidFrame));
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
enum FactoryStreamError {
    #[error("Factory upstream SSE ended without [DONE]")]
    MissingDone,
    #[error("Factory upstream SSE contained duplicate [DONE] markers")]
    DuplicateDone,
    #[error("Factory semantic response queue exceeded {items} items or {bytes} bytes")]
    QueueLimit { items: usize, bytes: usize },
    #[error("Factory semantic response contained an invalid body frame")]
    InvalidFrame,
    #[error("Factory semantic response canceled")]
    Cancelled,
}

fn object_with_type(kind: &str) -> Map<String, Value> {
    let mut value = Map::new();
    value.insert("type".to_owned(), Value::String(kind.to_owned()));
    value
}

fn block_value(
    kind: &'static str,
    event: &StreamEvent,
    field: Option<(&'static str, Value)>,
) -> Result<Map<String, Value>, FactoryEncodeError> {
    let id = event
        .effective_block_id()
        .ok_or(FactoryEncodeError::MissingBlockId(kind))?;
    let mut value = object_with_type(kind);
    value.insert("id".to_owned(), Value::String(id.to_owned()));
    if let Some((field_name, field_value)) = field {
        value.insert(field_name.to_owned(), field_value);
    }
    Ok(value)
}

fn insert_optional_string(value: &mut Map<String, Value>, key: &str, data: Option<&str>) {
    if let Some(data) = data {
        value.insert(key.to_owned(), Value::String(data.to_owned()));
    }
}

fn encode_media_source(source: &MediaSource) -> Value {
    match source {
        MediaSource::Inline(bytes) => serde_json::json!({
            "type": "data",
            "data": encode_base64(bytes),
        }),
        MediaSource::Uri(uri) => serde_json::json!({
            "type": "url",
            "url": uri,
        }),
    }
}

fn encode_usage(usage: &Usage, report: &mut ConversionReport) -> Value {
    let mut input = Map::new();
    input.insert("total".to_owned(), Value::from(usage.input_tokens));
    let no_cache = usage
        .cached_input_tokens
        .map(|cached| usage.input_tokens.saturating_sub(cached))
        .unwrap_or(usage.input_tokens);
    input.insert("noCache".to_owned(), Value::from(no_cache));
    if let Some(cached) = usage.cached_input_tokens {
        input.insert("cacheRead".to_owned(), Value::from(cached));
    }
    let mut output = Map::new();
    output.insert("total".to_owned(), Value::from(usage.output_tokens));
    if let Some(reasoning) = usage.reasoning_tokens {
        output.insert("reasoning".to_owned(), Value::from(reasoning));
        output.insert(
            "text".to_owned(),
            Value::from(usage.output_tokens.saturating_sub(reasoning)),
        );
    } else {
        output.insert("text".to_owned(), Value::from(usage.output_tokens));
    }
    let mut value = Map::new();
    value.insert("inputTokens".to_owned(), Value::Object(input));
    value.insert("outputTokens".to_owned(), Value::Object(output));
    if let Some(total) = usage.total_tokens {
        value.insert("totalTokens".to_owned(), Value::from(total));
        report.preserve_capability("usage.total_tokens");
    }
    if !usage.details.is_empty() {
        value.insert(
            "details".to_owned(),
            Value::Object(
                usage
                    .details
                    .iter()
                    .map(|(key, value)| (key.clone(), Value::from(*value)))
                    .collect(),
            ),
        );
        report.preserve_capability("usage.details");
    }
    Value::Object(value)
}

fn encode_finish_reason(reason: &FinishReason) -> (&'static str, Option<String>) {
    match reason {
        FinishReason::Stop => ("stop", None),
        FinishReason::Length => ("length", None),
        FinishReason::ToolCall => ("tool-calls", None),
        FinishReason::ContentFilter => ("content-filter", None),
        FinishReason::Error => ("error", None),
        FinishReason::Other(raw) => ("other", Some(raw.clone())),
    }
}

fn encode_stream_error(error: &StreamError) -> Value {
    let mut value = Map::new();
    value.insert("code".to_owned(), Value::String(error.code.clone()));
    value.insert("message".to_owned(), Value::String(error.message.clone()));
    value.insert("retryable".to_owned(), Value::Bool(error.retryable));
    if let Some(details) = &error.details {
        value.insert("details".to_owned(), details.value().clone());
    }
    Value::Object(value)
}

fn json_warning(kind: &str, feature: Option<&str>, message: &str) -> Value {
    let mut value = Map::new();
    value.insert("type".to_owned(), Value::String(kind.to_owned()));
    if kind == "other" {
        value.insert("message".to_owned(), Value::String(message.to_owned()));
    } else {
        value.insert(
            "feature".to_owned(),
            Value::String(feature.unwrap_or("conversion").to_owned()),
        );
        value.insert("details".to_owned(), Value::String(message.to_owned()));
    }
    Value::Object(value)
}

fn attach_extensions(
    value: &mut Map<String, Value>,
    extensions: &Extensions,
    report: &mut ConversionReport,
) -> Result<(), FactoryEncodeError> {
    if extensions.is_empty() {
        return Ok(());
    }
    let provider_metadata = value
        .entry("providerMetadata")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(providers) = provider_metadata else {
        return Err(FactoryEncodeError::ExtensionCollision(
            "providerMetadata".to_owned(),
        ));
    };
    for (key, extension) in extensions.iter() {
        let entry = providers
            .entry(key.namespace.as_str().to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(entry) = entry else {
            return Err(FactoryEncodeError::ExtensionCollision(key.as_str()));
        };
        if entry.contains_key(key.name.as_str()) {
            return Err(FactoryEncodeError::ExtensionCollision(key.as_str()));
        }
        let payload = serde_json::from_slice::<Value>(extension.as_bytes())
            .unwrap_or_else(|_| Value::String(encode_base64(extension.as_bytes())));
        entry.insert(key.name.as_str().to_owned(), payload);
        report.preserve_extension(key);
    }
    Ok(())
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        result.push(TABLE[(first >> 2) as usize] as char);
        result.push(TABLE[((first & 0x03) << 4 | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            result.push(TABLE[((second & 0x0f) << 2 | (third >> 6)) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(TABLE[(third & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn decode_base64(value: &str) -> Result<Vec<u8>, Base64Error> {
    if value.len() % 4 == 1 {
        return Err(Base64Error::Length);
    }
    let bytes = value.as_bytes();
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || bytes[..bytes.len().saturating_sub(padding)].contains(&b'=') {
        return Err(Base64Error::Padding);
    }

    let mut output = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.chunks(4) {
        let first = base64_value(chunk[0]).ok_or(Base64Error::Character)?;
        let second = base64_value(*chunk.get(1).ok_or(Base64Error::Length)?)
            .ok_or(Base64Error::Character)?;
        output.push((first << 2) | (second >> 4));

        if let Some(third) = chunk.get(2).copied().filter(|byte| *byte != b'=') {
            let third = base64_value(third).ok_or(Base64Error::Character)?;
            output.push((second << 4) | (third >> 2));
            if let Some(fourth) = chunk.get(3).copied().filter(|byte| *byte != b'=') {
                let fourth = base64_value(fourth).ok_or(Base64Error::Character)?;
                output.push((third << 6) | fourth);
            }
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum Base64Error {
    #[error("base64 has an invalid length")]
    Length,
    #[error("base64 has an invalid character")]
    Character,
    #[error("base64 has invalid padding")]
    Padding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pooler_protocol::InputItem;
    use serde_json::json;

    fn request_body() -> Value {
        json!({
            "prompt": [
                {"role": "system", "content": "You are concise."},
                {"role": "user", "content": [
                    {"type": "text", "text": "Find the answer."},
                    {"type": "file", "mediaType": "image/png", "data": [1, 2, 3]}
                ]},
                {"role": "assistant", "content": [
                    {"type": "tool-call", "toolCallId": "call-1", "toolName": "search", "input": {"q": "answer"}}
                ]},
                {"role": "tool", "content": [
                    {"type": "tool-result", "toolCallId": "call-1", "toolName": "search", "output": {"type": "text", "value": "result"}}
                ]},
            ],
            "tools": [{
                "type": "function",
                "name": "search",
                "description": "Search",
                "inputSchema": {"type": "object"},
                "strict": true
            }],
            "toolChoice": {"type": "auto"},
            "responseFormat": {"type": "json"},
            "temperature": 0.2,
            "maxOutputTokens": 20,
            "providerOptions": {"factory": {"trace": "test"}}
        })
    }

    #[test]
    fn decodes_prompt_tools_and_provider_options() {
        let decoded = FactoryLanguageModelDecoder::default()
            .decode_value(&request_body(), "factory-model")
            .expect("request");
        assert_eq!(decoded.request.model, "factory-model");
        assert_eq!(decoded.request.input.len(), 4);
        assert_eq!(decoded.request.tools[0].name, "search");
        assert_eq!(decoded.request.tool_choice, Some(ToolChoice::Auto));
        assert_eq!(
            decoded.request.response_format,
            Some(ResponseFormat::JsonObject)
        );
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.options"));
    }

    #[test]
    fn rejects_tool_choice_targeting_a_dropped_provider_tool() {
        let value = json!({
            "prompt": [{"role": "user", "content": [
                {"type": "text", "text": "hello"}
            ]}],
            "tools": [{
                "type": "provider",
                "name": "web_search"
            }],
            "toolChoice": {"type": "tool", "toolName": "web_search"}
        });

        let error = FactoryLanguageModelDecoder::default()
            .decode_value(&value, "factory-model")
            .expect_err("provider tool target must be rejected");

        assert!(error.to_string().contains("toolChoice.toolName"));
    }

    #[test]
    fn accounts_for_documented_fields_without_silent_drops() {
        let value = json!({
            "prompt": [{"role": "user", "content": [
                {"type": "text", "text": "hello", "providerOptions": {"factory": {"trace": true}}},
                {"type": "reasoning", "text": "think", "providerOptions": {"factory": {"reasoning": true}}}
            ]}],
            "tools": [{
                "type": "function",
                "name": "search",
                "inputSchema": {"type": "object"},
                "inputExamples": [{"input": {"query": "pooler"}}]
            }],
            "topK": 4,
            "responseFormat": {
                "type": "json",
                "schema": {"type": "object"},
                "name": "answer",
                "description": "structured answer",
                "strict": true
            }
        });
        let decoded = FactoryLanguageModelDecoder::default()
            .decode_value(&value, "factory-model")
            .expect("request");
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.input_examples"));
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.response_format"));
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.top_k"));
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.options"));
        assert!(decoded
            .report
            .dropped_optional_fields
            .iter()
            .any(|field| field == "prompt[0].content[0].providerOptions"));
        assert!(decoded.report.validate(LossPolicy::Reject).is_err());
        assert!(decoded.report.validate(LossPolicy::Degrade).is_ok());
        assert_eq!(
            decoded
                .request
                .sampling
                .extensions
                .get_str("factory.top_k")
                .unwrap()
                .as_bytes(),
            b"4"
        );
        assert_eq!(
            decoded.request.response_format,
            Some(ResponseFormat::JsonSchema {
                name: "answer".to_owned(),
                schema: PreservedJson::from_str("{\"type\":\"object\"}").unwrap(),
                strict: true,
            })
        );
    }

    #[test]
    fn preserves_nested_tool_result_provider_options() {
        let value = json!({
            "prompt": [{"role": "tool", "content": [{
                "type": "tool-result",
                "toolCallId": "call-1",
                "toolName": "search",
                "output": {
                    "type": "text",
                    "value": "result",
                    "providerOptions": {"factory": {"trace": "nested"}}
                },
                "providerOptions": {"factory": {"trace": "outer"}}
            }]}]
        });
        let decoded = FactoryLanguageModelDecoder::default()
            .decode_value(&value, "factory-model")
            .expect("tool result");
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.tool_result_output_options"));
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.tool_result_name"));
        assert!(decoded.report.is_lossless());
        assert!(decoded.report.validate(LossPolicy::Reject).is_ok());
        let InputItem::Message(message) = &decoded.request.input[0] else {
            panic!("message input");
        };
        let ContentPart::ToolResult(result) = &message.content[0] else {
            panic!("tool result content");
        };
        assert!(result
            .extensions
            .get_str("factory.tool_result_output_options")
            .is_some());
    }

    #[test]
    fn preserves_tool_provider_execution_metadata() {
        let value = json!({
            "prompt": [{"role": "assistant", "content": [{
                "type": "tool-call",
                "toolCallId": "call-1",
                "toolName": "search",
                "input": {"query": "pooler"},
                "providerExecuted": true
            }]}]
        });
        let decoded = FactoryLanguageModelDecoder::default()
            .decode_value(&value, "factory-model")
            .expect("tool call");
        assert!(decoded
            .report
            .preserved_extensions
            .iter()
            .any(|key| key.as_str() == "factory.tool_call_provider_executed"));
        let InputItem::Message(message) = &decoded.request.input[0] else {
            panic!("message input");
        };
        let ContentPart::ToolCall(call) = &message.content[0] else {
            panic!("tool call content");
        };
        assert!(call
            .extensions
            .get_str("factory.tool_call_provider_executed")
            .is_some());
    }

    #[test]
    fn rejects_non_image_files_by_default() {
        let value = json!({
            "prompt": [{"role": "user", "content": [{
                "type": "file", "mediaType": "application/pdf", "data": "document"
            }]}]
        });
        let error = FactoryLanguageModelDecoder::default()
            .decode_value(&value, "model")
            .expect_err("file should be rejected");
        assert!(matches!(error, FactoryDecodeError::UnsupportedFile(_)));
    }

    #[test]
    fn file_degrade_policy_records_loss() {
        let value = json!({
            "prompt": [{"role": "user", "content": [{
                "type": "file", "mediaType": "application/pdf", "data": "document"
            }]}]
        });
        let options = FactoryDecodeOptions {
            file_policy: FactoryFilePolicy::Degrade,
            ..FactoryDecodeOptions::default()
        };
        let decoded = FactoryLanguageModelDecoder::new(options)
            .decode_value(&value, "model")
            .expect("degraded file");
        assert!(decoded
            .report
            .degraded_fields
            .iter()
            .any(|field| field.starts_with("prompt[0]")));
    }

    #[test]
    fn tagged_media_data_distinguishes_base64_from_url() {
        let value = json!({
            "prompt": [{"role": "user", "content": [
                {"type": "file", "mediaType": "image/png", "data": {"type": "data", "data": "aGVsbG8="}},
                {"type": "file", "mediaType": "image/png", "data": {"type": "url", "url": "https://example.test/image.png"}}
            ]}]
        });
        let decoded = FactoryLanguageModelDecoder::default()
            .decode_value(&value, "model")
            .expect("media parts");
        let InputItem::Message(message) = &decoded.request.input[0] else {
            panic!("message input");
        };
        assert_eq!(
            message.content[0],
            ContentPart::image("image/png", MediaSource::inline(b"hello".to_vec()))
        );
        assert_eq!(
            message.content[1],
            ContentPart::image(
                "image/png",
                MediaSource::uri("https://example.test/image.png")
            )
        );

        let bare_value = json!({
            "prompt": [{"role": "user", "content": [
                {"type": "file", "mediaType": "image/png", "data": "aGVsbG8="},
                {"type": "file", "mediaType": "image/png", "data": "https://example.test/image.png"}
            ]}]
        });
        let decoded = FactoryLanguageModelDecoder::default()
            .decode_value(&bare_value, "model")
            .expect("bare media parts");
        let InputItem::Message(message) = &decoded.request.input[0] else {
            panic!("message input");
        };
        assert_eq!(
            message.content[0],
            ContentPart::image("image/png", MediaSource::inline(b"hello".to_vec()))
        );
        assert_eq!(
            message.content[1],
            ContentPart::image(
                "image/png",
                MediaSource::uri("https://example.test/image.png")
            )
        );
    }

    #[test]
    fn encoded_media_parts_keep_their_source_kind() {
        let inline = StreamEvent::new(
            1,
            StreamEventKind::Media {
                media_type: "image/png".to_owned(),
                source: MediaSource::inline(vec![1, 2, 3]),
            },
        );
        let uri = StreamEvent::new(
            2,
            StreamEventKind::Media {
                media_type: "image/png".to_owned(),
                source: MediaSource::uri("https://example.test/image.png"),
            },
        );
        let inline: Value = serde_json::from_slice(
            &FactoryEventEncoder
                .encode_json(&inline, LossPolicy::Reject)
                .expect("inline event")
                .body,
        )
        .expect("inline JSON");
        let uri: Value = serde_json::from_slice(
            &FactoryEventEncoder
                .encode_json(&uri, LossPolicy::Reject)
                .expect("URI event")
                .body,
        )
        .expect("URI JSON");
        assert_eq!(inline["data"]["type"], "data");
        assert_eq!(inline["data"]["data"], "AQID");
        assert_eq!(uri["data"]["type"], "url");
        assert_eq!(uri["data"]["url"], "https://example.test/image.png");
    }

    #[test]
    fn encodes_v3_stream_parts_with_sse_framing() {
        let event = StreamEvent::new(
            1,
            StreamEventKind::TextDelta {
                text: "hello".into(),
            },
        )
        .with_block_id("text-1");
        let encoded = FactoryEventEncoder
            .encode_sse(&event, LossPolicy::Reject)
            .expect("event");
        assert!(encoded.report.is_lossless());
        assert!(encoded.body.starts_with(b"data:"));
        assert!(encoded.body.ends_with(b"\n\n"));
        let value: Value =
            serde_json::from_slice(&encoded.body[5..encoded.body.len() - 2]).expect("JSON");
        assert_eq!(value["type"], "text-delta");
        assert_eq!(value["id"], "text-1");
        assert_eq!(value["delta"], "hello");
    }

    #[test]
    fn encodes_completion_usage_and_finish_reason() {
        let event = StreamEvent::new(
            2,
            StreamEventKind::Completion {
                finish_reason: FinishReason::ToolCall,
                usage: Some(Usage::new(3, 4)),
            },
        );
        let value: Value = serde_json::from_slice(
            &FactoryEventEncoder
                .encode_json(&event, LossPolicy::Reject)
                .expect("event")
                .body,
        )
        .expect("JSON");
        assert_eq!(value["type"], "finish");
        assert_eq!(value["finishReason"]["unified"], "tool-calls");
        assert_eq!(value["usage"]["inputTokens"]["total"], 3);
        assert_eq!(value["usage"]["outputTokens"]["total"], 4);
    }

    #[test]
    fn preserves_reasoning_final_metadata_usage_details_and_raw_events() {
        let reasoning = ReasoningBlock {
            id: Some("reasoning-1".to_owned()),
            text: Some("private chain".to_owned()),
            summary: Some("summary".to_owned()),
            encrypted_content: Some(vec![1, 2]),
            signature: Some(vec![3, 4]),
            extensions: Extensions::default(),
        };
        let reasoning_event = StreamEvent::new(
            1,
            StreamEventKind::ReasoningEnd {
                reasoning: Some(reasoning),
            },
        )
        .with_block_id("reasoning-1");
        let reasoning_encoded = FactoryEventEncoder
            .encode_json(&reasoning_event, LossPolicy::Reject)
            .expect("reasoning metadata");
        let reasoning_value: Value =
            serde_json::from_slice(&reasoning_encoded.body).expect("reasoning JSON");
        assert_eq!(
            reasoning_value["providerMetadata"]["pooler"]["reasoning"]["summary"],
            "summary"
        );
        assert!(reasoning_encoded
            .report
            .preserved_capabilities
            .contains(&"reasoning.final_metadata".to_owned()));

        let mut usage = Usage::new(3, 4);
        usage.total_tokens = Some(99);
        usage.details.insert("cache_write".to_owned(), 5);
        let usage_event = StreamEvent::new(
            2,
            StreamEventKind::Completion {
                finish_reason: FinishReason::Stop,
                usage: Some(usage),
            },
        );
        let usage_encoded = FactoryEventEncoder
            .encode_json(&usage_event, LossPolicy::Reject)
            .expect("usage");
        let usage_value: Value = serde_json::from_slice(&usage_encoded.body).expect("usage JSON");
        assert_eq!(usage_value["usage"]["totalTokens"], 99);
        assert_eq!(usage_value["usage"]["details"]["cache_write"], 5);
        assert!(usage_encoded
            .report
            .preserved_capabilities
            .contains(&"usage.details".to_owned()));

        let raw_event = StreamEvent::new(
            3,
            StreamEventKind::Opaque {
                media_type: "application/octet-stream".to_owned(),
                data: vec![0, 255],
            },
        );
        let raw_encoded = FactoryEventEncoder
            .encode_json(&raw_event, LossPolicy::Reject)
            .expect("raw event");
        let raw_value: Value = serde_json::from_slice(&raw_encoded.body).expect("raw JSON");
        assert_eq!(
            raw_value["rawValue"]["mediaType"],
            "application/octet-stream"
        );
        assert_eq!(raw_value["rawValue"]["data"], "AP8=");
        assert!(raw_encoded
            .report
            .preserved_capabilities
            .contains(&"event.raw".to_owned()));
    }

    #[test]
    fn sse_encoding_enforces_explicit_bounds() {
        let event = StreamEvent::new(
            1,
            StreamEventKind::TextDelta {
                text: "hello".to_owned(),
            },
        )
        .with_block_id("text-1");
        let error = FactoryEventEncoder
            .encode_sse_with_limits(&event, LossPolicy::Reject, SseLimits::new(8, 16))
            .expect_err("small SSE limit");
        assert!(matches!(
            error,
            FactoryEncodeError::Sse(SseError::LineTooLarge { .. })
        ));
    }

    #[test]
    fn refuses_semantics_without_a_v3_representation() {
        let event = StreamEvent::new(
            1,
            StreamEventKind::Refusal {
                text: "no".to_owned(),
            },
        );
        assert!(matches!(
            FactoryEventEncoder.encode_json(&event, LossPolicy::Reject),
            Err(FactoryEncodeError::UnsupportedEvent("refusal"))
        ));
        assert!(matches!(
            FactoryEventEncoder.encode_json(&event, LossPolicy::Degrade),
            Err(FactoryEncodeError::UnsupportedEvent("refusal"))
        ));

        let completion_without_usage =
            StreamEvent::new(2, StreamEventKind::completion(FinishReason::Stop, None));
        assert!(matches!(
            FactoryEventEncoder.encode_json(&completion_without_usage, LossPolicy::Degrade),
            Err(FactoryEncodeError::MissingUsage)
        ));
    }

    #[tokio::test]
    async fn rejects_duplicate_done_markers_after_stream_completion() {
        let body = http_body_util::Full::new(Bytes::from_static(
            b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\ndata: [DONE]\n\ndata: [DONE]\n\n",
        ))
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed();
        let response = FactoryResponseBody::new(
            body,
            LossPolicy::Reject,
            SseLimits::default(),
            16,
            4096,
            CancellationToken::new(),
        );
        let error = response
            .collect()
            .await
            .expect_err("duplicate done marker must fail");
        assert!(error.to_string().contains("duplicate [DONE]"));
    }

    #[tokio::test]
    async fn incomplete_stream_ends_with_an_explicit_factory_error() {
        let body = http_body_util::Full::new(Bytes::from_static(
            b"data: {\"id\":\"chat-1\",\"model\":\"gpt-test\",\"choices\":[]}\n\n",
        ))
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed();
        let mut response = FactoryResponseBody::new(
            body,
            LossPolicy::Reject,
            SseLimits::default(),
            16,
            4096,
            CancellationToken::new(),
        );
        let mut saw_error = false;
        let mut saw_done = false;
        loop {
            match response.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        saw_error |= data
                            .windows(b"\"type\":\"error\"".len())
                            .any(|window| window == b"\"type\":\"error\"");
                        saw_done |= data
                            .windows(b"[DONE]".len())
                            .any(|window| window == b"[DONE]");
                    }
                }
                Some(Err(error)) => panic!("explicit failure must close cleanly: {error}"),
                None => break,
            }
        }
        assert!(saw_error);
        assert!(saw_done);
    }

    #[test]
    fn validates_and_strips_factory_only_request_headers() {
        let route = pooler_config::compile_yaml(
            "factory-route.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: factory
    listen: local
    ingress: {mode: semantic, decoder: decode.factory.language_model}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}
    loss_policy: reject
"#,
        )
        .expect("factory route")
        .routes()[0]
            .clone();
        let body = br#"{"prompt":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}"#;
        let adapter = FactorySemanticAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(MODEL_ID_HEADER, HeaderValue::from_static("gpt-test"));
        headers.insert(SPECIFICATION_VERSION_HEADER, HeaderValue::from_static("2"));
        headers.insert(STREAMING_HEADER, HeaderValue::from_static("true"));
        assert!(matches!(
            adapter.encode_request(&route, &headers, body),
            Err(error) if error.to_string().contains("version must be 3 or 4")
        ));

        headers.insert(
            SPECIFICATION_VERSION_HEADER,
            HeaderValue::from_static(SPECIFICATION_VERSION_V3),
        );
        adapter
            .encode_request(&route, &headers, body)
            .expect("valid Factory headers");
        adapter.sanitize_request_headers(&mut headers);
        assert!(headers.get(MODEL_ID_HEADER).is_none());
        assert!(headers.get(SPECIFICATION_VERSION_HEADER).is_none());
        assert!(headers.get(STREAMING_HEADER).is_none());

        headers.insert(MODEL_ID_HEADER, HeaderValue::from_static("gpt-test"));
        headers.insert(
            SPECIFICATION_VERSION_HEADER,
            HeaderValue::from_static(SPECIFICATION_VERSION_V4),
        );
        assert!(matches!(
            adapter.encode_request(&route, &headers, body),
            Err(error) if error.to_string().contains("Gateway protocol version")
        ));
        headers.insert(
            GATEWAY_PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static(GATEWAY_PROTOCOL_VERSION),
        );
        adapter
            .encode_request(&route, &headers, body)
            .expect("valid Factory V4 headers");
        adapter.sanitize_request_headers(&mut headers);
        assert!(headers.get(GATEWAY_PROTOCOL_VERSION_HEADER).is_none());
    }

    #[test]
    fn adapter_flattens_factory_tool_result_for_openai_chat() {
        let route = pooler_config::compile_yaml(
            "factory-tool-result.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: factory
    listen: local
    ingress: {mode: semantic, decoder: decode.factory.language_model}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}
    loss_policy: reject
"#,
        )
        .expect("factory route")
        .routes()[0]
            .clone();
        let body = br#"{
          "prompt":[{"role":"tool","content":[{
            "type":"tool-result",
            "toolCallId":"call-1",
            "output":{"type":"text","value":"sunny"}
          }]}]
        }"#;
        let mut headers = HeaderMap::new();
        headers.insert(MODEL_ID_HEADER, HeaderValue::from_static("gpt-test"));
        headers.insert(
            SPECIFICATION_VERSION_HEADER,
            HeaderValue::from_static(SPECIFICATION_VERSION_V3),
        );
        headers.insert(STREAMING_HEADER, HeaderValue::from_static("true"));

        let encoded = FactorySemanticAdapter
            .encode_request(&route, &headers, body)
            .expect("encode tool result");
        let value: Value = serde_json::from_slice(&encoded.body).expect("OpenAI JSON");

        assert_eq!(value["messages"][0]["role"], "tool");
        assert_eq!(value["messages"][0]["tool_call_id"], "call-1");
        assert_eq!(value["messages"][0]["content"], "sunny");
    }

    #[test]
    fn selection_context_prefers_body_session_and_previous_response_ids() {
        let route = pooler_config::compile_yaml(
            "factory-selection.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: factory
    listen: local
    ingress: {mode: semantic, decoder: decode.factory.language_model}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}
    loss_policy: reject
"#,
        )
        .expect("Factory route")
        .routes()[0]
            .clone();
        let body = br#"{
            "sessionId":"body-session",
            "previousResponseId":"response-42",
            "prompt":[{"role":"user","content":[{"type":"text","text":"hello"}]}]
        }"#;
        let mut headers = HeaderMap::new();
        headers.insert(MODEL_ID_HEADER, HeaderValue::from_static("gpt-test"));
        headers.insert(
            SPECIFICATION_VERSION_HEADER,
            HeaderValue::from_static(SPECIFICATION_VERSION_V3),
        );
        let context = FactorySemanticAdapter
            .selection_context(&route, &headers, body)
            .expect("selection context");
        assert_eq!(
            context.affinity_value("request.session_id"),
            Some("body-session")
        );
        assert_eq!(
            context.affinity_value("openai.previous_response_id"),
            Some("response-42")
        );
        assert!(context
            .required_capabilities()
            .contains(pooler_core::Capability::Text));
        assert!(context
            .required_capabilities()
            .contains(pooler_core::Capability::Streaming));
        assert_eq!(context.codec(), Some("decode.factory.language_model"));
    }

    #[test]
    fn selection_context_ignores_nested_identity_fields() {
        let route = pooler_config::compile_yaml(
            "factory-selection-nested.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: factory
    listen: local
    ingress: {mode: semantic, decoder: decode.factory.language_model}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.factory.events}
    loss_policy: reject
"#,
        )
        .expect("Factory route")
        .routes()[0]
            .clone();
        let body = br#"{
            "sessionId":"top-session",
            "metadata":{"sessionId":"nested-session","previousResponseId":"nested-response"},
            "prompt":[{"role":"user","content":[{"type":"text","text":"hello"}]}]
        }"#;
        let mut headers = HeaderMap::new();
        headers.insert(MODEL_ID_HEADER, HeaderValue::from_static("gpt-test"));
        let context = FactorySemanticAdapter
            .selection_context(&route, &headers, body)
            .expect("selection context");

        assert_eq!(
            context.affinity_value("request.session_id"),
            Some("top-session")
        );
        assert_eq!(context.affinity_value("openai.previous_response_id"), None);
    }
}
