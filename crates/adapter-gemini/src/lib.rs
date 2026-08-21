#![forbid(unsafe_code)]
#![doc = "Google Gemini GenerateContent codecs for Pooler's semantic model."]

mod runtime;

pub use runtime::{
    GeminiSemanticAdapter, GEMINI_REQUEST_DECODER, GEMINI_RESPONSE_DECODER, GEMINI_RESPONSE_ENCODER,
};

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use pooler_protocol::{
    CacheHints, ContentPart, ConversionError, ConversionReport, Extensions, FinishReason,
    InputItem, LossPolicy, MediaSource, Message, OpaqueExtension, PreservedJson, ReasoningBlock,
    ReasoningConfig, ReasoningEffort, ReplayPolicy, RequestValidationError, ResponseFormat, Role,
    SemanticRequest, StreamError, StreamEvent, StreamEventKind, ToolCall, ToolChoice,
    ToolDefinition, ToolResult, Usage,
};
use serde_json::{Map, Value};
use thiserror::Error;

/// Gemini REST action for a unary GenerateContent request.
pub const GENERATE_CONTENT_ACTION: &str = "generateContent";
/// Gemini REST action for a streaming GenerateContent request.
pub const STREAM_GENERATE_CONTENT_ACTION: &str = "streamGenerateContent";
/// Media type used by unary Gemini request and response bodies.
pub const GEMINI_JSON_CONTENT_TYPE: &str = "application/json";
/// Query value that selects server-sent events for streamGenerateContent.
pub const GEMINI_SSE_QUERY: &str = "alt=sse";
/// Internal media type for one provider-native Gemini response Part.
pub const GEMINI_PART_JSON_CONTENT_TYPE: &str = "application/vnd.google.gemini.part+json";

const GEMINI_NAMESPACE: &str = "google.gemini.generate-content";
const REQUEST_FIELDS_EXTENSION: &str = "request-fields";
const GENERATION_CONFIG_EXTENSION: &str = "generation-config";
const PROVIDER_TOOLS_EXTENSION: &str = "provider-tools";
const TOOL_LAYOUT_EXTENSION: &str = "tool-layout";
const TOOL_CONFIG_EXTENSION: &str = "tool-config";
const CONTENT_FIELDS_EXTENSION: &str = "content-fields";
const PART_METADATA_EXTENSION: &str = "part-metadata";
const PART_FIELDS_EXTENSION: &str = "part-fields";
const VIDEO_METADATA_EXTENSION: &str = "video-metadata";
const CANDIDATE_FIELDS_EXTENSION: &str = "candidate-fields";
const SAFETY_RATINGS_EXTENSION: &str = "safety-ratings";
const GROUNDING_METADATA_EXTENSION: &str = "grounding-metadata";
const TOOL_FIELDS_EXTENSION: &str = "tool-fields";
const FUNCTION_NAME_EXTENSION: &str = "function-name";
const FUNCTION_ID_ABSENT_EXTENSION: &str = "function-id-absent";
const THOUGHT_SIGNATURE_EXTENSION: &str = "thought-signature";
const THINKING_BUDGET_EXTENSION: &str = "thinking-budget";

/// Which Gemini GenerateContent REST method matched a request path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeminiMethod {
    /// `models.generateContent`.
    GenerateContent,
    /// `models.streamGenerateContent`.
    StreamGenerateContent,
}

impl GeminiMethod {
    /// Returns whether this method produces a streamed response.
    #[must_use]
    pub const fn is_streaming(self) -> bool {
        matches!(self, Self::StreamGenerateContent)
    }
}

/// A model and method extracted from a Gemini REST path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeminiPath<'a> {
    /// Model identifier between `/models/` and the action suffix.
    pub model: &'a str,
    /// GenerateContent method selected by the action suffix.
    pub method: GeminiMethod,
}

/// Matches both v1 and v1beta Gemini model paths without accepting unrelated actions.
#[must_use]
pub fn parse_gemini_path(path_and_query: &str) -> Option<GeminiPath<'_>> {
    let path = path_and_query.split('?').next()?;
    let model_and_action = path
        .strip_prefix("/v1/models/")
        .or_else(|| path.strip_prefix("/v1beta/models/"))?;
    let (model, action) = model_and_action.rsplit_once(':')?;
    let method = match action {
        GENERATE_CONTENT_ACTION => GeminiMethod::GenerateContent,
        STREAM_GENERATE_CONTENT_ACTION => GeminiMethod::StreamGenerateContent,
        _ => return None,
    };
    if model.is_empty()
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(GeminiPath { model, method })
}

/// Failures while converting Gemini GenerateContent requests or responses.
#[derive(Debug, Error)]
pub enum GeminiError {
    /// JSON could not be parsed or serialized.
    #[error("invalid Gemini JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A required wire field was absent.
    #[error("missing Gemini field `{field}`")]
    MissingField {
        /// Dot-separated field path.
        field: String,
    },
    /// A wire field had the wrong JSON shape.
    #[error("invalid Gemini field `{field}`; expected {expected}")]
    InvalidShape {
        /// Dot-separated field path.
        field: String,
        /// Redacted expected shape.
        expected: &'static str,
    },
    /// A wire field had an unsupported value.
    #[error("invalid Gemini field `{field}`: {message}")]
    InvalidValue {
        /// Dot-separated field path.
        field: String,
        /// Redacted invariant explanation.
        message: String,
    },
    /// Base64 media or a thought signature could not be decoded.
    #[error("invalid base64 in Gemini field `{field}`")]
    InvalidBase64 {
        /// Dot-separated field path.
        field: String,
    },
    /// A provider-specific extension could not be constructed.
    #[error("invalid Gemini extension: {0}")]
    Extension(#[from] pooler_protocol::ExtensionError),
    /// Preserved JSON could not be constructed.
    #[error("invalid preserved Gemini JSON: {0}")]
    PreservedJson(#[from] pooler_protocol::PreservedJsonError),
    /// The semantic request was invalid independently of Gemini.
    #[error("invalid semantic request: {0}")]
    RequestValidation(#[from] RequestValidationError),
    /// A conversion report was rejected by the selected route policy.
    #[error("Gemini conversion rejected: {0}")]
    Conversion(#[from] ConversionError),
    /// Chunks violated one response stream's invariants.
    #[error("invalid Gemini response stream: {message}")]
    InvalidStream {
        /// Redacted stream invariant explanation.
        message: String,
    },
    /// A semantic event cannot be represented by GenerateContent.
    #[error("Gemini cannot encode semantic event: {message}")]
    UnsupportedEvent {
        /// Redacted event invariant explanation.
        message: String,
    },
}

/// A decoded Gemini request and explicit conversion accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedGeminiRequest {
    /// Protocol-neutral request.
    pub request: SemanticRequest,
    /// Fields and extensions preserved while decoding.
    pub report: ConversionReport,
}

impl DecodedGeminiRequest {
    /// Separates the semantic request from its conversion report.
    #[must_use]
    pub fn into_parts(self) -> (SemanticRequest, ConversionReport) {
        (self.request, self.report)
    }
}

/// A GenerateContent request encoded for the model carried in its URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedGeminiRequest {
    /// Model identifier used to construct the REST path.
    pub model: String,
    /// UTF-8 JSON body, which deliberately does not repeat the model.
    pub body: Vec<u8>,
    /// Fields represented or explicitly degraded by conversion.
    pub report: ConversionReport,
}

/// One complete GenerateContentResponse JSON object for a stream chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedGeminiChunk {
    /// UTF-8 JSON response object without SSE framing.
    pub body: Vec<u8>,
    /// Fields represented or explicitly degraded by conversion.
    pub report: ConversionReport,
}

/// One complete unary GenerateContentResponse JSON object.
pub type EncodedGeminiResponse = EncodedGeminiChunk;

/// Stateless entry points for Gemini request and unary response conversion.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeminiGenerateContentCodec;

impl GeminiGenerateContentCodec {
    /// Decodes a request and requires a lossless semantic representation.
    pub fn decode_request(
        input: &[u8],
        model: impl Into<String>,
    ) -> Result<SemanticRequest, GeminiError> {
        let decoded = Self::decode_request_with_report(input, model)?;
        decoded.report.validate(LossPolicy::Reject)?;
        Ok(decoded.request)
    }

    /// Decodes a request while exposing preservation and degradation accounting.
    pub fn decode_request_with_report(
        input: &[u8],
        model: impl Into<String>,
    ) -> Result<DecodedGeminiRequest, GeminiError> {
        decode_generate_content_request_with_report(input, model)
    }

    /// Encodes a semantic request for either GenerateContent method.
    pub fn encode_request(
        request: &SemanticRequest,
        policy: LossPolicy,
    ) -> Result<EncodedGeminiRequest, GeminiError> {
        encode_generate_content_request(request, policy)
    }

    /// Decodes one complete unary GenerateContentResponse.
    pub fn decode_response(input: &[u8]) -> Result<Vec<StreamEvent>, GeminiError> {
        let mut decoder = GeminiEventDecoder::new();
        let events = decoder.decode_chunk(input)?;
        decoder.finish()?;
        Ok(events)
    }

    /// Encodes a complete unary response from an ordered semantic event stream.
    pub fn encode_response(
        events: &[StreamEvent],
        policy: LossPolicy,
    ) -> Result<EncodedGeminiResponse, GeminiError> {
        encode_unary_response(events, policy)
    }
}

/// Decode a Gemini GenerateContent request and require lossless conversion.
pub fn decode_generate_content_request(
    input: &[u8],
    model: impl Into<String>,
) -> Result<SemanticRequest, GeminiError> {
    GeminiGenerateContentCodec::decode_request(input, model)
}

/// Decode a Gemini GenerateContent request with conversion accounting.
pub fn decode_generate_content_request_with_report(
    input: &[u8],
    model: impl Into<String>,
) -> Result<DecodedGeminiRequest, GeminiError> {
    let model = model.into();
    if model.trim().is_empty() {
        return Err(GeminiError::InvalidValue {
            field: "model".to_owned(),
            message: "must not be empty".to_owned(),
        });
    }
    let value: Value = serde_json::from_slice(input)?;
    let mut object = into_object(value, "request")?;
    let mut request = SemanticRequest::new(model);
    let mut report = ConversionReport::default();

    if let Some(system) = object.remove("systemInstruction") {
        request.push_message(decode_content(
            &system,
            Some(Role::System),
            "systemInstruction",
            0,
            &mut report,
        )?);
    }

    let contents = object
        .remove("contents")
        .ok_or_else(|| missing("contents"))?;
    let contents = as_array(&contents, "contents")?;
    if contents.is_empty() {
        return Err(invalid_value(
            "contents",
            "must contain at least one content turn",
        ));
    }
    for (index, content) in contents.iter().enumerate() {
        request.push_message(decode_content(
            content,
            None,
            &format!("contents[{index}]"),
            index,
            &mut report,
        )?);
    }

    if let Some(tools) = object.remove("tools") {
        decode_tools(&tools, &mut request, &mut report)?;
    }
    if let Some(config) = object.remove("toolConfig") {
        decode_tool_config(&config, &mut request, &mut report)?;
    }
    if let Some(config) = object.remove("generationConfig") {
        decode_generation_config(&config, &mut request, &mut report)?;
    }
    if let Some(cached) = object.remove("cachedContent") {
        let cached = as_string(&cached, "cachedContent")?;
        request.cache = Some(CacheHints {
            allow_prompt_cache: true,
            prefer_cache_read: true,
            key: Some(cached.to_owned()),
            extensions: Extensions::default(),
        });
    }
    if !object.is_empty() {
        preserve_json_extension(
            &mut request.extensions,
            REQUEST_FIELDS_EXTENSION,
            Value::Object(object),
            &mut report,
        )?;
    }
    request.validate()?;
    Ok(DecodedGeminiRequest { request, report })
}

fn decode_content(
    value: &Value,
    forced_role: Option<Role>,
    field: &str,
    content_index: usize,
    report: &mut ConversionReport,
) -> Result<Message, GeminiError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    let role = if let Some(role) = forced_role {
        if object.remove("role").is_some() {
            report.apply_rule("gemini.system_instruction_role_ignored");
        }
        role
    } else {
        match object.remove("role") {
            None => Role::User,
            Some(value) => match as_string(&value, &format!("{field}.role"))? {
                "user" => Role::User,
                "model" => Role::Assistant,
                "function" => {
                    report.apply_rule("gemini.legacy_function_role");
                    Role::Tool
                }
                other => {
                    return Err(invalid_value(
                        &format!("{field}.role"),
                        format!("unsupported role `{other}`"),
                    ))
                }
            },
        }
    };
    let parts = object
        .remove("parts")
        .ok_or_else(|| missing(format!("{field}.parts")))?;
    let parts = as_array(&parts, &format!("{field}.parts"))?;
    let mut message = Message::new(role);
    let mut part_metadata = Vec::with_capacity(parts.len());
    for (part_index, part) in parts.iter().enumerate() {
        let decoded = decode_part(part, field, content_index, part_index, report)?;
        message.push_content(decoded.part);
        part_metadata.push(decoded.metadata);
    }
    if part_metadata.iter().any(|value| !value.is_null()) {
        preserve_json_extension(
            &mut message.extensions,
            PART_METADATA_EXTENSION,
            Value::Array(part_metadata),
            report,
        )?;
    }
    if !object.is_empty() {
        preserve_json_extension(
            &mut message.extensions,
            CONTENT_FIELDS_EXTENSION,
            Value::Object(object),
            report,
        )?;
    }
    Ok(message)
}

struct DecodedPart {
    part: ContentPart,
    metadata: Value,
}

fn decode_part(
    value: &Value,
    content_field: &str,
    content_index: usize,
    part_index: usize,
    report: &mut ConversionReport,
) -> Result<DecodedPart, GeminiError> {
    let field = format!("{content_field}.parts[{part_index}]");
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape(&field, "an object"))?;
    let thought = take_bool(&mut object, "thought", &format!("{field}.thought"))?.unwrap_or(false);
    let signature = take_base64(
        &mut object,
        "thoughtSignature",
        &format!("{field}.thoughtSignature"),
    )?;

    let data_fields = [
        "text",
        "inlineData",
        "fileData",
        "functionCall",
        "functionResponse",
        "executableCode",
        "codeExecutionResult",
        "toolCall",
        "toolResponse",
    ];
    let present = data_fields
        .iter()
        .filter(|name| object.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if present.len() != 1 {
        return Err(invalid_value(
            &field,
            "must contain exactly one supported Part data field",
        ));
    }
    let data_field = present[0];
    let data = object
        .remove(data_field)
        .ok_or_else(|| missing(format!("{field}.{data_field}")))?;

    let part = match data_field {
        "text" if thought => ContentPart::Reasoning(ReasoningBlock {
            text: Some(as_string(&data, &format!("{field}.text"))?.to_owned()),
            signature: signature.clone(),
            ..ReasoningBlock::default()
        }),
        "text" => ContentPart::text(as_string(&data, &format!("{field}.text"))?),
        "inlineData" => decode_inline_data(&data, &format!("{field}.inlineData"))?,
        "fileData" => decode_file_data(&data, &format!("{field}.fileData"))?,
        "functionCall" => decode_function_call(
            &data,
            &format!("{field}.functionCall"),
            content_index,
            part_index,
            signature.as_deref(),
            report,
        )?,
        "functionResponse" => decode_function_response(
            &data,
            &format!("{field}.functionResponse"),
            content_index,
            part_index,
            report,
        )?,
        _ => {
            let mut original = object.clone();
            original.insert(data_field.to_owned(), data);
            if thought {
                original.insert("thought".to_owned(), Value::Bool(true));
            }
            if let Some(signature) = signature.as_ref() {
                original.insert(
                    "thoughtSignature".to_owned(),
                    Value::String(BASE64.encode(signature)),
                );
            }
            report.preserve_capability(format!("gemini.part.{data_field}"));
            ContentPart::Provider {
                namespace: GEMINI_NAMESPACE.to_owned(),
                name: "part".to_owned(),
                data: PreservedJson::from_value(Value::Object(original))?,
            }
        }
    };

    if !thought && signature.is_some() {
        object.insert(
            "thoughtSignature".to_owned(),
            Value::String(BASE64.encode(signature.as_deref().unwrap_or_default())),
        );
    }
    let metadata = if object.is_empty() {
        Value::Null
    } else {
        Value::Object(object)
    };
    Ok(DecodedPart { part, metadata })
}

fn decode_inline_data(value: &Value, field: &str) -> Result<ContentPart, GeminiError> {
    let object = as_object(value, field)?;
    let media_type = required_string(object, "mimeType", &format!("{field}.mimeType"))?;
    let data = required_string(object, "data", &format!("{field}.data"))?;
    let bytes = BASE64
        .decode(data)
        .map_err(|_| GeminiError::InvalidBase64 {
            field: format!("{field}.data"),
        })?;
    Ok(media_part(media_type, MediaSource::inline(bytes)))
}

fn decode_file_data(value: &Value, field: &str) -> Result<ContentPart, GeminiError> {
    let object = as_object(value, field)?;
    let media_type = required_string(object, "mimeType", &format!("{field}.mimeType"))?;
    let uri = required_string(object, "fileUri", &format!("{field}.fileUri"))?;
    Ok(media_part(media_type, MediaSource::uri(uri)))
}

fn media_part(media_type: &str, source: MediaSource) -> ContentPart {
    if media_type.starts_with("image/") {
        ContentPart::image(media_type, source)
    } else if media_type.starts_with("audio/") {
        ContentPart::audio(media_type, source)
    } else {
        ContentPart::file(None, media_type, source)
    }
}

fn decode_function_call(
    value: &Value,
    field: &str,
    content_index: usize,
    part_index: usize,
    signature: Option<&[u8]>,
    report: &mut ConversionReport,
) -> Result<ContentPart, GeminiError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    let id = take_string(&mut object, "id", &format!("{field}.id"))?;
    let id_was_absent = id.is_none();
    let id = id.unwrap_or_else(|| {
        report.apply_rule("gemini.generated_function_call_id");
        format!("gemini-call-{content_index}-{part_index}")
    });
    let name = take_required_string(&mut object, "name", &format!("{field}.name"))?;
    let args = object
        .remove("args")
        .unwrap_or_else(|| Value::Object(Map::new()));
    if !args.is_object() {
        return Err(invalid_shape(&format!("{field}.args"), "an object"));
    }
    let mut call = ToolCall::new(id, name, PreservedJson::from_value(args)?);
    if id_was_absent {
        preserve_text_extension(
            &mut call.extensions,
            FUNCTION_ID_ABSENT_EXTENSION,
            "true",
            report,
        )?;
    }
    if let Some(signature) = signature {
        preserve_bytes_extension(
            &mut call.extensions,
            THOUGHT_SIGNATURE_EXTENSION,
            signature,
            report,
        )?;
    }
    if !object.is_empty() {
        preserve_json_extension(
            &mut call.extensions,
            TOOL_FIELDS_EXTENSION,
            Value::Object(object),
            report,
        )?;
    }
    Ok(ContentPart::ToolCall(call))
}

fn decode_function_response(
    value: &Value,
    field: &str,
    content_index: usize,
    part_index: usize,
    report: &mut ConversionReport,
) -> Result<ContentPart, GeminiError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    let id = take_string(&mut object, "id", &format!("{field}.id"))?;
    let id_was_absent = id.is_none();
    let id = id.unwrap_or_else(|| {
        report.apply_rule("gemini.generated_function_response_id");
        format!("gemini-response-{content_index}-{part_index}")
    });
    let name = take_required_string(&mut object, "name", &format!("{field}.name"))?;
    let response = object
        .remove("response")
        .ok_or_else(|| missing(format!("{field}.response")))?;
    if !response.is_object() {
        return Err(invalid_shape(&format!("{field}.response"), "an object"));
    }
    let text = serde_json::to_string(&response)?;
    let is_error = response.get("error").is_some();
    let mut result = ToolResult {
        tool_call_id: id,
        content: vec![ContentPart::text(text)],
        is_error,
        extensions: Extensions::default(),
    };
    preserve_text_extension(
        &mut result.extensions,
        FUNCTION_NAME_EXTENSION,
        &name,
        report,
    )?;
    if id_was_absent {
        preserve_text_extension(
            &mut result.extensions,
            FUNCTION_ID_ABSENT_EXTENSION,
            "true",
            report,
        )?;
    }
    if !object.is_empty() {
        preserve_json_extension(
            &mut result.extensions,
            TOOL_FIELDS_EXTENSION,
            Value::Object(object),
            report,
        )?;
    }
    Ok(ContentPart::ToolResult(result))
}

fn decode_tools(
    value: &Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let tools = as_array(value, "tools")?;
    let mut layout = Vec::with_capacity(tools.len());
    for (tool_index, tool) in tools.iter().enumerate() {
        let mut object = tool
            .as_object()
            .cloned()
            .ok_or_else(|| invalid_shape(&format!("tools[{tool_index}]"), "an object"))?;
        let declaration_count = if let Some(declarations) = object.remove("functionDeclarations") {
            let declarations = as_array(
                &declarations,
                &format!("tools[{tool_index}].functionDeclarations"),
            )?;
            for (declaration_index, declaration) in declarations.iter().enumerate() {
                request.tools.push(decode_tool_definition(
                    declaration,
                    &format!("tools[{tool_index}].functionDeclarations[{declaration_index}]"),
                    report,
                )?);
            }
            declarations.len()
        } else {
            0
        };
        layout.push(serde_json::json!({
            "functionDeclarationCount": declaration_count,
            "providerFields": object,
        }));
    }
    if !layout.is_empty() {
        preserve_json_extension(
            &mut request.extensions,
            TOOL_LAYOUT_EXTENSION,
            Value::Array(layout),
            report,
        )?;
    }
    Ok(())
}

fn decode_tool_definition(
    value: &Value,
    field: &str,
    report: &mut ConversionReport,
) -> Result<ToolDefinition, GeminiError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape(field, "an object"))?;
    let name = take_required_string(&mut object, "name", &format!("{field}.name"))?;
    let description = take_string(&mut object, "description", &format!("{field}.description"))?;
    let parameters = match (
        object.remove("parametersJsonSchema"),
        object.remove("parameters"),
    ) {
        (Some(_), Some(_)) => {
            return Err(invalid_value(
                field,
                "parametersJsonSchema and parameters are mutually exclusive",
            ))
        }
        (Some(schema), None) | (None, Some(schema)) => Some(PreservedJson::from_value(schema)?),
        (None, None) => None,
    };
    let mut definition = ToolDefinition::new(name, parameters);
    definition.description = description;
    if !object.is_empty() {
        preserve_json_extension(
            &mut definition.extensions,
            TOOL_FIELDS_EXTENSION,
            Value::Object(object),
            report,
        )?;
    }
    Ok(definition)
}

fn decode_tool_config(
    value: &Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape("toolConfig", "an object"))?;
    if let Some(config) = object.remove("functionCallingConfig") {
        let mut config = config
            .as_object()
            .cloned()
            .ok_or_else(|| invalid_shape("toolConfig.functionCallingConfig", "an object"))?;
        let mode = take_string(&mut config, "mode", "toolConfig.functionCallingConfig.mode")?
            .unwrap_or_else(|| "AUTO".to_owned());
        let allowed = config
            .remove("allowedFunctionNames")
            .map(|value| {
                string_array(
                    &value,
                    "toolConfig.functionCallingConfig.allowedFunctionNames",
                )
            })
            .transpose()?
            .unwrap_or_default();
        request.tool_choice = Some(match mode.as_str() {
            "AUTO" | "MODE_UNSPECIFIED" if allowed.is_empty() => ToolChoice::Auto,
            "NONE" if allowed.is_empty() => ToolChoice::None,
            "ANY" if allowed.is_empty() => ToolChoice::Required,
            "ANY" | "AUTO" if allowed.len() == 1 => ToolChoice::Tool {
                name: allowed[0].clone(),
            },
            _ => {
                config.insert("mode".to_owned(), Value::String(mode));
                if !allowed.is_empty() {
                    config.insert(
                        "allowedFunctionNames".to_owned(),
                        Value::Array(allowed.into_iter().map(Value::String).collect()),
                    );
                }
                ToolChoice::Auto
            }
        });
        if !config.is_empty() {
            object.insert("functionCallingConfig".to_owned(), Value::Object(config));
        }
    }
    if !object.is_empty() {
        preserve_json_extension(
            &mut request.extensions,
            TOOL_CONFIG_EXTENSION,
            Value::Object(object),
            report,
        )?;
    }
    Ok(())
}

fn decode_generation_config(
    value: &Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let mut config = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape("generationConfig", "an object"))?;
    request.sampling.temperature =
        take_f32(&mut config, "temperature", "generationConfig.temperature")?;
    request.sampling.top_p = take_f32(&mut config, "topP", "generationConfig.topP")?;
    request.sampling.max_output_tokens = take_u32(
        &mut config,
        "maxOutputTokens",
        "generationConfig.maxOutputTokens",
    )?;
    request.sampling.seed = take_u64(&mut config, "seed", "generationConfig.seed")?;
    request.sampling.presence_penalty = take_f32(
        &mut config,
        "presencePenalty",
        "generationConfig.presencePenalty",
    )?;
    request.sampling.frequency_penalty = take_f32(
        &mut config,
        "frequencyPenalty",
        "generationConfig.frequencyPenalty",
    )?;
    if let Some(stop) = config.remove("stopSequences") {
        request.sampling.stop = string_array(&stop, "generationConfig.stopSequences")?;
    }
    if let Some(count) = config.remove("candidateCount") {
        let count = as_u64(&count, "generationConfig.candidateCount")?;
        if count != 1 {
            report.unsupported_required(
                "generationConfig.candidateCount",
                "Pooler semantic responses contain one candidate",
            );
        }
    }
    decode_response_format(&mut config, request)?;
    if let Some(thinking) = config.remove("thinkingConfig") {
        decode_thinking_config(&thinking, request, report)?;
    }
    if !config.is_empty() {
        preserve_json_extension(
            &mut request.extensions,
            GENERATION_CONFIG_EXTENSION,
            Value::Object(config),
            report,
        )?;
    }
    Ok(())
}

fn decode_response_format(
    config: &mut Map<String, Value>,
    request: &mut SemanticRequest,
) -> Result<(), GeminiError> {
    let mime_type = take_string(
        config,
        "responseMimeType",
        "generationConfig.responseMimeType",
    )?;
    let schema = config.remove("responseJsonSchema");
    request.response_format = match (mime_type.as_deref(), schema) {
        (None, None) | (Some("text/plain"), None) => None,
        (Some("application/json"), None) => Some(ResponseFormat::JsonObject),
        (Some("application/json"), Some(schema)) | (None, Some(schema)) => {
            Some(ResponseFormat::JsonSchema {
                name: "gemini_response".to_owned(),
                schema: PreservedJson::from_value(schema)?,
                strict: true,
            })
        }
        (Some(other), schema) => {
            if let Some(schema) = schema {
                config.insert("responseJsonSchema".to_owned(), schema);
            }
            config.insert(
                "responseMimeType".to_owned(),
                Value::String(other.to_owned()),
            );
            None
        }
    };
    Ok(())
}

fn decode_thinking_config(
    value: &Value,
    request: &mut SemanticRequest,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape("generationConfig.thinkingConfig", "an object"))?;
    let include_summary = take_bool(
        &mut object,
        "includeThoughts",
        "generationConfig.thinkingConfig.includeThoughts",
    )?
    .unwrap_or(false);
    let effort = take_string(
        &mut object,
        "thinkingLevel",
        "generationConfig.thinkingConfig.thinkingLevel",
    )?
    .map(|level| match level.as_str() {
        "MINIMAL" | "LOW" => ReasoningEffort::Low,
        "MEDIUM" => ReasoningEffort::Medium,
        "HIGH" => ReasoningEffort::High,
        _ => ReasoningEffort::Custom(level),
    });
    let mut reasoning = ReasoningConfig {
        effort,
        include_summary,
        extensions: Extensions::default(),
    };
    if let Some(budget) = object.remove("thinkingBudget") {
        preserve_json_extension(
            &mut reasoning.extensions,
            THINKING_BUDGET_EXTENSION,
            budget,
            report,
        )?;
    }
    if !object.is_empty() {
        preserve_json_extension(
            &mut reasoning.extensions,
            GENERATION_CONFIG_EXTENSION,
            Value::Object(object),
            report,
        )?;
    }
    request.reasoning = Some(reasoning);
    Ok(())
}

/// Encode a semantic request as a GenerateContent request body.
pub fn encode_generate_content_request(
    request: &SemanticRequest,
    policy: LossPolicy,
) -> Result<EncodedGeminiRequest, GeminiError> {
    request.validate()?;
    let mut report = ConversionReport::default();
    let mut object = request_extension_object(&request.extensions, REQUEST_FIELDS_EXTENSION)?
        .unwrap_or_default();
    let call_names = collect_call_names(request);
    let mut system_parts = Vec::new();
    let mut contents = Vec::new();

    for item in &request.input {
        match item {
            InputItem::Message(message)
                if matches!(message.role, Role::System | Role::Developer) =>
            {
                if message.role == Role::Developer {
                    report.degrade_field(
                        "input.developer.role",
                        "Gemini combines developer instructions with systemInstruction",
                    );
                }
                for part in &message.content {
                    system_parts.push(encode_system_part(part, &mut report)?);
                }
                report_unhandled_extensions(
                    "message.extensions",
                    &message.extensions,
                    &[PART_METADATA_EXTENSION, CONTENT_FIELDS_EXTENSION],
                    &mut report,
                );
            }
            InputItem::Message(message) => {
                let content = encode_message(message, &call_names, &mut report)?;
                push_content(&mut contents, content);
            }
            InputItem::ToolCall(call) => {
                let part = encode_tool_call(call, &mut report)?;
                push_content(&mut contents, content_value("model", vec![part]));
            }
            InputItem::ToolResult(result) => {
                let part = encode_tool_result(result, &call_names, &mut report)?;
                push_content(&mut contents, content_value("user", vec![part]));
            }
            InputItem::Content(part) => {
                let part = encode_content_part(part, &call_names, &mut report)?;
                push_content(&mut contents, content_value("user", vec![part]));
            }
            InputItem::Provider {
                namespace,
                name,
                data,
            } if namespace == GEMINI_NAMESPACE && name == "content" => {
                push_content(&mut contents, data.value().clone());
                report.preserve_capability("gemini.content");
            }
            InputItem::Provider {
                namespace, name, ..
            } => {
                report.unsupported_required(
                    format!("input.provider.{namespace}.{name}"),
                    "provider input has no Gemini GenerateContent representation",
                );
            }
        }
    }

    if contents.is_empty() {
        report.unsupported_required("input", "Gemini requires at least one content turn");
    }
    object.insert("contents".to_owned(), Value::Array(contents));
    if !system_parts.is_empty() {
        object.insert(
            "systemInstruction".to_owned(),
            Value::Object(Map::from_iter([(
                "parts".to_owned(),
                Value::Array(system_parts),
            )])),
        );
    }
    encode_tools(request, &mut object, &mut report)?;
    encode_tool_config(request, &mut object, &mut report)?;
    encode_generation_config(request, &mut object, &mut report)?;
    if let Some(cache) = &request.cache {
        if let Some(key) = &cache.key {
            object.insert("cachedContent".to_owned(), Value::String(key.clone()));
        } else if cache.allow_prompt_cache || cache.prefer_cache_read {
            report.drop_optional(
                "cache",
                "Gemini cachedContent requires a concrete cached resource name",
            );
        }
        report_unhandled_extensions("cache.extensions", &cache.extensions, &[], &mut report);
    }
    if request.target.is_some() {
        report.drop_optional(
            "target",
            "routing target metadata is carried outside the Gemini request body",
        );
    }
    if request.continuation_id.is_some() {
        report.drop_optional(
            "continuation_id",
            "GenerateContent continuation is represented by explicit contents",
        );
    }
    if request.session_id.is_some() {
        report.drop_optional("session_id", "Gemini has no request session field");
    }
    if !request.metadata.is_empty() {
        report.drop_optional("metadata", "Gemini has no portable request metadata field");
    }
    report_unhandled_extensions(
        "request.extensions",
        &request.extensions,
        &[
            REQUEST_FIELDS_EXTENSION,
            GENERATION_CONFIG_EXTENSION,
            PROVIDER_TOOLS_EXTENSION,
            TOOL_LAYOUT_EXTENSION,
            TOOL_CONFIG_EXTENSION,
        ],
        &mut report,
    );
    report.validate(policy)?;
    Ok(EncodedGeminiRequest {
        model: request.model.clone(),
        body: serde_json::to_vec(&Value::Object(object))?,
        report,
    })
}

fn encode_message(
    message: &Message,
    call_names: &BTreeMap<String, String>,
    report: &mut ConversionReport,
) -> Result<Value, GeminiError> {
    let role = match message.role {
        Role::User | Role::Tool => "user",
        Role::Assistant => "model",
        Role::System | Role::Developer => {
            return Err(GeminiError::UnsupportedEvent {
                message: "system messages must be encoded as systemInstruction".to_owned(),
            })
        }
    };
    let metadata = extension_value(&message.extensions, PART_METADATA_EXTENSION)?
        .map(|value| {
            value
                .as_array()
                .cloned()
                .ok_or_else(|| invalid_shape("message.extensions.part-metadata", "an array"))
        })
        .transpose()?
        .unwrap_or_default();
    let mut parts = Vec::with_capacity(message.content.len());
    for (index, part) in message.content.iter().enumerate() {
        let mut encoded = encode_content_part(part, call_names, report)?;
        if let Some(fields) = metadata.get(index).filter(|value| !value.is_null()) {
            merge_fields(
                as_object_mut(&mut encoded, "encoded part")?,
                as_object(fields, "message.extensions.part-metadata[]")?,
                "message.extensions.part-metadata",
            )?;
        }
        parts.push(encoded);
    }
    let mut content = extension_value(&message.extensions, CONTENT_FIELDS_EXTENSION)?
        .map(|value| into_object(value, "message.extensions.content-fields"))
        .transpose()?
        .unwrap_or_default();
    content.insert("role".to_owned(), Value::String(role.to_owned()));
    content.insert("parts".to_owned(), Value::Array(parts));
    if message.name.is_some() {
        report.drop_optional("message.name", "Gemini content has no speaker name field");
    }
    if message.tool_call_id.is_some() {
        report.drop_optional(
            "message.tool_call_id",
            "Gemini carries function identifiers inside function parts",
        );
    }
    if !message.metadata.is_empty() {
        report.drop_optional("message.metadata", "Gemini content has no metadata map");
    }
    report_unhandled_extensions(
        "message.extensions",
        &message.extensions,
        &[PART_METADATA_EXTENSION, CONTENT_FIELDS_EXTENSION],
        report,
    );
    Ok(Value::Object(content))
}

fn encode_system_part(
    part: &ContentPart,
    report: &mut ConversionReport,
) -> Result<Value, GeminiError> {
    match part {
        ContentPart::Text { text } => Ok(serde_json::json!({"text":text})),
        ContentPart::Reasoning(reasoning) => {
            report.degrade_field(
                "systemInstruction.reasoning",
                "Gemini systemInstruction supports text only",
            );
            Ok(serde_json::json!({"text":reasoning_text(reasoning)}))
        }
        _ => {
            report.unsupported_required(
                "systemInstruction.parts",
                "Gemini systemInstruction supports text only",
            );
            Ok(serde_json::json!({"text":""}))
        }
    }
}

fn encode_content_part(
    part: &ContentPart,
    call_names: &BTreeMap<String, String>,
    report: &mut ConversionReport,
) -> Result<Value, GeminiError> {
    match part {
        ContentPart::Text { text } => Ok(serde_json::json!({"text":text})),
        ContentPart::Image {
            media_type,
            source,
            detail,
        } => {
            if detail.is_some() {
                report.drop_optional("image.detail", "Gemini has no portable image detail field");
            }
            encode_media(media_type, source)
        }
        ContentPart::File {
            name,
            media_type,
            source,
        } => {
            if name.is_some() {
                report.drop_optional("file.name", "Gemini Part has no file display name");
            }
            encode_media(media_type, source)
        }
        ContentPart::Audio { media_type, source } => encode_media(media_type, source),
        ContentPart::Reasoning(reasoning) => {
            let mut object = Map::from_iter([
                ("text".to_owned(), Value::String(reasoning_text(reasoning))),
                ("thought".to_owned(), Value::Bool(true)),
            ]);
            if let Some(signature) = &reasoning.signature {
                object.insert(
                    "thoughtSignature".to_owned(),
                    Value::String(BASE64.encode(signature)),
                );
            }
            if reasoning.encrypted_content.is_some() {
                report.drop_optional(
                    "reasoning.encrypted_content",
                    "Gemini uses thoughtSignature instead of encrypted content",
                );
            }
            report_unhandled_extensions("reasoning.extensions", &reasoning.extensions, &[], report);
            Ok(Value::Object(object))
        }
        ContentPart::ToolCall(call) => encode_tool_call(call, report),
        ContentPart::ToolResult(result) => encode_tool_result(result, call_names, report),
        ContentPart::Provider {
            namespace,
            name,
            data,
        } if namespace == GEMINI_NAMESPACE && name == "part" => {
            report.preserve_capability("gemini.part");
            Ok(data.value().clone())
        }
        ContentPart::Provider {
            namespace, name, ..
        } => {
            report.unsupported_required(
                format!("content.provider.{namespace}.{name}"),
                "provider content has no Gemini Part representation",
            );
            Ok(serde_json::json!({"text":""}))
        }
    }
}

fn encode_media(media_type: &str, source: &MediaSource) -> Result<Value, GeminiError> {
    Ok(match source {
        MediaSource::Inline(bytes) => serde_json::json!({
            "inlineData":{"mimeType":media_type,"data":BASE64.encode(bytes)}
        }),
        MediaSource::Uri(uri) => serde_json::json!({
            "fileData":{"mimeType":media_type,"fileUri":uri}
        }),
    })
}

fn encode_tool_call(call: &ToolCall, report: &mut ConversionReport) -> Result<Value, GeminiError> {
    if !call.arguments.value().is_object() {
        report.unsupported_required(
            "tool_call.arguments",
            "Gemini functionCall args must be a JSON object",
        );
    }
    let mut function = extension_value(&call.extensions, TOOL_FIELDS_EXTENSION)?
        .map(|value| into_object(value, "tool_call.extensions.tool-fields"))
        .transpose()?
        .unwrap_or_default();
    if extension_text(&call.extensions, FUNCTION_ID_ABSENT_EXTENSION)?.is_none() {
        function.insert("id".to_owned(), Value::String(call.id.clone()));
    }
    function.insert("name".to_owned(), Value::String(call.name.clone()));
    function.insert("args".to_owned(), call.arguments.value().clone());
    let mut part = Map::from_iter([("functionCall".to_owned(), Value::Object(function))]);
    if let Some(signature) = extension_bytes(&call.extensions, THOUGHT_SIGNATURE_EXTENSION) {
        part.insert(
            "thoughtSignature".to_owned(),
            Value::String(BASE64.encode(signature)),
        );
        report.preserve_capability("gemini.thought_signature");
    }
    if !call.dependencies.is_empty() {
        report.drop_optional(
            "tool_call.dependencies",
            "Gemini functionCall has no dependency list",
        );
    }
    report_unhandled_extensions(
        "tool_call.extensions",
        &call.extensions,
        &[
            TOOL_FIELDS_EXTENSION,
            FUNCTION_ID_ABSENT_EXTENSION,
            THOUGHT_SIGNATURE_EXTENSION,
        ],
        report,
    );
    Ok(Value::Object(part))
}

fn encode_tool_result(
    result: &ToolResult,
    call_names: &BTreeMap<String, String>,
    report: &mut ConversionReport,
) -> Result<Value, GeminiError> {
    let name = extension_text(&result.extensions, FUNCTION_NAME_EXTENSION)?
        .map(ToOwned::to_owned)
        .or_else(|| call_names.get(&result.tool_call_id).cloned());
    let Some(name) = name else {
        report.unsupported_required(
            "tool_result.name",
            "Gemini functionResponse requires the prior function name",
        );
        return Ok(serde_json::json!({
            "functionResponse":{
                "id":result.tool_call_id,
                "name":"missing_function_name",
                "response":{"error":"missing function name"}
            }
        }));
    };
    let mut response = tool_result_value(result, report)?;
    if result.is_error && response.get("error").is_none() {
        response = serde_json::json!({"error":response});
    }
    let mut function = extension_value(&result.extensions, TOOL_FIELDS_EXTENSION)?
        .map(|value| into_object(value, "tool_result.extensions.tool-fields"))
        .transpose()?
        .unwrap_or_default();
    if extension_text(&result.extensions, FUNCTION_ID_ABSENT_EXTENSION)?.is_none() {
        function.insert("id".to_owned(), Value::String(result.tool_call_id.clone()));
    }
    function.insert("name".to_owned(), Value::String(name));
    function.insert("response".to_owned(), response);
    report_unhandled_extensions(
        "tool_result.extensions",
        &result.extensions,
        &[
            FUNCTION_NAME_EXTENSION,
            FUNCTION_ID_ABSENT_EXTENSION,
            TOOL_FIELDS_EXTENSION,
        ],
        report,
    );
    Ok(serde_json::json!({"functionResponse":function}))
}

fn tool_result_value(
    result: &ToolResult,
    report: &mut ConversionReport,
) -> Result<Value, GeminiError> {
    if result.content.len() == 1 {
        if let ContentPart::Text { text } = &result.content[0] {
            return Ok(match serde_json::from_str::<Value>(text) {
                Ok(value) if value.is_object() => value,
                Ok(value) => serde_json::json!({"result":value}),
                Err(_) => serde_json::json!({"result":text}),
            });
        }
    }
    let mut text = String::new();
    for part in &result.content {
        match part {
            ContentPart::Text { text: value } => text.push_str(value),
            _ => report.unsupported_required(
                "tool_result.content",
                "Gemini functionResponse response is a JSON object",
            ),
        }
    }
    Ok(serde_json::json!({"result":text}))
}

fn collect_call_names(request: &SemanticRequest) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for item in &request.input {
        match item {
            InputItem::ToolCall(call) => {
                names.insert(call.id.clone(), call.name.clone());
            }
            InputItem::Message(message) => {
                for part in &message.content {
                    if let ContentPart::ToolCall(call) = part {
                        names.insert(call.id.clone(), call.name.clone());
                    }
                }
            }
            InputItem::ToolResult(_) | InputItem::Content(_) | InputItem::Provider { .. } => {}
        }
    }
    names
}

fn encode_tools(
    request: &SemanticRequest,
    object: &mut Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let mut declarations = Vec::with_capacity(request.tools.len());
    for definition in &request.tools {
        declarations.push(encode_tool_definition(definition, report)?);
    }

    let tools = if let Some(layout) = extension_value(&request.extensions, TOOL_LAYOUT_EXTENSION)? {
        let layout = layout
            .as_array()
            .ok_or_else(|| invalid_shape("request.extensions.tool-layout", "an array"))?;
        let mut tools = Vec::with_capacity(layout.len());
        let mut declaration_index = 0usize;
        for (layout_index, entry) in layout.iter().enumerate() {
            let entry = as_object(
                entry,
                &format!("request.extensions.tool-layout[{layout_index}]"),
            )?;
            let count = entry
                .get("functionDeclarationCount")
                .ok_or_else(|| {
                    missing(format!(
                        "request.extensions.tool-layout[{layout_index}].functionDeclarationCount"
                    ))
                })
                .and_then(|value| {
                    as_u64(
                        value,
                        &format!(
                            "request.extensions.tool-layout[{layout_index}].functionDeclarationCount"
                        ),
                    )
                })? as usize;
            let mut tool = entry
                .get("providerFields")
                .ok_or_else(|| {
                    missing(format!(
                        "request.extensions.tool-layout[{layout_index}].providerFields"
                    ))
                })
                .and_then(|value| {
                    value.as_object().cloned().ok_or_else(|| {
                        invalid_shape(
                            &format!(
                                "request.extensions.tool-layout[{layout_index}].providerFields"
                            ),
                            "an object",
                        )
                    })
                })?;
            let end = declaration_index.saturating_add(count);
            if end > declarations.len() {
                return Err(invalid_value(
                    "request.extensions.tool-layout",
                    "function declaration counts exceed semantic tools",
                ));
            }
            if count > 0 {
                tool.insert(
                    "functionDeclarations".to_owned(),
                    Value::Array(declarations[declaration_index..end].to_vec()),
                );
            }
            declaration_index = end;
            tools.push(Value::Object(tool));
        }
        if declaration_index != declarations.len() {
            return Err(invalid_value(
                "request.extensions.tool-layout",
                "function declaration counts do not cover semantic tools",
            ));
        }
        tools
    } else {
        let mut tools = extension_value(&request.extensions, PROVIDER_TOOLS_EXTENSION)?
            .map(|value| {
                value
                    .as_array()
                    .cloned()
                    .ok_or_else(|| invalid_shape("request.extensions.provider-tools", "an array"))
            })
            .transpose()?
            .unwrap_or_default();
        if !declarations.is_empty() {
            tools.insert(0, serde_json::json!({"functionDeclarations":declarations}));
        }
        tools
    };
    if !tools.is_empty() {
        object.insert("tools".to_owned(), Value::Array(tools));
    }
    Ok(())
}

fn encode_tool_definition(
    definition: &ToolDefinition,
    report: &mut ConversionReport,
) -> Result<Value, GeminiError> {
    let mut declaration = extension_value(&definition.extensions, TOOL_FIELDS_EXTENSION)?
        .map(|value| into_object(value, "tool.extensions.tool-fields"))
        .transpose()?
        .unwrap_or_default();
    declaration.insert("name".to_owned(), Value::String(definition.name.clone()));
    if let Some(description) = &definition.description {
        declaration.insert("description".to_owned(), Value::String(description.clone()));
    }
    if let Some(parameters) = &definition.parameters {
        declaration.insert(
            "parametersJsonSchema".to_owned(),
            parameters.value().clone(),
        );
    }
    if definition.strict.is_some() {
        report.drop_optional(
            format!("tools.{}.strict", definition.name),
            "Gemini function declarations have no strict toggle",
        );
    }
    report_unhandled_extensions(
        "tool.extensions",
        &definition.extensions,
        &[TOOL_FIELDS_EXTENSION],
        report,
    );
    Ok(Value::Object(declaration))
}

fn encode_tool_config(
    request: &SemanticRequest,
    object: &mut Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let mut config = extension_value(&request.extensions, TOOL_CONFIG_EXTENSION)?
        .map(|value| into_object(value, "request.extensions.tool-config"))
        .transpose()?
        .unwrap_or_default();
    if !config.contains_key("functionCallingConfig") {
        if let Some(choice) = &request.tool_choice {
            let function = match choice {
                ToolChoice::Auto => serde_json::json!({"mode":"AUTO"}),
                ToolChoice::None => serde_json::json!({"mode":"NONE"}),
                ToolChoice::Required => serde_json::json!({"mode":"ANY"}),
                ToolChoice::Tool { name } => {
                    serde_json::json!({"mode":"ANY","allowedFunctionNames":[name]})
                }
            };
            config.insert("functionCallingConfig".to_owned(), function);
        }
    }
    if !config.is_empty() {
        object.insert("toolConfig".to_owned(), Value::Object(config));
    }
    if request.tool_choice.is_some() && request.tools.is_empty() {
        report.unsupported_required(
            "tool_choice",
            "Gemini function calling configuration requires declared tools",
        );
    }
    Ok(())
}

fn encode_generation_config(
    request: &SemanticRequest,
    object: &mut Map<String, Value>,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let mut config = request_extension_object(&request.extensions, GENERATION_CONFIG_EXTENSION)?
        .unwrap_or_default();
    if let Some(value) = request.sampling.temperature {
        config.insert("temperature".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = request.sampling.top_p {
        config.insert("topP".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = request.sampling.max_output_tokens {
        config.insert("maxOutputTokens".to_owned(), serde_json::json!(value));
    }
    if !request.sampling.stop.is_empty() {
        config.insert(
            "stopSequences".to_owned(),
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
    if let Some(value) = request.sampling.seed {
        config.insert("seed".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = request.sampling.presence_penalty {
        config.insert("presencePenalty".to_owned(), serde_json::json!(value));
    }
    if let Some(value) = request.sampling.frequency_penalty {
        config.insert("frequencyPenalty".to_owned(), serde_json::json!(value));
    }
    report_unhandled_extensions(
        "sampling.extensions",
        &request.sampling.extensions,
        &[],
        report,
    );
    if let Some(format) = &request.response_format {
        match format {
            ResponseFormat::Text => {
                config.insert(
                    "responseMimeType".to_owned(),
                    Value::String("text/plain".to_owned()),
                );
            }
            ResponseFormat::JsonObject => {
                config.insert(
                    "responseMimeType".to_owned(),
                    Value::String("application/json".to_owned()),
                );
            }
            ResponseFormat::JsonSchema {
                name,
                schema,
                strict,
            } => {
                config.insert(
                    "responseMimeType".to_owned(),
                    Value::String("application/json".to_owned()),
                );
                config.insert("responseJsonSchema".to_owned(), schema.value().clone());
                if name != "gemini_response" {
                    report.drop_optional(
                        "response_format.name",
                        "Gemini response schemas do not carry a name",
                    );
                }
                if !strict {
                    report.degrade_field(
                        "response_format.strict",
                        "Gemini schema output is always constrained",
                    );
                }
            }
        }
    }
    if let Some(reasoning) = &request.reasoning {
        let mut thinking = extension_value(&reasoning.extensions, GENERATION_CONFIG_EXTENSION)?
            .map(|value| into_object(value, "reasoning.extensions.generation-config"))
            .transpose()?
            .unwrap_or_default();
        if reasoning.include_summary {
            thinking.insert("includeThoughts".to_owned(), Value::Bool(true));
        }
        if let Some(effort) = &reasoning.effort {
            let level = match effort {
                ReasoningEffort::Low => "LOW".to_owned(),
                ReasoningEffort::Medium => "MEDIUM".to_owned(),
                ReasoningEffort::High => "HIGH".to_owned(),
                ReasoningEffort::Max => {
                    report.degrade_field(
                        "reasoning.effort",
                        "Gemini's highest portable thinking level is HIGH",
                    );
                    "HIGH".to_owned()
                }
                ReasoningEffort::Custom(value) => value.to_ascii_uppercase(),
            };
            thinking.insert("thinkingLevel".to_owned(), Value::String(level));
        }
        if let Some(budget) = extension_value(&reasoning.extensions, THINKING_BUDGET_EXTENSION)? {
            thinking.insert("thinkingBudget".to_owned(), budget);
        }
        report_unhandled_extensions(
            "reasoning.extensions",
            &reasoning.extensions,
            &[THINKING_BUDGET_EXTENSION, GENERATION_CONFIG_EXTENSION],
            report,
        );
        if !thinking.is_empty() {
            config.insert("thinkingConfig".to_owned(), Value::Object(thinking));
        }
    }
    if !config.is_empty() {
        object.insert("generationConfig".to_owned(), Value::Object(config));
    }
    Ok(())
}

fn push_content(contents: &mut Vec<Value>, content: Value) {
    let Some(incoming) = content.as_object() else {
        contents.push(content);
        return;
    };
    let Some(role) = incoming.get("role") else {
        contents.push(content);
        return;
    };
    let Some(last) = contents.last_mut().and_then(Value::as_object_mut) else {
        contents.push(content);
        return;
    };
    if last.get("role") != Some(role) || last.len() != 2 || incoming.len() != 2 {
        contents.push(content);
        return;
    }
    let Some(incoming_parts) = incoming.get("parts").and_then(Value::as_array) else {
        contents.push(content);
        return;
    };
    let Some(last_parts) = last.get_mut("parts").and_then(Value::as_array_mut) else {
        contents.push(content);
        return;
    };
    last_parts.extend(incoming_parts.iter().cloned());
}

fn content_value(role: &str, parts: Vec<Value>) -> Value {
    serde_json::json!({"role":role,"parts":parts})
}

fn reasoning_text(reasoning: &ReasoningBlock) -> String {
    reasoning
        .text
        .as_ref()
        .or(reasoning.summary.as_ref())
        .cloned()
        .unwrap_or_default()
}

/// Stateful decoder for unary responses and streamGenerateContent JSON chunks.
#[derive(Clone, Debug, Default)]
pub struct GeminiEventDecoder {
    next_sequence: u64,
    next_block: u64,
    next_call: u64,
    response_id: Option<String>,
    model: Option<String>,
    response_started: bool,
    saw_tool_call: bool,
    pending_call_order: Vec<String>,
    pending_calls: BTreeMap<String, DecodedToolCall>,
    completed: bool,
}

#[derive(Clone, Debug)]
struct DecodedToolCall {
    name: String,
    arguments: Map<String, Value>,
    signature: Option<Vec<u8>>,
}

impl GeminiEventDecoder {
    /// Creates a decoder for one response stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes one complete GenerateContentResponse JSON object.
    pub fn decode_chunk(&mut self, input: &[u8]) -> Result<Vec<StreamEvent>, GeminiError> {
        if self.completed {
            return Err(GeminiError::InvalidStream {
                message: "chunk appeared after terminal response".to_owned(),
            });
        }
        let value: Value = serde_json::from_slice(input)?;
        let object = as_object(&value, "response")?;
        if let Some(error) = object.get("error") {
            return self.decode_error(error);
        }
        self.update_identity(object)?;
        let mut events = Vec::new();
        self.ensure_started(&mut events);

        let usage = object.get("usageMetadata").map(parse_usage).transpose()?;
        let candidates = object
            .get("candidates")
            .map(|value| as_array(value, "candidates"))
            .transpose()?
            .unwrap_or_default();
        if candidates.len() > 1 {
            return Err(GeminiError::InvalidStream {
                message: "semantic responses support one Gemini candidate".to_owned(),
            });
        }
        if candidates.is_empty() {
            if let Some(feedback) = object.get("promptFeedback") {
                if feedback.get("blockReason").is_some() {
                    self.completed = true;
                    events.push(self.event(StreamEventKind::Failure {
                        error: stream_error_from_prompt_feedback(feedback)?,
                    }));
                    return Ok(events);
                }
            }
            if let Some(usage) = usage {
                events.push(self.event(StreamEventKind::Usage { usage }));
            }
            return Ok(events);
        }

        let candidate = as_object(&candidates[0], "candidates[0]")?;
        if let Some(index) = candidate.get("index") {
            if as_u64(index, "candidates[0].index")? != 0 {
                return Err(GeminiError::InvalidStream {
                    message: "candidate index changed from zero".to_owned(),
                });
            }
        }
        if let Some(content) = candidate.get("content") {
            self.decode_candidate_content(content, &mut events)?;
        }
        let candidate_fields = preserved_candidate_fields(candidate);
        if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
            if is_error_finish_reason(reason) {
                self.completed = true;
                self.pending_calls.clear();
                self.pending_call_order.clear();
                let message = candidate
                    .get("finishMessage")
                    .and_then(Value::as_str)
                    .unwrap_or("Gemini stopped with an error finish reason");
                let mut error = StreamError::new(reason, message);
                error.details = Some(PreservedJson::from_value(Value::Object(candidate.clone()))?);
                events.push(self.event(StreamEventKind::Failure { error }));
            } else {
                events.extend(self.finish_tool_calls()?);
                self.completed = true;
                let finish_reason = if self.saw_tool_call && reason == "STOP" {
                    FinishReason::ToolCall
                } else {
                    decode_finish_reason(reason)
                };
                let mut completion = self.event(StreamEventKind::Completion {
                    finish_reason,
                    usage,
                });
                attach_candidate_fields(&mut completion.extensions, candidate_fields)?;
                events.push(completion);
            }
        } else {
            if !candidate_fields.is_empty() {
                let mut metadata = self.event(StreamEventKind::Metadata {
                    values: BTreeMap::new(),
                });
                attach_candidate_fields(&mut metadata.extensions, candidate_fields)?;
                events.push(metadata);
            }
            if let Some(usage) = usage {
                events.push(self.event(StreamEventKind::Usage { usage }));
            }
        }
        Ok(events)
    }

    /// Verifies that the provider produced a terminal finish reason or error.
    pub fn finish(&mut self) -> Result<Vec<StreamEvent>, GeminiError> {
        if self.completed {
            Ok(Vec::new())
        } else {
            Err(GeminiError::InvalidStream {
                message: "response ended without finishReason or error".to_owned(),
            })
        }
    }

    fn update_identity(&mut self, object: &Map<String, Value>) -> Result<(), GeminiError> {
        update_stable_string(
            &mut self.response_id,
            object.get("responseId"),
            "responseId",
        )?;
        update_stable_string(&mut self.model, object.get("modelVersion"), "modelVersion")?;
        Ok(())
    }

    fn ensure_started(&mut self, events: &mut Vec<StreamEvent>) {
        if self.response_started {
            return;
        }
        events.push(self.event(StreamEventKind::ResponseStart {
            response_id: self.response_id.clone(),
            model: self.model.clone(),
        }));
        self.response_started = true;
    }

    fn decode_error(&mut self, value: &Value) -> Result<Vec<StreamEvent>, GeminiError> {
        let object = as_object(value, "error")?;
        let message = required_string(object, "message", "error.message")?;
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("GEMINI_ERROR");
        let numeric_code = object.get("code").and_then(Value::as_u64);
        let retryable = numeric_code
            .is_some_and(|code| matches!(code, 408 | 409 | 429 | 500 | 502 | 503 | 504))
            || matches!(
                status,
                "ABORTED" | "DEADLINE_EXCEEDED" | "RESOURCE_EXHAUSTED" | "UNAVAILABLE"
            );
        let mut error = StreamError::new(status, message).with_retryable(retryable);
        error.details = Some(PreservedJson::from_value(value.clone())?);
        self.completed = true;
        Ok(vec![self.event(StreamEventKind::Failure { error })])
    }

    fn decode_candidate_content(
        &mut self,
        value: &Value,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), GeminiError> {
        let object = as_object(value, "candidates[0].content")?;
        if let Some(role) = object.get("role").and_then(Value::as_str) {
            if role != "model" {
                return Err(invalid_value(
                    "candidates[0].content.role",
                    format!("expected model, got `{role}`"),
                ));
            }
        }
        let parts = object
            .get("parts")
            .map(|value| as_array(value, "candidates[0].content.parts"))
            .transpose()?
            .unwrap_or_default();
        for (index, part) in parts.iter().enumerate() {
            self.decode_response_part(part, index, events)?;
        }
        Ok(())
    }

    fn decode_response_part(
        &mut self,
        value: &Value,
        index: usize,
        events: &mut Vec<StreamEvent>,
    ) -> Result<(), GeminiError> {
        let object = as_object(value, &format!("candidates[0].content.parts[{index}]"))?;
        let signature = object
            .get("thoughtSignature")
            .map(|value| {
                let value = as_string(value, "thoughtSignature")?;
                BASE64
                    .decode(value)
                    .map_err(|_| GeminiError::InvalidBase64 {
                        field: "thoughtSignature".to_owned(),
                    })
            })
            .transpose()?;
        if let Some(text) = object.get("text") {
            let text = as_string(text, "part.text")?;
            let block_id = self.block_id(if object.get("thought") == Some(&Value::Bool(true)) {
                "reasoning"
            } else {
                "text"
            });
            if object.get("thought") == Some(&Value::Bool(true)) {
                events.push(self.block_event(StreamEventKind::ReasoningStart, &block_id));
                if !text.is_empty() {
                    events.push(self.block_event(
                        StreamEventKind::ReasoningDelta {
                            text: text.to_owned(),
                        },
                        &block_id,
                    ));
                }
                events.push(self.block_event(
                    StreamEventKind::ReasoningEnd {
                        reasoning: Some(ReasoningBlock {
                            signature,
                            ..ReasoningBlock::default()
                        }),
                    },
                    &block_id,
                ));
            } else {
                let mut start = self.block_event(StreamEventKind::TextStart, &block_id);
                if let Some(signature) = signature {
                    attach_signature(&mut start.extensions, &signature)?;
                }
                events.push(start);
                if !text.is_empty() {
                    events.push(self.block_event(
                        StreamEventKind::TextDelta {
                            text: text.to_owned(),
                        },
                        &block_id,
                    ));
                }
                events.push(self.block_event(StreamEventKind::TextEnd, &block_id));
            }
            return Ok(());
        }
        if let Some(call) = object.get("functionCall") {
            let call = as_object(call, "part.functionCall")?;
            let id = call
                .get("id")
                .map(|value| as_string(value, "part.functionCall.id").map(ToOwned::to_owned))
                .transpose()?
                .unwrap_or_else(|| {
                    self.next_call = self.next_call.saturating_add(1);
                    format!("gemini-call-{}", self.next_call)
                });
            let name = required_string(call, "name", "part.functionCall.name")?;
            let args = call
                .get("args")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            let args = args
                .as_object()
                .cloned()
                .ok_or_else(|| invalid_shape("part.functionCall.args", "an object"))?;
            self.accumulate_tool_call(id, name, args, signature)?;
            return Ok(());
        }
        if let Some(data) = object.get("inlineData") {
            let part = decode_inline_data(data, "part.inlineData")?;
            if let Some((media_type, source)) = semantic_media(part) {
                let mut event = self.event(StreamEventKind::Media { media_type, source });
                attach_response_part_fields(&mut event.extensions, object, "inlineData")?;
                events.push(event);
            }
            return Ok(());
        }
        if let Some(data) = object.get("fileData") {
            let part = decode_file_data(data, "part.fileData")?;
            if let Some((media_type, source)) = semantic_media(part) {
                let mut event = self.event(StreamEventKind::Media { media_type, source });
                attach_response_part_fields(&mut event.extensions, object, "fileData")?;
                events.push(event);
            }
            return Ok(());
        }
        events.push(self.event(StreamEventKind::Opaque {
            media_type: GEMINI_PART_JSON_CONTENT_TYPE.to_owned(),
            data: serde_json::to_vec(value)?,
        }));
        Ok(())
    }

    fn accumulate_tool_call(
        &mut self,
        id: String,
        name: &str,
        arguments: Map<String, Value>,
        signature: Option<Vec<u8>>,
    ) -> Result<(), GeminiError> {
        if let Some(call) = self.pending_calls.get_mut(&id) {
            if call.name != name {
                return Err(GeminiError::InvalidStream {
                    message: format!("tool call `{id}` changed names"),
                });
            }
            if call
                .signature
                .as_ref()
                .zip(signature.as_ref())
                .is_some_and(|(existing, incoming)| existing != incoming)
            {
                return Err(GeminiError::InvalidStream {
                    message: format!("tool call `{id}` changed thought signatures"),
                });
            }
            if call.signature.is_none() {
                call.signature = signature;
            }
            call.arguments.extend(arguments);
        } else {
            self.pending_call_order.push(id.clone());
            self.pending_calls.insert(
                id,
                DecodedToolCall {
                    name: name.to_owned(),
                    arguments,
                    signature,
                },
            );
        }
        self.saw_tool_call = true;
        Ok(())
    }

    fn finish_tool_calls(&mut self) -> Result<Vec<StreamEvent>, GeminiError> {
        let order = std::mem::take(&mut self.pending_call_order);
        let mut calls = std::mem::take(&mut self.pending_calls);
        let mut events = Vec::new();
        for id in order {
            let call = calls
                .remove(&id)
                .ok_or_else(|| GeminiError::InvalidStream {
                    message: format!("tool call `{id}` disappeared before completion"),
                })?;
            let mut start = self.event(StreamEventKind::ToolCallStart {
                id: id.clone(),
                name: call.name,
            });
            start.block_id = Some(id.clone());
            if let Some(signature) = call.signature {
                attach_signature(&mut start.extensions, &signature)?;
            }
            events.push(start);
            events.push(self.block_event(
                StreamEventKind::ToolCallDelta {
                    id: id.clone(),
                    arguments: serde_json::to_string(&Value::Object(call.arguments))?,
                },
                &id,
            ));
            events.push(self.block_event(StreamEventKind::ToolCallEnd { id: id.clone() }, &id));
        }
        Ok(events)
    }

    fn block_id(&mut self, kind: &str) -> String {
        self.next_block = self.next_block.saturating_add(1);
        format!("gemini-{kind}-{}", self.next_block)
    }

    fn event(&mut self, kind: StreamEventKind) -> StreamEvent {
        self.next_sequence = self.next_sequence.saturating_add(1);
        StreamEvent::new(self.next_sequence, kind)
    }

    fn block_event(&mut self, kind: StreamEventKind, block_id: &str) -> StreamEvent {
        self.event(kind).with_block_id(block_id)
    }
}

fn semantic_media(part: ContentPart) -> Option<(String, MediaSource)> {
    match part {
        ContentPart::Image {
            media_type, source, ..
        }
        | ContentPart::File {
            media_type, source, ..
        }
        | ContentPart::Audio { media_type, source } => Some((media_type, source)),
        ContentPart::Text { .. }
        | ContentPart::Reasoning(_)
        | ContentPart::ToolCall(_)
        | ContentPart::ToolResult(_)
        | ContentPart::Provider { .. } => None,
    }
}

fn stream_error_from_prompt_feedback(value: &Value) -> Result<StreamError, GeminiError> {
    let object = as_object(value, "promptFeedback")?;
    let reason = object
        .get("blockReason")
        .and_then(Value::as_str)
        .unwrap_or("BLOCKED");
    let mut error = StreamError::new(
        format!("GEMINI_PROMPT_{reason}"),
        "Gemini blocked the request prompt",
    );
    error.details = Some(PreservedJson::from_value(value.clone())?);
    Ok(error)
}

fn decode_finish_reason(value: &str) -> FinishReason {
    match value {
        "STOP" => FinishReason::Stop,
        "MAX_TOKENS" => FinishReason::Length,
        "SAFETY"
        | "RECITATION"
        | "LANGUAGE"
        | "BLOCKLIST"
        | "PROHIBITED_CONTENT"
        | "SPII"
        | "IMAGE_SAFETY"
        | "IMAGE_PROHIBITED_CONTENT" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_owned()),
    }
}

fn is_error_finish_reason(value: &str) -> bool {
    matches!(
        value,
        "MALFORMED_FUNCTION_CALL"
            | "UNEXPECTED_TOOL_CALL"
            | "TOO_MANY_TOOL_CALLS"
            | "MISSING_THOUGHT_SIGNATURE"
            | "MALFORMED_RESPONSE"
            | "ESCALATION"
    )
}

fn parse_usage(value: &Value) -> Result<Usage, GeminiError> {
    let object = as_object(value, "usageMetadata")?;
    let input_tokens =
        optional_u64(object, "promptTokenCount", "usageMetadata.promptTokenCount")?.unwrap_or(0);
    let output_tokens = optional_u64(
        object,
        "candidatesTokenCount",
        "usageMetadata.candidatesTokenCount",
    )?
    .unwrap_or(0);
    let mut usage = Usage {
        input_tokens,
        output_tokens,
        reasoning_tokens: optional_u64(
            object,
            "thoughtsTokenCount",
            "usageMetadata.thoughtsTokenCount",
        )?,
        cached_input_tokens: optional_u64(
            object,
            "cachedContentTokenCount",
            "usageMetadata.cachedContentTokenCount",
        )?,
        total_tokens: optional_u64(object, "totalTokenCount", "usageMetadata.totalTokenCount")?,
        details: BTreeMap::new(),
    };
    if let Some(value) = optional_u64(
        object,
        "toolUsePromptTokenCount",
        "usageMetadata.toolUsePromptTokenCount",
    )? {
        usage
            .details
            .insert("tool_use_prompt_tokens".to_owned(), value);
    }
    Ok(usage)
}

fn preserved_candidate_fields(candidate: &Map<String, Value>) -> Map<String, Value> {
    candidate
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "content" | "finishReason" | "index"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[derive(Clone, Debug)]
struct PendingToolCall {
    name: String,
    arguments: String,
    signature: Option<Vec<u8>>,
}

/// Stateful encoder for streamGenerateContent response JSON objects.
#[derive(Clone, Debug, Default)]
pub struct GeminiEventEncoder {
    response_id: Option<String>,
    model: Option<String>,
    text_signature: Option<Vec<u8>>,
    tools: BTreeMap<String, PendingToolCall>,
    completed: bool,
}

impl GeminiEventEncoder {
    /// Creates an encoder for one response stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encodes one semantic event as one complete GenerateContentResponse object.
    /// Lifecycle-only events return `None`.
    pub fn encode_event(
        &mut self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<Option<EncodedGeminiChunk>, GeminiError> {
        if self.completed {
            return Err(GeminiError::UnsupportedEvent {
                message: "event appeared after terminal response".to_owned(),
            });
        }
        let mut report = ConversionReport::default();
        let value = match &event.kind {
            StreamEventKind::ResponseStart { response_id, model } => {
                self.response_id.clone_from(response_id);
                self.model.clone_from(model);
                None
            }
            StreamEventKind::TextStart => {
                self.text_signature = event_signature(&event.extensions).map(ToOwned::to_owned);
                None
            }
            StreamEventKind::TextDelta { text } => {
                let mut part = Map::from_iter([("text".to_owned(), Value::String(text.clone()))]);
                if let Some(signature) = self.text_signature.take() {
                    part.insert(
                        "thoughtSignature".to_owned(),
                        Value::String(BASE64.encode(signature)),
                    );
                    report.preserve_capability("gemini.thought_signature");
                }
                Some(self.part_response(Value::Object(part)))
            }
            StreamEventKind::TextEnd => self.text_signature.take().map(|signature| {
                self.part_response(serde_json::json!({
                    "text":"",
                    "thoughtSignature":BASE64.encode(signature)
                }))
            }),
            StreamEventKind::ReasoningStart => None,
            StreamEventKind::ReasoningDelta { text } => {
                Some(self.part_response(serde_json::json!({"text":text,"thought":true})))
            }
            StreamEventKind::ReasoningEnd { reasoning } => reasoning
                .as_ref()
                .and_then(|reasoning| reasoning.signature.as_ref())
                .map(|signature| {
                    self.part_response(serde_json::json!({
                        "text":"",
                        "thought":true,
                        "thoughtSignature":BASE64.encode(signature)
                    }))
                }),
            StreamEventKind::ToolCallStart { id, name } => {
                self.tools.insert(
                    id.clone(),
                    PendingToolCall {
                        name: name.clone(),
                        arguments: String::new(),
                        signature: event_signature(&event.extensions).map(ToOwned::to_owned),
                    },
                );
                None
            }
            StreamEventKind::ToolCallDelta { id, arguments } => {
                let tool = self
                    .tools
                    .get_mut(id)
                    .ok_or_else(|| GeminiError::UnsupportedEvent {
                        message: format!("tool call `{id}` has no start event"),
                    })?;
                tool.arguments.push_str(arguments);
                None
            }
            StreamEventKind::ToolCallEnd { id } => {
                let tool = self
                    .tools
                    .remove(id)
                    .ok_or_else(|| GeminiError::UnsupportedEvent {
                        message: format!("tool call `{id}` has no start event"),
                    })?;
                let args = if tool.arguments.is_empty() {
                    Value::Object(Map::new())
                } else {
                    serde_json::from_str(&tool.arguments)?
                };
                if !args.is_object() {
                    return Err(invalid_shape("tool_call.arguments", "an object"));
                }
                let mut part = Map::from_iter([(
                    "functionCall".to_owned(),
                    serde_json::json!({"id":id,"name":tool.name,"args":args}),
                )]);
                if let Some(signature) = tool.signature {
                    part.insert(
                        "thoughtSignature".to_owned(),
                        Value::String(BASE64.encode(signature)),
                    );
                    report.preserve_capability("gemini.thought_signature");
                }
                Some(self.part_response(Value::Object(part)))
            }
            StreamEventKind::Media { media_type, source } => {
                let mut part =
                    into_object(encode_media(media_type, source)?, "encoded media part")?;
                if let Some(video_metadata) =
                    extension_value(&event.extensions, VIDEO_METADATA_EXTENSION)?
                {
                    part.insert("videoMetadata".to_owned(), video_metadata);
                }
                if let Some(fields) = extension_value(&event.extensions, PART_FIELDS_EXTENSION)? {
                    merge_fields(
                        &mut part,
                        &into_object(fields, "event.extensions.part-fields")?,
                        "event.extensions.part-fields",
                    )?;
                }
                Some(self.part_response(Value::Object(part)))
            }
            StreamEventKind::Usage { usage } => {
                let mut response = self.base_response();
                response.insert("usageMetadata".to_owned(), encode_usage(usage));
                Some(Value::Object(response))
            }
            StreamEventKind::Refusal { text } => {
                Some(self.part_response(serde_json::json!({"text":text})))
            }
            StreamEventKind::Completion {
                finish_reason,
                usage,
            } => {
                if !self.tools.is_empty() {
                    return Err(GeminiError::UnsupportedEvent {
                        message: "completion appeared with an open tool call".to_owned(),
                    });
                }
                let mut response = self.base_response();
                let mut candidate =
                    candidate_extension_object(&event.extensions)?.unwrap_or_default();
                candidate.insert("index".to_owned(), Value::Number(0.into()));
                candidate.insert(
                    "finishReason".to_owned(),
                    Value::String(encode_finish_reason(finish_reason)),
                );
                response.insert(
                    "candidates".to_owned(),
                    Value::Array(vec![Value::Object(candidate)]),
                );
                if let Some(usage) = usage {
                    response.insert("usageMetadata".to_owned(), encode_usage(usage));
                }
                self.completed = true;
                Some(Value::Object(response))
            }
            StreamEventKind::Failure { error } => {
                self.completed = true;
                Some(encode_stream_error(error))
            }
            StreamEventKind::Metadata { .. } => {
                if let Some(mut candidate) = candidate_extension_object(&event.extensions)? {
                    candidate.insert("index".to_owned(), Value::Number(0.into()));
                    let mut response = self.base_response();
                    response.insert(
                        "candidates".to_owned(),
                        Value::Array(vec![Value::Object(candidate)]),
                    );
                    Some(Value::Object(response))
                } else {
                    report.drop_optional(
                        "event.metadata",
                        "Gemini response chunks have no portable semantic metadata event",
                    );
                    None
                }
            }
            StreamEventKind::Warning { .. } => {
                report.drop_optional(
                    "event.warning",
                    "Gemini response chunks have no portable semantic warning event",
                );
                None
            }
            StreamEventKind::Opaque { media_type, data }
                if media_type == GEMINI_PART_JSON_CONTENT_TYPE =>
            {
                let part: Value = serde_json::from_slice(data)?;
                if !part.is_object() {
                    return Err(invalid_shape("event.opaque", "a Gemini Part object"));
                }
                report.preserve_capability("gemini.response.part");
                Some(self.part_response(part))
            }
            StreamEventKind::Opaque { .. } => {
                report.unsupported_required(
                    "event.opaque",
                    "non-JSON opaque events cannot become Gemini response objects",
                );
                None
            }
        };
        let mut handled_extensions = vec![THOUGHT_SIGNATURE_EXTENSION];
        match event.kind {
            StreamEventKind::Media { .. } => {
                handled_extensions.extend([PART_FIELDS_EXTENSION, VIDEO_METADATA_EXTENSION]);
            }
            StreamEventKind::Completion { .. } | StreamEventKind::Metadata { .. } => {
                handled_extensions.extend([
                    CANDIDATE_FIELDS_EXTENSION,
                    SAFETY_RATINGS_EXTENSION,
                    GROUNDING_METADATA_EXTENSION,
                ]);
            }
            _ => {}
        }
        report_unhandled_extensions(
            "event.extensions",
            &event.extensions,
            &handled_extensions,
            &mut report,
        );
        report.validate(policy)?;
        value
            .map(|value| {
                Ok(EncodedGeminiChunk {
                    body: serde_json::to_vec(&value)?,
                    report,
                })
            })
            .transpose()
    }

    fn base_response(&self) -> Map<String, Value> {
        let mut response = Map::new();
        if let Some(response_id) = &self.response_id {
            response.insert("responseId".to_owned(), Value::String(response_id.clone()));
        }
        if let Some(model) = &self.model {
            response.insert("modelVersion".to_owned(), Value::String(model.clone()));
        }
        response
    }

    fn part_response(&self, part: Value) -> Value {
        let mut response = self.base_response();
        response.insert(
            "candidates".to_owned(),
            serde_json::json!([{
                "index":0,
                "content":{"role":"model","parts":[part]}
            }]),
        );
        Value::Object(response)
    }
}

fn encode_unary_response(
    events: &[StreamEvent],
    policy: LossPolicy,
) -> Result<EncodedGeminiResponse, GeminiError> {
    let mut encoder = GeminiEventEncoder::new();
    let mut report = ConversionReport::default();
    let mut response = Map::new();
    let mut parts = Vec::new();
    let mut finish_reason = None;
    let mut candidate_fields = Map::new();
    for event in events {
        let Some(chunk) = encoder.encode_event(event, policy)? else {
            continue;
        };
        report.merge(chunk.report);
        let value: Value = serde_json::from_slice(&chunk.body)?;
        let chunk = into_object(value, "encoded response chunk")?;
        if chunk.contains_key("error") {
            return Ok(EncodedGeminiResponse {
                body: serde_json::to_vec(&Value::Object(chunk))?,
                report,
            });
        }
        if let Some(value) = chunk.get("responseId") {
            response.insert("responseId".to_owned(), value.clone());
        }
        if let Some(value) = chunk.get("modelVersion") {
            response.insert("modelVersion".to_owned(), value.clone());
        }
        if let Some(value) = chunk.get("usageMetadata") {
            response.insert("usageMetadata".to_owned(), value.clone());
        }
        if let Some(candidate) = chunk
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_object)
        {
            if let Some(value) = candidate.get("finishReason") {
                finish_reason = Some(value.clone());
            }
            for (key, value) in candidate {
                if matches!(key.as_str(), "content" | "finishReason" | "index") {
                    continue;
                }
                if candidate_fields
                    .get(key)
                    .is_some_and(|existing| existing != value)
                {
                    return Err(GeminiError::InvalidStream {
                        message: format!(
                            "candidate field `{key}` changed while building a unary response"
                        ),
                    });
                }
                candidate_fields.insert(key.clone(), value.clone());
            }
            if let Some(values) = candidate
                .get("content")
                .and_then(|value| value.get("parts"))
                .and_then(Value::as_array)
            {
                parts.extend(values.iter().cloned());
            }
        }
    }
    let mut candidate = candidate_fields;
    candidate.insert("index".to_owned(), Value::Number(0.into()));
    if !parts.is_empty() {
        candidate.insert(
            "content".to_owned(),
            serde_json::json!({"role":"model","parts":parts}),
        );
    }
    if let Some(finish_reason) = finish_reason {
        candidate.insert("finishReason".to_owned(), finish_reason);
    }
    response.insert(
        "candidates".to_owned(),
        Value::Array(vec![Value::Object(candidate)]),
    );
    report.validate(policy)?;
    Ok(EncodedGeminiResponse {
        body: serde_json::to_vec(&Value::Object(response))?,
        report,
    })
}

fn encode_finish_reason(reason: &FinishReason) -> String {
    match reason {
        FinishReason::Stop | FinishReason::ToolCall => "STOP".to_owned(),
        FinishReason::Length => "MAX_TOKENS".to_owned(),
        FinishReason::ContentFilter => "SAFETY".to_owned(),
        FinishReason::Error => "OTHER".to_owned(),
        FinishReason::Other(value) => value.clone(),
    }
}

fn encode_usage(usage: &Usage) -> Value {
    let mut value = Map::from_iter([
        (
            "promptTokenCount".to_owned(),
            Value::Number(usage.input_tokens.into()),
        ),
        (
            "candidatesTokenCount".to_owned(),
            Value::Number(usage.output_tokens.into()),
        ),
        (
            "totalTokenCount".to_owned(),
            Value::Number(
                usage
                    .total_tokens
                    .unwrap_or_else(|| {
                        usage
                            .input_tokens
                            .saturating_add(usage.output_tokens)
                            .saturating_add(usage.reasoning_tokens.unwrap_or(0))
                    })
                    .into(),
            ),
        ),
    ]);
    if let Some(tokens) = usage.reasoning_tokens {
        value.insert(
            "thoughtsTokenCount".to_owned(),
            Value::Number(tokens.into()),
        );
    }
    if let Some(tokens) = usage.cached_input_tokens {
        value.insert(
            "cachedContentTokenCount".to_owned(),
            Value::Number(tokens.into()),
        );
    }
    if let Some(tokens) = usage.details.get("tool_use_prompt_tokens") {
        value.insert(
            "toolUsePromptTokenCount".to_owned(),
            Value::Number((*tokens).into()),
        );
    }
    Value::Object(value)
}

fn encode_stream_error(error: &StreamError) -> Value {
    let mut inner = Map::from_iter([
        ("message".to_owned(), Value::String(error.message.clone())),
        ("status".to_owned(), Value::String(error.code.clone())),
    ]);
    if let Some(details) = &error.details {
        if let Some(value) = details.value().get("details") {
            inner.insert("details".to_owned(), value.clone());
        }
        if let Some(value) = details.value().get("code") {
            inner.insert("code".to_owned(), value.clone());
        }
    }
    Value::Object(Map::from_iter([("error".to_owned(), Value::Object(inner))]))
}

fn preserve_json_extension(
    extensions: &mut Extensions,
    name: &str,
    value: Value,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let extension = OpaqueExtension::new(GEMINI_NAMESPACE, name, serde_json::to_vec(&value)?)?
        .with_media_type(GEMINI_JSON_CONTENT_TYPE)?
        .with_replay_policy(ReplayPolicy::IfSafe);
    let key = extension.key();
    extensions.insert(extension);
    report.preserve_extension(&key);
    Ok(())
}

fn preserve_bytes_extension(
    extensions: &mut Extensions,
    name: &str,
    value: &[u8],
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let extension = OpaqueExtension::new(GEMINI_NAMESPACE, name, value.to_vec())?
        .with_replay_policy(ReplayPolicy::IfSafe);
    let key = extension.key();
    extensions.insert(extension);
    report.preserve_extension(&key);
    Ok(())
}

fn preserve_text_extension(
    extensions: &mut Extensions,
    name: &str,
    value: &str,
    report: &mut ConversionReport,
) -> Result<(), GeminiError> {
    let extension = OpaqueExtension::new(GEMINI_NAMESPACE, name, value.as_bytes().to_vec())?
        .with_media_type("text/plain; charset=utf-8")?
        .with_replay_policy(ReplayPolicy::IfSafe);
    let key = extension.key();
    extensions.insert(extension);
    report.preserve_extension(&key);
    Ok(())
}

fn attach_signature(extensions: &mut Extensions, signature: &[u8]) -> Result<(), GeminiError> {
    extensions.insert(
        OpaqueExtension::new(
            GEMINI_NAMESPACE,
            THOUGHT_SIGNATURE_EXTENSION,
            signature.to_vec(),
        )?
        .with_replay_policy(ReplayPolicy::IfSafe),
    );
    Ok(())
}

fn attach_candidate_fields(
    extensions: &mut Extensions,
    mut fields: Map<String, Value>,
) -> Result<(), GeminiError> {
    if let Some(safety_ratings) = fields.remove("safetyRatings") {
        attach_json_extension(extensions, SAFETY_RATINGS_EXTENSION, safety_ratings)?;
    }
    if let Some(grounding_metadata) = fields.remove("groundingMetadata") {
        attach_json_extension(extensions, GROUNDING_METADATA_EXTENSION, grounding_metadata)?;
    }
    if !fields.is_empty() {
        attach_json_extension(
            extensions,
            CANDIDATE_FIELDS_EXTENSION,
            Value::Object(fields),
        )?;
    }
    Ok(())
}

fn attach_response_part_fields(
    extensions: &mut Extensions,
    part: &Map<String, Value>,
    data_field: &str,
) -> Result<(), GeminiError> {
    let mut fields = part.clone();
    fields.remove(data_field);
    if let Some(video_metadata) = fields.remove("videoMetadata") {
        attach_json_extension(extensions, VIDEO_METADATA_EXTENSION, video_metadata)?;
    }
    if !fields.is_empty() {
        attach_json_extension(extensions, PART_FIELDS_EXTENSION, Value::Object(fields))?;
    }
    Ok(())
}

fn attach_json_extension(
    extensions: &mut Extensions,
    name: &str,
    value: Value,
) -> Result<(), GeminiError> {
    extensions.insert(
        OpaqueExtension::new(GEMINI_NAMESPACE, name, serde_json::to_vec(&value)?)?
            .with_media_type(GEMINI_JSON_CONTENT_TYPE)?
            .with_replay_policy(ReplayPolicy::IfSafe),
    );
    Ok(())
}

fn extension_key(name: &str) -> String {
    format!("{GEMINI_NAMESPACE}.{name}")
}

fn extension_bytes<'a>(extensions: &'a Extensions, name: &str) -> Option<&'a [u8]> {
    extensions
        .get_str(&extension_key(name))
        .map(OpaqueExtension::as_bytes)
}

fn extension_text<'a>(
    extensions: &'a Extensions,
    name: &str,
) -> Result<Option<&'a str>, GeminiError> {
    extension_bytes(extensions, name)
        .map(|bytes| {
            std::str::from_utf8(bytes).map_err(|_| {
                invalid_value(
                    &format!("extensions.{}", extension_key(name)),
                    "must contain UTF-8 text",
                )
            })
        })
        .transpose()
}

fn extension_value(extensions: &Extensions, name: &str) -> Result<Option<Value>, GeminiError> {
    extension_bytes(extensions, name)
        .map(|bytes| serde_json::from_slice(bytes).map_err(GeminiError::Json))
        .transpose()
}

fn candidate_extension_object(
    extensions: &Extensions,
) -> Result<Option<Map<String, Value>>, GeminiError> {
    let mut fields = extension_value(extensions, CANDIDATE_FIELDS_EXTENSION)?
        .map(|value| into_object(value, "event.extensions.candidate-fields"))
        .transpose()?
        .unwrap_or_default();
    for (wire_name, extension_name) in [
        ("safetyRatings", SAFETY_RATINGS_EXTENSION),
        ("groundingMetadata", GROUNDING_METADATA_EXTENSION),
    ] {
        if let Some(value) = extension_value(extensions, extension_name)? {
            if fields.insert(wire_name.to_owned(), value).is_some() {
                return Err(invalid_value(
                    "event.extensions",
                    format!("duplicate Gemini candidate field `{wire_name}`"),
                ));
            }
        }
    }
    Ok((!fields.is_empty()).then_some(fields))
}

fn request_extension_object(
    extensions: &Extensions,
    name: &str,
) -> Result<Option<Map<String, Value>>, GeminiError> {
    extension_value(extensions, name)?
        .map(|value| into_object(value, &format!("request.extensions.{name}")))
        .transpose()
}

fn event_signature(extensions: &Extensions) -> Option<&[u8]> {
    extension_bytes(extensions, THOUGHT_SIGNATURE_EXTENSION)
}

fn report_unhandled_extensions(
    field: &str,
    extensions: &Extensions,
    handled_names: &[&str],
    report: &mut ConversionReport,
) {
    for (key, _) in extensions {
        if key.namespace.as_str() == GEMINI_NAMESPACE && handled_names.contains(&key.name.as_str())
        {
            report.preserve_extension(key);
        } else {
            report.drop_optional(
                format!("{field}.{}", key.as_str()),
                "extension has no Gemini GenerateContent representation",
            );
        }
    }
}

fn merge_fields(
    destination: &mut Map<String, Value>,
    source: &Map<String, Value>,
    field: &str,
) -> Result<(), GeminiError> {
    for (key, value) in source {
        if let Some(existing) = destination.get(key) {
            if existing != value {
                return Err(invalid_value(
                    field,
                    format!("extension field `{key}` collides with semantic data"),
                ));
            }
        } else {
            destination.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

fn into_object(value: Value, field: &str) -> Result<Map<String, Value>, GeminiError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_shape(field, "an object"))
}

fn as_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, GeminiError> {
    value
        .as_object()
        .ok_or_else(|| invalid_shape(field, "an object"))
}

fn as_object_mut<'a>(
    value: &'a mut Value,
    field: &str,
) -> Result<&'a mut Map<String, Value>, GeminiError> {
    value
        .as_object_mut()
        .ok_or_else(|| invalid_shape(field, "an object"))
}

fn as_array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], GeminiError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_shape(field, "an array"))
}

fn as_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, GeminiError> {
    value
        .as_str()
        .ok_or_else(|| invalid_shape(field, "a string"))
}

fn as_u64(value: &Value, field: &str) -> Result<u64, GeminiError> {
    value
        .as_u64()
        .ok_or_else(|| invalid_shape(field, "an unsigned integer"))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, GeminiError> {
    object
        .get(key)
        .ok_or_else(|| missing(field))
        .and_then(|value| as_string(value, field))
}

fn take_required_string(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<String, GeminiError> {
    object
        .remove(key)
        .ok_or_else(|| missing(field))
        .and_then(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid_shape(field, "a string"))
        })
}

fn take_string(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<String>, GeminiError> {
    object
        .remove(key)
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid_shape(field, "a string"))
        })
        .transpose()
}

fn take_bool(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<bool>, GeminiError> {
    object
        .remove(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid_shape(field, "a boolean"))
        })
        .transpose()
}

fn take_base64(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<Vec<u8>>, GeminiError> {
    take_string(object, key, field)?
        .map(|value| {
            BASE64
                .decode(value)
                .map_err(|_| GeminiError::InvalidBase64 {
                    field: field.to_owned(),
                })
        })
        .transpose()
}

fn take_f32(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<f32>, GeminiError> {
    object
        .remove(key)
        .map(|value| {
            let value = value
                .as_f64()
                .ok_or_else(|| invalid_shape(field, "a number"))?;
            if !value.is_finite() || value < f32::MIN as f64 || value > f32::MAX as f64 {
                return Err(invalid_value(
                    field,
                    "number is outside the supported range",
                ));
            }
            Ok(value as f32)
        })
        .transpose()
}

fn take_u64(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<u64>, GeminiError> {
    object
        .remove(key)
        .map(|value| as_u64(&value, field))
        .transpose()
}

fn take_u32(
    object: &mut Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<u32>, GeminiError> {
    take_u64(object, key, field)?
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| invalid_value(field, "integer is outside the supported range"))
        })
        .transpose()
}

fn optional_u64(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<u64>, GeminiError> {
    object
        .get(key)
        .map(|value| as_u64(value, field))
        .transpose()
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>, GeminiError> {
    as_array(value, field)?
        .iter()
        .enumerate()
        .map(|(index, value)| as_string(value, &format!("{field}[{index}]")).map(ToOwned::to_owned))
        .collect()
}

fn update_stable_string(
    destination: &mut Option<String>,
    value: Option<&Value>,
    field: &str,
) -> Result<(), GeminiError> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = as_string(value, field)?;
    if let Some(previous) = destination {
        if previous != value {
            return Err(GeminiError::InvalidStream {
                message: format!("{field} changed within one stream"),
            });
        }
    } else {
        *destination = Some(value.to_owned());
    }
    Ok(())
}

fn missing(field: impl Into<String>) -> GeminiError {
    GeminiError::MissingField {
        field: field.into(),
    }
}

fn invalid_shape(field: &str, expected: &'static str) -> GeminiError {
    GeminiError::InvalidShape {
        field: field.to_owned(),
        expected,
    }
}

fn invalid_value(field: &str, message: impl Into<String>) -> GeminiError {
    GeminiError::InvalidValue {
        field: field.to_owned(),
        message: message.into(),
    }
}
