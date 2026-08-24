//! Devin chat request and streamed response semantic codecs.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use prost::Message as ProstMessage;
use std::{collections::BTreeMap, fmt, mem};
use thiserror::Error;

use crate::{
    connect::{
        encode_connect_frame_with_limits, read_connect_trailer_error, ConnectDecoder, ConnectError,
        ConnectFrame, ConnectLimits,
    },
    metadata::{
        metadata, normalize_devin_session_token, DevinClientMetadata, DEVIN_DEFAULT_STOP_PATTERNS,
    },
    proto::{
        chat_tool_choice, CacheControlType, ChatMessagePrompt, ChatMessageRequestType,
        ChatMessageSource, ChatToolCall, ChatToolChoice, ChatToolDefinition,
        CompletionConfiguration, ConversationalPlannerMode, GetChatMessageRequest,
        GetChatMessageResponse, ImageData, ModelUsageStats, PromptCacheOptions, StopReason,
    },
};
use pooler_core::LossPolicy;
use pooler_protocol::{
    ContentPart, ConversionReport, Extensions, FinishReason, InputItem, MediaSource, Message,
    OpaqueExtension, PreservedJson, ReasoningBlock, Role, SemanticRequest, StreamError,
    StreamEvent, StreamEventKind, ToolCall, ToolChoice, ToolDefinition, ToolResult, Usage,
};

/// Maximum input messages accepted by the default Devin decoder.
pub const DEFAULT_MAX_CHAT_MESSAGES: usize = 4096;
/// Maximum content bytes accepted by the default Devin decoder.
pub const DEFAULT_MAX_CHAT_CONTENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum tool declarations accepted by the default Devin decoder.
pub const DEFAULT_MAX_CHAT_TOOLS: usize = 512;
/// Maximum serialized tool argument bytes retained for one call.
pub const DEFAULT_MAX_TOOL_ARGUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum streamed tool calls retained by the default response decoder.
pub const DEFAULT_MAX_RESPONSE_TOOL_CALLS: usize = 256;
/// Maximum cumulative argument bytes retained for one streamed tool call.
pub const DEFAULT_MAX_RESPONSE_TOOL_ARGUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum cumulative reasoning text and signature bytes retained.
pub const DEFAULT_MAX_RESPONSE_REASONING_BYTES: usize = 4 * 1024 * 1024;

/// Bounds applied to state retained while decoding one response stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevinChatResponseLimits {
    /// Maximum distinct streamed tool calls.
    pub max_tool_calls: usize,
    /// Maximum cumulative argument bytes retained per call.
    pub max_tool_argument_bytes: usize,
    /// Maximum cumulative reasoning text and signature bytes.
    pub max_reasoning_bytes: usize,
}

impl Default for DevinChatResponseLimits {
    fn default() -> Self {
        Self {
            max_tool_calls: DEFAULT_MAX_RESPONSE_TOOL_CALLS,
            max_tool_argument_bytes: DEFAULT_MAX_RESPONSE_TOOL_ARGUMENT_BYTES,
            max_reasoning_bytes: DEFAULT_MAX_RESPONSE_REASONING_BYTES,
        }
    }
}

/// Bounds applied before a Devin request is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevinChatLimits {
    /// Connect envelope limits.
    pub connect: ConnectLimits,
    /// Maximum prior message count.
    pub max_messages: usize,
    /// Maximum aggregate prompt/content bytes.
    pub max_content_bytes: usize,
    /// Maximum tool declarations.
    pub max_tools: usize,
    /// Maximum serialized tool-call argument bytes per invocation.
    pub max_tool_argument_bytes: usize,
    /// Response-state bounds.
    pub response: DevinChatResponseLimits,
}

impl Default for DevinChatLimits {
    fn default() -> Self {
        Self {
            connect: ConnectLimits::default(),
            max_messages: DEFAULT_MAX_CHAT_MESSAGES,
            max_content_bytes: DEFAULT_MAX_CHAT_CONTENT_BYTES,
            max_tools: DEFAULT_MAX_CHAT_TOOLS,
            max_tool_argument_bytes: DEFAULT_MAX_TOOL_ARGUMENT_BYTES,
            response: DevinChatResponseLimits::default(),
        }
    }
}

/// Devin identifiers that must survive semantic translation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DevinIdentifiers {
    /// Conversation/cascade identifier.
    pub cascade_id: Option<String>,
    /// Current execution identifier.
    pub execution_id: Option<String>,
}

/// Decoded Devin request and explicit conversion accounting.
#[derive(Clone, PartialEq)]
pub struct DecodedDevinChatRequest {
    /// Protocol-neutral request.
    pub request: SemanticRequest,
    /// Identifiers carried by the Devin request.
    pub identifiers: DevinIdentifiers,
    /// Metadata used for provider authentication and client identity.
    ///
    /// This value includes secrets when the wire request included them.  It is
    /// intentionally not included in [`ConversionReport`] or debug output of
    /// the codec itself; callers must keep it in a secret-bearing boundary.
    pub metadata: Option<crate::proto::Metadata>,
    /// Explicit preservation/degradation accounting.
    pub report: ConversionReport,
}

impl fmt::Debug for DecodedDevinChatRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedDevinChatRequest")
            .field("request", &self.request)
            .field("identifiers", &self.identifiers)
            .field(
                "metadata",
                &self.metadata.as_ref().map(|_| "<redacted Devin metadata>"),
            )
            .field("report", &self.report)
            .finish()
    }
}

/// Options for encoding a semantic request as Devin chat protobuf.
#[derive(Clone, Debug, PartialEq)]
pub struct DevinChatEncodeOptions {
    /// Raw session token, without requiring callers to add the wire prefix.
    pub api_key: Option<String>,
    /// User JWT returned by the auth handler.
    pub user_jwt: Option<String>,
    /// Optional client identity overrides.
    pub client_metadata: Option<DevinClientMetadata>,
    /// Explicit cascade ID.  Request session ID is used when absent.
    pub cascade_id: Option<String>,
    /// Explicit execution ID.  Request continuation ID is used when absent.
    pub execution_id: Option<String>,
    /// Whether the resulting Connect request is gzip compressed.
    pub compress: bool,
    /// Explicit frame limits.
    pub connect_limits: ConnectLimits,
}

impl Default for DevinChatEncodeOptions {
    fn default() -> Self {
        Self {
            api_key: None,
            user_jwt: None,
            client_metadata: None,
            cascade_id: None,
            execution_id: None,
            compress: true,
            connect_limits: ConnectLimits::default(),
        }
    }
}

/// Encoded Devin request body and conversion accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct EncodedDevinChatRequest {
    /// One Connect-framed protobuf request.
    pub body: Vec<u8>,
    /// The decoded protobuf message before framing.
    pub message: GetChatMessageRequest,
    /// Explicit conversion accounting.
    pub report: ConversionReport,
    /// Identifiers carried by the encoded request.
    pub identifiers: DevinIdentifiers,
}

/// One encoded Devin response frame and conversion accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedDevinFrame {
    /// Connect-framed protobuf or trailer bytes. `None` means a lifecycle
    /// event had no direct wire representation.
    pub body: Option<Vec<u8>>,
    /// Explicit conversion accounting.
    pub report: ConversionReport,
}

/// Decoder/encoder failures for Devin semantic chat conversion.
#[derive(Debug, Error)]
pub enum DevinChatCodecError {
    /// Connect framing failed.
    #[error("Devin Connect framing failed: {0}")]
    Connect(#[from] ConnectError),
    /// Protobuf payload failed to decode.
    #[error("invalid Devin chat protobuf: {0}")]
    Protobuf(#[from] prost::DecodeError),
    /// Protobuf payload failed to encode.
    #[error("cannot encode Devin chat protobuf: {0}")]
    Encode(#[from] prost::EncodeError),
    /// A request had no complete frame.
    #[error("Devin chat request must contain exactly one non-trailer frame")]
    InvalidRequestFrame,
    /// A request contained too many frames.
    #[error("Devin chat request contains more than one protobuf frame")]
    MultipleRequestFrames,
    /// A request field was missing or invalid.
    #[error("invalid Devin chat field `{field}`: {reason}")]
    InvalidField { field: String, reason: String },
    /// A configured request bound was exceeded.
    #[error("Devin chat field `{field}` has {observed} bytes/entries; limit is {limit}")]
    LimitExceeded {
        field: &'static str,
        observed: usize,
        limit: usize,
    },
    /// An image's base64 representation was invalid.
    #[error("invalid Devin image data: {0}")]
    InvalidImage(#[source] base64::DecodeError),
    /// A tool argument document could not be preserved as JSON.
    #[error("invalid Devin tool arguments for `{field}`: {reason}")]
    InvalidToolArguments { field: String, reason: String },
    /// The selected loss policy rejected explicit conversion accounting.
    #[error("Devin chat conversion rejected: {0}")]
    Conversion(#[from] pooler_protocol::ConversionError),
    /// A semantic event has no safe Devin representation.
    #[error("Devin chat does not represent semantic {0} events")]
    UnsupportedEvent(&'static str),
}

/// Decodes one Connect-framed Devin chat request.
pub fn decode_chat_request(
    body: &[u8],
    limits: DevinChatLimits,
) -> Result<DecodedDevinChatRequest, DevinChatCodecError> {
    let mut decoder = ConnectDecoder::with_gzip(limits.connect);
    let frames = decoder.push(body)?;
    decoder.finish()?;
    let mut frames = frames.into_iter().filter(|frame| !frame.is_end_stream());
    let Some(frame) = frames.next() else {
        return Err(DevinChatCodecError::InvalidRequestFrame);
    };
    if frames.next().is_some() {
        return Err(DevinChatCodecError::MultipleRequestFrames);
    }
    let message = GetChatMessageRequest::decode(frame.payload.as_slice())?;
    decode_chat_message(message, body, limits)
}

/// Decodes a protobuf request that has already been unframed.
pub fn decode_chat_message(
    message: GetChatMessageRequest,
    _raw_body: &[u8],
    limits: DevinChatLimits,
) -> Result<DecodedDevinChatRequest, DevinChatCodecError> {
    let model = message.chat_model_uid.trim();
    if model.is_empty() {
        return Err(DevinChatCodecError::InvalidField {
            field: "chat_model_uid".to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    if message.chat_message_prompts.len() > limits.max_messages {
        return Err(DevinChatCodecError::LimitExceeded {
            field: "chat_message_prompts",
            observed: message.chat_message_prompts.len(),
            limit: limits.max_messages,
        });
    }
    if message.tools.len() > limits.max_tools {
        return Err(DevinChatCodecError::LimitExceeded {
            field: "tools",
            observed: message.tools.len(),
            limit: limits.max_tools,
        });
    }
    let mut report = ConversionReport::default();
    let mut request = SemanticRequest::new(model);
    let mut content_bytes = message.prompt.len();
    if !message.prompt.is_empty() {
        request.push_message(Message::text(Role::System, message.prompt.clone()));
        report.preserve_capability("devin.system_prompt");
    }
    for (index, prompt) in message.chat_message_prompts.iter().enumerate() {
        let (decoded, bytes) = decode_prompt(prompt, index, &mut report, limits)?;
        content_bytes = content_bytes.saturating_add(bytes);
        if content_bytes > limits.max_content_bytes {
            return Err(DevinChatCodecError::LimitExceeded {
                field: "chat_message_prompts",
                observed: content_bytes,
                limit: limits.max_content_bytes,
            });
        }
        request.push_message(decoded);
    }
    for (index, tool) in message.tools.iter().enumerate() {
        let schema = if tool.json_schema_string.trim().is_empty() {
            None
        } else {
            Some(
                PreservedJson::from_str(&tool.json_schema_string).map_err(|error| {
                    DevinChatCodecError::InvalidField {
                        field: format!("tools[{index}].json_schema_string"),
                        reason: error.to_string(),
                    }
                })?,
            )
        };
        let mut definition = ToolDefinition::new(tool.name.clone(), schema);
        if !tool.description.is_empty() {
            definition.description = Some(tool.description.clone());
        }
        definition.strict = Some(tool.strict);
        request.tools.push(definition);
    }
    request.tool_choice = decode_tool_choice(message.tool_choice.as_ref())?;
    if let Some(configuration) = message.configuration.as_ref() {
        request.sampling.max_output_tokens = u32::try_from(configuration.max_tokens).ok();
        if configuration.temperature.is_finite() {
            request.sampling.temperature = Some(configuration.temperature as f32);
        }
        if configuration.top_p.is_finite() {
            request.sampling.top_p = Some(configuration.top_p as f32);
        }
        request.sampling.stop = configuration.stop_patterns.clone();
    }
    if message.system_prompt_cache_options.is_some() {
        request.cache = Some(pooler_protocol::CacheHints {
            allow_prompt_cache: true,
            prefer_cache_read: true,
            key: None,
            extensions: Extensions::default(),
        });
    }
    let identifiers = DevinIdentifiers {
        cascade_id: nonempty(message.cascade_id),
        execution_id: nonempty(message.execution_id),
    };
    request.session_id = identifiers.cascade_id.clone();
    request.continuation_id = identifiers.execution_id.clone();
    if message.disable_parallel_tool_calls {
        report.preserve_capability("devin.disable_parallel_tool_calls");
    }
    if let Some(identifier_extension) = identifier_extension(&identifiers) {
        report.preserve_extension(&identifier_extension.key());
        request.extensions.insert(identifier_extension);
    }
    // Do not retain the raw protobuf body: it can contain `api_key` and
    // `user_jwt` metadata.  The typed metadata is returned separately to the
    // credential-bearing boundary, while semantic state retains only the
    // non-secret identifiers above.
    request
        .validate()
        .map_err(|error| DevinChatCodecError::InvalidField {
            field: "request".to_owned(),
            reason: error.to_string(),
        })?;
    Ok(DecodedDevinChatRequest {
        request,
        identifiers,
        metadata: message.metadata,
        report,
    })
}

/// Encodes a semantic request as one Connect-framed Devin request.
pub fn encode_chat_request(
    request: &SemanticRequest,
    options: &DevinChatEncodeOptions,
    policy: LossPolicy,
) -> Result<EncodedDevinChatRequest, DevinChatCodecError> {
    request
        .validate()
        .map_err(|error| DevinChatCodecError::InvalidField {
            field: "request".to_owned(),
            reason: error.to_string(),
        })?;
    let mut report = ConversionReport::default();
    let cascade_id = options
        .cascade_id
        .clone()
        .or_else(|| request.session_id.clone())
        .unwrap_or_else(|| stable_id(&request.model, "cascade"));
    let execution_id = options
        .execution_id
        .clone()
        .or_else(|| request.continuation_id.clone())
        .unwrap_or_else(|| stable_id(&cascade_id, "execution"));
    let identifiers = DevinIdentifiers {
        cascade_id: Some(cascade_id.clone()),
        execution_id: Some(execution_id.clone()),
    };
    let mut system_prompt = Vec::new();
    let mut prompts = Vec::new();
    for (index, item) in request.input.iter().enumerate() {
        match item {
            InputItem::Message(message) => {
                let prompt = encode_message(message, &cascade_id, index, &mut report)?;
                if matches!(message.role, Role::System | Role::Developer)
                    && system_prompt.is_empty()
                    && prompts.is_empty()
                    && prompt.tool_calls.is_empty()
                    && prompt.images.is_empty()
                {
                    system_prompt.push(prompt.prompt.clone());
                    report.preserve_capability("devin.system_prompt");
                } else {
                    prompts.push(prompt);
                }
            }
            InputItem::ToolCall(call) => {
                prompts.push(ChatMessagePrompt {
                    message_id: stable_id(&cascade_id, &format!("tool-call-{index}")),
                    source: ChatMessageSource::System as i32,
                    tool_calls: vec![encode_tool_call(call, &mut report)?],
                    ..Default::default()
                });
            }
            InputItem::ToolResult(result) => {
                prompts.push(encode_tool_result(result, &cascade_id, index, &mut report)?);
            }
            InputItem::Content(content) => {
                let mut message = Message::new(Role::User);
                message.push_content(content.clone());
                prompts.push(encode_message(&message, &cascade_id, index, &mut report)?);
            }
            InputItem::Provider {
                namespace, name, ..
            } => {
                report.unsupported_required(
                    format!("input.provider.{namespace}.{name}"),
                    "Devin chat has no wire representation for this provider input",
                );
            }
        }
    }
    if system_prompt.len() > 1 {
        report.degrade_field(
            "system_prompt.multiple",
            "Devin has one dedicated system prompt field; additional system messages are retained as prompts",
        );
    }
    let tools = request
        .tools
        .iter()
        .map(|tool| encode_tool_definition(tool, &mut report))
        .collect::<Result<Vec<_>, _>>()?;
    let tool_choice = encode_tool_choice(request.tool_choice.as_ref(), &mut report)?;
    let configuration = encode_configuration(request);
    let message = GetChatMessageRequest {
        metadata: Some(metadata(
            &normalize_devin_session_token(options.api_key.as_deref()),
            options.user_jwt.as_deref().unwrap_or_default(),
            options.client_metadata.as_ref(),
        )),
        prompt: system_prompt.join("\n\n"),
        chat_message_prompts: prompts,
        chat_model_uid: request.model.clone(),
        request_type: ChatMessageRequestType::Cascade as i32,
        configuration: Some(configuration),
        tools,
        disable_parallel_tool_calls: true,
        tool_choice,
        system_prompt_cache_options: request.cache.as_ref().and_then(|cache| {
            cache.allow_prompt_cache.then_some(PromptCacheOptions {
                r#type: CacheControlType::Ephemeral as i32,
            })
        }),
        cascade_id,
        planner_mode: ConversationalPlannerMode::Default as i32,
        execution_id,
        ..Default::default()
    };
    report.validate(policy)?;
    let body = encode_connect_frame_with_limits(
        &message.encode_to_vec(),
        options.compress,
        false,
        options.connect_limits,
    )?;
    Ok(EncodedDevinChatRequest {
        body,
        message,
        report,
        identifiers,
    })
}

/// Stateful decoder for fragmented Devin response messages.
#[derive(Debug)]
pub struct DevinChatEventDecoder {
    model: Option<String>,
    identifiers: DevinIdentifiers,
    sequence: u64,
    started: bool,
    reasoning_open: bool,
    text_open: bool,
    tools: BTreeMap<String, ToolCallState>,
    active_tool_id: Option<String>,
    latest_stop_reason: StopReason,
    latest_usage: Option<Usage>,
    latest_signature: String,
    reasoning_bytes: usize,
    max_response_tool_calls: usize,
    max_response_tool_argument_bytes: usize,
    max_response_reasoning_bytes: usize,
    terminal: bool,
    report: ConversionReport,
}

#[derive(Clone, Debug)]
struct ToolCallState {
    name: String,
    arguments_json: String,
}

impl DevinChatEventDecoder {
    /// Creates a decoder for one response stream.
    #[must_use]
    pub fn new(model: Option<String>, identifiers: DevinIdentifiers) -> Self {
        Self::with_limits(model, identifiers, DevinChatResponseLimits::default())
    }

    /// Creates a decoder with explicit response-state bounds.
    #[must_use]
    pub fn with_limits(
        model: Option<String>,
        identifiers: DevinIdentifiers,
        response_limits: DevinChatResponseLimits,
    ) -> Self {
        Self {
            model,
            identifiers,
            sequence: 0,
            started: false,
            reasoning_open: false,
            text_open: false,
            tools: BTreeMap::new(),
            active_tool_id: None,
            latest_stop_reason: StopReason::Unspecified,
            latest_usage: None,
            latest_signature: String::new(),
            reasoning_bytes: 0,
            max_response_tool_calls: response_limits.max_tool_calls,
            max_response_tool_argument_bytes: response_limits.max_tool_argument_bytes,
            max_response_reasoning_bytes: response_limits.max_reasoning_bytes,
            terminal: false,
            report: ConversionReport::default(),
        }
    }

    /// Returns conversion accounting accumulated by this decoder.
    #[must_use]
    pub const fn report(&self) -> &ConversionReport {
        &self.report
    }

    /// Decodes one unframed Devin response message.
    pub fn decode_message(
        &mut self,
        message: GetChatMessageResponse,
    ) -> Result<Vec<StreamEvent>, DevinChatCodecError> {
        if self.terminal {
            return Ok(Vec::new());
        }
        let mut events = self.start_events();
        if !message.delta_thinking.is_empty() || !message.delta_signature.is_empty() {
            let reasoning_delta_bytes = message
                .delta_thinking
                .len()
                .saturating_add(message.delta_signature.len());
            let next_reasoning_bytes = self.reasoning_bytes.saturating_add(reasoning_delta_bytes);
            if next_reasoning_bytes > self.max_response_reasoning_bytes {
                return Err(DevinChatCodecError::LimitExceeded {
                    field: "response.reasoning",
                    observed: next_reasoning_bytes,
                    limit: self.max_response_reasoning_bytes,
                });
            }
            self.reasoning_bytes = next_reasoning_bytes;
            self.close_text(&mut events);
            if !self.reasoning_open {
                self.reasoning_open = true;
                events.push(self.event(StreamEventKind::ReasoningStart, Some("reasoning")));
            }
            if !message.delta_thinking.is_empty() {
                events.push(self.event(
                    StreamEventKind::reasoning_delta(message.delta_thinking),
                    Some("reasoning"),
                ));
            }
            if !message.delta_signature.is_empty() {
                self.latest_signature.push_str(&message.delta_signature);
            }
        }
        if !message.delta_text.is_empty() {
            self.close_reasoning(&mut events);
            if !self.text_open {
                self.text_open = true;
                events.push(self.event(StreamEventKind::TextStart, Some("text")));
            }
            events.push(self.event(
                StreamEventKind::text_delta(message.delta_text),
                Some("text"),
            ));
        }
        for call in message.delta_tool_calls {
            self.close_reasoning(&mut events);
            self.close_text(&mut events);
            let Some(id) = nonempty(call.id).or_else(|| self.active_tool_id.clone()) else {
                self.report.unsupported_required(
                    "tool_call.id",
                    "Devin emitted a tool delta without an identifier",
                );
                continue;
            };
            let previous = self.tools.get(&id).cloned();
            if previous.is_none() && self.tools.len() >= self.max_response_tool_calls {
                return Err(DevinChatCodecError::LimitExceeded {
                    field: "response.tool_calls",
                    observed: self.tools.len().saturating_add(1),
                    limit: self.max_response_tool_calls,
                });
            }
            let previous_arguments = previous
                .as_ref()
                .map_or("", |state| state.arguments_json.as_str());
            let argument_bytes = if call.arguments_json.starts_with(previous_arguments) {
                call.arguments_json.len()
            } else {
                previous_arguments
                    .len()
                    .saturating_add(call.arguments_json.len())
            };
            if argument_bytes > self.max_response_tool_argument_bytes {
                return Err(DevinChatCodecError::LimitExceeded {
                    field: "response.tool_call.arguments_json",
                    observed: argument_bytes,
                    limit: self.max_response_tool_argument_bytes,
                });
            }
            let arguments_json = if call.arguments_json.starts_with(previous_arguments) {
                call.arguments_json.clone()
            } else {
                format!("{previous_arguments}{}", call.arguments_json)
            };
            let state = ToolCallState {
                name: nonempty(call.name)
                    .or_else(|| previous.as_ref().map(|value| value.name.clone()))
                    .unwrap_or_default(),
                arguments_json: arguments_json.clone(),
            };
            if state.name.is_empty() {
                self.report.unsupported_required(
                    format!("tool_call[{id}].name"),
                    "Devin emitted a tool delta without a name",
                );
            }
            self.tools.insert(id.clone(), state.clone());
            self.active_tool_id = Some(id.clone());
            if previous.is_none() {
                events.push(self.event(
                    StreamEventKind::ToolCallStart {
                        id: id.clone(),
                        name: state.name,
                    },
                    Some(&id),
                ));
            }
            let delta = arguments_json
                .get(previous_arguments.len()..)
                .unwrap_or_default()
                .to_owned();
            if !delta.is_empty() {
                events.push(self.event(
                    StreamEventKind::ToolCallDelta {
                        id: id.clone(),
                        arguments: delta,
                    },
                    Some(&id),
                ));
            }
        }
        if let Some(usage) = message.usage {
            let usage = Usage {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                reasoning_tokens: None,
                cached_input_tokens: Some(usage.cache_read_tokens),
                total_tokens: Some(usage.input_tokens.saturating_add(usage.output_tokens)),
                details: [
                    ("cache_write_tokens".to_owned(), usage.cache_write_tokens),
                    ("cache_read_tokens".to_owned(), usage.cache_read_tokens),
                ]
                .into_iter()
                .collect(),
            };
            self.latest_usage = Some(usage.clone());
            events.push(self.event(StreamEventKind::Usage { usage }, None));
        }
        if let Ok(reason) = StopReason::try_from(message.stop_reason) {
            if reason != StopReason::Unspecified {
                self.latest_stop_reason = reason;
            }
        }
        Ok(events)
    }

    /// Decodes a complete Connect frame, including protobuf or trailer error.
    pub fn decode_frame(
        &mut self,
        frame: &ConnectFrame,
    ) -> Result<Vec<StreamEvent>, DevinChatCodecError> {
        if frame.is_end_stream() {
            if let Some(message) = read_connect_trailer_error(&frame.payload) {
                self.terminal = true;
                let event = self.event(
                    StreamEventKind::Failure {
                        error: StreamError::new("devin.stream", message),
                    },
                    None,
                );
                return Ok(self.start_events().into_iter().chain([event]).collect());
            }
            return Ok(Vec::new());
        }
        let message = GetChatMessageResponse::decode(frame.payload.as_slice())?;
        self.decode_message(message)
    }

    /// Closes open blocks and emits the terminal completion event.
    pub fn finish(&mut self) -> Result<Vec<StreamEvent>, DevinChatCodecError> {
        if self.terminal {
            return Ok(Vec::new());
        }
        let mut events = self.start_events();
        self.close_reasoning(&mut events);
        self.close_text(&mut events);
        let had_tools = !self.tools.is_empty();
        for (id, state) in mem::take(&mut self.tools) {
            let mut event = self.event(StreamEventKind::ToolCallEnd { id: id.clone() }, Some(&id));
            if let Ok(arguments) = PreservedJson::from_str(&state.arguments_json) {
                let extension =
                    OpaqueExtension::new("devin", "tool_arguments", arguments.to_bytes()).ok();
                if let Some(extension) = extension {
                    event.extensions.insert(extension.clone());
                    self.report.preserve_extension(&extension.key());
                }
            }
            events.push(event);
        }
        let reason = finish_reason(self.latest_stop_reason, had_tools);
        let usage = self.latest_usage.take();
        events.push(self.event(
            StreamEventKind::Completion {
                finish_reason: reason,
                usage,
            },
            None,
        ));
        self.terminal = true;
        Ok(events)
    }

    fn start_events(&mut self) -> Vec<StreamEvent> {
        if self.started {
            return Vec::new();
        }
        self.started = true;
        let response_id = self.identifiers.execution_id.clone();
        let mut event = self.event(
            StreamEventKind::response_start(response_id, self.model.clone()),
            None,
        );
        if let Some(extension) = identifier_extension(&self.identifiers) {
            self.report.preserve_extension(&extension.key());
            event.extensions.insert(extension);
        }
        vec![event]
    }

    fn event(&mut self, kind: StreamEventKind, block_id: Option<&str>) -> StreamEvent {
        self.sequence = self.sequence.saturating_add(1);
        let mut event = StreamEvent::new(self.sequence, kind);
        if let Some(block_id) = block_id {
            event.block_id = Some(block_id.to_owned());
        }
        event
    }

    fn close_reasoning(&mut self, events: &mut Vec<StreamEvent>) {
        if self.reasoning_open {
            self.reasoning_open = false;
            let signature = (!self.latest_signature.is_empty())
                .then(|| self.latest_signature.as_bytes().to_vec());
            events.push(self.event(
                StreamEventKind::ReasoningEnd {
                    reasoning: Some(ReasoningBlock {
                        id: Some("reasoning".to_owned()),
                        text: None,
                        summary: None,
                        encrypted_content: None,
                        signature,
                        extensions: Extensions::default(),
                    }),
                },
                Some("reasoning"),
            ));
        }
    }

    fn close_text(&mut self, events: &mut Vec<StreamEvent>) {
        if self.text_open {
            self.text_open = false;
            events.push(self.event(StreamEventKind::TextEnd, Some("text")));
        }
    }
}

/// Decodes all frames in one Devin response body.
pub fn decode_chat_response(
    body: &[u8],
    model: Option<String>,
    identifiers: DevinIdentifiers,
    limits: ConnectLimits,
) -> Result<DecodedDevinChatResponse, DevinChatCodecError> {
    decode_chat_response_with_limits(
        body,
        model,
        identifiers,
        limits,
        DevinChatResponseLimits::default(),
    )
}

/// Decodes all frames in one Devin response body with explicit semantic
/// response-state bounds.
pub fn decode_chat_response_with_limits(
    body: &[u8],
    model: Option<String>,
    identifiers: DevinIdentifiers,
    limits: ConnectLimits,
    response_limits: DevinChatResponseLimits,
) -> Result<DecodedDevinChatResponse, DevinChatCodecError> {
    let mut decoder = ConnectDecoder::with_gzip(limits);
    let frames = decoder.push(body)?;
    decoder.finish()?;
    let mut events = Vec::new();
    let mut codec = DevinChatEventDecoder::with_limits(model, identifiers, response_limits);
    for frame in &frames {
        events.extend(codec.decode_frame(frame)?);
    }
    events.extend(codec.finish()?);
    Ok(DecodedDevinChatResponse {
        events,
        report: codec.report,
    })
}

/// Fully decoded Devin response and conversion accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedDevinChatResponse {
    /// Ordered semantic events.
    pub events: Vec<StreamEvent>,
    /// Explicit conversion accounting.
    pub report: ConversionReport,
}

/// Stateless Devin event encoder.
#[derive(Clone, Copy, Debug)]
pub struct DevinChatEventEncoder {
    /// Whether response frames are gzip compressed.
    pub compress: bool,
    /// Explicit frame bounds.
    pub connect_limits: ConnectLimits,
}

impl Default for DevinChatEventEncoder {
    fn default() -> Self {
        Self {
            compress: true,
            connect_limits: ConnectLimits::default(),
        }
    }
}

impl DevinChatEventEncoder {
    /// Encodes one semantic event as an optional Devin frame.
    pub fn encode_event(
        &self,
        event: &StreamEvent,
        policy: LossPolicy,
    ) -> Result<EncodedDevinFrame, DevinChatCodecError> {
        let mut report = ConversionReport::default();
        let message = match &event.kind {
            StreamEventKind::TextDelta { text } => GetChatMessageResponse {
                delta_text: text.clone(),
                ..Default::default()
            },
            StreamEventKind::ReasoningDelta { text } => GetChatMessageResponse {
                delta_thinking: text.clone(),
                ..Default::default()
            },
            StreamEventKind::ReasoningEnd { reasoning } => {
                let signature = reasoning
                    .as_ref()
                    .and_then(|value| value.signature.as_deref())
                    .and_then(|value| String::from_utf8(value.to_vec()).ok())
                    .unwrap_or_default();
                GetChatMessageResponse {
                    delta_signature: signature,
                    ..Default::default()
                }
            }
            StreamEventKind::ToolCallStart { id, name } => GetChatMessageResponse {
                delta_tool_calls: vec![ChatToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            StreamEventKind::ToolCallDelta { id, arguments } => GetChatMessageResponse {
                delta_tool_calls: vec![ChatToolCall {
                    id: id.clone(),
                    arguments_json: arguments.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            StreamEventKind::Usage { usage } => GetChatMessageResponse {
                usage: Some(ModelUsageStats {
                    input_tokens: usage.input_tokens,
                    output_tokens: usage.output_tokens,
                    cache_write_tokens: usage
                        .details
                        .get("cache_write_tokens")
                        .copied()
                        .unwrap_or(0),
                    cache_read_tokens: usage.cached_input_tokens.unwrap_or(0),
                    ..Default::default()
                }),
                ..Default::default()
            },
            StreamEventKind::Completion {
                finish_reason,
                usage,
            } => GetChatMessageResponse {
                stop_reason: encode_stop_reason(finish_reason) as i32,
                usage: usage.as_ref().map(encode_usage),
                ..Default::default()
            },
            StreamEventKind::Failure { error } => {
                report.apply_rule("devin.failure_end_stream_trailer");
                let mut error_value = serde_json::Map::new();
                error_value.insert(
                    "code".to_owned(),
                    serde_json::Value::String(error.code.clone()),
                );
                error_value.insert(
                    "message".to_owned(),
                    serde_json::Value::String(error.message.clone()),
                );
                error_value.insert(
                    "retryable".to_owned(),
                    serde_json::Value::Bool(error.retryable),
                );
                if let Some(details) = &error.details {
                    error_value.insert("details".to_owned(), details.value().clone());
                }
                let payload = serde_json::to_vec(&serde_json::json!({
                    "error": error_value,
                }))
                .map_err(|error| DevinChatCodecError::InvalidField {
                    field: "stream.error".to_owned(),
                    reason: error.to_string(),
                })?;
                return Ok(EncodedDevinFrame {
                    body: Some(encode_connect_frame_with_limits(
                        &payload,
                        false,
                        true,
                        self.connect_limits,
                    )?),
                    report,
                });
            }
            StreamEventKind::ResponseStart { .. } => {
                report.apply_rule("devin.response_metadata_implicit");
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::Metadata { .. } => {
                report.apply_rule("devin.response_metadata_not_wire_visible");
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::TextStart | StreamEventKind::TextEnd => {
                report.apply_rule("devin.text_lifecycle_implicit");
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::ReasoningStart => {
                report.apply_rule("devin.reasoning_lifecycle_implicit");
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::ToolCallEnd { .. } => {
                report.apply_rule("devin.tool_call_end_implicit");
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::Media { .. } => {
                report.unsupported_required(
                    "response.media",
                    "Devin chat response protobuf has no media output field",
                );
                report.validate(policy)?;
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::Refusal { text } => {
                report.degrade_field(
                    "response.refusal",
                    "Devin represents refusal text as ordinary text",
                );
                GetChatMessageResponse {
                    delta_text: text.clone(),
                    ..Default::default()
                }
            }
            StreamEventKind::Warning { warning } => {
                report.drop_optional(
                    "response.warning",
                    format!("Devin has no warning event field: {}", warning.message),
                );
                report.validate(policy)?;
                return Ok(EncodedDevinFrame { body: None, report });
            }
            StreamEventKind::Opaque { .. } => {
                report.unsupported_required(
                    "response.opaque",
                    "Devin chat response protobuf has no opaque event field",
                );
                report.validate(policy)?;
                return Ok(EncodedDevinFrame { body: None, report });
            }
        };
        report.validate(policy)?;
        Ok(EncodedDevinFrame {
            body: Some(encode_connect_frame_with_limits(
                &message.encode_to_vec(),
                self.compress,
                false,
                self.connect_limits,
            )?),
            report,
        })
    }
}

fn decode_prompt(
    prompt: &ChatMessagePrompt,
    index: usize,
    report: &mut ConversionReport,
    limits: DevinChatLimits,
) -> Result<(Message, usize), DevinChatCodecError> {
    let source = ChatMessageSource::try_from(prompt.source).map_err(|_| {
        DevinChatCodecError::InvalidField {
            field: format!("chat_message_prompts[{index}].source"),
            reason: "unknown Devin message source".to_owned(),
        }
    })?;
    let role = match source {
        ChatMessageSource::User => Role::User,
        ChatMessageSource::Tool => Role::Tool,
        ChatMessageSource::System => Role::Assistant,
        ChatMessageSource::Unknown | ChatMessageSource::SystemPrompt => Role::System,
        ChatMessageSource::Unspecified => {
            return Err(DevinChatCodecError::InvalidField {
                field: format!("chat_message_prompts[{index}].source"),
                reason: "unspecified Devin message source".to_owned(),
            });
        }
    };
    let mut message = Message::new(role);
    message.id = nonempty(prompt.message_id.clone());
    if !prompt.prompt.is_empty() {
        message.push_content(ContentPart::text(prompt.prompt.clone()));
    }
    for image in &prompt.images {
        let bytes = BASE64
            .decode(image.base64_data.as_bytes())
            .map_err(DevinChatCodecError::InvalidImage)?;
        message.push_content(ContentPart::Image {
            media_type: image.mime_type.clone(),
            source: MediaSource::Inline(bytes),
            detail: None,
        });
    }
    if !prompt.thinking.is_empty() || !prompt.signature.is_empty() {
        message.push_content(ContentPart::Reasoning(ReasoningBlock {
            id: None,
            text: (!prompt.thinking.is_empty()).then(|| prompt.thinking.clone()),
            summary: None,
            encrypted_content: None,
            signature: (!prompt.signature.is_empty()).then(|| prompt.signature.as_bytes().to_vec()),
            extensions: Extensions::default(),
        }));
        report.preserve_capability("reasoning.signature");
    }
    for (call_index, call) in prompt.tool_calls.iter().enumerate() {
        if call.id.trim().is_empty() || call.name.trim().is_empty() {
            return Err(DevinChatCodecError::InvalidField {
                field: format!("chat_message_prompts[{index}].tool_calls[{call_index}]"),
                reason: "tool call id and name are required".to_owned(),
            });
        }
        if call.arguments_json.len() > limits.max_tool_argument_bytes {
            return Err(DevinChatCodecError::LimitExceeded {
                field: "tool_call.arguments_json",
                observed: call.arguments_json.len(),
                limit: limits.max_tool_argument_bytes,
            });
        }
        let arguments = PreservedJson::from_str(if call.arguments_json.trim().is_empty() {
            "{}"
        } else {
            &call.arguments_json
        })
        .map_err(|error| DevinChatCodecError::InvalidToolArguments {
            field: format!("chat_message_prompts[{index}].tool_calls[{call_index}].arguments_json"),
            reason: error.to_string(),
        })?;
        message.push_content(ContentPart::ToolCall(ToolCall::new(
            call.id.clone(),
            call.name.clone(),
            arguments,
        )));
    }
    if role == Role::Tool {
        message.tool_call_id = nonempty(prompt.tool_call_id.clone());
        if message.tool_call_id.is_none() {
            report.unsupported_required(
                format!("chat_message_prompts[{index}].tool_call_id"),
                "Devin tool result did not include the invocation identifier",
            );
        }
        if prompt.tool_result_is_error {
            report.drop_optional(
                format!("chat_message_prompts[{index}].tool_result_is_error"),
                "OpenAI Chat has no standard tool-result error flag",
            );
        }
        message.content = vec![ContentPart::text(prompt.prompt.clone())];
    }
    Ok((message, prompt.prompt.len() + prompt.thinking.len()))
}

fn encode_message(
    message: &Message,
    cascade_id: &str,
    index: usize,
    report: &mut ConversionReport,
) -> Result<ChatMessagePrompt, DevinChatCodecError> {
    let mut prompt = ChatMessagePrompt {
        message_id: message
            .id
            .clone()
            .unwrap_or_else(|| stable_id(cascade_id, &format!("message-{index}"))),
        source: encode_source(message.role) as i32,
        ..Default::default()
    };
    for part in &message.content {
        match part {
            ContentPart::Text { text } => prompt.prompt.push_str(text),
            ContentPart::Image {
                media_type, source, ..
            } => match source {
                MediaSource::Inline(bytes) => prompt.images.push(ImageData {
                    base64_data: BASE64.encode(bytes),
                    mime_type: media_type.clone(),
                    ..Default::default()
                }),
                MediaSource::Uri(uri) => {
                    report.degrade_field(
                        "message.image.uri",
                        format!("Devin chat only accepts inline images; URI `{uri}` omitted"),
                    );
                }
            },
            ContentPart::Reasoning(reasoning) => {
                if let Some(text) = reasoning.text.as_deref() {
                    prompt.thinking.push_str(text);
                }
                if let Some(signature) = reasoning.signature.as_deref() {
                    prompt
                        .signature
                        .push_str(&String::from_utf8_lossy(signature));
                }
            }
            ContentPart::ToolCall(call) => prompt.tool_calls.push(encode_tool_call(call, report)?),
            ContentPart::ToolResult(result) => {
                if message.role != Role::Tool {
                    report.degrade_field(
                        "message.tool_result.role",
                        "Devin expects tool results as source=tool messages",
                    );
                }
                prompt.tool_call_id = result.tool_call_id.clone();
                prompt.tool_result_is_error = result.is_error;
                append_result_content(&mut prompt.prompt, &result.content, report);
            }
            ContentPart::File { .. } | ContentPart::Audio { .. } => {
                report.unsupported_required(
                    "message.content.media",
                    "Devin chat request schema only represents text and images",
                );
            }
            ContentPart::Provider {
                namespace, name, ..
            } => {
                report.unsupported_required(
                    format!("message.content.provider.{namespace}.{name}"),
                    "Devin chat has no provider content extension field",
                );
            }
        }
    }
    Ok(prompt)
}

fn append_result_content(
    text: &mut String,
    content: &[ContentPart],
    report: &mut ConversionReport,
) {
    for part in content {
        match part {
            ContentPart::Text { text: value } => text.push_str(value),
            ContentPart::Image { .. } => report.degrade_field(
                "tool_result.image",
                "Devin tool result prompt has no image content field",
            ),
            _ => report.degrade_field(
                "tool_result.content",
                "Devin tool result prompt only represents text",
            ),
        }
    }
}

fn encode_tool_call(
    call: &ToolCall,
    _report: &mut ConversionReport,
) -> Result<ChatToolCall, DevinChatCodecError> {
    Ok(ChatToolCall {
        id: call.id.clone(),
        name: call.name.clone(),
        arguments_json: String::from_utf8_lossy(&call.arguments.to_bytes()).into_owned(),
        ..Default::default()
    })
}

fn encode_tool_result(
    result: &ToolResult,
    cascade_id: &str,
    index: usize,
    report: &mut ConversionReport,
) -> Result<ChatMessagePrompt, DevinChatCodecError> {
    let mut prompt = ChatMessagePrompt {
        message_id: stable_id(cascade_id, &format!("tool-result-{index}")),
        source: ChatMessageSource::Tool as i32,
        tool_call_id: result.tool_call_id.clone(),
        tool_result_is_error: result.is_error,
        ..Default::default()
    };
    append_result_content(&mut prompt.prompt, &result.content, report);
    Ok(prompt)
}

fn encode_tool_definition(
    tool: &ToolDefinition,
    _report: &mut ConversionReport,
) -> Result<ChatToolDefinition, DevinChatCodecError> {
    Ok(ChatToolDefinition {
        name: tool.name.clone(),
        description: tool.description.clone().unwrap_or_default(),
        json_schema_string: tool.parameters.as_ref().map_or_else(
            || "{}".to_owned(),
            |value| String::from_utf8_lossy(&value.to_bytes()).into_owned(),
        ),
        strict: tool.strict.unwrap_or(false),
        ..Default::default()
    })
}

fn decode_tool_choice(
    value: Option<&ChatToolChoice>,
) -> Result<Option<ToolChoice>, DevinChatCodecError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(choice) = value.choice.as_ref() else {
        return Ok(None);
    };
    Ok(Some(match choice {
        chat_tool_choice::Choice::OptionName(value) if value.eq_ignore_ascii_case("auto") => {
            ToolChoice::Auto
        }
        chat_tool_choice::Choice::OptionName(value) if value.eq_ignore_ascii_case("none") => {
            ToolChoice::None
        }
        chat_tool_choice::Choice::OptionName(value) if value.eq_ignore_ascii_case("required") => {
            ToolChoice::Required
        }
        chat_tool_choice::Choice::ToolName(name) => ToolChoice::Tool { name: name.clone() },
        chat_tool_choice::Choice::OptionName(value) => {
            return Err(DevinChatCodecError::InvalidField {
                field: "tool_choice".to_owned(),
                reason: format!("unsupported option `{value}`"),
            });
        }
    }))
}

fn encode_tool_choice(
    choice: Option<&ToolChoice>,
    _report: &mut ConversionReport,
) -> Result<Option<ChatToolChoice>, DevinChatCodecError> {
    let Some(choice) = choice else {
        return Ok(Some(ChatToolChoice {
            choice: Some(chat_tool_choice::Choice::OptionName("auto".to_owned())),
        }));
    };
    Ok(Some(ChatToolChoice {
        choice: Some(match choice {
            ToolChoice::Auto => chat_tool_choice::Choice::OptionName("auto".to_owned()),
            ToolChoice::None => chat_tool_choice::Choice::OptionName("none".to_owned()),
            ToolChoice::Required => chat_tool_choice::Choice::OptionName("required".to_owned()),
            ToolChoice::Tool { name } => chat_tool_choice::Choice::ToolName(name.clone()),
        }),
    }))
}

fn encode_configuration(request: &SemanticRequest) -> CompletionConfiguration {
    let temperature = request.sampling.temperature.unwrap_or(0.4) as f64;
    CompletionConfiguration {
        num_completions: 1,
        max_tokens: request.sampling.max_output_tokens.map_or(64_000, u64::from),
        max_newlines: 200,
        temperature,
        first_temperature: temperature,
        top_k: 50,
        top_p: request.sampling.top_p.unwrap_or(1.0) as f64,
        stop_patterns: DEVIN_DEFAULT_STOP_PATTERNS
            .iter()
            .map(ToString::to_string)
            .chain(request.sampling.stop.iter().cloned())
            .collect(),
        fim_eot_prob_threshold: 1.0,
        ..Default::default()
    }
}

fn encode_usage(usage: &Usage) -> ModelUsageStats {
    ModelUsageStats {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cache_write_tokens: usage
            .details
            .get("cache_write_tokens")
            .copied()
            .unwrap_or(0),
        cache_read_tokens: usage.cached_input_tokens.unwrap_or(0),
        ..Default::default()
    }
}

fn encode_source(role: Role) -> ChatMessageSource {
    match role {
        Role::User => ChatMessageSource::User,
        Role::Tool => ChatMessageSource::Tool,
        Role::Assistant => ChatMessageSource::System,
        Role::System | Role::Developer => ChatMessageSource::SystemPrompt,
    }
}

fn encode_stop_reason(reason: &FinishReason) -> StopReason {
    match reason {
        FinishReason::Stop => StopReason::StopPattern,
        FinishReason::Length => StopReason::MaxTokens,
        FinishReason::ToolCall => StopReason::FunctionCall,
        FinishReason::ContentFilter => StopReason::ContentFilter,
        FinishReason::Error | FinishReason::Other(_) => StopReason::Error,
    }
}

fn finish_reason(reason: StopReason, had_tools: bool) -> FinishReason {
    match reason {
        StopReason::MaxTokens | StopReason::MaxNewlines => FinishReason::Length,
        StopReason::FunctionCall => FinishReason::ToolCall,
        StopReason::ContentFilter => FinishReason::ContentFilter,
        StopReason::Error => FinishReason::Error,
        StopReason::Unspecified if had_tools => FinishReason::ToolCall,
        StopReason::Incomplete | StopReason::Partial => {
            FinishReason::Other("incomplete".to_owned())
        }
        _ => FinishReason::Stop,
    }
}

fn identifier_extension(identifiers: &DevinIdentifiers) -> Option<OpaqueExtension> {
    let value = serde_json::json!({
        "cascade_id": identifiers.cascade_id,
        "execution_id": identifiers.execution_id,
    });
    OpaqueExtension::new("devin", "identifiers", value.to_string().into_bytes()).ok()
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn stable_id(seed: &str, label: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed.bytes().chain([0].into_iter()).chain(label.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("devin-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::{
        decode_chat_request, encode_chat_request, DevinChatEncodeOptions, DevinChatEventDecoder,
        DevinChatLimits, DevinChatResponseLimits, DevinIdentifiers,
    };
    use crate::{
        connect::encode_connect_frame,
        proto::{
            ChatMessagePrompt, ChatMessageSource, ChatToolCall, GetChatMessageRequest,
            GetChatMessageResponse, ModelUsageStats,
        },
    };
    use pooler_core::LossPolicy;
    use pooler_http::SemanticAdapter;
    use pooler_protocol::{
        ContentPart, FinishReason, Message, OpenAiChatCodec, Role, SemanticRequest, StreamEventKind,
    };
    use prost::Message as _;

    #[test]
    fn request_round_trip_preserves_ids_reasoning_images_tools_and_usage_shape() {
        let request = GetChatMessageRequest {
            chat_model_uid: "model-a".into(),
            prompt: "system".into(),
            cascade_id: "cascade-1".into(),
            execution_id: "execution-1".into(),
            chat_message_prompts: vec![ChatMessagePrompt {
                message_id: "user-1".into(),
                source: ChatMessageSource::User as i32,
                prompt: "hello".into(),
                images: vec![crate::proto::ImageData {
                    base64_data: "aGVsbG8=".into(),
                    mime_type: "image/png".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            tools: vec![crate::proto::ChatToolDefinition {
                name: "search".into(),
                json_schema_string: "{\"type\":\"object\"}".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let raw = encode_connect_frame(&request.encode_to_vec(), true, false).expect("frame");
        let decoded = decode_chat_request(&raw, DevinChatLimits::default()).expect("decode");
        assert_eq!(decoded.request.model, "model-a");
        assert_eq!(decoded.identifiers.cascade_id.as_deref(), Some("cascade-1"));
        assert!(decoded.request.messages().any(|message| {
            message.id.as_deref() == Some("user-1")
                && message
                    .content
                    .iter()
                    .any(|part| matches!(part, ContentPart::Image { .. }))
        }));
        assert_eq!(decoded.request.tools[0].name, "search");
        assert!(decoded
            .request
            .extensions
            .get_str("devin.raw_request")
            .is_none());
    }

    #[test]
    fn semantic_request_encodes_tool_choice_sampling_and_identifiers() {
        let mut request = SemanticRequest::new("model-a");
        request.session_id = Some("cascade-1".into());
        request.continuation_id = Some("execution-1".into());
        request.push_message(Message::text(Role::System, "system"));
        request.push_message(Message::text(Role::User, "hello"));
        request.sampling.max_output_tokens = Some(123);
        request.tools.push(pooler_protocol::ToolDefinition::new(
            "search",
            Some(
                pooler_protocol::PreservedJson::from_str("{\"type\":\"object\"}").expect("schema"),
            ),
        ));
        let encoded = encode_chat_request(
            &request,
            &DevinChatEncodeOptions {
                api_key: Some("raw".into()),
                user_jwt: Some("jwt".into()),
                compress: true,
                ..Default::default()
            },
            LossPolicy::Reject,
        )
        .expect("encode");
        assert_eq!(encoded.message.cascade_id, "cascade-1");
        assert_eq!(encoded.message.execution_id, "execution-1");
        assert_eq!(
            encoded.message.configuration.expect("config").max_tokens,
            123
        );
        assert_eq!(encoded.message.tools[0].name, "search");
    }

    #[test]
    fn current_client_tool_result_maps_to_a_standalone_openai_tool_message() {
        let result = "command completed: stdout=POOLER_DEVIN_TOOL_OK; stderr=; exit_code=0; cwd=/workspace; t=0000000000000000";
        assert_eq!(result.len(), 104);
        let request = GetChatMessageRequest {
            chat_model_uid: "gpt-5.6-sol-low".into(),
            chat_message_prompts: vec![
                ChatMessagePrompt {
                    message_id: "assistant-live-1".into(),
                    source: ChatMessageSource::System as i32,
                    tool_calls: vec![ChatToolCall {
                        id: "call-live-1".into(),
                        name: "run_command".into(),
                        arguments_json: r#"{"command":"printf POOLER_DEVIN_TOOL_OK"}"#.into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ChatMessagePrompt {
                    message_id: "tool-live-1".into(),
                    source: ChatMessageSource::Tool as i32,
                    prompt: result.into(),
                    tool_call_id: "call-live-1".into(),
                    ..Default::default()
                },
            ],
            tools: vec![crate::proto::ChatToolDefinition {
                name: "run_command".into(),
                json_schema_string: r#"{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}"#.into(),
                ..Default::default()
            }],
            cascade_id: "cascade-live-1".into(),
            execution_id: "execution-live-2".into(),
            ..Default::default()
        };
        let raw = encode_connect_frame(&request.encode_to_vec(), false, false).expect("frame");
        let decoded = decode_chat_request(&raw, DevinChatLimits::default()).expect("decode");
        let mut semantic = decoded.request.clone();
        semantic.session_id = None;
        semantic.continuation_id = None;
        semantic.extensions.remove(
            &pooler_protocol::ExtensionKey::parse("devin.identifiers")
                .expect("identifier extension key"),
        );
        let encoded =
            OpenAiChatCodec::encode_request(&semantic, LossPolicy::Reject).expect("OpenAI request");
        let json: serde_json::Value = serde_json::from_slice(&encoded.body).expect("JSON");
        assert_eq!(json["messages"][0]["role"], "assistant");
        assert_eq!(json["messages"][0]["tool_calls"][0]["id"], "call-live-1");
        assert_eq!(json["messages"][1]["role"], "tool");
        assert_eq!(json["messages"][1]["tool_call_id"], "call-live-1");
        assert_eq!(json["messages"][1]["content"], result);
        assert!(decoded.report.is_lossless());
    }

    #[test]
    fn empty_current_client_tool_result_maps_to_empty_openai_content() {
        let request = GetChatMessageRequest {
            chat_model_uid: "gpt-5.6-sol-low".into(),
            chat_message_prompts: vec![
                ChatMessagePrompt {
                    message_id: "assistant-live-1".into(),
                    source: ChatMessageSource::System as i32,
                    tool_calls: vec![ChatToolCall {
                        id: "call-live-1".into(),
                        name: "run_command".into(),
                        arguments_json: r#"{"command":"true"}"#.into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ChatMessagePrompt {
                    message_id: "tool-live-1".into(),
                    source: ChatMessageSource::Tool as i32,
                    tool_call_id: "call-live-1".into(),
                    ..Default::default()
                },
            ],
            cascade_id: "cascade-live-1".into(),
            execution_id: "execution-live-2".into(),
            ..Default::default()
        };
        let raw = encode_connect_frame(&request.encode_to_vec(), false, false).expect("frame");
        let decoded = decode_chat_request(&raw, DevinChatLimits::default()).expect("decode");
        let mut semantic = decoded.request.clone();
        semantic.session_id = None;
        semantic.continuation_id = None;
        semantic.extensions.remove(
            &pooler_protocol::ExtensionKey::parse("devin.identifiers")
                .expect("identifier extension key"),
        );
        let encoded =
            OpenAiChatCodec::encode_request(&semantic, LossPolicy::Reject).expect("OpenAI request");
        let json: serde_json::Value = serde_json::from_slice(&encoded.body).expect("JSON");

        assert_eq!(json["messages"][1]["role"], "tool");
        assert_eq!(json["messages"][1]["tool_call_id"], "call-live-1");
        assert_eq!(json["messages"][1]["content"], "");
        assert!(decoded.report.is_lossless());
    }

    #[test]
    fn sanitized_current_client_tool_fixture_matches_openai_shape() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/devin/current-client-tool-follow-up.json"
        ))
        .expect("current Devin fixture");
        let request_value = &fixture["request"];
        let mut prompts = Vec::new();
        for value in request_value["messages"].as_array().expect("messages") {
            let source = match value["source"].as_str().expect("message source") {
                "system" => ChatMessageSource::System,
                "tool" => ChatMessageSource::Tool,
                other => panic!("unsupported fixture source {other}"),
            };
            let tool_calls = value["tool_calls"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|call| ChatToolCall {
                    id: call["id"].as_str().expect("tool call id").to_owned(),
                    name: call["name"].as_str().expect("tool name").to_owned(),
                    arguments_json: call["arguments_json"]
                        .as_str()
                        .expect("tool arguments")
                        .to_owned(),
                    ..Default::default()
                })
                .collect();
            prompts.push(ChatMessagePrompt {
                message_id: value["message_id"].as_str().expect("message ID").to_owned(),
                source: source as i32,
                prompt: value["prompt"].as_str().unwrap_or_default().to_owned(),
                tool_calls,
                tool_call_id: value["tool_call_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                ..Default::default()
            });
        }
        let tools = request_value["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .map(|tool| crate::proto::ChatToolDefinition {
                name: tool["name"].as_str().expect("tool name").to_owned(),
                json_schema_string: tool["json_schema_string"]
                    .as_str()
                    .expect("tool schema")
                    .to_owned(),
                ..Default::default()
            })
            .collect();
        let request = GetChatMessageRequest {
            chat_model_uid: request_value["model"].as_str().expect("model").to_owned(),
            chat_message_prompts: prompts,
            tools,
            tool_choice: Some(crate::proto::ChatToolChoice {
                choice: Some(crate::proto::chat_tool_choice::Choice::OptionName(
                    "auto".to_owned(),
                )),
            }),
            cascade_id: request_value["cascade_id"]
                .as_str()
                .expect("cascade ID")
                .to_owned(),
            execution_id: request_value["execution_id"]
                .as_str()
                .expect("execution ID")
                .to_owned(),
            ..Default::default()
        };
        let raw = encode_connect_frame(&request.encode_to_vec(), false, false).expect("frame");
        let route = pooler_config::compile_yaml(
            "devin-current-client-tool.yaml",
            r#"
version: 2
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:1}}
routes:
  - id: devin
    listen: local
    ingress: {mode: semantic, framing: decode.connect.envelope, decoder: decode.devin.chat}
    target: local
    response: {mode: semantic, decoder: decode.openai.chat.events, encoder: encode.devin.connect}
    loss_policy: reject
"#,
        )
        .expect("route")
        .routes()[0]
            .clone();
        let encoded = crate::DevinSemanticAdapter
            .encode_request(&route, &http::HeaderMap::new(), &raw)
            .expect("OpenAI request");
        let actual: serde_json::Value = serde_json::from_slice(&encoded.body).expect("OpenAI JSON");
        assert_eq!(actual, fixture["expected_openai_request"]);
    }

    #[test]
    fn message_sources_round_trip_assistant_and_system_roles() {
        let mut report = pooler_protocol::ConversionReport::default();
        let assistant_wire = ChatMessagePrompt {
            message_id: "assistant-1".into(),
            source: ChatMessageSource::System as i32,
            prompt: "previous answer".into(),
            ..Default::default()
        };
        let (assistant, _) =
            super::decode_prompt(&assistant_wire, 0, &mut report, DevinChatLimits::default())
                .expect("decode assistant");
        assert_eq!(assistant.role, Role::Assistant);
        let assistant_encoded =
            super::encode_message(&assistant, "cascade", 0, &mut report).expect("encode assistant");
        assert_eq!(
            ChatMessageSource::try_from(assistant_encoded.source).expect("assistant source"),
            ChatMessageSource::System
        );

        let system_wire = ChatMessagePrompt {
            message_id: "system-1".into(),
            source: ChatMessageSource::SystemPrompt as i32,
            prompt: "follow policy".into(),
            ..Default::default()
        };
        let (system, _) =
            super::decode_prompt(&system_wire, 1, &mut report, DevinChatLimits::default())
                .expect("decode system");
        assert_eq!(system.role, Role::System);
        let system_encoded =
            super::encode_message(&system, "cascade", 1, &mut report).expect("encode system");
        assert_eq!(
            ChatMessageSource::try_from(system_encoded.source).expect("system source"),
            ChatMessageSource::SystemPrompt
        );
    }

    #[test]
    fn fragmented_response_decoder_emits_lifecycle_text_reasoning_tools_usage_and_completion() {
        let mut decoder = DevinChatEventDecoder::new(
            Some("model-a".into()),
            DevinIdentifiers {
                cascade_id: Some("cascade-1".into()),
                execution_id: Some("execution-1".into()),
            },
        );
        let events = decoder
            .decode_message(GetChatMessageResponse {
                delta_thinking: "think".into(),
                delta_signature: "sig".into(),
                ..Default::default()
            })
            .expect("thinking");
        let mut all = events;
        all.extend(
            decoder
                .decode_message(GetChatMessageResponse {
                    delta_text: "hello".into(),
                    delta_tool_calls: vec![ChatToolCall {
                        id: "call-1".into(),
                        name: "search".into(),
                        arguments_json: "{\"q\"".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .expect("text/tool"),
        );
        all.extend(
            decoder
                .decode_message(GetChatMessageResponse {
                    delta_tool_calls: vec![ChatToolCall {
                        id: "call-1".into(),
                        arguments_json: ":\"x\"}".into(),
                        ..Default::default()
                    }],
                    usage: Some(ModelUsageStats {
                        input_tokens: 2,
                        output_tokens: 3,
                        cache_read_tokens: 4,
                        cache_write_tokens: 5,
                        ..Default::default()
                    }),
                    stop_reason: crate::proto::StopReason::FunctionCall as i32,
                    ..Default::default()
                })
                .expect("tool/usage"),
        );
        all.extend(decoder.finish().expect("finish"));
        assert!(all
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::ReasoningDelta { .. })));
        assert!(all
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::TextDelta { .. })));
        assert!(all
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::ToolCallStart { .. })));
        assert!(all
            .iter()
            .any(|event| matches!(event.kind, StreamEventKind::Usage { .. })));
        assert!(all.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::ToolCall,
                ..
            }
        )));
    }

    #[test]
    fn unspecified_stop_with_tools_completes_as_tool_call_before_state_is_drained() {
        let mut decoder =
            DevinChatEventDecoder::new(Some("model-a".into()), DevinIdentifiers::default());
        decoder
            .decode_message(GetChatMessageResponse {
                delta_tool_calls: vec![ChatToolCall {
                    id: "call-1".into(),
                    name: "search".into(),
                    arguments_json: "{}".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .expect("tool delta");
        let events = decoder.finish().expect("finish");
        assert!(events.iter().any(|event| matches!(
            event.kind,
            StreamEventKind::Completion {
                finish_reason: FinishReason::ToolCall,
                ..
            }
        )));
    }

    #[test]
    fn response_state_limits_reject_tool_count_arguments_and_reasoning_growth() {
        let limits = DevinChatResponseLimits {
            max_tool_calls: 1,
            max_tool_argument_bytes: 3,
            max_reasoning_bytes: 2,
        };
        let mut decoder = DevinChatEventDecoder::with_limits(
            Some("model-a".into()),
            DevinIdentifiers::default(),
            limits,
        );
        assert!(decoder
            .decode_message(GetChatMessageResponse {
                delta_tool_calls: vec![ChatToolCall {
                    id: "call-1".into(),
                    name: "search".into(),
                    arguments_json: "{}".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .is_ok());
        assert!(decoder
            .decode_message(GetChatMessageResponse {
                delta_tool_calls: vec![ChatToolCall {
                    id: "call-2".into(),
                    name: "search".into(),
                    arguments_json: "{}".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .is_err());

        let mut argument_decoder = DevinChatEventDecoder::with_limits(
            Some("model-a".into()),
            DevinIdentifiers::default(),
            DevinChatResponseLimits {
                max_tool_calls: 1,
                max_tool_argument_bytes: 2,
                max_reasoning_bytes: 10,
            },
        );
        assert!(argument_decoder
            .decode_message(GetChatMessageResponse {
                delta_tool_calls: vec![ChatToolCall {
                    id: "call-1".into(),
                    name: "search".into(),
                    arguments_json: "{}{}".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .is_err());

        let mut reasoning_decoder = DevinChatEventDecoder::with_limits(
            Some("model-a".into()),
            DevinIdentifiers::default(),
            DevinChatResponseLimits {
                max_tool_calls: 1,
                max_tool_argument_bytes: 10,
                max_reasoning_bytes: 2,
            },
        );
        assert!(reasoning_decoder
            .decode_message(GetChatMessageResponse {
                delta_thinking: "123".into(),
                ..Default::default()
            })
            .is_err());
    }

    #[test]
    fn decoded_debug_and_extensions_do_not_retain_wire_credentials() {
        let request = GetChatMessageRequest {
            chat_model_uid: "model-a".into(),
            metadata: Some(crate::proto::Metadata {
                api_key: "secret-api-key".into(),
                user_jwt: "secret-jwt".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = encode_connect_frame(&request.encode_to_vec(), true, false).expect("frame");
        let decoded = decode_chat_request(&raw, DevinChatLimits::default()).expect("decode");
        assert!(decoded
            .request
            .extensions
            .get_str("devin.raw_request")
            .is_none());
        let debug = format!("{decoded:?}");
        assert!(!debug.contains("secret-api-key"));
        assert!(!debug.contains("secret-jwt"));
    }
}
