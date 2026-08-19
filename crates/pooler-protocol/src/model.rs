//! Protocol-neutral request semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Extensions, PreservedJson};

/// The speaker or owner of a semantic message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Provider or application instructions.
    System,
    /// Developer-authored instructions.
    Developer,
    /// End-user input.
    User,
    /// Model output.
    Assistant,
    /// A tool result supplied to the model.
    Tool,
}

/// Information resolved by routing before an upstream request is encoded.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TargetMetadata {
    /// Provider selected for this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Model identifier selected at the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Fixed endpoint or deployment name, if routing resolved one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional provider region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional account pseudonym selected by policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Adapter-defined target attributes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Provider-specific target state.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// An ordered request item.  Items are not collapsed into one provider-shaped
/// prompt so that adapters can retain message, tool, and provider boundaries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InputItem {
    /// A role-bearing message.
    Message(Message),
    /// A model tool invocation.
    ToolCall(ToolCall),
    /// A result returned by a tool.
    ToolResult(ToolResult),
    /// A standalone content part.
    Content(ContentPart),
    /// A provider-defined semantic input retained as JSON.
    Provider {
        /// Extension namespace.
        namespace: String,
        /// Provider-defined item name.
        name: String,
        /// Original provider item.
        data: PreservedJson,
    },
}

impl InputItem {
    /// Wraps a message as an input item.
    #[must_use]
    pub fn message(message: Message) -> Self {
        Self::Message(message)
    }

    /// Wraps a tool call as an input item.
    #[must_use]
    pub fn tool_call(call: ToolCall) -> Self {
        Self::ToolCall(call)
    }

    /// Wraps a tool result as an input item.
    #[must_use]
    pub fn tool_result(result: ToolResult) -> Self {
        Self::ToolResult(result)
    }

    /// Wraps a content part as an input item.
    #[must_use]
    pub fn content(content: ContentPart) -> Self {
        Self::Content(content)
    }
}

/// A role-bearing message with ordered multimodal content.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Optional stable message identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Message role.
    pub role: Role,
    /// Ordered text, media, reasoning, and tool parts.
    #[serde(default)]
    pub content: Vec<ContentPart>,
    /// Optional provider-visible speaker name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional tool call associated with this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Small application metadata map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Provider-specific message state.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

impl Message {
    /// Creates an empty message for a role.
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            role,
            ..Self::default()
        }
    }

    /// Creates a text-only message.
    #[must_use]
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            content: vec![ContentPart::text(text)],
            ..Self::default()
        }
    }

    /// Adds a content part while retaining input order.
    pub fn push_content(&mut self, content: ContentPart) {
        self.content.push(content);
    }
}

/// A source for an image, file, or audio part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum MediaSource {
    /// Bytes embedded in the semantic request.
    Inline(Vec<u8>),
    /// A URI understood by the selected provider.
    Uri(String),
}

impl MediaSource {
    /// Creates an inline source.
    #[must_use]
    pub fn inline(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Inline(bytes.into())
    }

    /// Creates a URI source.
    #[must_use]
    pub fn uri(uri: impl Into<String>) -> Self {
        Self::Uri(uri.into())
    }
}

/// A multimodal content part.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// UTF-8 text.
    Text {
        /// Text contents.
        text: String,
    },
    /// An image with a MIME type and inline or URI source.
    Image {
        /// Image media type.
        media_type: String,
        /// Image bytes or URI.
        source: MediaSource,
        /// Optional provider detail hint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// A file attachment.
    File {
        /// File name shown to the provider.
        name: Option<String>,
        /// File media type.
        media_type: String,
        /// File bytes or URI.
        source: MediaSource,
    },
    /// Audio input.
    Audio {
        /// Audio media type.
        media_type: String,
        /// Audio bytes or URI.
        source: MediaSource,
    },
    /// A reasoning block produced by or supplied to a model.
    Reasoning(ReasoningBlock),
    /// A tool invocation represented inside message content.
    ToolCall(ToolCall),
    /// A tool result represented inside message content.
    ToolResult(ToolResult),
    /// An adapter-specific content part that has no common shape.
    Provider {
        /// Extension namespace.
        namespace: String,
        /// Provider-defined part name.
        name: String,
        /// Original provider data.
        data: PreservedJson,
    },
}

impl ContentPart {
    /// Creates text content.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Creates an image part.
    #[must_use]
    pub fn image(media_type: impl Into<String>, source: MediaSource) -> Self {
        Self::Image {
            media_type: media_type.into(),
            source,
            detail: None,
        }
    }

    /// Creates a file part.
    #[must_use]
    pub fn file(name: Option<String>, media_type: impl Into<String>, source: MediaSource) -> Self {
        Self::File {
            name,
            media_type: media_type.into(),
            source,
        }
    }

    /// Creates an audio part.
    #[must_use]
    pub fn audio(media_type: impl Into<String>, source: MediaSource) -> Self {
        Self::Audio {
            media_type: media_type.into(),
            source,
        }
    }

    /// Creates a provider-defined JSON part.
    #[must_use]
    pub fn provider(
        namespace: impl Into<String>,
        name: impl Into<String>,
        data: PreservedJson,
    ) -> Self {
        Self::Provider {
            namespace: namespace.into(),
            name: name.into(),
            data,
        }
    }
}

/// Reasoning configuration requested by a caller.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ReasoningConfig {
    /// Requested reasoning effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<ReasoningEffort>,
    /// Whether a human-readable summary should be returned.
    #[serde(default)]
    pub include_summary: bool,
    /// Provider-specific reasoning options.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// A coarse reasoning effort understood by multiple providers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    /// Small reasoning budget.
    Low,
    /// Balanced reasoning budget.
    Medium,
    /// Large reasoning budget.
    High,
    /// Maximum available reasoning budget.
    Max,
    /// A provider-specific effort label.
    Custom(String),
}

/// A reasoning block in an input message or output event.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ReasoningBlock {
    /// Stable block identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Plain reasoning text, when exposed by a provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Summary text, when the provider exposes only a summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Encrypted provider reasoning payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Vec<u8>>,
    /// Provider signature associated with this block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    /// Provider-specific reasoning state not covered above.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// A tool schema exposed to a model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Stable tool name.
    pub name: String,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON schema for tool arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<PreservedJson>,
    /// Whether the provider should enforce the schema exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    /// Provider-specific definition state.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

impl ToolDefinition {
    /// Creates a tool definition with an optional JSON schema.
    #[must_use]
    pub fn new(name: impl Into<String>, parameters: Option<PreservedJson>) -> Self {
        Self {
            name: name.into(),
            description: None,
            parameters,
            strict: None,
            extensions: Extensions::default(),
        }
    }
}

/// Tool selection behavior requested by a caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolChoice {
    /// Let the model choose whether to call a tool.
    Auto,
    /// Do not allow tool calls.
    None,
    /// Require a tool call.
    Required,
    /// Require this named tool.
    Tool {
        /// Required tool name.
        name: String,
    },
}

/// A model-generated tool invocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Stable invocation identifier.
    pub id: String,
    /// Tool name.
    pub name: String,
    /// JSON arguments, retaining provider formatting until changed.
    pub arguments: PreservedJson,
    /// Optional dependency identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// Provider-specific invocation state.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

impl ToolCall {
    /// Creates a tool call from a JSON argument document.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, arguments: PreservedJson) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
            dependencies: Vec::new(),
            extensions: Extensions::default(),
        }
    }
}

/// A result returned by a tool invocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    /// Invocation identifier this result answers.
    pub tool_call_id: String,
    /// Ordered result content.
    #[serde(default)]
    pub content: Vec<ContentPart>,
    /// Whether the tool failed.
    #[serde(default)]
    pub is_error: bool,
    /// Provider-specific result state.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

impl ToolResult {
    /// Creates a text tool result.
    #[must_use]
    pub fn text(tool_call_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            tool_call_id: tool_call_id.into(),
            content: vec![ContentPart::text(text)],
            is_error: false,
            extensions: Extensions::default(),
        }
    }
}

/// Sampling and output controls common across model APIs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SamplingParameters {
    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Maximum output token count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// Stop strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    /// Optional deterministic seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Presence penalty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    /// Frequency penalty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    /// Provider-specific sampling controls.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// The requested response representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseFormat {
    /// Plain text output.
    Text,
    /// A JSON object without a fixed schema.
    JsonObject,
    /// JSON constrained by a caller-provided schema.
    JsonSchema {
        /// Schema name.
        name: String,
        /// JSON schema document.
        schema: PreservedJson,
        /// Whether to reject output that does not validate exactly.
        #[serde(default)]
        strict: bool,
    },
}

/// Cache behavior hints supplied by a caller.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheHints {
    /// Permit provider prompt caching where available.
    #[serde(default)]
    pub allow_prompt_cache: bool,
    /// Request a cache read when supported.
    #[serde(default)]
    pub prefer_cache_read: bool,
    /// Caller-provided cache key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Provider-specific cache options.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// A protocol-neutral model request.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SemanticRequest {
    /// Public model identifier from the downstream request.
    pub model: String,
    /// Target metadata selected by routing, if resolution has happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetMetadata>,
    /// Ordered semantic input items.
    #[serde(default)]
    pub input: Vec<InputItem>,
    /// Tools available to the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDefinition>,
    /// Tool selection behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Reasoning controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningConfig>,
    /// Sampling and output controls.
    #[serde(default)]
    pub sampling: SamplingParameters,
    /// Requested response format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// Prompt cache hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheHints>,
    /// Provider continuation or response identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_id: Option<String>,
    /// Session/conversation identifier used for affinity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Small application metadata map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Provider-specific request state.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// Alias for callers that use the shorter request name.
pub type Request = SemanticRequest;

impl SemanticRequest {
    /// Creates a request with one public model identifier.
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Self::default()
        }
    }

    /// Appends an ordered input item.
    pub fn push_input(&mut self, item: InputItem) {
        self.input.push(item);
    }

    /// Appends a message input item.
    pub fn push_message(&mut self, message: Message) {
        self.push_input(InputItem::Message(message));
    }

    /// Returns message inputs in their original order.
    pub fn messages(&self) -> impl Iterator<Item = &Message> {
        self.input.iter().filter_map(|item| match item {
            InputItem::Message(message) => Some(message),
            InputItem::ToolCall(_)
            | InputItem::ToolResult(_)
            | InputItem::Content(_)
            | InputItem::Provider { .. } => None,
        })
    }

    /// Validates fields that can be checked without provider capability data.
    pub fn validate(&self) -> Result<(), RequestValidationError> {
        if self.model.trim().is_empty() {
            return Err(RequestValidationError::EmptyModel);
        }
        let mut tool_names = Vec::new();
        for tool in &self.tools {
            if tool.name.trim().is_empty() {
                return Err(RequestValidationError::EmptyToolName);
            }
            if tool_names.iter().any(|name| name == &tool.name) {
                return Err(RequestValidationError::DuplicateToolName(tool.name.clone()));
            }
            tool_names.push(tool.name.clone());
        }
        Ok(())
    }
}

/// Errors found by provider-independent request validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RequestValidationError {
    /// A semantic request must identify a public model.
    #[error("semantic request model cannot be empty")]
    EmptyModel,
    /// A tool definition must identify a tool.
    #[error("tool name cannot be empty")]
    EmptyToolName,
    /// Two tool definitions use one name.
    #[error("duplicate tool name `{0}`")]
    DuplicateToolName(String),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ContentPart, InputItem, Message, Role, SemanticRequest, ToolDefinition};
    use crate::PreservedJson;

    #[test]
    fn request_keeps_ordered_roles_and_multimodal_parts() {
        let mut request = SemanticRequest::new("model-a");
        let mut user = Message::new(Role::User);
        user.push_content(ContentPart::text("look at this"));
        user.push_content(ContentPart::image(
            "image/png",
            super::MediaSource::inline(vec![1, 2, 3]),
        ));
        request.push_message(user);
        request.push_message(Message::text(Role::Assistant, "previous"));
        assert_eq!(request.messages().count(), 2);
        assert_eq!(request.input.len(), 2);
    }

    #[test]
    fn tool_schema_and_arguments_use_preserved_json() {
        let schema = PreservedJson::from_str("{ \"type\": \"object\" }").expect("schema");
        let mut request = SemanticRequest::new("model-a");
        request
            .tools
            .push(ToolDefinition::new("search", Some(schema)));
        request.validate().expect("valid request");
        let encoded = serde_json::to_value(&request).expect("serialize");
        assert_eq!(encoded["tools"][0]["name"], json!("search"));
    }

    #[test]
    fn duplicate_tools_are_rejected_before_provider_execution() {
        let mut request = SemanticRequest::new("model-a");
        request.tools.push(ToolDefinition::new("search", None));
        request.tools.push(ToolDefinition::new("search", None));
        assert!(request.validate().is_err());
    }

    #[test]
    fn provider_items_round_trip() {
        let data = PreservedJson::from_str("{\"opaque\":true}").expect("data");
        let item = InputItem::Provider {
            namespace: "provider".to_owned(),
            name: "item".to_owned(),
            data,
        };
        let encoded = serde_json::to_string(&item).expect("serialize");
        let decoded: InputItem = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, item);
    }
}
