#![forbid(unsafe_code)]
#![doc = "Protocol-neutral semantic values and explicit conversion accounting for Pooler."]

mod connect;
mod conversion;
mod events;
mod extensions;
mod json;
mod model;
mod openai_chat;
mod openai_responses;

use serde::{Deserialize, Serialize};

pub use connect::{
    decode_connect_envelopes, decode_gzip_payload, encode_connect_envelope, ConnectCompression,
    ConnectDecoder, ConnectEncoder, ConnectEnvelope, ConnectError, ConnectLimits,
    CONNECT_ENVELOPE_HEADER_BYTES, CONNECT_FLAG_COMPRESSED, CONNECT_FLAG_END_STREAM,
    DEFAULT_CONNECT_MAX_DECOMPRESSED_BYTES, DEFAULT_CONNECT_MAX_FRAME_BYTES,
};
pub use conversion::{
    ConversionError, ConversionReport, ConversionResult, ConversionWarning, WarningSeverity,
};
pub use events::{
    FinishReason, SemanticEvent, StreamError, StreamEvent, StreamEventKind, StreamValidationError,
    StreamValidator, Usage,
};
pub use extensions::{
    ExtensionError, ExtensionKey, ExtensionName, ExtensionNamespace, Extensions, OpaqueExtension,
    OpaqueExtensions, ReplayPolicy,
};
pub use json::{
    JsonInspectionError, JsonPatchError, JsonPatchLimits, PreservedJson, PreservedJsonError,
    DEFAULT_JSON_PATCH_MAX_POINTER_BYTES, DEFAULT_JSON_PATCH_MAX_POINTER_DEPTH,
    DEFAULT_JSON_PATCH_MAX_VALUE_BYTES,
};
pub use model::{
    CacheHints, ContentPart, InputItem, MediaSource, Message, ReasoningBlock, ReasoningConfig,
    ReasoningEffort, Request, RequestValidationError, ResponseFormat, Role, SamplingParameters,
    SemanticRequest, TargetMetadata, ToolCall, ToolChoice, ToolDefinition, ToolResult,
};
pub use openai_chat::{
    decode_chat_request, decode_chat_request_with_report, encode_chat_request, DecodedChatRequest,
    EncodedChatChunk, EncodedChatRequest, OpenAiChatCodec, OpenAiChatError, OpenAiChatEventDecoder,
    OpenAiChatEventEncoder, OPENAI_CHAT_UNKNOWN_FIELDS_EXTENSION,
};
pub use openai_responses::{
    decode_responses_request, decode_responses_request_with_report, encode_responses_request,
    DecodedResponsesRequest, EncodedResponsesEvent, EncodedResponsesRequest,
    OpenAiResponsesCodec, OpenAiResponsesError, OpenAiResponsesEventDecoder,
    OpenAiResponsesEventEncoder, OPENAI_RESPONSES_UNKNOWN_FIELDS_EXTENSION,
};
pub use pooler_core::LossPolicy;

/// Request body representations used by route plans.
// Keep semantic bodies inline: boxing would add an allocation to every decoded
// request solely to reduce the stack size of this boundary enum.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RequestBody {
    /// Bytes or frames that do not require semantic decoding.
    Opaque(Vec<u8>),
    /// A JSON body whose original bytes can still be forwarded.
    Json(PreservedJson),
    /// A decoded protocol-neutral request.
    Semantic(SemanticRequest),
}

impl RequestBody {
    /// Returns the body as preserved JSON, if this is the JSON representation.
    #[must_use]
    pub const fn as_json(&self) -> Option<&PreservedJson> {
        match self {
            Self::Json(value) => Some(value),
            Self::Opaque(_) | Self::Semantic(_) => None,
        }
    }

    /// Returns the body as a semantic request, if this is the semantic
    /// representation.
    #[must_use]
    pub const fn as_semantic(&self) -> Option<&SemanticRequest> {
        match self {
            Self::Semantic(value) => Some(value),
            Self::Opaque(_) | Self::Json(_) => None,
        }
    }
}

/// Response body representations used by route plans.
// Stream events cross this boundary one at a time; keep them inline instead of
// adding one heap allocation per event.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResponseBody {
    /// Opaque response bytes.
    Opaque(Vec<u8>),
    /// A preserved JSON response.
    Json(PreservedJson),
    /// One semantic stream event.
    Event(StreamEvent),
}

impl Default for Role {
    fn default() -> Self {
        Self::User
    }
}

#[cfg(test)]
mod tests {
    use super::{PreservedJson, RequestBody, SemanticRequest};

    #[test]
    fn request_body_keeps_json_and_semantic_paths_distinct() {
        let json = PreservedJson::from_str("{\"model\":\"x\"}").expect("JSON");
        let body = RequestBody::Json(json);
        assert!(body.as_json().is_some());
        assert!(body.as_semantic().is_none());

        let semantic = RequestBody::Semantic(SemanticRequest::new("x"));
        assert!(semantic.as_semantic().is_some());
        assert!(semantic.as_json().is_none());
    }
}
