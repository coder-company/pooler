#![forbid(unsafe_code)]
#![doc = "Anthropic Messages codecs normalized through Pooler's semantic model."]

mod request;
mod runtime;
mod stream;

pub use request::{
    AnthropicMessagesCodec, AnthropicRequestError, DecodedAnthropicRequest, EncodedAnthropicRequest,
};
pub use runtime::AnthropicSemanticAdapter;
pub use stream::{
    AnthropicEventDecoder, AnthropicEventEncoder, AnthropicMessageCodec, AnthropicStreamError,
    DecodedAnthropicMessage, EncodedAnthropicEvents, EncodedAnthropicMessage,
};

/// Anthropic's Messages HTTP endpoint.
pub const ANTHROPIC_MESSAGES_PATH: &str = "/v1/messages";
/// Droid's observed Anthropic Messages API revision header.
pub const ANTHROPIC_VERSION_HEADER: &str = "anthropic-version";
/// Anthropic beta-feature selection header.
pub const ANTHROPIC_BETA_HEADER: &str = "anthropic-beta";
/// API-key header used by Droid's Anthropic custom-model client.
pub const ANTHROPIC_API_KEY_HEADER: &str = "x-api-key";
/// Anthropic Messages request decoder component identity.
pub const DECODE_ANTHROPIC_MESSAGES: &str = "decode.anthropic.messages";
/// Anthropic Messages request encoder component identity.
pub const ENCODE_ANTHROPIC_MESSAGES: &str = "encode.anthropic.messages";
/// Anthropic Messages SSE decoder component identity.
pub const DECODE_ANTHROPIC_EVENTS: &str = "decode.anthropic.messages.events";
/// Anthropic Messages SSE encoder component identity.
pub const ENCODE_ANTHROPIC_EVENTS: &str = "encode.anthropic.messages.events";
