//! Native xAI request and stream codecs.
//!
//! xAI's inference API accepts OpenAI-compatible JSON while adding provider
//! fields and a long-lived Responses WebSocket mode. This crate keeps those
//! differences at the adapter boundary. It owns no HTTP client, credential,
//! route, or server configuration state.

#![forbid(unsafe_code)]

mod chat;
mod realtime;
mod rest;

pub use chat::XaiChatEventDecoder;
pub use realtime::{
    DecodedXaiRealtimeEvent, EncodedXaiRealtimeRequest, XaiRealtimeEventDecoder,
    XaiRealtimeEventKind, XaiRealtimeLimits, XaiRealtimeRequestCodec,
};
pub use rest::{
    DecodedXaiChatRequest, PreparedXaiRestRequest, XaiRestAdapter, XaiRestEndpoint, XaiRestError,
    XaiRestLimits, XaiRestTransport,
};

/// xAI inference API origin.
pub const XAI_API_ORIGIN: &str = "https://api.x.ai";
/// OpenAI-compatible Chat Completions path.
pub const XAI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
/// OpenAI-compatible Responses path, including WebSocket mode.
pub const XAI_RESPONSES_PATH: &str = "/v1/responses";
/// Responses context-compaction path.
pub const XAI_RESPONSES_COMPACT_PATH: &str = "/v1/responses/compact";
/// Full xAI Responses WebSocket URL.
pub const XAI_RESPONSES_WEBSOCKET_URL: &str = "wss://api.x.ai/v1/responses";
/// OpenAI-compatible minimal model discovery path.
pub const XAI_MODELS_PATH: &str = "/v1/models";
/// xAI language-model discovery path with modalities and aliases.
pub const XAI_LANGUAGE_MODELS_PATH: &str = "/v1/language-models";
