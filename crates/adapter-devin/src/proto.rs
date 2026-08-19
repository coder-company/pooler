//! Bindings generated from the pinned widevin application protobuf sources.
//!
//! `build.rs` compiles the vendored source closure from the widevin snapshot
//! recorded in `proto/SOURCE.lock`. The aliases below keep adapter code focused
//! on protocol roles while retaining the authoritative package namespaces in
//! the generated bindings.

include!(concat!(env!("OUT_DIR"), "/mod.rs"));

pub use exa::api_server_pb::{
    ChatMessageRequestType, GetChatMessageRequest, GetChatMessageResponse,
    GetCliModelConfigsRequest, GetCliModelConfigsResponse,
};
pub use exa::auth_pb::{GetUserJwtRequest, GetUserJwtResponse};
pub use exa::chat_pb::{
    chat_tool_choice, CacheControlType, ChatMessagePrompt, ChatToolChoice, ChatToolDefinition,
    PromptCacheOptions,
};
pub use exa::codeium_common_pb::{
    ChatMessageSource, ChatToolCall, ClientModelConfig, CompletionConfiguration,
    ConversationalPlannerMode, ImageData, Metadata, ModelFeatures, ModelInfo, ModelUsageStats,
    StopReason,
};
