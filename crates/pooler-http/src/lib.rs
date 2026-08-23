//! HTTP primitives shared by Pooler's listeners and adapters.
//!
//! The crate deliberately keeps transport policy small and explicit.  In
//! particular, header filtering does not attempt to guess application
//! headers, body helpers are bounded before allocation, and stream retries
//! are only available while no response has been committed downstream.

#![forbid(unsafe_code)]

mod auth;
mod body;
mod cache;
mod drain;
mod headers;
mod media;
mod native;
mod openai_realtime;
mod openai_websocket;
mod pool;
mod proxy;
mod resources;
mod sse;
mod stream;

pub use auth::{
    extract_bearer, extract_bearer_secret, extract_bearer_token, BearerError, BearerToken,
};
pub use body::{
    collect_body_limited, read_body_limited, BodyLimitError, FrameLimitedBody, LimitedBody,
};
pub use cache::{
    replayable_response_headers, response_from_cache, safe_key_header, safe_method_for_cache,
    safe_request_for_cache, safe_response_for_cache, CacheFollower, CacheKey, CacheKeyInput,
    CacheLeader, CacheLookup, CachePolicy, CachedResponse, ResponseCache, CACHE_KEY_VERSION,
    DEFAULT_CACHE_MAX_BYTES, DEFAULT_CACHE_MAX_ENTRIES, DEFAULT_CACHE_TTL, MAX_CACHE_KEY_HEADERS,
};
pub use drain::{DrainController, DrainError, DrainGuard, DrainedBody};
pub use headers::{
    remove_hop_by_hop_headers, retry_after_delay, sanitize_headers, strip_hop_by_hop_headers,
    HOP_BY_HOP_HEADERS,
};
pub use media::{
    MediaSemanticAdapter, MediaSemanticAdapterError, MEDIA_BINARY_DECODER, MEDIA_MULTIPART_DECODER,
};
pub use native::{
    NativeAuthorization, NativeAuthorizationRequest, NativeRuntime, NativeRuntimeError,
};
pub use pool::{
    apply_configured_account_auth, PersistenceStatus, PersistenceStream, PoolError, PoolFailure,
    PoolSelection, PoolingCoordinator, SelectionContext, SelectionTiming,
};
pub use proxy::{
    apply_configured_upstream_auth, apply_configured_upstream_headers, BoxError, HttpProxy,
    NoSemanticAdapter, ProxyBody, ProxyError, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody, SemanticResponseHint, SemanticResponseMode, SemanticWebSocketTransport,
};
pub use resources::{RuntimeResourceGuard, RuntimeResourceSnapshot, RuntimeResources};
pub use sse::{
    SseEncoder, SseError, SseEvent, SseLimits, SseParser, DEFAULT_SSE_MAX_EVENT_BYTES,
    DEFAULT_SSE_MAX_LINE_BYTES,
};
pub use stream::{
    wait_for_retry, CommitmentError, RetryError, RetryWaitError, StreamCommitment, StreamEvent,
    StreamState,
};
