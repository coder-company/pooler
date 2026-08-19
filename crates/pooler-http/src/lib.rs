//! HTTP primitives shared by Pooler's listeners and adapters.
//!
//! The crate deliberately keeps transport policy small and explicit.  In
//! particular, header filtering does not attempt to guess application
//! headers, body helpers are bounded before allocation, and stream retries
//! are only available while no response has been committed downstream.

#![forbid(unsafe_code)]

mod auth;
mod body;
mod drain;
mod headers;
mod proxy;
mod sse;
mod stream;

pub use auth::{
    extract_bearer, extract_bearer_secret, extract_bearer_token, BearerError, BearerToken,
};
pub use body::{
    collect_body_limited, read_body_limited, BodyLimitError, FrameLimitedBody, LimitedBody,
};
pub use drain::{DrainController, DrainError, DrainGuard, DrainedBody};
pub use headers::{
    remove_hop_by_hop_headers, sanitize_headers, strip_hop_by_hop_headers, HOP_BY_HOP_HEADERS,
};
pub use proxy::{
    BoxError, HttpProxy, NoSemanticAdapter, ProxyBody, ProxyError, SemanticAdapter,
    SemanticRequestBody, SemanticResponseBody,
};
pub use sse::{
    SseEncoder, SseError, SseEvent, SseLimits, SseParser, DEFAULT_SSE_MAX_EVENT_BYTES,
    DEFAULT_SSE_MAX_LINE_BYTES,
};
pub use stream::{CommitmentError, RetryError, StreamCommitment, StreamEvent, StreamState};
