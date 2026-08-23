//! Bounded resource limits shared by listeners, route plans, and codecs.

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::error::{PoolerError, PoolerResult};

const DEFAULT_REQUEST_BODY_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_RESPONSE_BODY_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_HEADER_COUNT: u32 = 128;
const DEFAULT_HEADER_BYTES: u64 = 64 * 1024;
const DEFAULT_FRAME_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_EVENT_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_BOOTSTRAP_BYTES: u64 = 64 * 1024;
const DEFAULT_BOOTSTRAP_EVENTS: u32 = 1;
const DEFAULT_QUEUE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_QUEUE_ITEMS: u32 = 256;

/// A resource that can be rejected by a route limit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitResource {
    RequestBody,
    ResponseBody,
    HeaderCount,
    HeaderBytes,
    Frame,
    Event,
    BootstrapBytes,
    BootstrapEvents,
    QueueBytes,
    QueueItems,
}

impl std::fmt::Display for LimitResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RequestBody => "request body",
            Self::ResponseBody => "response body",
            Self::HeaderCount => "header count",
            Self::HeaderBytes => "header bytes",
            Self::Frame => "frame",
            Self::Event => "event",
            Self::BootstrapBytes => "bootstrap bytes",
            Self::BootstrapEvents => "bootstrap events",
            Self::QueueBytes => "queue bytes",
            Self::QueueItems => "queue items",
        })
    }
}

/// Validation failures for an invalid route limit configuration.
#[derive(Clone, Copy, Debug, Eq, Error, Hash, PartialEq)]
pub enum LimitValidationError {
    /// A positive resource limit was set to zero.
    #[error("{resource} limit must be greater than zero")]
    Zero { resource: LimitResource },
    /// A configured timeout was zero.
    #[error("{resource} timeout must be greater than zero")]
    ZeroTimeout { resource: TimeoutResource },
}

/// A timeout represented in [`RouteLimits`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeoutResource {
    Request,
    Connect,
}

impl std::fmt::Display for TimeoutResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Request => "request",
            Self::Connect => "connect",
        })
    }
}

/// Route-level bounds applied before buffering, framing, or queueing data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteLimits {
    /// Maximum decompressed request body size.
    pub max_request_body_bytes: u64,
    /// Maximum buffered response body size.
    pub max_response_body_bytes: u64,
    /// Maximum number of request headers.
    pub max_header_count: u32,
    /// Maximum total request header bytes.
    pub max_header_bytes: u64,
    /// Maximum one transport frame or message.
    pub max_frame_bytes: u64,
    /// Maximum one SSE/event-semantic event.
    pub max_event_bytes: u64,
    /// Maximum bytes retained while deciding whether a stream is committed.
    pub max_bootstrap_bytes: u64,
    /// Maximum events retained while deciding whether a stream is committed.
    pub max_bootstrap_events: u32,
    /// Maximum bytes waiting in one bounded channel.
    pub max_queue_bytes: u64,
    /// Maximum items waiting in one bounded channel.
    pub max_queue_items: u32,
    /// End-to-end request timeout. `None` is allowed for an explicitly managed stream.
    #[serde(with = "optional_duration_millis")]
    pub request_timeout: Option<Duration>,
    /// Upstream TCP/TLS connection timeout. Response headers remain bounded
    /// by `request_timeout`.
    #[serde(with = "optional_duration_millis")]
    pub connect_timeout: Option<Duration>,
}

impl Default for RouteLimits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_REQUEST_BODY_BYTES,
            max_response_body_bytes: DEFAULT_RESPONSE_BODY_BYTES,
            max_header_count: DEFAULT_HEADER_COUNT,
            max_header_bytes: DEFAULT_HEADER_BYTES,
            max_frame_bytes: DEFAULT_FRAME_BYTES,
            max_event_bytes: DEFAULT_EVENT_BYTES,
            max_bootstrap_bytes: DEFAULT_BOOTSTRAP_BYTES,
            max_bootstrap_events: DEFAULT_BOOTSTRAP_EVENTS,
            max_queue_bytes: DEFAULT_QUEUE_BYTES,
            max_queue_items: DEFAULT_QUEUE_ITEMS,
            request_timeout: Some(Duration::from_secs(30 * 60)),
            connect_timeout: Some(Duration::from_secs(5)),
        }
    }
}

impl RouteLimits {
    /// Validate that all bounded resources and configured timeouts are usable.
    pub fn validate(&self) -> Result<(), LimitValidationError> {
        let resources = [
            (self.max_request_body_bytes, LimitResource::RequestBody),
            (self.max_response_body_bytes, LimitResource::ResponseBody),
            (u64::from(self.max_header_count), LimitResource::HeaderCount),
            (self.max_header_bytes, LimitResource::HeaderBytes),
            (self.max_frame_bytes, LimitResource::Frame),
            (self.max_event_bytes, LimitResource::Event),
            (self.max_bootstrap_bytes, LimitResource::BootstrapBytes),
            (
                u64::from(self.max_bootstrap_events),
                LimitResource::BootstrapEvents,
            ),
            (self.max_queue_bytes, LimitResource::QueueBytes),
            (u64::from(self.max_queue_items), LimitResource::QueueItems),
        ];
        for (value, resource) in resources {
            if value == 0 {
                return Err(LimitValidationError::Zero { resource });
            }
        }
        if self
            .request_timeout
            .is_some_and(|timeout| timeout.is_zero())
        {
            return Err(LimitValidationError::ZeroTimeout {
                resource: TimeoutResource::Request,
            });
        }
        if self
            .connect_timeout
            .is_some_and(|timeout| timeout.is_zero())
        {
            return Err(LimitValidationError::ZeroTimeout {
                resource: TimeoutResource::Connect,
            });
        }
        Ok(())
    }

    /// Validate and convert a limit configuration error to the shared error type.
    pub fn validate_result(&self) -> PoolerResult<()> {
        self.validate()
            .map_err(|error| PoolerError::InvalidConfiguration {
                message: error.to_string(),
            })
    }

    /// Check a request body size against the configured decompressed bound.
    pub fn check_request_body(&self, observed: u64) -> PoolerResult<()> {
        check(
            LimitResource::RequestBody,
            observed,
            self.max_request_body_bytes,
        )
    }

    /// Check a response body size against the configured bound.
    pub fn check_response_body(&self, observed: u64) -> PoolerResult<()> {
        check(
            LimitResource::ResponseBody,
            observed,
            self.max_response_body_bytes,
        )
    }

    /// Check a frame or WebSocket message size.
    pub fn check_frame(&self, observed: u64) -> PoolerResult<()> {
        check(LimitResource::Frame, observed, self.max_frame_bytes)
    }

    /// Check one event size.
    pub fn check_event(&self, observed: u64) -> PoolerResult<()> {
        check(LimitResource::Event, observed, self.max_event_bytes)
    }

    /// Check the number of headers and their total bytes.
    pub fn check_headers(&self, count: u32, bytes: u64) -> PoolerResult<()> {
        check(
            LimitResource::HeaderCount,
            u64::from(count),
            u64::from(self.max_header_count),
        )?;
        check(LimitResource::HeaderBytes, bytes, self.max_header_bytes)
    }

    /// Check bounded bootstrap state before a stream is committed.
    pub fn check_bootstrap(&self, bytes: u64, events: u32) -> PoolerResult<()> {
        check(
            LimitResource::BootstrapBytes,
            bytes,
            self.max_bootstrap_bytes,
        )?;
        check(
            LimitResource::BootstrapEvents,
            u64::from(events),
            u64::from(self.max_bootstrap_events),
        )
    }

    /// Check one bounded queue state.
    pub fn check_queue(&self, bytes: u64, items: u32) -> PoolerResult<()> {
        check(LimitResource::QueueBytes, bytes, self.max_queue_bytes)?;
        check(
            LimitResource::QueueItems,
            u64::from(items),
            u64::from(self.max_queue_items),
        )
    }
}

fn check(resource: LimitResource, observed: u64, limit: u64) -> PoolerResult<()> {
    if observed > limit {
        Err(PoolerError::LimitExceeded {
            resource,
            limit,
            observed,
        })
    } else {
        Ok(())
    }
}

mod optional_duration_millis {
    use super::*;

    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .map(|duration| duration.as_millis() as u64)
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = Option::<u64>::deserialize(deserializer)?;
        Ok(millis.map(Duration::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn defaults_are_bounded_and_valid() {
        let limits = RouteLimits::default();
        limits.validate().expect("default limits are valid");
        assert_eq!(limits.max_bootstrap_events, 1);
        assert_eq!(limits.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn checks_report_the_resource_and_values() {
        let limits = RouteLimits {
            max_frame_bytes: 8,
            ..RouteLimits::default()
        };
        let error = limits.check_frame(9).expect_err("frame should be rejected");
        assert_eq!(
            error,
            PoolerError::LimitExceeded {
                resource: LimitResource::Frame,
                limit: 8,
                observed: 9,
            }
        );
        assert!(limits.check_frame(8).is_ok());
    }

    #[test]
    fn invalid_zero_limits_fail_before_runtime_use() {
        let limits = RouteLimits {
            max_event_bytes: 0,
            ..RouteLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(LimitValidationError::Zero {
                resource: LimitResource::Event,
            })
        );
        let limits = RouteLimits {
            max_event_bytes: 1,
            request_timeout: Some(Duration::ZERO),
            ..limits
        };
        assert_eq!(
            limits.validate(),
            Err(LimitValidationError::ZeroTimeout {
                resource: TimeoutResource::Request,
            })
        );
    }

    #[test]
    fn limits_serialize_duration_as_milliseconds() {
        let limits = RouteLimits {
            request_timeout: Some(Duration::from_millis(1250)),
            connect_timeout: None,
            ..RouteLimits::default()
        };
        let json = serde_json::to_value(&limits).expect("serialize limits");
        assert_eq!(json["request_timeout"], 1250);
        assert!(json["connect_timeout"].is_null());
        let decoded: RouteLimits = serde_json::from_value(json).expect("deserialize limits");
        assert_eq!(decoded, limits);
    }
}
