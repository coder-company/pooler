//! Stable, bounded errors returned by the management control plane.
//!
//! Management errors are deliberately separate from compiler, provider, and
//! storage error text.  Callers get a small versioned contract while logs can
//! retain the richer internal error.  Detail values are added only by typed
//! constructors below and are bounded before serialization.

use std::collections::BTreeMap;

use http::StatusCode;
use serde::Serialize;
use serde_json::{json, Value};

pub const SCHEMA_VERSION: u8 = 1;
const MAX_DETAIL_KEY_BYTES: usize = 64;
const MAX_DETAIL_VALUE_BYTES: usize = 256;
const MAX_DETAILS: usize = 8;

/// Stable management error codes and their HTTP semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementErrorCode {
    ConfigDraftEtagMismatch,
    ConfigGenerationConflict,
    OperationInProgress,
    OAuthTokenGenerationConflict,
    ConfirmationInvalid,
    DraftExpired,
    ValidationFailed,
    CapacityExceeded,
    StateUnavailable,
    DependencyUnavailable,
    AuthenticationRequired,
    AuthenticationNotConfigured,
    ForbiddenHost,
    ForbiddenOrigin,
    NotFound,
    AccountNotFound,
    ModelNotFound,
    RequestNotFound,
    MethodNotAllowed,
    PreconditionRequired,
    UnsupportedOperation,
    PayloadTooLarge,
    RequestTimeout,
    InvalidRequest,
    InvalidModelIdentifier,
    OAuthUnsupported,
    OAuthAuthorizationFailed,
    OAuthCallbackInvalid,
    OAuthCallbackConsumed,
    OAuthUnavailable,
    RequestHistoryIncomplete,
    InternalFailure,
}

impl ManagementErrorCode {
    /// Wire-stable snake-case code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigDraftEtagMismatch => "config_draft_etag_mismatch",
            Self::ConfigGenerationConflict => "config_generation_conflict",
            Self::OperationInProgress => "operation_in_progress",
            Self::OAuthTokenGenerationConflict => "oauth_token_generation_conflict",
            Self::ConfirmationInvalid => "confirmation_invalid",
            Self::DraftExpired => "draft_expired",
            Self::ValidationFailed => "validation_failed",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::StateUnavailable => "state_unavailable",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::AuthenticationRequired => "authentication_required",
            Self::AuthenticationNotConfigured => "authentication_not_configured",
            Self::ForbiddenHost => "forbidden_host",
            Self::ForbiddenOrigin => "forbidden_origin",
            Self::NotFound => "not_found",
            Self::AccountNotFound => "account_not_found",
            Self::ModelNotFound => "model_not_found",
            Self::RequestNotFound => "request_not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::PreconditionRequired => "precondition_required",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RequestTimeout => "request_timeout",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidModelIdentifier => "invalid_model_identifier",
            Self::OAuthUnsupported => "oauth_unsupported",
            Self::OAuthAuthorizationFailed => "oauth_authorization_failed",
            Self::OAuthCallbackInvalid => "oauth_callback_invalid",
            Self::OAuthCallbackConsumed => "oauth_callback_consumed",
            Self::OAuthUnavailable => "oauth_unavailable",
            Self::RequestHistoryIncomplete => "request_history_incomplete",
            Self::InternalFailure => "internal_failure",
        }
    }

    /// Contract status for this code.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::ConfigDraftEtagMismatch
            | Self::ConfigGenerationConflict
            | Self::PreconditionRequired => StatusCode::PRECONDITION_FAILED,
            Self::OperationInProgress
            | Self::OAuthTokenGenerationConflict
            | Self::ConfirmationInvalid
            | Self::OAuthUnsupported => StatusCode::CONFLICT,
            Self::DraftExpired => StatusCode::GONE,
            Self::ValidationFailed | Self::InvalidModelIdentifier => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::CapacityExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::StateUnavailable
            | Self::DependencyUnavailable
            | Self::RequestHistoryIncomplete => StatusCode::SERVICE_UNAVAILABLE,
            Self::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            Self::AuthenticationNotConfigured
            | Self::ForbiddenHost
            | Self::ForbiddenOrigin => StatusCode::FORBIDDEN,
            Self::NotFound
            | Self::AccountNotFound
            | Self::ModelNotFound
            | Self::RequestNotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::UnsupportedOperation
            | Self::PayloadTooLarge
            | Self::RequestTimeout
            | Self::InvalidRequest
            | Self::OAuthAuthorizationFailed
            | Self::OAuthCallbackInvalid
            | Self::OAuthCallbackConsumed => match self {
                Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
                Self::OAuthCallbackConsumed => StatusCode::CONFLICT,
                Self::UnsupportedOperation => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_REQUEST,
            },
            Self::OAuthUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InternalFailure => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether retrying the same operation may succeed after state changes.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::ConfigDraftEtagMismatch
                | Self::ConfigGenerationConflict
                | Self::OperationInProgress
                | Self::OAuthTokenGenerationConflict
                | Self::CapacityExceeded
                | Self::StateUnavailable
                | Self::DependencyUnavailable
                | Self::OAuthUnavailable
                | Self::RequestHistoryIncomplete
        )
    }
}

/// JSON body returned for an unsuccessful management operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManagementErrorEnvelope {
    pub schema_version: u8,
    pub error: ManagementErrorBody,
}

/// The bounded error object nested in [`ManagementErrorEnvelope`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManagementErrorBody {
    pub code: String,
    pub message: String,
    pub details: BTreeMap<String, Value>,
    pub retryable: bool,
    pub current_generation: Option<u64>,
}

/// Typed management failure before it is converted to an HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementError {
    code: ManagementErrorCode,
    message: String,
    details: BTreeMap<String, Value>,
    current_generation: Option<u64>,
    retry_after_seconds: Option<u64>,
}

impl ManagementError {
    /// Construct a contract error using the stable code's status and retry
    /// semantics.
    #[must_use]
    pub fn new(code: ManagementErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message: message.to_owned(),
            details: BTreeMap::new(),
            current_generation: None,
            retry_after_seconds: None,
        }
    }

    /// Add a bounded non-secret string detail. Invalid or excess details are
    /// ignored so an internal value can never escape by accident.
    #[must_use]
    pub fn with_detail(self, key: &'static str, value: &str) -> Self {
        if key.is_empty()
            || key.len() > MAX_DETAIL_KEY_BYTES
            || value.is_empty()
            || value.len() > MAX_DETAIL_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            return self;
        }
        self.with_value(key, Value::String(value.to_owned()))
    }

    /// Add a bounded numeric detail.
    #[must_use]
    pub fn with_detail_u64(self, key: &'static str, value: u64) -> Self {
        self.with_value(key, json!(value))
    }

    /// Include the active configuration generation in the stable location.
    #[must_use]
    pub const fn with_current_generation(mut self, generation: Option<u64>) -> Self {
        self.current_generation = generation;
        self
    }

    /// Add a bounded `Retry-After` value for capacity errors.
    #[must_use]
    pub const fn with_retry_after_seconds(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    fn with_value(mut self, key: &'static str, value: Value) -> Self {
        if self.details.len() < MAX_DETAILS
            && key.len() <= MAX_DETAIL_KEY_BYTES
            && !key.chars().any(char::is_control)
        {
            self.details.insert(key.to_owned(), value);
        }
        self
    }

    /// Stable code.
    #[must_use]
    pub const fn code(&self) -> ManagementErrorCode {
        self.code
    }

    /// HTTP status selected by the stable code mapping.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.code.status()
    }

    /// Optional `Retry-After` seconds.
    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// Convert this failure to its redacted, versioned JSON envelope.
    #[must_use]
    pub fn envelope(&self) -> ManagementErrorEnvelope {
        ManagementErrorEnvelope {
            schema_version: SCHEMA_VERSION,
            error: ManagementErrorBody {
                code: self.code.as_str().to_owned(),
                message: self.message.clone(),
                details: self.details.clone(),
                retryable: self.code.retryable(),
                current_generation: self.current_generation,
            },
        }
    }

    /// Convert this failure to a JSON value for response serialization.
    #[must_use]
    pub fn value(&self) -> Value {
        serde_json::to_value(self.envelope()).expect("management error envelope is serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_has_stable_shape_and_bounded_details() {
        let error = ManagementError::new(
            ManagementErrorCode::ConfigDraftEtagMismatch,
            "configuration draft does not match the active revision",
        )
        .with_detail("expected_etag", "expected-1")
        .with_detail("current_etag", "current-2")
        .with_current_generation(Some(2));
        let value = error.value();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["error"]["code"], "config_draft_etag_mismatch");
        assert_eq!(value["error"]["retryable"], true);
        assert_eq!(value["error"]["current_generation"], 2);
        assert_eq!(value["error"]["details"]["expected_etag"], "expected-1");
        assert_eq!(error.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn capacity_uses_retry_after_without_exposing_details() {
        let error = ManagementError::new(
            ManagementErrorCode::CapacityExceeded,
            "management operation capacity is temporarily exhausted",
        )
        .with_retry_after_seconds(3)
        .with_detail("secret", "\u{0}");
        assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.retry_after_seconds(), Some(3));
        assert!(error.value()["error"]["details"].get("secret").is_none());
    }
}
