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
const MAX_MESSAGE_BYTES: usize = 256;
const MAX_RETRY_AFTER_SECONDS: u64 = 3_600;

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
    ManagementNotConfigured,
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
            Self::ManagementNotConfigured => "management_not_configured",
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
            | Self::ConfigGenerationConflict => StatusCode::PRECONDITION_FAILED,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::OperationInProgress
            | Self::OAuthTokenGenerationConflict
            | Self::ConfirmationInvalid
            | Self::OAuthUnsupported
            | Self::ManagementNotConfigured => StatusCode::CONFLICT,
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

    /// Choose the least-specific stable code for a legacy status/message
    /// response while callers are migrated to typed constructors.
    #[must_use]
    pub const fn for_status(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST => Self::InvalidRequest,
            StatusCode::UNAUTHORIZED => Self::AuthenticationRequired,
            StatusCode::FORBIDDEN => Self::ForbiddenOrigin,
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => Self::MethodNotAllowed,
            StatusCode::REQUEST_TIMEOUT => Self::RequestTimeout,
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge,
            StatusCode::CONFLICT => Self::OperationInProgress,
            StatusCode::GONE => Self::DraftExpired,
            StatusCode::PRECONDITION_FAILED => Self::ConfigDraftEtagMismatch,
            StatusCode::PRECONDITION_REQUIRED => Self::PreconditionRequired,
            StatusCode::UNPROCESSABLE_ENTITY => Self::ValidationFailed,
            StatusCode::TOO_MANY_REQUESTS => Self::CapacityExceeded,
            StatusCode::SERVICE_UNAVAILABLE => Self::StateUnavailable,
            _ => Self::InternalFailure,
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
    pub fn new(code: ManagementErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: bounded_message(message.into()),
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
        self.retry_after_seconds = Some(if seconds > MAX_RETRY_AFTER_SECONDS {
            MAX_RETRY_AFTER_SECONDS
        } else {
            seconds
        });
        self
    }

    /// Construct a typed error for a response that has not yet been migrated
    /// to a more specific code. The message is bounded and control-free.
    #[must_use]
    pub fn from_status(status: StatusCode, message: impl Into<String>) -> Self {
        Self::new(ManagementErrorCode::for_status(status), message)
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

    /// Return the bounded error object used by asynchronous status records.
    #[must_use]
    pub fn body(&self) -> ManagementErrorBody {
        self.envelope().error
    }

    /// Return the bounded error object as JSON for status records.
    #[must_use]
    pub fn body_value(&self) -> Value {
        serde_json::to_value(self.body()).expect("management error body is serializable")
    }

    /// Convert this failure to a JSON value for response serialization.
    #[must_use]
    pub fn value(&self) -> Value {
        serde_json::to_value(self.envelope()).expect("management error envelope is serializable")
    }
}

fn bounded_message(message: String) -> String {
    if message.is_empty() || message.chars().any(char::is_control) {
        return "management request failed".to_owned();
    }
    let mut bounded = String::with_capacity(message.len().min(MAX_MESSAGE_BYTES));
    let mut bytes = 0;
    for character in message.chars() {
        let width = character.len_utf8();
        if bytes + width > MAX_MESSAGE_BYTES {
            break;
        }
        bounded.push(character);
        bytes += width;
    }
    bounded
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

    #[test]
    fn management_error_contract_has_stable_status_mappings() {
        let cases = [
            (
                ManagementErrorCode::ConfigDraftEtagMismatch,
                StatusCode::PRECONDITION_FAILED,
                "config_draft_etag_mismatch",
            ),
            (
                ManagementErrorCode::ConfigGenerationConflict,
                StatusCode::PRECONDITION_FAILED,
                "config_generation_conflict",
            ),
            (
                ManagementErrorCode::OperationInProgress,
                StatusCode::CONFLICT,
                "operation_in_progress",
            ),
            (
                ManagementErrorCode::DraftExpired,
                StatusCode::GONE,
                "draft_expired",
            ),
            (
                ManagementErrorCode::ValidationFailed,
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
            ),
            (
                ManagementErrorCode::CapacityExceeded,
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exceeded",
            ),
            (
                ManagementErrorCode::StateUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "state_unavailable",
            ),
        ];
        for (code, status, wire_code) in cases {
            let error = ManagementError::new(code, "bounded message");
            let value = error.value();
            assert_eq!(error.status(), status);
            assert_eq!(value["schema_version"], SCHEMA_VERSION);
            assert_eq!(value["error"]["code"], wire_code);
            assert!(value["error"].get("message").and_then(Value::as_str).is_some());
            assert!(value["error"].get("retryable").is_some());
            assert!(value["error"].get("details").is_some_and(Value::is_object));
            assert!(value["error"].get("current_generation").is_some());
        }
    }

    #[test]
    fn status_fallback_and_retry_after_are_bounded() {
        let error = ManagementError::from_status(
            StatusCode::TOO_MANY_REQUESTS,
            format!("{}\nsecret", "x".repeat(MAX_MESSAGE_BYTES + 20)),
        )
        .with_retry_after_seconds(u64::MAX);
        assert_eq!(error.code(), ManagementErrorCode::CapacityExceeded);
        assert_eq!(error.retry_after_seconds(), Some(MAX_RETRY_AFTER_SECONDS));
        assert_eq!(error.envelope().error.message, "management request failed");
    }
}
