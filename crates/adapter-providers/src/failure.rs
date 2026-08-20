//! Bounded, redaction-safe provider quota and failure classification.

use std::time::Duration;

use http::HeaderMap;
use pooler_core::ErrorClass;
use pooler_policy::{
    CooldownSpec, CredentialCausation, FailureClassification, FailureClassifier, FailureSource,
    ObservedFailure, ProviderFailureClassifier, QuotaObservation, QuotaScope, QuotaSignal,
    QuotaUnit, RedactedEvidence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::ProviderKind;

/// Provider ownership proved by a quota response.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaScope {
    /// Subscription/user account. Multiple keys may share it.
    Account,
    /// Google Cloud project. Multiple credentials may share it.
    Project,
    /// Selected provider model.
    Model,
    /// Shared provider capacity or an unqualified throttle.
    Provider,
}

/// One independently enforced provider quota dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderQuotaWindow {
    unit: QuotaUnit,
    limit: Option<u64>,
    remaining: Option<u64>,
    reset_after: Option<Duration>,
}

impl ProviderQuotaWindow {
    /// Provider-neutral unit retained without collapsing request and token limits.
    #[must_use]
    pub const fn unit(&self) -> QuotaUnit {
        self.unit
    }

    /// Advertised limit for this dimension.
    #[must_use]
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Advertised remaining units for this dimension.
    #[must_use]
    pub const fn remaining(&self) -> Option<u64> {
        self.remaining
    }

    /// Advertised reset for this dimension.
    #[must_use]
    pub const fn reset_after(&self) -> Option<Duration> {
        self.reset_after
    }
}

/// Bounded, redacted quota evidence suitable for policy input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderQuota {
    scope: ProviderQuotaScope,
    code: String,
    retry_after: Option<Duration>,
    windows: Vec<ProviderQuotaWindow>,
    credential_causation: CredentialCausation,
}

impl ProviderQuota {
    /// Provider ownership established by the response.
    #[must_use]
    pub const fn scope(&self) -> ProviderQuotaScope {
        self.scope
    }

    /// Normalized allow-listed provider reason.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Explicit retry delay advertised by the provider, before window resets are considered.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Independently typed quota dimensions.
    #[must_use]
    pub fn windows(&self) -> &[ProviderQuotaWindow] {
        &self.windows
    }

    /// Strictest recovery delay across Retry-After, Google RetryInfo, and every window reset.
    #[must_use]
    pub fn strictest_recovery_after(&self) -> Option<Duration> {
        self.windows
            .iter()
            .filter_map(|window| window.reset_after)
            .chain(self.retry_after)
            .max()
    }

    /// Whether the response proves the selected credential owns this quota.
    #[must_use]
    pub const fn credential_causation(&self) -> CredentialCausation {
        self.credential_causation
    }

    /// Convert every retained dimension into the shared provider-neutral policy DTO.
    #[must_use]
    pub fn to_policy_observations(&self) -> Vec<QuotaObservation> {
        let scope = match self.scope {
            ProviderQuotaScope::Account
                if self.credential_causation == CredentialCausation::Proven =>
            {
                QuotaScope::Credential
            }
            ProviderQuotaScope::Account | ProviderQuotaScope::Project => QuotaScope::Project,
            ProviderQuotaScope::Model => QuotaScope::ProviderModel,
            ProviderQuotaScope::Provider => QuotaScope::Provider,
        };
        let signal = if self.code.contains("rate_limit")
            || self.code.contains("resource_exhausted")
            || self.scope == ProviderQuotaScope::Provider
        {
            QuotaSignal::RateLimited
        } else {
            QuotaSignal::Exhausted
        };
        self.windows
            .iter()
            .copied()
            .map(|window| {
                let mut observation = QuotaObservation::new(signal, scope, window.unit)
                    .with_window(window.limit, window.remaining)
                    .with_provider_code(self.code.clone());
                if let Some(retry_after) = self.retry_after {
                    observation = observation.with_retry_after(retry_after);
                }
                if let Some(reset_after) = window.reset_after {
                    observation = observation.with_reset_after(reset_after);
                }
                observation
            })
            .collect()
    }
}

/// Bounded provider parse errors. Raw bodies are intentionally absent.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProviderParseError {
    #[error("provider response exceeds the {limit}-byte parser bound")]
    BodyTooLarge { limit: usize },
    #[error("provider response is not valid JSON")]
    InvalidJson,
    #[error("provider response has an invalid quota shape")]
    InvalidShape,
    #[error("provider quota response contains too many entries")]
    TooManyEntries,
}

/// Provider-aware response classifier with a hard body bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderResponseClassifier {
    provider: ProviderKind,
    max_body_bytes: usize,
}

impl ProviderResponseClassifier {
    /// Construct with the default 64 KiB body bound.
    #[must_use]
    pub const fn new(provider: ProviderKind) -> Self {
        Self {
            provider,
            max_body_bytes: 64 * 1024,
        }
    }

    /// Construct with an explicit body bound.
    #[must_use]
    pub const fn with_max_body_bytes(provider: ProviderKind, max_body_bytes: usize) -> Self {
        Self {
            provider,
            max_body_bytes,
        }
    }

    /// Parse explicit quota evidence without retaining provider response bytes.
    pub fn parse_quota(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Option<ProviderQuota>, ProviderParseError> {
        let value = self.parse_json(body)?;
        Ok(self.quota_from_value(status, headers, &value))
    }

    /// Parse directly into shared policy observations for runtime quota recovery.
    pub fn parse_policy_observations(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Vec<QuotaObservation>, ProviderParseError> {
        Ok(self
            .parse_quota(status, headers, body)?
            .map_or_else(Vec::new, |quota| quota.to_policy_observations()))
    }

    /// Classify an HTTP response. Malformed and oversized bodies fall back to status-only rules.
    #[must_use]
    pub fn classify_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> FailureClassification {
        let value = self.parse_json(body).ok();
        if let Some(quota) = value
            .as_ref()
            .and_then(|value| self.quota_from_value(status, headers, value))
        {
            return quota_classification(status, quota);
        }

        let provider_code = value.as_ref().and_then(response_code);
        let retry_after = strictest_response_recovery(headers, value.as_ref());
        let observed = ObservedFailure {
            source: FailureSource::Upstream,
            status: Some(status),
            provider_code,
            message: None,
            retry_after,
        };
        self.classify_observed(&observed)
    }

    fn parse_json(&self, body: &[u8]) -> Result<Value, ProviderParseError> {
        if body.len() > self.max_body_bytes {
            return Err(ProviderParseError::BodyTooLarge {
                limit: self.max_body_bytes,
            });
        }
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(body).map_err(|_| ProviderParseError::InvalidJson)
    }

    fn quota_from_value(
        &self,
        status: u16,
        headers: &HeaderMap,
        value: &Value,
    ) -> Option<ProviderQuota> {
        if !matches!(status, 200..=299 | 402 | 429) {
            return None;
        }
        let reason = google_error_reason(value);
        let code = reason.clone().or_else(|| response_code(value));
        let message_hint = response_message_hint(value);
        let marker = code.as_deref().or(message_hint.as_deref());
        let (scope, causation) = quota_scope(self.provider, status, marker).or_else(|| {
            has_zero_rate_header(headers).then_some(match self.provider {
                ProviderKind::Kimi => (ProviderQuotaScope::Account, CredentialCausation::Unknown),
                ProviderKind::Vertex => (ProviderQuotaScope::Project, CredentialCausation::Unknown),
                ProviderKind::Antigravity | ProviderKind::OpenAiCompatible => {
                    (ProviderQuotaScope::Provider, CredentialCausation::Unknown)
                }
            })
        })?;
        let code = code
            .or(message_hint)
            .unwrap_or_else(|| default_quota_code(scope).to_owned());
        let mut windows = rate_header_windows(headers);
        if windows.is_empty() {
            let limit = quota_number(value, "limit");
            let remaining = quota_number(value, "remaining");
            windows.push(ProviderQuotaWindow {
                unit: QuotaUnit::Requests,
                limit,
                remaining,
                reset_after: None,
            });
        }
        Some(ProviderQuota {
            scope,
            code,
            retry_after: [header_retry_after(headers), retry_info_duration(value)]
                .into_iter()
                .flatten()
                .max(),
            windows,
            credential_causation: causation,
        })
    }

    fn classify_observed(&self, failure: &ObservedFailure) -> FailureClassification {
        let code = failure.provider_code.as_deref().unwrap_or_default();
        if matches!(
            self.provider,
            ProviderKind::Vertex | ProviderKind::Antigravity
        ) && code.eq_ignore_ascii_case("resource_exhausted")
        {
            return status_classification(
                ErrorClass::ProviderRateLimited,
                failure.status,
                failure.provider_code.clone(),
                failure.retry_after,
            );
        }
        let mut classified = ProviderFailureClassifier.classify(failure);
        classified.evidence.summary =
            Some(safe_summary(classified.classification.class).to_owned());
        classified
    }
}

impl FailureClassifier for ProviderResponseClassifier {
    fn classify(&self, failure: &ObservedFailure) -> FailureClassification {
        self.classify_observed(failure)
    }
}

fn quota_scope(
    provider: ProviderKind,
    status: u16,
    marker: Option<&str>,
) -> Option<(ProviderQuotaScope, CredentialCausation)> {
    let marker = marker.unwrap_or_default().to_ascii_lowercase();
    if is_request_or_auth_marker(&marker) {
        return None;
    }
    if marker.contains("model_quota")
        || marker.contains("model_limit")
        || marker.contains("model_capacity")
    {
        return Some((ProviderQuotaScope::Model, CredentialCausation::Unknown));
    }
    match provider {
        ProviderKind::Antigravity
            if marker.contains("insufficient_g1_credits_balance")
                || marker.contains("quota_exhausted") =>
        {
            Some((ProviderQuotaScope::Account, CredentialCausation::Proven))
        }
        ProviderKind::Vertex
            if marker.contains("quota_exceeded") || marker.contains("quota_exhausted") =>
        {
            Some((ProviderQuotaScope::Project, CredentialCausation::Unknown))
        }
        ProviderKind::Vertex | ProviderKind::Antigravity
            if marker.contains("resource_exhausted") || marker.contains("rate_limit_exceeded") =>
        {
            Some((ProviderQuotaScope::Provider, CredentialCausation::Unknown))
        }
        ProviderKind::Kimi
            if is_account_quota_marker(&marker)
                || marker.contains("rate_limit")
                || status == 402 =>
        {
            // Kimi documents limits at the user level and shared across keys/models.
            Some((ProviderQuotaScope::Account, CredentialCausation::Unknown))
        }
        ProviderKind::OpenAiCompatible if is_account_quota_marker(&marker) || status == 402 => {
            Some((ProviderQuotaScope::Account, CredentialCausation::Unknown))
        }
        _ if marker.contains("rate_limit")
            || marker.contains("too_many_requests")
            || marker.contains("resource_exhausted")
            || (status == 429 && marker.is_empty()) =>
        {
            Some((ProviderQuotaScope::Provider, CredentialCausation::Unknown))
        }
        _ => None,
    }
}

fn quota_classification(status: u16, quota: ProviderQuota) -> FailureClassification {
    let (class, summary) = match quota.scope {
        ProviderQuotaScope::Account => (
            ErrorClass::CredentialQuotaExhausted,
            "provider account quota is exhausted",
        ),
        ProviderQuotaScope::Project => (
            ErrorClass::CredentialQuotaExhausted,
            "provider project quota is exhausted",
        ),
        ProviderQuotaScope::Model => (
            ErrorClass::ModelQuotaExhausted,
            "provider model quota is exhausted",
        ),
        ProviderQuotaScope::Provider => (
            ErrorClass::ProviderRateLimited,
            "provider capacity is temporarily limited",
        ),
    };
    let recovery = quota
        .strictest_recovery_after()
        .unwrap_or(match quota.scope {
            ProviderQuotaScope::Provider => Duration::from_secs(1),
            ProviderQuotaScope::Account
            | ProviderQuotaScope::Project
            | ProviderQuotaScope::Model => Duration::from_secs(60),
        });
    let mut result = FailureClassification::for_class(class);
    if recovery > Duration::ZERO {
        result = result.with_recovery_after(recovery);
        let cooldown = match quota.scope {
            ProviderQuotaScope::Account
                if quota.credential_causation == CredentialCausation::Proven =>
            {
                Some(CooldownSpec::credential(recovery))
            }
            ProviderQuotaScope::Model => Some(CooldownSpec::model(recovery)),
            ProviderQuotaScope::Provider => Some(CooldownSpec::provider(recovery)),
            ProviderQuotaScope::Account | ProviderQuotaScope::Project => None,
        };
        if let Some(cooldown) = cooldown {
            result = result.with_cooldown(cooldown);
        }
    }
    result.evidence = RedactedEvidence {
        status: Some(status),
        provider_code: Some(quota.code),
        summary: Some(summary.to_owned()),
    };
    result.with_credential_causation(quota.credential_causation)
}

fn status_classification(
    class: ErrorClass,
    status: Option<u16>,
    provider_code: Option<String>,
    retry_after: Option<Duration>,
) -> FailureClassification {
    let mut result = FailureClassification::for_class(class);
    if let Some(delay) = retry_after.filter(|delay| *delay > Duration::ZERO) {
        result = result.with_recovery_after(delay);
        if class == ErrorClass::ProviderRateLimited {
            result = result.with_cooldown(CooldownSpec::provider(delay));
        }
    }
    result.evidence = RedactedEvidence {
        status,
        provider_code,
        summary: Some(safe_summary(class).to_owned()),
    };
    result
}

fn response_code(value: &Value) -> Option<String> {
    let error = value.get("error");
    [
        error.and_then(|value| value.get("code")),
        error.and_then(|value| value.get("type")),
        error.and_then(|value| value.get("status")),
        value.get("code"),
        value.get("type"),
    ]
    .into_iter()
    .flatten()
    .find_map(normalized_value_marker)
}

fn google_error_reason(value: &Value) -> Option<String> {
    let details = value
        .get("error")
        .and_then(|error| error.get("details"))
        .and_then(Value::as_array)?;
    details.iter().take(64).find_map(|detail| {
        let kind = detail.get("@type").and_then(Value::as_str)?;
        if !kind.ends_with("/google.rpc.ErrorInfo") {
            return None;
        }
        detail.get("reason").and_then(normalized_value_marker)
    })
}

fn retry_info_duration(value: &Value) -> Option<Duration> {
    let details = value
        .get("error")
        .and_then(|error| error.get("details"))
        .and_then(Value::as_array)?;
    details.iter().take(64).find_map(|detail| {
        let kind = detail.get("@type").and_then(Value::as_str)?;
        if !kind.ends_with("/google.rpc.RetryInfo") {
            return None;
        }
        parse_json_duration(detail.get("retryDelay")?)
    })
}

fn response_message_hint(value: &Value) -> Option<String> {
    let message = value
        .get("error")
        .and_then(|error| error.get("message"))
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)?;
    if message.len() > 4096 {
        return None;
    }
    let message = message.to_ascii_lowercase();
    [
        "insufficient_g1_credits_balance",
        "model_quota_exhausted",
        "model_capacity_exhausted",
        "quota_exhausted",
        "quota_exceeded",
        "insufficient_quota",
        "usage_limit_reached",
        "rate_limit_exceeded",
        "resource_exhausted",
        "too_many_requests",
        "invalid_request",
        "invalid_api_key",
    ]
    .into_iter()
    .find(|marker| message.contains(marker))
    .map(str::to_owned)
}

fn normalized_value_marker(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => normalized_marker(value),
        Value::Number(value) => normalized_marker(&value.to_string()),
        _ => None,
    }
}

fn normalized_marker(value: &str) -> Option<String> {
    let mut normalized = String::with_capacity(value.len().min(64));
    let mut last_separator = false;
    for character in value.trim().chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() {
            normalized.push(character);
            last_separator = false;
        } else if !last_separator && !normalized.is_empty() {
            normalized.push('_');
            last_separator = true;
        }
        if normalized.len() > 64 {
            return None;
        }
    }
    while normalized.ends_with('_') {
        normalized.pop();
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn is_request_or_auth_marker(marker: &str) -> bool {
    marker.contains("invalid_request")
        || marker.contains("invalid_argument")
        || marker.contains("validation_error")
        || marker.contains("malformed")
        || marker.contains("unauthorized")
        || marker.contains("authentication")
        || marker.contains("invalid_api_key")
}

fn is_account_quota_marker(marker: &str) -> bool {
    marker.contains("insufficient_quota")
        || marker.contains("quota_exceeded")
        || marker.contains("quota_exhausted")
        || marker.contains("usage_limit_reached")
        || marker.contains("plan_limit_reached")
        || marker.contains("credits_exhausted")
        || marker.contains("daily_limit")
        || marker.contains("monthly_limit")
}

const fn default_quota_code(scope: ProviderQuotaScope) -> &'static str {
    match scope {
        ProviderQuotaScope::Account => "account_quota_exhausted",
        ProviderQuotaScope::Project => "project_quota_exhausted",
        ProviderQuotaScope::Model => "model_quota_exhausted",
        ProviderQuotaScope::Provider => "provider_rate_limited",
    }
}

const fn safe_summary(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::DownstreamAuthentication => "downstream authentication failed",
        ErrorClass::InvalidRequest => "provider rejected the request",
        ErrorClass::UnsupportedConversion => "provider conversion is unsupported",
        ErrorClass::ProviderAuthentication => "provider authentication failed",
        ErrorClass::CredentialQuotaExhausted => "provider account quota is exhausted",
        ErrorClass::ModelQuotaExhausted => "provider model quota is exhausted",
        ErrorClass::ProviderRateLimited => "provider capacity is temporarily limited",
        ErrorClass::ProviderUnavailable => "provider is temporarily unavailable",
        ErrorClass::Network => "provider network operation failed",
        ErrorClass::Timeout => "provider operation timed out",
        ErrorClass::InvalidUpstreamResponse => "provider response is invalid",
        ErrorClass::IncompleteStream => "provider stream ended unexpectedly",
        ErrorClass::InternalInvariant => "internal provider invariant failed",
        ErrorClass::DownstreamDisconnected => "downstream disconnected",
    }
}

fn quota_number(value: &Value, field: &str) -> Option<u64> {
    value
        .get(field)
        .or_else(|| value.get("quota").and_then(|quota| quota.get(field)))
        .or_else(|| value.get("error").and_then(|error| error.get(field)))
        .and_then(json_u64)
}

fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
}

fn header_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_provider_duration)
}

fn strictest_response_recovery(headers: &HeaderMap, value: Option<&Value>) -> Option<Duration> {
    header_retry_after(headers)
        .into_iter()
        .chain(value.and_then(retry_info_duration))
        .chain(
            rate_header_windows(headers)
                .into_iter()
                .filter_map(|window| window.reset_after),
        )
        .max()
}

fn rate_header_windows(headers: &HeaderMap) -> Vec<ProviderQuotaWindow> {
    [
        ("requests", QuotaUnit::Requests),
        ("tokens", QuotaUnit::Tokens),
    ]
    .into_iter()
    .filter_map(|(dimension, unit)| {
        let limit = rate_dimension_number(headers, "limit", dimension);
        let remaining = rate_dimension_number(headers, "remaining", dimension);
        let reset_header = format!("x-ratelimit-reset-{dimension}");
        let reset_after = headers
            .get(reset_header.as_str())
            .and_then(|value| value.to_str().ok())
            .and_then(parse_provider_duration);
        (limit.is_some() || remaining.is_some() || reset_after.is_some()).then_some(
            ProviderQuotaWindow {
                unit,
                limit,
                remaining,
                reset_after,
            },
        )
    })
    .collect()
}

fn rate_dimension_number(headers: &HeaderMap, field: &str, dimension: &str) -> Option<u64> {
    let name = format!("x-ratelimit-{field}-{dimension}");
    headers
        .get(name.as_str())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn has_zero_rate_header(headers: &HeaderMap) -> bool {
    rate_header_windows(headers)
        .iter()
        .any(|window| window.remaining == Some(0))
}

fn parse_json_duration(value: &Value) -> Option<Duration> {
    if let Some(value) = value.as_str() {
        return parse_provider_duration(value);
    }
    let object = value.as_object()?;
    let seconds = object.get("seconds").and_then(json_u64).unwrap_or(0);
    let nanos = object
        .get("nanos")
        .and_then(json_u64)
        .unwrap_or(0)
        .min(999_999_999);
    bounded_duration(seconds, u32::try_from(nanos).ok()?)
}

fn parse_provider_duration(value: &str) -> Option<Duration> {
    let value = value.trim().to_ascii_lowercase();
    if let Ok(seconds) = value.parse::<u64>() {
        return bounded_duration(seconds, 0);
    }
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let mut remaining = value.as_str();
    let mut total_seconds = 0.0f64;
    while !remaining.is_empty() {
        let unit_start =
            remaining.find(|character: char| !character.is_ascii_digit() && character != '.')?;
        if unit_start == 0 {
            return None;
        }
        let amount = remaining[..unit_start].parse::<f64>().ok()?;
        let (unit, rest) = if remaining[unit_start..].starts_with("ms") {
            ("ms", &remaining[unit_start + 2..])
        } else {
            (
                &remaining[unit_start..unit_start + 1],
                &remaining[unit_start + 1..],
            )
        };
        let multiplier = match unit {
            "ms" => 0.001,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        total_seconds = amount.mul_add(multiplier, total_seconds);
        if !total_seconds.is_finite()
            || total_seconds.is_sign_negative()
            || total_seconds > MAX_DELAY_SECONDS as f64
        {
            return None;
        }
        remaining = rest;
    }
    Duration::try_from_secs_f64(total_seconds).ok()
}

const MAX_DELAY_SECONDS: u64 = 7 * 24 * 60 * 60;

fn bounded_duration(seconds: u64, nanos: u32) -> Option<Duration> {
    (seconds <= MAX_DELAY_SECONDS).then(|| Duration::new(seconds, nanos))
}

/// One Antigravity paid-tier credit entry from the pinned compatibility response.
#[derive(Clone, Debug, PartialEq)]
pub struct AntigravityCredits {
    paid_tier_id: Option<String>,
    credit_type: String,
    credit_amount: f64,
    minimum_credit_amount: f64,
}

impl AntigravityCredits {
    /// Paid tier identifier, when the provider supplied one.
    #[must_use]
    pub fn paid_tier_id(&self) -> Option<&str> {
        self.paid_tier_id.as_deref()
    }

    /// Compatibility credit type, currently `GOOGLE_ONE_AI` in the pinned evidence.
    #[must_use]
    pub fn credit_type(&self) -> &str {
        &self.credit_type
    }

    /// Current credit balance.
    #[must_use]
    pub const fn credit_amount(&self) -> f64 {
        self.credit_amount
    }

    /// Minimum balance required for a request.
    #[must_use]
    pub const fn minimum_credit_amount(&self) -> f64 {
        self.minimum_credit_amount
    }

    /// Whether the current balance meets the provider-advertised minimum.
    #[must_use]
    pub fn available(&self) -> bool {
        self.credit_amount >= self.minimum_credit_amount
    }

    /// Convert the actionable credit state into the shared policy DTO.
    ///
    /// Provider decimal amounts are deliberately not rounded into integer
    /// policy counters; `remaining` is a typed availability bit (one or zero).
    #[must_use]
    pub fn to_policy_observation(&self) -> QuotaObservation {
        let available = self.available();
        QuotaObservation::new(
            if available {
                QuotaSignal::Snapshot
            } else {
                QuotaSignal::Exhausted
            },
            QuotaScope::Credential,
            QuotaUnit::Credits,
        )
        .with_window(Some(1), Some(u64::from(available)))
        .with_provider_code("antigravity_google_one_ai_credits")
    }
}

/// Bounded parser for Antigravity's pinned `paidTier.availableCredits` shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AntigravityCreditParser {
    max_body_bytes: usize,
    max_entries: usize,
}

impl Default for AntigravityCreditParser {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            max_entries: 64,
        }
    }
}

impl AntigravityCreditParser {
    /// Construct with explicit body and entry-count bounds.
    #[must_use]
    pub const fn new(max_body_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_body_bytes,
            max_entries,
        }
    }

    /// Parse the first `GOOGLE_ONE_AI` entry, if present.
    pub fn parse(&self, body: &[u8]) -> Result<Option<AntigravityCredits>, ProviderParseError> {
        if body.len() > self.max_body_bytes {
            return Err(ProviderParseError::BodyTooLarge {
                limit: self.max_body_bytes,
            });
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| ProviderParseError::InvalidJson)?;
        let Some(credits) = value
            .get("paidTier")
            .and_then(|tier| tier.get("availableCredits"))
        else {
            return Ok(None);
        };
        let credits = credits.as_array().ok_or(ProviderParseError::InvalidShape)?;
        if credits.len() > self.max_entries {
            return Err(ProviderParseError::TooManyEntries);
        }
        let paid_tier_id = value
            .get("paidTier")
            .and_then(|tier| tier.get("id"))
            .and_then(Value::as_str)
            .and_then(bounded_credit_label)
            .map(str::to_owned);
        for credit in credits {
            let credit_type = credit
                .get("creditType")
                .and_then(Value::as_str)
                .and_then(bounded_credit_label);
            if !credit_type.is_some_and(|value| value.eq_ignore_ascii_case("GOOGLE_ONE_AI")) {
                continue;
            }
            let credit_amount = credit
                .get("creditAmount")
                .and_then(json_nonnegative_f64)
                .ok_or(ProviderParseError::InvalidShape)?;
            let minimum_credit_amount = credit
                .get("minimumCreditAmountForUsage")
                .and_then(json_nonnegative_f64)
                .ok_or(ProviderParseError::InvalidShape)?;
            return Ok(Some(AntigravityCredits {
                paid_tier_id,
                credit_type: "GOOGLE_ONE_AI".to_owned(),
                credit_amount,
                minimum_credit_amount,
            }));
        }
        Ok(None)
    }
}

fn bounded_credit_label(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')))
    .then_some(value)
}

fn json_nonnegative_f64(value: &Value) -> Option<f64> {
    let value = value
        .as_f64()
        .or_else(|| value.as_str()?.trim().parse::<f64>().ok())?;
    (value.is_finite() && !value.is_sign_negative()).then_some(value)
}
