#![forbid(unsafe_code)]
#![doc = "Structured observability primitives for Pooler.\n\nThe types in this crate deliberately keep credentials out of the public data\nmodel. Values that originate in an untrusted request should still be passed\nthrough [`RedactionPolicy`] before they are recorded."]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const REDACTED: &str = "[REDACTED]";
const DEPTH_LIMIT: &str = "[REDACTED:DEPTH_LIMIT]";
const TRUNCATED: &str = "…[TRUNCATED]";

const DEFAULT_ALLOWED_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-length",
    "content-type",
    "host",
    "traceparent",
    "tracestate",
    "user-agent",
    "x-request-id",
];

// These markers are intentionally conservative. A marker is only treated as
// a key when it has a non-identifier boundary on both sides, so a harmless
// word such as "authentication" is not accidentally treated as a secret.
const SENSITIVE_MARKERS: &[&str] = &[
    "access_token",
    "access-token",
    "api_key",
    "api-key",
    "apikey",
    "authorization",
    "bearer",
    "basic",
    "client_secret",
    "client-secret",
    "connection_string",
    "connection-string",
    "cookie",
    "credential",
    "credentials",
    "id_token",
    "id-token",
    "password",
    "passphrase",
    "private_key",
    "private-key",
    "proxy_authorization",
    "proxy-authorization",
    "refresh_token",
    "refresh-token",
    "refresh",
    "secret",
    "session_token",
    "session-token",
    "set_cookie",
    "set-cookie",
    "signing_key",
    "signing-key",
    "token",
    "webhook_secret",
    "webhook-secret",
    "x_api_key",
    "x-api-key",
];

const KNOWN_TOKEN_PREFIXES: &[&str] = &[
    "AKIA",
    "ASIA",
    "AIza",
    "gho_",
    "ghp_",
    "github_pat_",
    "glpat-",
    "hf_",
    "npm_",
    "pypi-",
    "r8_",
    "sk-",
    "xapp-",
    "xoxb-",
    "xoxp-",
];

/// The value emitted when a field is not safe to include in an observation.
pub const REDACTED_VALUE: &str = REDACTED;

fn default_allowed_headers() -> BTreeSet<String> {
    DEFAULT_ALLOWED_HEADERS
        .iter()
        .map(|header| (*header).to_owned())
        .collect()
}

fn default_sensitive_keys() -> BTreeSet<String> {
    SENSITIVE_MARKERS
        .iter()
        .filter(|marker| **marker != "bearer" && **marker != "basic")
        .map(|marker| marker.replace('-', "_"))
        .collect()
}

fn default_max_string_length() -> usize {
    16 * 1024
}

fn default_max_depth() -> usize {
    64
}

/// Policy used to remove credentials and other secret material from logs,
/// audit records, diagnostics, and captured JSON.
///
/// Header handling is an allowlist by default: only the small set of headers
/// useful for diagnosis are retained. Call [`RedactionPolicy::allow_header`]
/// for a route-specific, non-sensitive header that is safe to record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionPolicy {
    /// Case-insensitive JSON/object keys that always have their value
    /// replaced. Hyphens and underscores are treated equivalently.
    #[serde(default = "default_sensitive_keys")]
    pub sensitive_keys: BTreeSet<String>,
    /// Case-insensitive headers whose values may be retained after pattern
    /// sanitization.
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: BTreeSet<String>,
    /// Permit headers outside `allowed_headers`. Sensitive header names still
    /// win and are always redacted.
    #[serde(default)]
    pub allow_unknown_headers: bool,
    /// Replacement text used for secret values.
    #[serde(default = "default_placeholder")]
    pub placeholder: String,
    /// Maximum length of a retained string. Secret scanning occurs before this
    /// limit is applied.
    #[serde(default = "default_max_string_length")]
    pub max_string_length: usize,
    /// Maximum recursion depth for JSON values.
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
}

fn default_placeholder() -> String {
    REDACTED.to_owned()
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            sensitive_keys: default_sensitive_keys(),
            allowed_headers: default_allowed_headers(),
            allow_unknown_headers: false,
            placeholder: default_placeholder(),
            max_string_length: default_max_string_length(),
            max_depth: default_max_depth(),
        }
    }
}

impl RedactionPolicy {
    /// Construct the strict built-in policy.
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Add a safe, non-sensitive header to the logging allowlist.
    #[must_use]
    pub fn allow_header(mut self, name: impl AsRef<str>) -> Self {
        self.allowed_headers
            .insert(normalize_header_name(name.as_ref()));
        self
    }

    /// Add a JSON key to the sensitive-key set.
    #[must_use]
    pub fn redact_key(mut self, name: impl AsRef<str>) -> Self {
        self.sensitive_keys.insert(normalize_key(name.as_ref()));
        self
    }

    /// Explicitly allow all non-sensitive header names. This is intended for
    /// controlled development diagnostics, not a production default.
    #[must_use]
    pub fn allow_all_headers(mut self) -> Self {
        self.allow_unknown_headers = true;
        self
    }

    /// Set the replacement text used for secret values.
    #[must_use]
    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = placeholder.into();
        self
    }

    /// Set the maximum retained string length. A value of zero disables
    /// truncation while retaining secret scanning.
    #[must_use]
    pub fn with_max_string_length(mut self, max_string_length: usize) -> Self {
        self.max_string_length = max_string_length;
        self
    }

    /// Set the maximum JSON recursion depth.
    #[must_use]
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Return whether an object key should have its value replaced.
    #[must_use]
    pub fn is_sensitive_key(&self, key: &str) -> bool {
        let normalized = normalize_key(key);
        self.sensitive_keys.contains(&normalized) || matches_sensitive_key(&normalized)
    }

    /// Return whether a header name is always sensitive.
    #[must_use]
    pub fn is_sensitive_header(&self, name: &str) -> bool {
        let normalized = normalize_header_name(name);
        matches_sensitive_key(&normalized.replace('-', "_"))
            || matches!(
                normalized.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "set-cookie"
                    | "x-api-key"
                    | "x-auth-token"
                    | "x-access-token"
                    | "x-refresh-token"
            )
            || normalized.ends_with("-token")
            || normalized.ends_with("-secret")
            || normalized.ends_with("-credential")
    }

    /// Return whether a non-sensitive header is present in the allowlist.
    #[must_use]
    pub fn is_allowed_header(&self, name: &str) -> bool {
        self.allow_unknown_headers || self.allowed_headers.contains(&normalize_header_name(name))
    }

    /// Sanitize a JSON value recursively, replacing sensitive object fields
    /// and secret-looking strings while preserving numbers, booleans, arrays,
    /// and non-sensitive structure.
    #[must_use]
    pub fn sanitize_json(&self, value: &Value) -> Value {
        self.sanitize_json_value(value)
    }

    /// Alias for [`RedactionPolicy::sanitize_json`].
    #[must_use]
    pub fn sanitize_json_value(&self, value: &Value) -> Value {
        self.sanitize_json_at_depth(value, 0)
    }

    fn sanitize_json_at_depth(&self, value: &Value, depth: usize) -> Value {
        if depth > self.max_depth {
            return Value::String(DEPTH_LIMIT.to_owned());
        }

        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
            Value::String(text) => Value::String(self.sanitize_text(text)),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| self.sanitize_json_at_depth(value, depth + 1))
                    .collect(),
            ),
            Value::Object(object) => {
                let mut sanitized = Map::with_capacity(object.len());
                for (key, value) in object {
                    let sanitized_key = self.sanitize_text(key);
                    if self.is_sensitive_key(key) {
                        sanitized.insert(sanitized_key, Value::String(self.placeholder.clone()));
                    } else {
                        sanitized
                            .insert(sanitized_key, self.sanitize_json_at_depth(value, depth + 1));
                    }
                }
                Value::Object(sanitized)
            }
        }
    }

    /// Sanitize free-form text. This catches common authorization schemes,
    /// key/value forms, JWTs, and well-known provider key prefixes. Arbitrary
    /// values should still be represented as JSON and passed to
    /// [`RedactionPolicy::sanitize_json`] where key context is available.
    #[must_use]
    pub fn sanitize_text(&self, text: &str) -> String {
        let ranges = sensitive_ranges(text);
        let mut sanitized = replace_ranges(text, &ranges, &self.placeholder);

        if self.max_string_length > 0 && sanitized.chars().count() > self.max_string_length {
            sanitized = sanitized.chars().take(self.max_string_length).collect();
            sanitized.push_str(TRUNCATED);
        }
        sanitized
    }

    /// Sanitize one HTTP header map. The result is sorted and lower-case so it
    /// can be serialized deterministically. Duplicate values are joined with
    /// `, `, matching HTTP's list representation for diagnostic purposes.
    #[must_use]
    pub fn sanitize_headers(&self, headers: &HeaderMap) -> SanitizedHeaders {
        let mut sanitized = SanitizedHeaders::new();
        for (name, value) in headers {
            let name = normalize_header_name(name.as_str());
            let value = if self.is_sensitive_header(&name) || !self.is_allowed_header(&name) {
                self.placeholder.clone()
            } else {
                value.to_str().map_or_else(
                    |_| self.placeholder.clone(),
                    |value| self.sanitize_text(value),
                )
            };

            match sanitized.get_mut(&name) {
                Some(existing) if existing == &self.placeholder || value == self.placeholder => {
                    *existing = self.placeholder.clone();
                }
                Some(existing) => {
                    existing.push_str(", ");
                    existing.push_str(&value);
                }
                None => {
                    sanitized.insert(name, value);
                }
            }
        }
        sanitized
    }

    /// Alias for [`RedactionPolicy::sanitize_headers`].
    #[must_use]
    pub fn sanitize_header_map(&self, headers: &HeaderMap) -> SanitizedHeaders {
        self.sanitize_headers(headers)
    }

    /// Preserve duplicate header entries while applying the same policy as
    /// [`RedactionPolicy::sanitize_headers`].
    #[must_use]
    pub fn sanitize_header_entries(&self, headers: &HeaderMap) -> Vec<SanitizedHeader> {
        headers
            .iter()
            .map(|(name, value)| {
                let name = normalize_header_name(name.as_str());
                let value = if self.is_sensitive_header(&name) || !self.is_allowed_header(&name) {
                    self.placeholder.clone()
                } else {
                    value.to_str().map_or_else(
                        |_| self.placeholder.clone(),
                        |value| self.sanitize_text(value),
                    )
                };
                SanitizedHeader { name, value }
            })
            .collect()
    }
}

/// A deterministic, sanitized representation of a header entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SanitizedHeader {
    pub name: String,
    pub value: String,
}

/// A deterministic, sanitized representation of HTTP headers.
pub type SanitizedHeaders = BTreeMap<String, String>;

/// Sanitize an HTTP header map using [`RedactionPolicy::default`].
#[must_use]
pub fn sanitize_headers(headers: &HeaderMap) -> SanitizedHeaders {
    RedactionPolicy::default().sanitize_headers(headers)
}

/// Sanitize a JSON value using [`RedactionPolicy::default`].
#[must_use]
pub fn sanitize_json(value: &Value) -> Value {
    RedactionPolicy::default().sanitize_json(value)
}

/// Sanitize free-form text using [`RedactionPolicy::default`].
#[must_use]
pub fn sanitize_text(text: &str) -> String {
    RedactionPolicy::default().sanitize_text(text)
}

fn normalize_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    let mut previous_was_lower_or_digit = false;

    for character in key.trim().chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() && previous_was_lower_or_digit {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit =
                character.is_ascii_lowercase() || character.is_ascii_digit();
        } else {
            if !normalized.ends_with('_') {
                normalized.push('_');
            }
            previous_was_lower_or_digit = false;
        }
    }

    normalized.trim_matches('_').to_owned()
}

fn normalize_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

fn matches_sensitive_key(normalized: &str) -> bool {
    let normalized = normalized.replace('-', "_");
    SENSITIVE_MARKERS.iter().any(|marker| {
        let marker = marker.replace('-', "_");
        normalized == marker || normalized.ends_with(&format!("_{marker}"))
    })
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'.' | b'_' | b'-' | b'/' | b'+' | b'=' | b'~' | b':')
}

fn marker_is_auth_scheme(marker: &str) -> bool {
    marker == "bearer" || marker == "basic"
}

fn sensitive_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = marked_value_ranges(text);
    ranges.extend(known_prefix_ranges(text));
    ranges.extend(jwt_ranges(text));
    ranges.sort_unstable_by_key(|(start, end)| (*start, *end));

    let mut merged = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if start >= end {
            continue;
        }
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn marked_value_ranges(text: &str) -> Vec<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut ranges = Vec::new();

    for marker in SENSITIVE_MARKERS {
        let mut search_from = 0;
        while search_from < bytes.len() {
            let Some(relative) = lower[search_from..].find(marker) else {
                break;
            };
            let marker_start = search_from + relative;
            let marker_end = marker_start + marker.len();
            search_from = marker_end;

            let follows_assignment = value_separator(bytes, marker_end)
                .is_some_and(|separator| matches!(separator, b':' | b'='));
            if marker_start > 0
                && is_identifier_byte(bytes[marker_start - 1])
                && !follows_assignment
            {
                continue;
            }
            if marker_end < bytes.len() && is_identifier_byte(bytes[marker_end]) {
                continue;
            }

            let mut cursor = marker_end;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            let is_auth_scheme = marker_is_auth_scheme(marker);
            if cursor >= bytes.len() {
                continue;
            }
            if matches!(bytes.get(cursor), Some(b':' | b'=')) {
                cursor += 1;
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
            } else if !is_auth_scheme {
                continue;
            }

            if cursor >= bytes.len() {
                continue;
            }
            let (start, end) = if matches!(bytes[cursor], b'\'' | b'"') {
                let quote = bytes[cursor];
                let start = cursor + 1;
                let mut end = start;
                while end < bytes.len() {
                    if bytes[end] == quote && (end == start || bytes[end - 1] != b'\\') {
                        break;
                    }
                    end += 1;
                }
                (start, end.min(bytes.len()))
            } else {
                let start = cursor;
                let mut end = start;
                while end < bytes.len()
                    && !bytes[end].is_ascii_whitespace()
                    && !matches!(bytes[end], b',' | b';' | b'}' | b']' | b'&')
                {
                    end += 1;
                }
                (start, end)
            };
            if start < end {
                ranges.push((start, end));
            }
        }
    }

    ranges
}

fn value_separator(bytes: &[u8], mut cursor: usize) -> Option<u8> {
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    bytes.get(cursor).copied()
}

fn known_prefix_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for prefix in KNOWN_TOKEN_PREFIXES {
        let mut search_from = 0;
        while search_from < text.len() {
            let Some(relative) = text[search_from..].find(prefix) else {
                break;
            };
            let start = search_from + relative;
            search_from = start + prefix.len();
            if start > 0 && is_identifier_byte(text.as_bytes()[start - 1]) {
                continue;
            }
            let mut end = start + prefix.len();
            while end < text.len() && is_token_byte(text.as_bytes()[end]) {
                end += 1;
            }
            if end.saturating_sub(start) >= prefix.len() + 6 {
                ranges.push((start, end));
            }
        }
    }
    ranges
}

fn jwt_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut search_from = 0;
    while search_from + 3 <= text.len() {
        let Some(relative) = text[search_from..].find("eyJ") else {
            break;
        };
        let start = search_from + relative;
        search_from = start + 3;
        if start > 0 && is_identifier_byte(text.as_bytes()[start - 1]) {
            continue;
        }
        let mut end = start;
        let mut dots = 0;
        while end < text.len() && is_token_byte(text.as_bytes()[end]) {
            if text.as_bytes()[end] == b'.' {
                dots += 1;
            }
            end += 1;
        }
        if dots >= 2 && end.saturating_sub(start) >= 20 {
            ranges.push((start, end));
        }
    }
    ranges
}

fn replace_ranges(text: &str, ranges: &[(usize, usize)], replacement: &str) -> String {
    if ranges.is_empty() {
        return text.to_owned();
    }

    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    for &(start, end) in ranges {
        if start > cursor {
            result.push_str(&text[cursor..start]);
        }
        result.push_str(replacement);
        cursor = end.max(cursor);
    }
    result.push_str(&text[cursor..]);
    result
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

/// Why a candidate was or was not selected.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CandidateRecord {
    pub provider: String,
    #[serde(default)]
    pub credential_pseudonym: Option<String>,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub eligible: bool,
    #[serde(default)]
    pub filter_reasons: Vec<String>,
}

/// Session-affinity information attached to a selection decision. The key is
/// represented by a pseudonym/hash; raw prompt or session content is never a
/// field in this type.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AffinityDecision {
    #[serde(default)]
    pub key_pseudonym: Option<String>,
    #[serde(default)]
    pub previous_provider: Option<String>,
    #[serde(default)]
    pub selected_provider: Option<String>,
    #[serde(default)]
    pub rebound: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Token usage attached to a completed request, when the upstream supplied
/// usage accounting.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub output_tokens: Option<u64>,
    #[serde(default)]
    pub total_tokens: Option<u64>,
}

/// Normalized result class for a request or attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionClass {
    Success,
    DownstreamError,
    InvalidRequest,
    Unsupported,
    UpstreamError,
    IncompleteStream,
    Cancelled,
    InternalError,
    Unknown,
}

impl Default for CompletionClass {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for CompletionClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Success => "success",
            Self::DownstreamError => "downstream_error",
            Self::InvalidRequest => "invalid_request",
            Self::Unsupported => "unsupported",
            Self::UpstreamError => "upstream_error",
            Self::IncompleteStream => "incomplete_stream",
            Self::Cancelled => "cancelled",
            Self::InternalError => "internal_error",
            Self::Unknown => "unknown",
        };
        formatter.write_str(value)
    }
}

/// Explainable provider/credential selection record.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct DecisionRecord {
    pub timestamp_ms: u64,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub listener: Option<String>,
    pub route: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub credential_pseudonym: Option<String>,
    pub attempt: u32,
    pub retry_reason: Option<String>,
    pub time_to_headers_ms: Option<u64>,
    pub time_to_first_event_ms: Option<u64>,
    pub completion_class: Option<CompletionClass>,
    pub usage: Option<Usage>,
    pub candidates: Vec<CandidateRecord>,
    pub selected_provider: Option<String>,
    pub selected_model: Option<String>,
    pub model_alias: Option<String>,
    pub affinity: Option<AffinityDecision>,
    pub config_generation: Option<u64>,
    pub outcome: Option<String>,
    pub evidence: BTreeMap<String, Value>,
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct DecisionRecordWire<'a> {
    timestamp_ms: u64,
    request_id: &'a Option<String>,
    trace_id: &'a Option<String>,
    listener: &'a Option<String>,
    route: &'a Option<String>,
    model: &'a Option<String>,
    provider: &'a Option<String>,
    credential_pseudonym: &'a Option<String>,
    attempt: u32,
    retry_reason: &'a Option<String>,
    time_to_headers_ms: &'a Option<u64>,
    time_to_first_event_ms: &'a Option<u64>,
    completion_class: &'a Option<CompletionClass>,
    usage: &'a Option<Usage>,
    candidates: &'a [CandidateRecord],
    selected_provider: &'a Option<String>,
    selected_model: &'a Option<String>,
    model_alias: &'a Option<String>,
    affinity: &'a Option<AffinityDecision>,
    config_generation: &'a Option<u64>,
    outcome: &'a Option<String>,
    evidence: &'a BTreeMap<String, Value>,
    attributes: &'a BTreeMap<String, Value>,
}

impl DecisionRecord {
    /// Start a decision record with request and trace identifiers.
    #[must_use]
    pub fn new(request_id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            timestamp_ms: now_unix_millis(),
            request_id: Some(request_id.into()),
            trace_id: Some(trace_id.into()),
            ..Self::default()
        }
    }

    /// Start a builder with a strict redaction policy for evidence and
    /// attributes.
    #[must_use]
    pub fn builder() -> DecisionRecordBuilder {
        DecisionRecordBuilder::default()
    }

    /// Return a policy-specific sanitized JSON representation.
    #[must_use]
    pub fn sanitized_json(&self, policy: &RedactionPolicy) -> Value {
        policy.sanitize_json(&self.raw_json())
    }

    /// Alias for [`DecisionRecord::sanitized_json`].
    #[must_use]
    pub fn redacted_json(&self, policy: &RedactionPolicy) -> Value {
        self.sanitized_json(policy)
    }

    /// Record sanitized evidence without requiring callers to construct a
    /// separate JSON object first.
    pub fn add_evidence(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let policy = RedactionPolicy::default();
        self.evidence
            .insert(key.into(), policy.sanitize_json(&value.into()));
    }

    /// Record sanitized auxiliary attributes.
    pub fn add_attribute(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let policy = RedactionPolicy::default();
        self.attributes
            .insert(key.into(), policy.sanitize_json(&value.into()));
    }

    fn raw_json(&self) -> Value {
        serde_json::to_value(DecisionRecordWire {
            timestamp_ms: self.timestamp_ms,
            request_id: &self.request_id,
            trace_id: &self.trace_id,
            listener: &self.listener,
            route: &self.route,
            model: &self.model,
            provider: &self.provider,
            credential_pseudonym: &self.credential_pseudonym,
            attempt: self.attempt,
            retry_reason: &self.retry_reason,
            time_to_headers_ms: &self.time_to_headers_ms,
            time_to_first_event_ms: &self.time_to_first_event_ms,
            completion_class: &self.completion_class,
            usage: &self.usage,
            candidates: &self.candidates,
            selected_provider: &self.selected_provider,
            selected_model: &self.selected_model,
            model_alias: &self.model_alias,
            affinity: &self.affinity,
            config_generation: &self.config_generation,
            outcome: &self.outcome,
            evidence: &self.evidence,
            attributes: &self.attributes,
        })
        .unwrap_or(Value::Null)
    }
}

impl From<&pooler_policy::SelectionExplanation> for DecisionRecord {
    fn from(selection: &pooler_policy::SelectionExplanation) -> Self {
        let mut record = DecisionRecord::builder()
            .model(selection.model_alias_resolution.requested.to_string())
            .attempt(selection.attempt)
            .config_generation(selection.configuration_generation.value());
        if let Some(selected) = &selection.selected {
            record = record
                .provider(selected.provider.to_string())
                .selected_provider(selected.provider.to_string())
                .selected_model(selected.model.to_string())
                .credential_pseudonym(selected.credential_pseudonym.as_str().to_owned());
        }
        if selection.model_alias_resolution.alias_used {
            record = record.model_alias(selection.model_alias_resolution.resolved.to_string());
        }
        for candidate in &selection.candidates {
            record = record.candidate(CandidateRecord {
                provider: candidate.target.provider.to_string(),
                credential_pseudonym: Some(
                    candidate.target.credential_pseudonym.as_str().to_owned(),
                ),
                score: candidate.score,
                eligible: candidate.is_eligible(),
                filter_reasons: candidate
                    .filter_reasons
                    .iter()
                    .map(observe_filter_reason)
                    .collect(),
            });
        }
        if let Some(affinity) = observe_affinity(&selection.affinity) {
            record = record.affinity(affinity);
        }
        record.build()
    }
}

impl From<&pooler_store::DecisionRecord> for DecisionRecord {
    fn from(stored: &pooler_store::DecisionRecord) -> Self {
        let mut record = DecisionRecord::builder()
            .request_id(stored.request_id.clone())
            .route(stored.route_id.clone())
            .model(stored.model.clone())
            .attempt(stored.attempt)
            .config_generation(stored.configuration_generation)
            .outcome(
                stored
                    .reason
                    .clone()
                    .unwrap_or_else(|| "selected".to_owned()),
            );
        record.record.timestamp_ms = stored.recorded_at;
        if let Some(provider) = &stored.selected_provider {
            record = record
                .provider(provider.clone())
                .selected_provider(provider.clone());
        }
        if let Some(credential) = &stored.selected_credential {
            record = record.credential_pseudonym(credential.clone());
        }
        if let Some(model) = &stored.upstream_model {
            record = record.selected_model(model.clone());
        }
        for candidate in &stored.candidates {
            record = record.candidate(CandidateRecord {
                provider: candidate.provider_id.clone(),
                credential_pseudonym: candidate.credential_id.clone(),
                score: Some(f64::from(candidate.score as i32)),
                eligible: candidate.eligible,
                filter_reasons: candidate.reason.clone().into_iter().collect(),
            });
        }
        record.build()
    }
}

fn observe_filter_reason(reason: &pooler_policy::FilterReason) -> String {
    match reason {
        pooler_policy::FilterReason::ModelMismatch => "model_mismatch".to_owned(),
        pooler_policy::FilterReason::MissingCapability(value) => {
            format!("missing_capability:{value}")
        }
        pooler_policy::FilterReason::CodecUnavailable(value) => {
            format!("codec_unavailable:{value}")
        }
        pooler_policy::FilterReason::CredentialUnavailable => "credential_unavailable".to_owned(),
        pooler_policy::FilterReason::CredentialCooldown => "credential_cooldown".to_owned(),
        pooler_policy::FilterReason::CredentialModelCooldown => {
            "credential_model_cooldown".to_owned()
        }
        pooler_policy::FilterReason::ModelCooldown => "model_cooldown".to_owned(),
        pooler_policy::FilterReason::ProviderCooldown => "provider_cooldown".to_owned(),
        pooler_policy::FilterReason::ProviderModelCooldown => "provider_model_cooldown".to_owned(),
        pooler_policy::FilterReason::RouteCooldown => "route_cooldown".to_owned(),
        pooler_policy::FilterReason::ConcurrencyLimit => "concurrency_limit".to_owned(),
        pooler_policy::FilterReason::RoutePolicy => "route_policy".to_owned(),
        pooler_policy::FilterReason::SessionAffinity => "session_affinity".to_owned(),
        pooler_policy::FilterReason::LossPolicy => "loss_policy".to_owned(),
        pooler_policy::FilterReason::QuotaExhausted => "quota_exhausted".to_owned(),
        pooler_policy::FilterReason::Disabled => "disabled".to_owned(),
    }
}

fn observe_affinity(affinity: &pooler_policy::AffinityDecision) -> Option<AffinityDecision> {
    match affinity {
        pooler_policy::AffinityDecision::NotRequested => None,
        pooler_policy::AffinityDecision::NoMatch { key_pseudonym } => Some(AffinityDecision {
            key_pseudonym: Some(key_pseudonym.clone()),
            reason: Some("no_match".to_owned()),
            ..AffinityDecision::default()
        }),
        pooler_policy::AffinityDecision::Matched {
            key_pseudonym,
            target,
        } => Some(AffinityDecision {
            key_pseudonym: Some(key_pseudonym.clone()),
            selected_provider: Some(target.provider.to_string()),
            reason: Some("matched".to_owned()),
            ..AffinityDecision::default()
        }),
        pooler_policy::AffinityDecision::Rebound {
            key_pseudonym,
            previous_provider,
            target,
        } => Some(AffinityDecision {
            key_pseudonym: Some(key_pseudonym.clone()),
            previous_provider: Some(previous_provider.to_string()),
            selected_provider: Some(target.provider.to_string()),
            rebound: true,
            reason: Some("rebound".to_owned()),
        }),
        pooler_policy::AffinityDecision::Unavailable {
            key_pseudonym,
            target,
        } => Some(AffinityDecision {
            key_pseudonym: Some(key_pseudonym.clone()),
            selected_provider: Some(target.provider.to_string()),
            reason: Some("unavailable".to_owned()),
            ..AffinityDecision::default()
        }),
    }
}

impl Serialize for DecisionRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.sanitized_json(&RedactionPolicy::default())
            .serialize(serializer)
    }
}

/// Builder for [`DecisionRecord`]. Evidence and attributes are sanitized as
/// they are inserted, and the record is sanitized again on serialization.
#[derive(Clone, Debug, Default)]
pub struct DecisionRecordBuilder {
    record: DecisionRecord,
    policy: RedactionPolicy,
}

impl DecisionRecordBuilder {
    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.record.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.record.trace_id = Some(trace_id.into());
        self
    }

    #[must_use]
    pub fn listener(mut self, listener: impl Into<String>) -> Self {
        self.record.listener = Some(listener.into());
        self
    }

    #[must_use]
    pub fn route(mut self, route: impl Into<String>) -> Self {
        self.record.route = Some(route.into());
        self
    }

    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.record.model = Some(model.into());
        self
    }

    #[must_use]
    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.record.provider = Some(provider.into());
        self
    }

    #[must_use]
    pub fn credential_pseudonym(mut self, credential: impl Into<String>) -> Self {
        self.record.credential_pseudonym = Some(credential.into());
        self
    }

    #[must_use]
    pub fn attempt(mut self, attempt: u32) -> Self {
        self.record.attempt = attempt;
        self
    }

    #[must_use]
    pub fn retry_reason(mut self, reason: impl Into<String>) -> Self {
        self.record.retry_reason = Some(reason.into());
        self
    }

    #[must_use]
    pub fn time_to_headers_ms(mut self, elapsed: u64) -> Self {
        self.record.time_to_headers_ms = Some(elapsed);
        self
    }

    #[must_use]
    pub fn time_to_first_event_ms(mut self, elapsed: u64) -> Self {
        self.record.time_to_first_event_ms = Some(elapsed);
        self
    }

    #[must_use]
    pub fn completion_class(mut self, completion: CompletionClass) -> Self {
        self.record.completion_class = Some(completion);
        self
    }

    #[must_use]
    pub fn usage(mut self, usage: Usage) -> Self {
        self.record.usage = Some(usage);
        self
    }

    #[must_use]
    pub fn candidate(mut self, candidate: CandidateRecord) -> Self {
        self.record.candidates.push(candidate);
        self
    }

    #[must_use]
    pub fn selected_provider(mut self, provider: impl Into<String>) -> Self {
        self.record.selected_provider = Some(provider.into());
        self
    }

    #[must_use]
    pub fn selected_model(mut self, model: impl Into<String>) -> Self {
        self.record.selected_model = Some(model.into());
        self
    }

    #[must_use]
    pub fn model_alias(mut self, alias: impl Into<String>) -> Self {
        self.record.model_alias = Some(alias.into());
        self
    }

    #[must_use]
    pub fn affinity(mut self, affinity: AffinityDecision) -> Self {
        self.record.affinity = Some(affinity);
        self
    }

    #[must_use]
    pub fn config_generation(mut self, generation: u64) -> Self {
        self.record.config_generation = Some(generation);
        self
    }

    #[must_use]
    pub fn outcome(mut self, outcome: impl Into<String>) -> Self {
        self.record.outcome = Some(outcome.into());
        self
    }

    #[must_use]
    pub fn evidence(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.record
            .evidence
            .insert(key.into(), self.policy.sanitize_json(&value.into()));
        self
    }

    #[must_use]
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.record
            .attributes
            .insert(key.into(), self.policy.sanitize_json(&value.into()));
        self
    }

    #[must_use]
    pub fn build(mut self) -> DecisionRecord {
        if self.record.timestamp_ms == 0 {
            self.record.timestamp_ms = now_unix_millis();
        }
        self.record
    }
}

/// Audit event categories emitted by request/attempt lifecycle code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    RequestStarted,
    Authentication,
    RouteMatched,
    TargetSelected,
    AttemptStarted,
    Retry,
    StreamCompleted,
    RequestCompleted,
    Error,
    Capture,
    Custom(String),
}

impl Default for AuditEventKind {
    fn default() -> Self {
        Self::Custom("custom".to_owned())
    }
}

/// Structured lifecycle/audit event. Details are sanitized on insertion and
/// again whenever the event is serialized.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuditEvent {
    pub timestamp_ms: u64,
    pub kind: AuditEventKind,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub route: Option<String>,
    pub decision: Option<DecisionRecord>,
    pub details: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct AuditEventWire<'a> {
    timestamp_ms: u64,
    kind: &'a AuditEventKind,
    request_id: &'a Option<String>,
    trace_id: &'a Option<String>,
    route: &'a Option<String>,
    decision: &'a Option<Value>,
    details: &'a BTreeMap<String, Value>,
}

impl AuditEvent {
    /// Construct an event with the current wall-clock timestamp.
    #[must_use]
    pub fn new(kind: AuditEventKind) -> Self {
        Self {
            timestamp_ms: now_unix_millis(),
            kind,
            ..Self::default()
        }
    }

    /// Construct a custom-named event for adapters and extensions.
    #[must_use]
    pub fn custom(kind: impl Into<String>) -> Self {
        Self::new(AuditEventKind::Custom(kind.into()))
    }

    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    #[must_use]
    pub fn route(mut self, route: impl Into<String>) -> Self {
        self.route = Some(route.into());
        self
    }

    #[must_use]
    pub fn decision(mut self, decision: DecisionRecord) -> Self {
        self.decision = Some(decision);
        self
    }

    #[must_use]
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        let policy = RedactionPolicy::default();
        self.details
            .insert(key.into(), policy.sanitize_json(&value.into()));
        self
    }

    /// Return a policy-specific sanitized JSON representation.
    #[must_use]
    pub fn sanitized_json(&self, policy: &RedactionPolicy) -> Value {
        let decision = self.decision.as_ref().map(DecisionRecord::raw_json);
        let raw = serde_json::to_value(AuditEventWire {
            timestamp_ms: self.timestamp_ms,
            kind: &self.kind,
            request_id: &self.request_id,
            trace_id: &self.trace_id,
            route: &self.route,
            decision: &decision,
            details: &self.details,
        })
        .unwrap_or(Value::Null);
        policy.sanitize_json(&raw)
    }

    /// Add a decision record as a nested audit event.
    #[must_use]
    pub fn from_decision(decision: DecisionRecord) -> Self {
        Self::new(AuditEventKind::TargetSelected).decision(decision)
    }
}

impl Serialize for AuditEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.sanitized_json(&RedactionPolicy::default())
            .serialize(serializer)
    }
}

/// Tracing subscriber configuration used by [`init_tracing_with`].
#[derive(Clone, Debug)]
pub struct TracingConfig {
    pub filter: String,
    pub json: bool,
    pub ansi: bool,
    pub with_target: bool,
    pub policy: RedactionPolicy,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            filter: "info".to_owned(),
            json: true,
            ansi: false,
            with_target: true,
            policy: RedactionPolicy::default(),
        }
    }
}

impl TracingConfig {
    #[must_use]
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = filter.into();
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub fn pretty(mut self) -> Self {
        self.json = false;
        self.ansi = true;
        self
    }
}

/// Errors returned while installing the process-wide tracing subscriber.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TracingInitError {
    #[error("invalid tracing filter: {0}")]
    InvalidFilter(String),
    #[error("a global tracing subscriber is already installed")]
    AlreadyInitialized,
}

/// Install the default JSON tracing subscriber with strict redaction.
pub fn init_tracing() -> Result<(), TracingInitError> {
    init_tracing_with(TracingConfig::default())
}

/// Install a process-wide tracing subscriber. Every complete output line is
/// sanitized by [`RedactingWriter`] immediately before it reaches stderr.
pub fn init_tracing_with(config: TracingConfig) -> Result<(), TracingInitError> {
    let filter = EnvFilter::try_new(&config.filter)
        .map_err(|error| TracingInitError::InvalidFilter(error.to_string()))?;
    let policy = config.policy;

    if config.json {
        let writer_policy = policy.clone();
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_ansi(config.ansi)
            .with_target(config.with_target)
            .with_writer(move || RedactingWriter::new(io::stderr(), writer_policy.clone()));
        tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init()
            .map_err(|_| TracingInitError::AlreadyInitialized)
    } else {
        let writer_policy = policy;
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(config.ansi)
            .with_target(config.with_target)
            .with_writer(move || RedactingWriter::new(io::stderr(), writer_policy.clone()));
        tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init()
            .map_err(|_| TracingInitError::AlreadyInitialized)
    }
}

/// A `Write` adapter that buffers complete lines and sanitizes them before
/// forwarding to the wrapped writer. Buffering prevents a token split across
/// adjacent writes from escaping the redaction pass.
pub struct RedactingWriter<W> {
    inner: W,
    policy: RedactionPolicy,
    pending: Vec<u8>,
}

impl<W> fmt::Debug for RedactingWriter<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactingWriter")
            .field("pending_bytes", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl<W> RedactingWriter<W> {
    #[must_use]
    pub fn new(inner: W, policy: RedactionPolicy) -> Self {
        Self {
            inner,
            policy,
            pending: Vec::new(),
        }
    }

    /// Flush pending data and return the wrapped writer.
    pub fn into_inner(mut self) -> io::Result<W>
    where
        W: Write,
    {
        self.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buffer);
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=newline).collect();
            let text = String::from_utf8_lossy(&line);
            let sanitized = self.policy.sanitize_text(&text);
            self.inner.write_all(sanitized.as_bytes())?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let text = String::from_utf8_lossy(&self.pending);
            let sanitized = self.policy.sanitize_text(&text);
            self.inner.write_all(sanitized.as_bytes())?;
            self.pending.clear();
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, COOKIE};
    use serde::de::DeserializeOwned;

    fn assert_not_present(value: &str, secrets: &[&str]) {
        for secret in secrets {
            assert!(
                !value.contains(secret),
                "secret `{secret}` leaked in `{value}`"
            );
        }
    }

    #[test]
    fn recursively_redacts_sensitive_json_keys_and_secret_forms() {
        let secrets = [
            "sk-live-1234567890",
            "refresh-live-secret",
            "nested-password",
            "eyJhbGciOiJIUzI1NiJ9.payload.signature",
        ];
        let value = serde_json::json!({
            "request": {
                "safe": "kept",
                "authorization": "Bearer sk-live-1234567890",
                "items": [
                    {"password": "nested-password"},
                    "Bearer refresh-live-secret",
                    "eyJhbGciOiJIUzI1NiJ9.payload.signature"
                ]
            }
        });

        let sanitized = RedactionPolicy::default().sanitize_json(&value);
        let encoded = serde_json::to_string(&sanitized).expect("JSON must serialize");
        assert_not_present(&encoded, &secrets);
        assert_eq!(sanitized["request"]["safe"], "kept");
        assert_eq!(sanitized["request"]["authorization"], REDACTED);
        assert_eq!(sanitized["request"]["items"][0]["password"], REDACTED);
    }

    #[test]
    fn redacts_camel_case_sensitive_json_keys() {
        let value = serde_json::json!({
            "accessToken": "access-token-value",
            "clientSecret": "client-secret-value",
        });

        let sanitized = RedactionPolicy::default().sanitize_json(&value);
        let encoded = serde_json::to_string(&sanitized).expect("JSON must serialize");

        assert_not_present(&encoded, &["access-token-value", "client-secret-value"]);
        assert_eq!(sanitized["accessToken"], REDACTED);
        assert_eq!(sanitized["clientSecret"], REDACTED);
    }

    #[test]
    fn text_redaction_catches_common_provider_tokens() {
        let text = "OPENAI_API_KEY=env-secret-value; authorization=Bearer sk-ant-api03-1234567890; jwt=eyJhbGciOiJIUzI1NiJ9.payload.signature; github=ghp_abcdefghijklmnopqrstuvwxyz";
        let sanitized = sanitize_text(text);
        assert_not_present(
            &sanitized,
            &[
                "env-secret-value",
                "sk-ant-api03-1234567890",
                "eyJhbGciOiJIUzI1NiJ9.payload.signature",
                "ghp_abcdefghijklmnopqrstuvwxyz",
            ],
        );
    }

    #[test]
    fn header_policy_is_strict_allowlist_and_preserves_safe_diagnostics() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer top-secret"));
        headers.insert(COOKIE, HeaderValue::from_static("session=private-cookie"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            "x-internal-secret",
            HeaderValue::from_static("do-not-log-this"),
        );

        let sanitized = sanitize_headers(&headers);
        assert_eq!(sanitized["authorization"], REDACTED);
        assert_eq!(sanitized["cookie"], REDACTED);
        assert_eq!(sanitized["content-type"], "application/json");
        assert_eq!(sanitized["x-internal-secret"], REDACTED);
        assert_not_present(
            &serde_json::to_string(&sanitized).expect("headers must serialize"),
            &["top-secret", "private-cookie", "do-not-log-this"],
        );
    }

    #[test]
    fn decision_and_audit_serialization_never_emits_secret_evidence() {
        let record = DecisionRecord::builder()
            .request_id("request-1")
            .trace_id("trace-1")
            .route("custom")
            .credential_pseudonym("credential-pseudonym-1")
            .evidence(
                "upstream",
                serde_json::json!({
                    "authorization": "Bearer sk-secret-123456789",
                    "nested": ["refresh=refresh-secret-value"]
                }),
            )
            .build();
        let event =
            AuditEvent::from_decision(record).detail("message", "cookie=session-secret-value");

        let encoded = serde_json::to_string(&event).expect("audit event must serialize");
        assert_not_present(
            &encoded,
            &[
                "sk-secret-123456789",
                "refresh-secret-value",
                "session-secret-value",
            ],
        );
        assert!(encoded.contains(REDACTED));
        assert!(encoded.contains("credential-pseudonym-1"));
    }

    #[test]
    fn policy_and_store_decisions_convert_to_one_observe_shape() {
        let provider = pooler_policy::ProviderId::new("provider").expect("provider");
        let model = pooler_policy::ModelId::new("model").expect("model");
        let mut selection = pooler_policy::SelectionExplanation::new(
            pooler_policy::ModelAliasResolution::exact(model.clone()),
            2,
            pooler_policy::ConfigGeneration::new(7),
        );
        selection.set_selected(
            pooler_policy::SelectionTarget::new(
                provider,
                model,
                pooler_policy::CredentialPseudonym::new("cred-redacted"),
            ),
            Some(1.0),
        );

        let from_policy = DecisionRecord::from(&selection);
        assert_eq!(from_policy.selected_provider.as_deref(), Some("provider"));
        assert_eq!(
            from_policy.credential_pseudonym.as_deref(),
            Some("cred-redacted")
        );
        assert_eq!(from_policy.attempt, 2);

        let stored =
            pooler_store::DecisionRecord::from_selection(&selection, "request", "route", 42);
        let from_store = DecisionRecord::from(&stored);
        assert_eq!(from_store.request_id.as_deref(), Some("request"));
        assert_eq!(from_store.route.as_deref(), Some("route"));
        assert_eq!(from_store.selected_model.as_deref(), Some("model"));
        assert_eq!(from_store.timestamp_ms, 42);
    }

    #[test]
    fn redacting_writer_handles_tokens_split_across_writes() {
        let mut writer = RedactingWriter::new(Vec::<u8>::new(), RedactionPolicy::default());
        writer
            .write_all(b"event=Bearer split-")
            .expect("first write");
        writer.write_all(b"secret-token\n").expect("second write");
        let output = String::from_utf8(writer.into_inner().expect("flush")).expect("UTF-8");
        assert_not_present(&output, &["split-secret-token"]);
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn custom_policy_keys_are_redacted_recursively() {
        let policy = RedactionPolicy::default().redact_key("internal-proof");
        let value = serde_json::json!({
            "internal-proof": "proof-secret",
            "normal": "visible"
        });
        let sanitized = policy.sanitize_json(&value);
        assert_eq!(sanitized["internal-proof"], REDACTED);
        assert_eq!(sanitized["normal"], "visible");
    }

    #[test]
    fn secret_looking_object_keys_are_redacted() {
        let value = serde_json::json!({"sk-secret-key-material": "value"});
        let encoded = RedactionPolicy::default().sanitize_json(&value).to_string();
        assert!(!encoded.contains("sk-secret-key-material"));
        assert!(encoded.contains(REDACTED));
    }

    #[test]
    fn custom_policy_applies_to_nested_decisions() {
        let record = DecisionRecord::builder()
            .evidence("operator-note", "keep only in a local test")
            .build();
        let event = AuditEvent::from_decision(record);
        let policy = RedactionPolicy::default().redact_key("operator-note");
        let encoded = serde_json::to_string(&event.sanitized_json(&policy)).expect("serialize");
        assert!(!encoded.contains("keep only in a local test"));
    }

    #[test]
    fn default_records_are_deserializable_after_sanitized_serialization() {
        let record = DecisionRecord::new("request", "trace");
        let encoded = serde_json::to_vec(&record).expect("serialize");
        let decoded: DecisionRecord = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded.request_id.as_deref(), Some("request"));
        assert_eq!(decoded.trace_id.as_deref(), Some("trace"));
    }

    #[test]
    fn redaction_policy_round_trips_without_secrets() {
        let policy = RedactionPolicy::default().allow_header("x-safe");
        let encoded = serde_json::to_string(&policy).expect("serialize policy");
        assert_not_present(&encoded, &["Bearer", "sk-"]);
        let decoded: RedactionPolicy = serde_json::from_str(&encoded).expect("deserialize");
        assert!(decoded.is_allowed_header("X-Safe"));
    }

    #[test]
    fn deserialize_owned_is_used_by_public_record_contracts() {
        fn assert_owned<T: DeserializeOwned>() {}
        assert_owned::<DecisionRecord>();
        assert_owned::<AuditEvent>();
    }
}
