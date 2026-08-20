//! Evidence-grounded contracts for the local Codex subscription bridge.
//!
//! The installed bridge stores OAuth credentials as JSON records containing
//! access and refresh tokens, optional identity fields, an account identifier,
//! and disabled/expired state. Its sanitized request logs show the native
//! request path and the account, originator, session, and user-agent headers.
//! This crate models those observed boundaries without claiming compatibility
//! for undocumented endpoints or response fields.

#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{self, File},
    future::Future,
    io::Read,
    net::IpAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::{header, HeaderMap, HeaderValue};
use pooler_auth::{
    constant_time_eq, CredentialId, OAuthTokens, RefreshCoordinator, RefreshError, SecretValue,
};
use pooler_core::{ErrorClass, ProviderId};
use pooler_policy::{
    CredentialCausation, FailureClassification, FailureClassifier, ObservedFailure,
    ProviderFailureClassifier, RedactedEvidence,
};
use ring::digest;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Provider identifier used by the local bridge's sanitized request logs.
pub const CODEX_PROVIDER_ID: &str = "codex";
/// Native response endpoint observed in the local bridge logs.
pub const CODEX_RESPONSES_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
/// Relative native response endpoint observed in the local bridge logs.
pub const CODEX_RESPONSES_PATH: &str = "/backend-api/codex/responses";
/// Native model discovery endpoint used by the Codex bridge.
pub const CODEX_MODELS_PATH: &str = "/backend-api/codex/models";
/// Native usage endpoint used by the Codex bridge.
pub const CODEX_USAGE_PATH: &str = "/wham/usage";
/// Header carrying the ChatGPT account identifier.
pub const CHATGPT_ACCOUNT_ID_HEADER: &str = "chatgpt-account-id";
/// Header identifying the originating Codex client.
pub const ORIGINATOR_HEADER: &str = "originator";
/// Header carrying the client session identifier.
pub const SESSION_ID_HEADER: &str = "session_id";
/// Default originator observed in the local Codex TUI request log.
pub const DEFAULT_ORIGINATOR: &str = "codex-tui";
/// Maximum persisted credential file size accepted by the provider.
pub const MAX_CODEX_CREDENTIAL_FILE_BYTES: u64 = 256 * 1024;

const DEFAULT_USER_AGENT: &str = "pooler-codex-provider/0.1";

/// Errors raised while loading or materializing Codex credentials.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodexCredentialError {
    /// The persisted record was not valid JSON.
    #[error("invalid Codex credential JSON")]
    InvalidJson,
    /// A required persisted field was absent or empty.
    #[error("Codex credential field {0} is missing")]
    MissingField(&'static str),
    /// A persisted field had a type or value that cannot be used safely.
    #[error("invalid Codex credential field {field}: {reason}")]
    InvalidField {
        /// Field whose value was invalid.
        field: &'static str,
        /// Safe, non-secret reason.
        reason: &'static str,
    },
    /// The credential was explicitly disabled by the local bridge.
    #[error("Codex credential is disabled")]
    Disabled,
    /// The persisted credential is marked expired and must be refreshed first.
    #[error("Codex credential is expired")]
    Expired,
    /// Native requests require the account identifier observed in the bridge.
    #[error("Codex credential has no account identifier")]
    MissingAccountId,
    /// The explicit account identifier did not match the ID-token claim.
    #[error("Codex credential account identifier does not match its ID token")]
    AccountIdMismatch,
    /// The owner-only credential file could not be read or validated.
    #[error("unable to read Codex credential file")]
    FileIo,
    /// The credential file exceeded the bounded parser input.
    #[error("Codex credential file is too large")]
    FileTooLarge,
    /// A header could not be represented as an HTTP header value.
    #[error("invalid Codex authorization header")]
    InvalidHeader,
}

/// Errors raised by provider OAuth response parsing or coordinated refresh.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodexOAuthError {
    /// The provider returned a malformed token response.
    #[error("invalid Codex OAuth token response")]
    InvalidResponse,
    /// The provider returned a safe OAuth error code.
    #[error("Codex OAuth request failed: {0}")]
    Provider(String),
    /// A refresh operation was cancelled or failed under the shared lease.
    #[error("Codex OAuth refresh failed: {0}")]
    Refresh(#[from] RefreshError),
    /// An OAuth URL or callback was malformed.
    #[error("invalid Codex OAuth request")]
    InvalidRequest,
    /// The callback state did not match the authorization request.
    #[error("Codex OAuth callback state did not match")]
    InvalidState,
}

/// Errors raised while parsing bounded Codex quota evidence.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodexQuotaError {
    /// The response body exceeded the parser bound.
    #[error("Codex quota response exceeds the parser limit")]
    BodyTooLarge,
    /// The response body was not a JSON object.
    #[error("Codex quota response is not a JSON object")]
    InvalidJson,
}

/// Request metadata carried alongside native Codex authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexRequestMetadata {
    /// Native client originator, such as codex-tui.
    pub originator: String,
    /// Optional request session identifier.
    pub session_id: Option<String>,
    /// User-agent string supplied to the native endpoint.
    pub user_agent: String,
}

impl Default for CodexRequestMetadata {
    fn default() -> Self {
        Self {
            originator: DEFAULT_ORIGINATOR.to_owned(),
            session_id: None,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        }
    }
}

impl CodexRequestMetadata {
    /// Construct metadata with an explicit native client user agent.
    pub fn new(
        originator: impl Into<String>,
        session_id: Option<impl Into<String>>,
        user_agent: impl Into<String>,
    ) -> Result<Self, CodexCredentialError> {
        let originator = originator.into();
        let user_agent = user_agent.into();
        if originator.trim().is_empty() {
            return Err(CodexCredentialError::InvalidField {
                field: "originator",
                reason: "must not be empty",
            });
        }
        if user_agent.trim().is_empty() {
            return Err(CodexCredentialError::InvalidField {
                field: "user_agent",
                reason: "must not be empty",
            });
        }
        let session_id = session_id.map(Into::into);
        if session_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(CodexCredentialError::InvalidField {
                field: "session_id",
                reason: "must not be empty",
            });
        }
        Ok(Self {
            originator,
            session_id,
            user_agent,
        })
    }

    /// Derive native metadata from downstream headers while retaining safe
    /// defaults for headers omitted by a client.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, CodexCredentialError> {
        let originator = headers
            .get(ORIGINATOR_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(DEFAULT_ORIGINATOR);
        let session_id = headers
            .get(SESSION_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty());
        let user_agent = headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(DEFAULT_USER_AGENT);
        Self::new(originator, session_id, user_agent)
    }
}

/// A credential record loaded from the local bridge's JSON storage format.
///
/// The token fields are protected immediately after parsing. The public type
/// never implements Serialize, and its debug output contains no token,
/// token length, email, or account identifier.
pub struct CodexCredential {
    tokens: OAuthTokens,
    id_token: Option<SecretValue>,
    account_id: Option<String>,
    email: Option<String>,
    auth_type: String,
    expired: bool,
    disabled: bool,
    last_refresh: Option<SystemTime>,
}

impl Clone for CodexCredential {
    fn clone(&self) -> Self {
        Self {
            tokens: self.tokens.clone(),
            id_token: self.id_token.clone(),
            account_id: self.account_id.clone(),
            email: self.email.clone(),
            auth_type: self.auth_type.clone(),
            expired: self.expired,
            disabled: self.disabled,
            last_refresh: self.last_refresh,
        }
    }
}

impl PartialEq for CodexCredential {
    fn eq(&self, other: &Self) -> bool {
        self.tokens == other.tokens
            && self.id_token == other.id_token
            && self.account_id == other.account_id
            && self.email == other.email
            && self.auth_type == other.auth_type
            && self.expired == other.expired
            && self.disabled == other.disabled
            && self.last_refresh == other.last_refresh
    }
}

impl Eq for CodexCredential {}

impl fmt::Debug for CodexCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCredential")
            .field("auth_type", &self.auth_type)
            .field("expired", &self.expired)
            .field("disabled", &self.disabled)
            .field("has_account_id", &self.account_id.is_some())
            .field("has_email", &self.email.is_some())
            .field("last_refresh", &self.last_refresh)
            .finish_non_exhaustive()
    }
}

impl CodexCredential {
    /// Construct an active credential from protected OAuth tokens.
    pub fn new(
        tokens: OAuthTokens,
        account_id: impl Into<String>,
    ) -> Result<Self, CodexCredentialError> {
        let account_id = account_id.into();
        if account_id.trim().is_empty() {
            return Err(CodexCredentialError::MissingAccountId);
        }
        Ok(Self {
            tokens,
            id_token: None,
            account_id: Some(account_id),
            email: None,
            auth_type: "oauth".to_owned(),
            expired: false,
            disabled: false,
            last_refresh: None,
        })
    }

    /// Parse a local bridge credential record and protect its token fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CodexCredentialError> {
        if bytes.len() as u64 > MAX_CODEX_CREDENTIAL_FILE_BYTES {
            return Err(CodexCredentialError::FileTooLarge);
        }
        let record: StoredCodexCredential =
            serde_json::from_slice(bytes).map_err(|_| CodexCredentialError::InvalidJson)?;
        Self::from_stored(record)
    }

    /// Load and parse an owner-only local bridge credential file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, CodexCredentialError> {
        Self::from_json(&Self::read_credential_file(path.as_ref())?)
    }

    fn read_bounded_credential_file(file: File) -> Result<Vec<u8>, CodexCredentialError> {
        let mut bytes = Vec::new();
        file.take(MAX_CODEX_CREDENTIAL_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CodexCredentialError::FileIo)?;
        if bytes.len() as u64 > MAX_CODEX_CREDENTIAL_FILE_BYTES {
            return Err(CodexCredentialError::FileTooLarge);
        }
        Ok(bytes)
    }

    #[cfg(unix)]
    fn read_credential_file(path: &Path) -> Result<Vec<u8>, CodexCredentialError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| CodexCredentialError::FileIo)?;
        let metadata = file.metadata().map_err(|_| CodexCredentialError::FileIo)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.mode() & 0o400 == 0
        {
            return Err(CodexCredentialError::FileIo);
        }
        if metadata.len() > MAX_CODEX_CREDENTIAL_FILE_BYTES {
            return Err(CodexCredentialError::FileTooLarge);
        }
        Self::read_bounded_credential_file(file)
    }

    #[cfg(not(unix))]
    fn read_credential_file(path: &Path) -> Result<Vec<u8>, CodexCredentialError> {
        pooler_auth::validate_owner_only_file(path).map_err(|_| CodexCredentialError::FileIo)?;
        let file = File::open(path).map_err(|_| CodexCredentialError::FileIo)?;
        let metadata = file.metadata().map_err(|_| CodexCredentialError::FileIo)?;
        if metadata.len() > MAX_CODEX_CREDENTIAL_FILE_BYTES {
            return Err(CodexCredentialError::FileTooLarge);
        }
        Self::read_bounded_credential_file(file)
    }

    fn from_stored(record: StoredCodexCredential) -> Result<Self, CodexCredentialError> {
        let access_token = non_empty_string(record.access_token, "access_token")?;
        let auth_type = record.auth_type.unwrap_or_else(|| "oauth".to_owned());
        if auth_type.trim().is_empty() {
            return Err(CodexCredentialError::InvalidField {
                field: "type",
                reason: "must not be empty",
            });
        }
        let explicit_account_id = record.account_id.filter(|value| !value.trim().is_empty());
        let id_token = record
            .id_token
            .filter(|value| !value.trim().is_empty())
            .map(SecretValue::new);
        let claimed_account_id = id_token
            .as_ref()
            .and_then(|token| account_id_from_id_token(token.expose_secret()));
        let account_id = match (explicit_account_id, claimed_account_id) {
            (Some(explicit), Some(claimed)) if explicit != claimed => {
                return Err(CodexCredentialError::AccountIdMismatch);
            }
            (Some(explicit), _) => Some(explicit),
            (None, claimed) => claimed,
        };
        let tokens = OAuthTokens::bearer(
            access_token,
            record
                .refresh_token
                .filter(|value| !value.trim().is_empty()),
            None,
        );
        Ok(Self {
            tokens,
            id_token,
            account_id,
            email: record.email.filter(|value| !value.trim().is_empty()),
            auth_type,
            expired: parse_expired(&record.expired),
            disabled: record.disabled,
            last_refresh: record.last_refresh.and_then(parse_timestamp),
        })
    }

    /// Protected OAuth token set used for one outbound operation.
    #[must_use]
    pub fn tokens(&self) -> &OAuthTokens {
        &self.tokens
    }

    /// Optional account identifier carried by native requests.
    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Optional protected ID token retained for encrypted import persistence.
    #[must_use]
    pub const fn id_token(&self) -> Option<&SecretValue> {
        self.id_token.as_ref()
    }

    /// Optional identity email from the local bridge record.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Provider storage type, normally oauth for the observed records.
    #[must_use]
    pub fn auth_type(&self) -> &str {
        &self.auth_type
    }

    /// Whether the local bridge disabled this credential.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Whether the local bridge marked this credential expired.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    /// Timestamp of the last persisted refresh, when available.
    #[must_use]
    pub const fn last_refresh(&self) -> Option<SystemTime> {
        self.last_refresh
    }

    /// Materialize native authorization headers for one request.
    pub fn materialize(
        &self,
        metadata: CodexRequestMetadata,
    ) -> Result<CodexAuthorization, CodexCredentialError> {
        if self.disabled {
            return Err(CodexCredentialError::Disabled);
        }
        if self.expired {
            return Err(CodexCredentialError::Expired);
        }
        let account_id = self
            .account_id
            .as_deref()
            .ok_or(CodexCredentialError::MissingAccountId)?;
        Ok(CodexAuthorization {
            tokens: self.tokens.clone(),
            account_id: account_id.to_owned(),
            metadata,
        })
    }
}

fn account_id_from_id_token(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let claims = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() || claims.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(claims.as_bytes()).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn non_empty_string(value: String, field: &'static str) -> Result<String, CodexCredentialError> {
    if value.trim().is_empty() {
        return Err(CodexCredentialError::MissingField(field));
    }
    Ok(value)
}

#[derive(Debug, Deserialize)]
struct StoredCodexCredential {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(rename = "type", default)]
    auth_type: Option<String>,
    #[serde(default)]
    expired: Value,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    last_refresh: Option<Value>,
}

fn parse_timestamp(value: Value) -> Option<SystemTime> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds))),
        Value::String(value) => value
            .parse::<u64>()
            .ok()
            .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
            .or_else(|| parse_rfc3339(&value)),
        _ => None,
    }
}

fn parse_expired(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::String(value) if value.eq_ignore_ascii_case("false") => false,
        Value::String(value) if value.eq_ignore_ascii_case("true") => true,
        _ => parse_timestamp(value.clone())
            .is_some_and(|expires_at| SystemTime::now().duration_since(expires_at).is_ok()),
    }
}

fn parse_rfc3339(value: &str) -> Option<SystemTime> {
    let (date, clock) = value.split_once('T').or_else(|| value.split_once('t'))?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<i64>().ok()?;
    let day = date_parts.next()?.parse::<i64>().ok()?;
    let (clock, offset_seconds) = if let Some(clock) = clock.strip_suffix('Z') {
        (clock, 0_i64)
    } else if let Some((clock, offset)) = clock.rsplit_once('+') {
        (clock, parse_timezone_offset(offset)?)
    } else if let Some((clock, offset)) = clock.rsplit_once('-') {
        (clock, -parse_timezone_offset(offset)?)
    } else {
        return None;
    };
    let mut clock_parts = clock.split(':');
    let hour = clock_parts.next()?.parse::<i64>().ok()?;
    let minute = clock_parts.next()?.parse::<i64>().ok()?;
    let second = clock_parts.next()?.split('.').next()?.parse::<i64>().ok()?;
    if !(-9999..=9999).contains(&year)
        || month == 0
        || month > 12
        || day == 0
        || day > 31
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?
        .checked_sub(offset_seconds)?;
    if seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(seconds).ok()?))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
}

fn parse_timezone_offset(value: &str) -> Option<i64> {
    let mut parts = value.split(':');
    let hours = parts.next()?.parse::<i64>().ok()?;
    let minutes = parts.next()?.parse::<i64>().ok()?;
    ((0..=23).contains(&hours) && (0..=59).contains(&minutes))
        .then_some(hours * 3_600 + minutes * 60)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 {
        year / 400
    } else {
        (year - 399) / 400
    };
    let year_of_era = year - era * 400;
    let month_offset = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_offset + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Protected native authorization material.
pub struct CodexAuthorization {
    tokens: OAuthTokens,
    account_id: String,
    metadata: CodexRequestMetadata,
}

impl fmt::Debug for CodexAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAuthorization")
            .field("has_access_token", &true)
            .field("account_id", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl CodexAuthorization {
    /// Apply native Codex authorization and observed request metadata.
    pub fn apply_to(&self, headers: &mut HeaderMap) -> Result<(), CodexCredentialError> {
        let authorization = format!(
            "{} {}",
            self.tokens.token_type(),
            self.tokens.access_token().expose_secret()
        );
        let authorization = HeaderValue::from_str(&authorization)
            .map_err(|_| CodexCredentialError::InvalidHeader)?;
        let account_id = HeaderValue::from_str(&self.account_id)
            .map_err(|_| CodexCredentialError::InvalidHeader)?;
        let originator = HeaderValue::from_str(&self.metadata.originator)
            .map_err(|_| CodexCredentialError::InvalidHeader)?;
        let user_agent = HeaderValue::from_str(&self.metadata.user_agent)
            .map_err(|_| CodexCredentialError::InvalidHeader)?;

        headers.insert(header::AUTHORIZATION, authorization);
        headers.insert(
            http::header::HeaderName::from_static(CHATGPT_ACCOUNT_ID_HEADER),
            account_id,
        );
        headers.insert(
            http::header::HeaderName::from_static(ORIGINATOR_HEADER),
            originator,
        );
        headers.insert(
            http::header::HeaderName::from_static("user-agent"),
            user_agent,
        );
        if let Some(session_id) = &self.metadata.session_id {
            let session_id = HeaderValue::from_str(session_id)
                .map_err(|_| CodexCredentialError::InvalidHeader)?;
            headers.insert(
                http::header::HeaderName::from_static(SESSION_ID_HEADER),
                session_id,
            );
        } else {
            headers.remove(http::header::HeaderName::from_static(SESSION_ID_HEADER));
        }
        Ok(())
    }

    /// Return the protected OAuth token set for an explicit transport boundary.
    #[must_use]
    pub fn tokens(&self) -> &OAuthTokens {
        &self.tokens
    }

    /// Return the account identifier for diagnostics that already enforce
    /// their own redaction policy.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

/// OAuth configuration for the native Codex subscription provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexOAuthConfig {
    /// OAuth client identifier registered for the caller.
    pub client_id: String,
    /// Authorization endpoint supplied by the deployment.
    pub authorization_endpoint: String,
    /// Token endpoint supplied by the deployment.
    pub token_endpoint: String,
    /// Optional device authorization endpoint.
    pub device_authorization_endpoint: Option<String>,
    /// Optional revocation endpoint.
    pub revocation_endpoint: Option<String>,
    /// Space-delimited OAuth scopes.
    pub scope: String,
    /// Exact loopback redirect URI authorized for this deployment.
    pub redirect_uri: Option<String>,
}

impl CodexOAuthConfig {
    /// Construct a PKCE-capable OAuth configuration.
    pub fn new(
        client_id: impl Into<String>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
    ) -> Result<Self, CodexOAuthError> {
        let config = Self {
            client_id: client_id.into(),
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            device_authorization_endpoint: None,
            revocation_endpoint: None,
            scope: "openid profile email offline_access".to_owned(),
            redirect_uri: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Add an explicitly configured device authorization endpoint.
    #[must_use]
    pub fn with_device_authorization_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.device_authorization_endpoint = Some(endpoint.into());
        self
    }

    /// Add an explicitly configured revocation endpoint.
    #[must_use]
    pub fn with_revocation_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(endpoint.into());
        self
    }

    /// Replace the configured OAuth scope string.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    /// Configure the exact loopback redirect URI accepted for PKCE.
    pub fn with_redirect_uri(
        mut self,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, CodexOAuthError> {
        let redirect_uri = redirect_uri.into();
        validate_loopback_redirect(&redirect_uri)?;
        self.redirect_uri = Some(redirect_uri);
        Ok(self)
    }

    fn validate(&self) -> Result<(), CodexOAuthError> {
        if self.client_id.trim().is_empty() || self.scope.trim().is_empty() {
            return Err(CodexOAuthError::InvalidRequest);
        }
        for endpoint in [
            Some(self.authorization_endpoint.as_str()),
            Some(self.token_endpoint.as_str()),
            self.device_authorization_endpoint.as_deref(),
            self.revocation_endpoint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let url = Url::parse(endpoint).map_err(|_| CodexOAuthError::InvalidRequest)?;
            if url.scheme() != "https" && url.scheme() != "http" {
                return Err(CodexOAuthError::InvalidRequest);
            }
        }
        if let Some(redirect_uri) = &self.redirect_uri {
            validate_loopback_redirect(redirect_uri)?;
        }
        Ok(())
    }
}

fn validate_loopback_redirect(redirect_uri: &str) -> Result<(), CodexOAuthError> {
    let url = Url::parse(redirect_uri).map_err(|_| CodexOAuthError::InvalidRequest)?;
    if url.scheme() != "http"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(CodexOAuthError::InvalidRequest);
    }
    let host = url.host_str().ok_or(CodexOAuthError::InvalidRequest)?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false);
    if !is_loopback {
        return Err(CodexOAuthError::InvalidRequest);
    }
    Ok(())
}

/// A generated PKCE authorization request.
pub struct CodexAuthorizationRequest {
    url: String,
    state: String,
    code_verifier: SecretValue,
    redirect_uri: String,
}

impl fmt::Debug for CodexAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAuthorizationRequest")
            .field("has_url", &true)
            .field("state", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("redirect_uri", &"[REDACTED]")
            .finish()
    }
}

impl CodexAuthorizationRequest {
    /// Browser URL to open for the OAuth authorization step.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// State value to validate on callback.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Protected verifier required for the code exchange.
    #[must_use]
    pub fn code_verifier(&self) -> &SecretValue {
        &self.code_verifier
    }

    /// Redirect URI used when constructing the request.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

/// A validated OAuth callback query.
#[derive(Clone, PartialEq, Eq)]
pub struct CodexAuthorizationCallback {
    /// Authorization code returned by the provider.
    code: SecretValue,
    /// State returned by the provider.
    state: SecretValue,
}

impl fmt::Debug for CodexAuthorizationCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAuthorizationCallback")
            .field("has_code", &true)
            .field("has_state", &true)
            .finish()
    }
}

impl CodexAuthorizationCallback {
    /// Parse a callback query string containing code and state.
    pub fn from_query(query: &str) -> Result<Self, CodexOAuthError> {
        let query = query.strip_prefix('?').unwrap_or(query);
        let mut code = None;
        let mut state = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "code" if code.is_none() => code = Some(value.into_owned()),
                "state" if state.is_none() => state = Some(value.into_owned()),
                "code" | "state" => return Err(CodexOAuthError::InvalidRequest),
                _ => {}
            }
        }
        let code = code
            .filter(|value| !value.trim().is_empty())
            .ok_or(CodexOAuthError::InvalidRequest)?;
        let state = state
            .filter(|value| !value.trim().is_empty())
            .ok_or(CodexOAuthError::InvalidRequest)?;
        Ok(Self {
            code: SecretValue::new(code),
            state: SecretValue::new(state),
        })
    }

    /// Authorization code for the explicit token-exchange boundary.
    #[must_use]
    pub fn code(&self) -> &SecretValue {
        &self.code
    }

    /// Callback state for the explicit validation boundary.
    #[must_use]
    pub fn state(&self) -> &SecretValue {
        &self.state
    }

    /// Compare callback state without early-returning on secret bytes.
    #[must_use]
    pub fn state_matches(&self, expected: &str) -> bool {
        constant_time_eq(self.state.expose_bytes(), expected.as_bytes())
    }
}

/// Build a native OAuth request and coordinate token refreshes.
#[derive(Clone)]
pub struct CodexProvider {
    oauth: CodexOAuthConfig,
    refresh: RefreshCoordinator,
}

impl fmt::Debug for CodexProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexProvider")
            .field("provider_id", &CODEX_PROVIDER_ID)
            .field("oauth", &self.oauth)
            .field("active_refresh_leases", &self.refresh.active_leases())
            .finish()
    }
}

impl CodexProvider {
    /// Construct a native provider with explicit OAuth endpoints.
    pub fn new(oauth: CodexOAuthConfig) -> Result<Self, CodexOAuthError> {
        oauth.validate()?;
        Ok(Self {
            oauth,
            refresh: RefreshCoordinator::new(),
        })
    }

    /// Stable provider identifier used by policy selection.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        ProviderId::new(CODEX_PROVIDER_ID).expect("static provider identifier is valid")
    }

    /// OAuth configuration used by this provider.
    #[must_use]
    pub fn oauth(&self) -> &CodexOAuthConfig {
        &self.oauth
    }

    /// Number of active refresh leases.
    #[must_use]
    pub fn active_refresh_leases(&self) -> usize {
        self.refresh.active_leases()
    }

    /// Generate a PKCE authorization request.
    pub fn begin_authorization(
        &self,
        redirect_uri: impl Into<String>,
    ) -> Result<CodexAuthorizationRequest, CodexOAuthError> {
        let redirect_uri = redirect_uri.into();
        if redirect_uri.trim().is_empty()
            || self.oauth.redirect_uri.as_deref() != Some(redirect_uri.as_str())
        {
            return Err(CodexOAuthError::InvalidRequest);
        }
        validate_loopback_redirect(&redirect_uri)?;
        let state = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let code_verifier = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let challenge =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, code_verifier.as_bytes()));
        let mut url = Url::parse(&self.oauth.authorization_endpoint)
            .map_err(|_| CodexOAuthError::InvalidRequest)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.oauth.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.oauth.scope)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(CodexAuthorizationRequest {
            url: url.into(),
            state,
            code_verifier: SecretValue::new(code_verifier),
            redirect_uri,
        })
    }

    /// Build the form body for an authorization-code exchange.
    pub fn code_exchange_body(
        &self,
        callback: &CodexAuthorizationCallback,
        request: &CodexAuthorizationRequest,
    ) -> Result<String, CodexOAuthError> {
        if !callback.state_matches(request.state()) {
            return Err(CodexOAuthError::InvalidState);
        }
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("client_id", &self.oauth.client_id)
            .append_pair("code", callback.code().expose_secret())
            .append_pair("redirect_uri", request.redirect_uri())
            .append_pair("code_verifier", request.code_verifier().expose_secret());
        Ok(form.finish())
    }

    /// Build the form body for a refresh-token exchange.
    pub fn refresh_body(&self, refresh_token: &SecretValue) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "refresh_token")
            .append_pair("client_id", &self.oauth.client_id)
            .append_pair("refresh_token", refresh_token.expose_secret());
        form.finish()
    }

    /// Coordinate one refresh operation per credential.
    pub async fn refresh_with<F, Fut>(
        &self,
        credential: CredentialId,
        refresh_token: SecretValue,
        operation: F,
    ) -> Result<OAuthTokens, CodexOAuthError>
    where
        F: FnOnce(SecretValue) -> Fut,
        Fut: Future<Output = Result<CodexTokenResponse, CodexOAuthError>>,
    {
        let result = self
            .refresh
            .get_or_refresh(credential, || async move {
                let previous_refresh_token = refresh_token.clone();
                let response = operation(refresh_token)
                    .await
                    .map_err(|error| RefreshError::Failed(safe_oauth_error(&error)))?;
                Ok(response.into_tokens(Some(previous_refresh_token)))
            })
            .await;
        result.map_err(CodexOAuthError::Refresh)
    }

    /// Parse a bounded provider response and classify it for pooling policy.
    #[must_use]
    pub fn classify_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> FailureClassification {
        CodexFailureClassifier::default().classify_response(status, headers, body)
    }
}

fn safe_oauth_error(error: &CodexOAuthError) -> String {
    match error {
        CodexOAuthError::InvalidResponse => "invalid_response".to_owned(),
        CodexOAuthError::Provider(code) => code.clone(),
        CodexOAuthError::Refresh(_) => "refresh_failed".to_owned(),
        CodexOAuthError::InvalidRequest => "invalid_request".to_owned(),
        CodexOAuthError::InvalidState => "invalid_state".to_owned(),
    }
}

/// Parsed OAuth token response retained in protected wrappers.
#[derive(Clone, PartialEq, Eq)]
pub struct CodexTokenResponse {
    access_token: SecretValue,
    refresh_token: Option<SecretValue>,
    token_type: String,
    expires_in: Option<Duration>,
}

impl fmt::Debug for CodexTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl CodexTokenResponse {
    /// Parse a successful or error OAuth token response.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CodexOAuthError> {
        let wire: TokenResponseWire =
            serde_json::from_slice(bytes).map_err(|_| CodexOAuthError::InvalidResponse)?;
        if let Some(error) = wire.error {
            let code = sanitize_oauth_code(&error);
            return Err(CodexOAuthError::Provider(code));
        }
        let access_token = wire
            .access_token
            .filter(|value| !value.trim().is_empty())
            .map(SecretValue::new)
            .ok_or(CodexOAuthError::InvalidResponse)?;
        let token_type = wire
            .token_type
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "Bearer".to_owned());
        let expires_in = wire
            .expires_in
            .and_then(|value| u64::try_from(value).ok())
            .map(Duration::from_secs);
        Ok(Self {
            access_token,
            refresh_token: wire
                .refresh_token
                .filter(|value| !value.trim().is_empty())
                .map(SecretValue::new),
            token_type,
            expires_in,
        })
    }

    /// Construct protected tokens while retaining a previous refresh token if
    /// the provider omitted it in a refresh response.
    #[must_use]
    pub fn into_tokens(self, previous_refresh_token: Option<SecretValue>) -> OAuthTokens {
        let refresh_token = self.refresh_token.or(previous_refresh_token);
        let expires_at = self
            .expires_in
            .and_then(|duration| SystemTime::now().checked_add(duration));
        OAuthTokens::new(
            self.access_token,
            refresh_token,
            expires_at,
            self.token_type,
        )
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponseWire {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    error: Option<String>,
}

fn sanitize_oauth_code(value: &str) -> String {
    let normalized = value.to_ascii_lowercase().replace('-', "_");
    if normalized.len() <= 64
        && normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        normalized
    } else {
        "provider_error".to_owned()
    }
}

/// Scope proven by a Codex quota or limit response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexQuotaScope {
    /// The subscription credential or account reached its allowance.
    Credential,
    /// The selected model reached a model-specific allowance.
    Model,
    /// The provider is throttling without account-specific evidence.
    Provider,
}

/// Bounded quota evidence extracted from a Codex response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexQuota {
    scope: CodexQuotaScope,
    code: String,
    retry_after: Option<std::time::Duration>,
    reset_at: Option<SystemTime>,
    remaining: Option<u64>,
    limit: Option<u64>,
}

impl CodexQuota {
    /// Scope proven by the response.
    #[must_use]
    pub const fn scope(&self) -> CodexQuotaScope {
        self.scope
    }

    /// Safe provider code retained for diagnostics.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Provider-advertised relative recovery delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<std::time::Duration> {
        self.retry_after
    }

    /// Provider-advertised absolute recovery instant, when supplied.
    #[must_use]
    pub const fn reset_at(&self) -> Option<SystemTime> {
        self.reset_at
    }

    /// Remaining quota units, when supplied.
    #[must_use]
    pub const fn remaining(&self) -> Option<u64> {
        self.remaining
    }

    /// Total quota units, when supplied.
    #[must_use]
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }
}

/// Parser for bounded Codex quota and throttling evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodexQuotaParser {
    max_body_bytes: usize,
}

impl Default for CodexQuotaParser {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
        }
    }
}

impl CodexQuotaParser {
    /// Construct a parser with an explicit response-body bound.
    #[must_use]
    pub const fn new(max_body_bytes: usize) -> Self {
        Self { max_body_bytes }
    }

    /// Parse only explicit account/model quota or provider-rate evidence.
    pub fn parse(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Option<CodexQuota>, CodexQuotaError> {
        if body.len() > self.max_body_bytes {
            return Err(CodexQuotaError::BodyTooLarge);
        }

        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(body).map_err(|_| CodexQuotaError::InvalidJson)?
        };
        let (code, message) = response_markers(&value);
        let retry_after = header_duration(headers, "retry-after")
            .or_else(|| value_duration(&value, "retry_after"));
        let reset_at = header_reset(headers)
            .or_else(|| value_system_time(&value, "reset_at"))
            .or_else(|| value_system_time(&value, "reset"));
        let scope = quota_scope(code.as_deref(), message.as_deref())
            .or_else(|| has_zero_quota_header(headers).then_some(CodexQuotaScope::Provider));
        let Some(scope) = scope else {
            return Ok(None);
        };
        let code = quota_code(scope, code.as_deref(), message.as_deref());
        Ok(Some(CodexQuota {
            scope,
            code,
            retry_after,
            reset_at,
            remaining: numeric_field(&value, "remaining")
                .or_else(|| header_quota_value(headers, "remaining")),
            limit: numeric_field(&value, "limit").or_else(|| header_quota_value(headers, "limit")),
        }))
    }

    /// Parse one bounded JSON data event from a native response stream.
    ///
    /// Non-data lines and terminal sentinels are ignored. The parser only
    /// returns a quota when an explicit provider marker is present.
    pub fn parse_event(&self, event: &[u8]) -> Result<Option<CodexQuota>, CodexQuotaError> {
        let mut data = Vec::new();
        for line in event.split(|byte| *byte == b'\n' || *byte == b'\r') {
            let Some(line) = line.strip_prefix(b"data:") else {
                continue;
            };
            let line = line.trim_ascii();
            if line.is_empty() || line == b"[DONE]" {
                continue;
            }
            let separator = usize::from(!data.is_empty());
            let next_len = data
                .len()
                .checked_add(separator)
                .and_then(|length| length.checked_add(line.len()))
                .ok_or(CodexQuotaError::BodyTooLarge)?;
            if next_len > self.max_body_bytes {
                return Err(CodexQuotaError::BodyTooLarge);
            }
            if !data.is_empty() {
                data.push(b'\n');
            }
            data.extend_from_slice(line);
        }
        if data.is_empty() {
            return Ok(None);
        }
        self.parse(&HeaderMap::new(), &data)
    }
}

/// Codex provider classifier that understands account and model quota markers.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodexFailureClassifier {
    parser: CodexQuotaParser,
}

impl CodexFailureClassifier {
    /// Construct a classifier with a bounded body parser.
    #[must_use]
    pub const fn new(max_body_bytes: usize) -> Self {
        Self {
            parser: CodexQuotaParser::new(max_body_bytes),
        }
    }

    /// Parse and classify one HTTP response without retaining its body.
    #[must_use]
    pub fn classify_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> FailureClassification {
        if !quota_status_allowed(status) {
            return classify_observed(ObservedFailure {
                source: pooler_policy::FailureSource::Upstream,
                status: Some(status),
                provider_code: None,
                message: None,
                retry_after: header_duration(headers, "retry-after"),
            });
        }
        match self.parser.parse(headers, body) {
            Ok(Some(quota)) => quota_classification(status, quota),
            Ok(None) | Err(_) => {
                let provider_code =
                    response_markers_from_bytes(body).and_then(|(code, _message)| code);
                classify_observed(ObservedFailure {
                    source: pooler_policy::FailureSource::Upstream,
                    status: Some(status),
                    provider_code,
                    message: None,
                    retry_after: header_duration(headers, "retry-after"),
                })
            }
        }
    }
}

impl FailureClassifier for CodexFailureClassifier {
    fn classify(&self, failure: &ObservedFailure) -> FailureClassification {
        let mut observed = failure.clone();
        if failure
            .status
            .is_some_and(|status| !quota_status_allowed(status))
        {
            observed.provider_code = None;
            observed.message = None;
        }
        classify_observed(observed)
    }
}

fn quota_status_allowed(status: u16) -> bool {
    matches!(status, 200..=299 | 402 | 429)
}

fn classify_observed(failure: ObservedFailure) -> FailureClassification {
    let mut result = ProviderFailureClassifier.classify(&failure);
    if failure
        .status
        .is_some_and(|status| (400..=499).contains(&status) && !matches!(status, 402 | 429))
    {
        result.cooldown = None;
        result.classification.recovery_after = None;
    }
    result
}

fn quota_classification(status: u16, quota: CodexQuota) -> FailureClassification {
    let (class, summary, causation) = match quota.scope {
        CodexQuotaScope::Credential => (
            ErrorClass::CredentialQuotaExhausted,
            "Codex account quota exhausted",
            CredentialCausation::Proven,
        ),
        CodexQuotaScope::Model => (
            ErrorClass::ModelQuotaExhausted,
            "Codex model quota exhausted",
            CredentialCausation::Unknown,
        ),
        CodexQuotaScope::Provider => (
            ErrorClass::ProviderRateLimited,
            "Codex provider rate limit",
            CredentialCausation::Unknown,
        ),
    };
    let mut result = FailureClassification::for_class(class);
    let recovery = quota.retry_after.unwrap_or(match quota.scope {
        CodexQuotaScope::Provider => std::time::Duration::from_secs(1),
        CodexQuotaScope::Credential | CodexQuotaScope::Model => std::time::Duration::from_secs(60),
    });
    if recovery > std::time::Duration::ZERO {
        result = result.with_recovery_after(recovery);
        let cooldown = match quota.scope {
            CodexQuotaScope::Credential => pooler_policy::CooldownSpec::credential(recovery),
            CodexQuotaScope::Model => pooler_policy::CooldownSpec::model(recovery),
            CodexQuotaScope::Provider => pooler_policy::CooldownSpec::provider(recovery),
        };
        result = result.with_cooldown(cooldown);
    }
    result.evidence = RedactedEvidence {
        status: Some(status),
        provider_code: Some(quota.code),
        summary: Some(summary.to_owned()),
    };
    result.with_credential_causation(causation)
}

fn response_markers_from_bytes(body: &[u8]) -> Option<(Option<String>, Option<String>)> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return None;
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .map(|value| response_markers(&value))
}

fn response_markers(value: &Value) -> (Option<String>, Option<String>) {
    let object = value.as_object();
    let error = object.and_then(|object| object.get("error"));
    let code = error
        .and_then(Value::as_object)
        .and_then(|object| object.get("code"))
        .or_else(|| object.and_then(|object| object.get("code")))
        .or_else(|| {
            error
                .and_then(Value::as_object)
                .and_then(|object| object.get("type"))
        })
        .or_else(|| object.and_then(|object| object.get("type")))
        .and_then(Value::as_str)
        .and_then(bounded_marker);
    let message = error
        .and_then(Value::as_object)
        .and_then(|object| object.get("message"))
        .or_else(|| object.and_then(|object| object.get("detail")))
        .or_else(|| object.and_then(|object| object.get("message")))
        .and_then(Value::as_str)
        .and_then(bounded_marker);
    (code, message)
}

fn bounded_marker(value: &str) -> Option<String> {
    let normalized = normalize_marker(value);
    (normalized.len() <= 64).then_some(normalized)
}

fn normalize_marker(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn quota_scope(code: Option<&str>, message: Option<&str>) -> Option<CodexQuotaScope> {
    if code.is_some_and(is_request_or_auth_marker) {
        return None;
    }
    if let Some(code) = code {
        if is_model_quota_marker(code) {
            return Some(CodexQuotaScope::Model);
        }
        if is_credential_quota_marker(code) {
            return Some(CodexQuotaScope::Credential);
        }
        if is_provider_rate_marker(code) {
            return Some(CodexQuotaScope::Provider);
        }
    }
    if message.is_some_and(is_request_or_auth_marker) {
        return None;
    }
    if message.is_some_and(is_model_quota_marker) {
        return Some(CodexQuotaScope::Model);
    }
    if message.is_some_and(is_credential_quota_marker) {
        return Some(CodexQuotaScope::Credential);
    }
    if message.is_some_and(is_provider_rate_marker) {
        return Some(CodexQuotaScope::Provider);
    }
    None
}

fn is_request_or_auth_marker(value: &str) -> bool {
    value.contains("invalid_request")
        || value.contains("invalid_argument")
        || value.contains("validation_error")
        || value.contains("malformed")
        || value.contains("unauthorized")
        || value.contains("authentication")
}

fn is_model_quota_marker(value: &str) -> bool {
    value.contains("model_quota")
        || value.contains("model_limit")
        || value.contains("model_capacity")
}

fn is_credential_quota_marker(value: &str) -> bool {
    value.contains("insufficient_quota")
        || value.contains("quota_exceeded")
        || value.contains("usage_limit_reached")
        || value.contains("plan_limit_reached")
        || value.contains("credits_exhausted")
        || value.contains("daily_limit")
        || value.contains("monthly_limit")
}

fn is_provider_rate_marker(value: &str) -> bool {
    value.contains("rate_limit")
        || value.contains("too_many_requests")
        || value.contains("throttl")
        || value.contains("overload")
        || value.contains("temporarily_unavailable")
        || value.contains("rate_limited")
}

fn quota_code(scope: CodexQuotaScope, code: Option<&str>, message: Option<&str>) -> String {
    if let Some(code) = code {
        if code.len() <= 64
            && code
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return code.to_owned();
        }
    }
    match scope {
        CodexQuotaScope::Credential => "usage_limit_reached".to_owned(),
        CodexQuotaScope::Model => "model_limit_reached".to_owned(),
        CodexQuotaScope::Provider => {
            if message.is_some_and(|message| message.contains("rate_limit")) {
                "rate_limit_exceeded".to_owned()
            } else {
                "provider_rate_limited".to_owned()
            }
        }
    }
}

fn header_duration(headers: &HeaderMap, name: &str) -> Option<Duration> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn header_reset(headers: &HeaderMap) -> Option<SystemTime> {
    ["x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"]
        .into_iter()
        .find_map(|name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_system_time)
        })
}

fn has_zero_quota_header(headers: &HeaderMap) -> bool {
    [
        "x-ratelimit-remaining-requests",
        "x-ratelimit-remaining-tokens",
        "x-openai-remaining-requests",
        "x-openai-remaining-tokens",
    ]
    .into_iter()
    .any(|name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            == Some(0)
    })
}

fn header_quota_value(headers: &HeaderMap, kind: &str) -> Option<u64> {
    let names = match kind {
        "remaining" => [
            "x-ratelimit-remaining-requests",
            "x-ratelimit-remaining-tokens",
            "x-openai-remaining-requests",
            "x-openai-remaining-tokens",
        ],
        "limit" => [
            "x-ratelimit-limit-requests",
            "x-ratelimit-limit-tokens",
            "x-openai-limit-requests",
            "x-openai-limit-tokens",
        ],
        _ => return None,
    };
    names.into_iter().find_map(|name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
    })
}

fn value_duration(value: &Value, field: &str) -> Option<Duration> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(|value| value.as_u64())
        .map(Duration::from_secs)
}

fn value_system_time(value: &Value, field: &str) -> Option<SystemTime> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(value_as_timestamp)
}

fn value_as_timestamp(value: &Value) -> Option<SystemTime> {
    match value {
        Value::Number(value) => value.as_u64().and_then(timestamp_from_seconds),
        Value::String(value) => parse_system_time(value),
        _ => None,
    }
}

fn parse_system_time(value: &str) -> Option<SystemTime> {
    let seconds = value.trim().parse::<u64>().ok()?;
    timestamp_from_seconds(seconds)
}

fn timestamp_from_seconds(seconds: u64) -> Option<SystemTime> {
    if seconds > 1_000_000_000 {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
    } else {
        SystemTime::now().checked_add(Duration::from_secs(seconds))
    }
}

fn numeric_field(value: &Value, field: &str) -> Option<u64> {
    let object = value.as_object()?;
    object
        .get(field)
        .and_then(Value::as_u64)
        .or_else(|| {
            object
                .get("quota")
                .and_then(Value::as_object)
                .and_then(|quota| quota.get(field))
                .and_then(Value::as_u64)
        })
        .or_else(|| {
            object
                .get("error")
                .and_then(Value::as_object)
                .and_then(|error| error.get(field))
                .and_then(Value::as_u64)
        })
}

/// A device authorization response with protected device code material.
pub struct CodexDeviceAuthorization {
    device_code: SecretValue,
    user_code: String,
    verification_uri: String,
    expires_in: Duration,
    interval: Duration,
}

impl fmt::Debug for CodexDeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexDeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("has_verification_uri", &true)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

impl CodexDeviceAuthorization {
    /// Parse a standard device authorization response.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CodexOAuthError> {
        let wire: DeviceAuthorizationWire =
            serde_json::from_slice(bytes).map_err(|_| CodexOAuthError::InvalidResponse)?;
        let device_code = wire
            .device_code
            .filter(|value| !value.trim().is_empty())
            .map(SecretValue::new)
            .ok_or(CodexOAuthError::InvalidResponse)?;
        let user_code = wire
            .user_code
            .filter(|value| !value.trim().is_empty())
            .ok_or(CodexOAuthError::InvalidResponse)?;
        let verification_uri = wire
            .verification_uri
            .or(wire.verification_url)
            .filter(|value| !value.trim().is_empty())
            .ok_or(CodexOAuthError::InvalidResponse)?;
        validate_verification_uri(&verification_uri)?;
        if wire.expires_in <= 0 {
            return Err(CodexOAuthError::InvalidResponse);
        }
        let interval = u64::try_from(wire.interval.unwrap_or(5).max(1))
            .map(Duration::from_secs)
            .map_err(|_| CodexOAuthError::InvalidResponse)?;
        Ok(Self {
            device_code,
            user_code,
            verification_uri,
            expires_in: Duration::from_secs(
                u64::try_from(wire.expires_in).map_err(|_| CodexOAuthError::InvalidResponse)?,
            ),
            interval,
        })
    }

    /// Device code for the explicit token-poll transport boundary.
    #[must_use]
    pub fn device_code(&self) -> &SecretValue {
        &self.device_code
    }

    /// User-facing code.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// User-facing verification URI.
    #[must_use]
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// Provider expiry duration.
    #[must_use]
    pub const fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// Minimum poll interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }
}

fn validate_verification_uri(uri: &str) -> Result<(), CodexOAuthError> {
    let url = Url::parse(uri).map_err(|_| CodexOAuthError::InvalidResponse)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(CodexOAuthError::InvalidResponse);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationWire {
    #[serde(default)]
    device_code: Option<String>,
    #[serde(default)]
    user_code: Option<String>,
    #[serde(default)]
    verification_uri: Option<String>,
    #[serde(default)]
    verification_url: Option<String>,
    expires_in: i64,
    #[serde(default)]
    interval: Option<i64>,
}

/// Result of polling a device token endpoint.
#[derive(Debug, PartialEq, Eq)]
pub enum CodexDevicePoll {
    /// The user has not completed authorization yet.
    AuthorizationPending,
    /// The provider asked the caller to slow polling.
    SlowDown,
    /// The device flow produced tokens.
    Authorized(CodexTokenResponse),
}

/// Parse one device token poll response without exposing token material.
pub fn parse_device_poll(bytes: &[u8]) -> Result<CodexDevicePoll, CodexOAuthError> {
    let wire: TokenResponseWire =
        serde_json::from_slice(bytes).map_err(|_| CodexOAuthError::InvalidResponse)?;
    if let Some(error) = wire.error {
        return match sanitize_oauth_code(&error).as_str() {
            "authorization_pending" => Ok(CodexDevicePoll::AuthorizationPending),
            "slow_down" => Ok(CodexDevicePoll::SlowDown),
            code => Err(CodexOAuthError::Provider(code.to_owned())),
        };
    }
    Ok(CodexDevicePoll::Authorized(CodexTokenResponse::from_json(
        bytes,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;
    use pooler_core::ErrorClass;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const STORED: &[u8] = br#"{
        "access_token": "access-secret",
        "refresh_token": "refresh-secret",
        "id_token": "id-secret",
        "account_id": "account-123",
        "email": "user@example.test",
        "type": "oauth",
        "expired": false,
        "disabled": false,
        "last_refresh": 1700000000
    }"#;

    fn provider() -> CodexProvider {
        let oauth = CodexOAuthConfig::new(
            "client-id",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
        )
        .expect("valid OAuth config")
        .with_redirect_uri("http://127.0.0.1/callback")
        .expect("valid redirect");
        CodexProvider::new(oauth).expect("valid provider")
    }

    #[test]
    fn loads_observed_credential_and_materializes_native_headers() {
        let credential = CodexCredential::from_json(STORED).expect("credential");
        assert_eq!(credential.account_id(), Some("account-123"));
        assert_eq!(credential.email(), Some("user@example.test"));
        assert_eq!(credential.auth_type(), "oauth");
        assert_eq!(
            credential.last_refresh(),
            Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );

        let metadata =
            CodexRequestMetadata::new("codex-tui", Some("session-123"), "codex-tui/0.144.0")
                .expect("metadata");
        let authorization = credential.materialize(metadata).expect("authorization");
        let mut headers = HeaderMap::new();
        authorization.apply_to(&mut headers).expect("headers");
        assert_eq!(
            headers[header::AUTHORIZATION],
            HeaderValue::from_static("Bearer access-secret")
        );
        assert_eq!(
            headers[CHATGPT_ACCOUNT_ID_HEADER],
            HeaderValue::from_static("account-123")
        );
        assert_eq!(
            headers[ORIGINATOR_HEADER],
            HeaderValue::from_static("codex-tui")
        );
        assert_eq!(
            headers[SESSION_ID_HEADER],
            HeaderValue::from_static("session-123")
        );
        assert_eq!(
            headers[header::USER_AGENT],
            HeaderValue::from_static("codex-tui/0.144.0")
        );
    }

    #[test]
    fn extracts_and_cross_checks_chatgpt_account_id_from_id_token() {
        let claims = serde_json::json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "account-from-token"
            }
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
        let id_token = format!("e30.{encoded}.signature");
        let extracted = serde_json::json!({
            "access_token": "access",
            "id_token": id_token,
            "type": "codex"
        });
        let credential =
            CodexCredential::from_json(&serde_json::to_vec(&extracted).expect("credential JSON"))
                .expect("account ID extracted");
        assert_eq!(credential.account_id(), Some("account-from-token"));

        let mismatched = serde_json::json!({
            "access_token": "access",
            "id_token": id_token,
            "account_id": "different-account",
            "type": "codex"
        });
        assert_eq!(
            CodexCredential::from_json(&serde_json::to_vec(&mismatched).expect("credential JSON"),),
            Err(CodexCredentialError::AccountIdMismatch)
        );
    }

    #[test]
    fn credential_debug_and_oauth_material_debug_are_redacted() {
        let credential = CodexCredential::from_json(STORED).expect("credential");
        let credential_debug = format!("{credential:?}");
        assert!(!credential_debug.contains("access-secret"));
        assert!(!credential_debug.contains("refresh-secret"));
        assert!(!credential_debug.contains("id-secret"));
        assert!(!credential_debug.contains("user@example.test"));
        assert!(!credential_debug.contains("account-123"));

        let request = provider()
            .begin_authorization("http://127.0.0.1/callback")
            .expect("request");
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(request.code_verifier().expose_secret()));
        assert!(!request_debug.contains(request.state()));
    }

    #[test]
    fn disabled_expired_and_missing_account_credentials_are_rejected() {
        let disabled = br#"{"access_token":"access","account_id":"account","disabled":true}"#;
        assert!(matches!(
            CodexCredential::from_json(disabled)
                .expect("credential")
                .materialize(CodexRequestMetadata::default()),
            Err(CodexCredentialError::Disabled)
        ));
        let expired = br#"{"access_token":"access","account_id":"account","expired":true}"#;
        assert!(matches!(
            CodexCredential::from_json(expired)
                .expect("credential")
                .materialize(CodexRequestMetadata::default()),
            Err(CodexCredentialError::Expired)
        ));
        let missing = br#"{"access_token":"access"}"#;
        assert!(matches!(
            CodexCredential::from_json(missing)
                .expect("credential")
                .materialize(CodexRequestMetadata::default()),
            Err(CodexCredentialError::MissingAccountId)
        ));

        let timestamp = br#"{
            "access_token":"access",
            "account_id":"account",
            "expired":"2099-01-01T00:00:00Z",
            "last_refresh":"2024-01-01T00:00:00Z"
        }"#;
        let credential = CodexCredential::from_json(timestamp).expect("timestamp credential");
        assert!(!credential.is_expired());
        assert!(credential.last_refresh().is_some());
    }

    #[test]
    fn pkce_request_contains_challenge_but_not_verifier() {
        let provider = provider();
        let request = provider
            .begin_authorization("http://127.0.0.1/callback")
            .expect("request");
        let url = Url::parse(request.url()).expect("URL");
        let params = url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            params
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert_eq!(
            params.get("client_id").map(|value| value.as_ref()),
            Some("client-id")
        );
        assert_eq!(
            params.get("redirect_uri").map(|value| value.as_ref()),
            Some("http://127.0.0.1/callback")
        );
        assert!(!request
            .url()
            .contains(request.code_verifier().expose_secret()));

        let callback = CodexAuthorizationCallback::from_query(&format!(
            "?code=code-123&state={}",
            request.state()
        ))
        .expect("callback");
        assert!(callback.state_matches(request.state()));
        assert!(!callback.state_matches("wrong-state"));
        let body = provider
            .code_exchange_body(&callback, &request)
            .expect("body");
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("client_id=client-id"));
        assert!(body.contains("code_verifier="));
    }

    #[test]
    fn code_exchange_rejects_callback_without_matching_authorization_request() {
        let provider = provider();
        let request = provider
            .begin_authorization("http://127.0.0.1/callback")
            .expect("request");
        let other_request = provider
            .begin_authorization("http://127.0.0.1/callback")
            .expect("other request");
        let callback = CodexAuthorizationCallback::from_query(&format!(
            "?code=code-123&state={}",
            other_request.state()
        ))
        .expect("callback");
        assert_eq!(
            provider.code_exchange_body(&callback, &request),
            Err(CodexOAuthError::InvalidState)
        );
    }

    #[test]
    fn callback_rejects_duplicate_code_or_state_parameters() {
        assert!(
            CodexAuthorizationCallback::from_query("?code=first&code=second&state=state").is_err()
        );
        assert!(
            CodexAuthorizationCallback::from_query("?code=code&state=first&state=second").is_err()
        );
    }

    #[test]
    fn callback_debug_redacts_code_and_state() {
        let callback =
            CodexAuthorizationCallback::from_query("?code=authorization-secret&state=state-secret")
                .expect("callback");
        let debug = format!("{callback:?}");
        assert!(!debug.contains("authorization-secret"));
        assert!(!debug.contains("state-secret"));
        assert_eq!(callback.code().expose_secret(), "authorization-secret");
        assert_eq!(callback.state().expose_secret(), "state-secret");
    }

    #[test]
    fn pkce_requires_exact_safe_configured_loopback_redirect() {
        let config = CodexOAuthConfig::new(
            "client-id",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
        )
        .expect("config");
        assert!(config
            .clone()
            .with_redirect_uri("https://example.test/callback")
            .is_err());
        assert!(config
            .clone()
            .with_redirect_uri("http://user:password@127.0.0.1/callback")
            .is_err());
        assert!(config
            .clone()
            .with_redirect_uri("http://127.0.0.1/callback#fragment")
            .is_err());

        let provider = CodexProvider::new(
            config
                .with_redirect_uri("http://127.0.0.1/callback")
                .expect("redirect"),
        )
        .expect("provider");
        assert!(provider
            .begin_authorization("http://127.0.0.1/other")
            .is_err());
        assert!(provider
            .begin_authorization("http://localhost/callback")
            .is_err());
        assert!(CodexProvider::new(
            CodexOAuthConfig::new(
                "client-id",
                "https://auth.example.test/authorize",
                "https://auth.example.test/token",
            )
            .expect("config")
        )
        .expect("provider")
        .begin_authorization("http://127.0.0.1/callback")
        .is_err());
    }

    #[test]
    fn request_debug_does_not_expose_endpoint_or_redirect_details() {
        let config = CodexOAuthConfig::new(
            "client-id",
            "https://auth.example.test/authorize?secret=query-value",
            "https://auth.example.test/token",
        )
        .expect("config")
        .with_redirect_uri("http://127.0.0.1/callback?secret=redirect-value")
        .expect("redirect");
        let request = CodexProvider::new(config)
            .expect("provider")
            .begin_authorization("http://127.0.0.1/callback?secret=redirect-value")
            .expect("request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("query-value"));
        assert!(!debug.contains("redirect-value"));
        assert!(!debug.contains("127.0.0.1"));
    }

    #[test]
    fn token_response_rejects_errors_and_redacts_success() {
        let success = CodexTokenResponse::from_json(
            br#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":60}"#,
        )
        .expect("token response");
        let debug = format!("{success:?}");
        assert!(!debug.contains("new-access"));
        assert!(!debug.contains("new-refresh"));
        let tokens = success.into_tokens(None);
        assert_eq!(tokens.access_token().expose_secret(), "new-access");
        assert_eq!(
            tokens.refresh_token().expect("refresh").expose_secret(),
            "new-refresh"
        );
        assert!(CodexTokenResponse::from_json(
            br#"{"error":"invalid_grant","error_description":"contains-secret"}"#
        )
        .is_err());
    }

    #[test]
    fn credential_file_input_is_bounded_before_json_parsing() {
        let oversized = vec![b' '; (MAX_CODEX_CREDENTIAL_FILE_BYTES + 1) as usize];
        assert_eq!(
            CodexCredential::from_json(&oversized),
            Err(CodexCredentialError::FileTooLarge)
        );
    }

    #[cfg(unix)]
    #[test]
    fn credential_file_open_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("credential.json");
        let link = directory.path().join("credential-link.json");
        std::fs::write(&target, STORED).expect("credential");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
        symlink(&target, &link).expect("symlink");
        assert_eq!(
            CodexCredential::from_file(&link),
            Err(CodexCredentialError::FileIo)
        );
    }

    #[test]
    fn quota_parser_distinguishes_account_model_and_provider_limits() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("30"));
        let parser = CodexQuotaParser::default();
        let account = parser
            .parse(
                &headers,
                br#"{"error":{"code":"usage_limit_reached","message":"account quota"},"remaining":0,"limit":100}"#,
            )
            .expect("account quota")
            .expect("quota evidence");
        assert_eq!(account.scope(), CodexQuotaScope::Credential);
        assert_eq!(account.code(), "usage_limit_reached");
        assert_eq!(account.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(account.remaining(), Some(0));
        assert_eq!(account.limit(), Some(100));

        let model = parser
            .parse(
                &HeaderMap::new(),
                br#"{"error":{"code":"model_quota_exceeded"}}"#,
            )
            .expect("model quota")
            .expect("quota evidence");
        assert_eq!(model.scope(), CodexQuotaScope::Model);

        let conflicting = parser
            .parse(
                &HeaderMap::new(),
                br#"{"error":{"code":"rate_limit_exceeded","message":"usage_limit_reached"}}"#,
            )
            .expect("conflicting markers")
            .expect("rate evidence");
        assert_eq!(conflicting.scope(), CodexQuotaScope::Provider);
        assert_eq!(
            parser
                .parse(
                    &HeaderMap::new(),
                    br#"{"error":{"code":"invalid_request_error","message":"usage_limit_reached"}}"#,
                )
                .expect("invalid marker"),
            None
        );

        let provider = parser
            .parse(&HeaderMap::new(), br#"{"detail":"Rate limit exceeded"}"#)
            .expect("rate limit")
            .expect("rate evidence");
        assert_eq!(provider.scope(), CodexQuotaScope::Provider);
        assert_eq!(provider.code(), "rate_limit_exceeded");

        let event = parser
            .parse_event(
                br#"event: error
data: {"type":"error","code":"usage_limit_reached"}

"#,
            )
            .expect("event")
            .expect("quota event");
        assert_eq!(event.scope(), CodexQuotaScope::Credential);

        let mut quota_headers = HeaderMap::new();
        quota_headers.insert(
            "x-ratelimit-remaining-requests",
            HeaderValue::from_static("0"),
        );
        quota_headers.insert("x-ratelimit-limit-requests", HeaderValue::from_static("10"));
        let header_quota = parser
            .parse(&quota_headers, b"")
            .expect("header quota")
            .expect("header evidence");
        assert_eq!(header_quota.scope(), CodexQuotaScope::Provider);
        assert_eq!(header_quota.remaining(), Some(0));
        assert_eq!(header_quota.limit(), Some(10));
    }

    #[test]
    fn classifier_proves_credential_causation_only_for_account_quota() {
        let classifier = CodexFailureClassifier::default();
        let account = classifier.classify_response(
            429,
            &HeaderMap::new(),
            br#"{"error":{"code":"usage_limit_reached"}}"#,
        );
        assert_eq!(
            account.classification.class,
            ErrorClass::CredentialQuotaExhausted
        );
        assert_eq!(
            account.credential_causation,
            pooler_policy::CredentialCausation::Proven
        );
        assert_eq!(
            account.evidence.summary.as_deref(),
            Some("Codex account quota exhausted")
        );

        let rate = classifier.classify_response(
            429,
            &HeaderMap::new(),
            br#"{"detail":"Rate limit exceeded"}"#,
        );
        assert_eq!(rate.classification.class, ErrorClass::ProviderRateLimited);
        assert_eq!(
            rate.credential_causation,
            pooler_policy::CredentialCausation::Unknown
        );
    }

    #[test]
    fn invalid_http_statuses_do_not_turn_quota_markers_into_cooldowns() {
        let classifier = CodexFailureClassifier::default();
        let body = br#"{"error":{"code":"usage_limit_reached"}}"#;
        for (status, class) in [
            (400, ErrorClass::InvalidRequest),
            (401, ErrorClass::ProviderAuthentication),
            (422, ErrorClass::InvalidRequest),
        ] {
            let result = classifier.classify_response(status, &HeaderMap::new(), body);
            assert_eq!(result.classification.class, class);
            assert_eq!(result.cooldown, None);
            assert_eq!(result.classification.recovery_after, None);
        }
        let valid = classifier.classify_response(429, &HeaderMap::new(), body);
        assert_eq!(
            valid.classification.class,
            ErrorClass::CredentialQuotaExhausted
        );
        assert!(valid.cooldown.is_some());
        let invalid_429 = classifier.classify_response(
            429,
            &HeaderMap::new(),
            br#"{"error":{"code":"invalid_request_error"}}"#,
        );
        assert_eq!(invalid_429.classification.class, ErrorClass::InvalidRequest);
        assert_eq!(invalid_429.cooldown, None);
    }

    #[test]
    fn oversized_or_malformed_quota_body_falls_back_conservatively() {
        let classifier = CodexFailureClassifier::new(8);
        let oversized = classifier.classify_response(429, &HeaderMap::new(), b"0123456789");
        assert_eq!(
            oversized.classification.class,
            ErrorClass::ProviderRateLimited
        );
        assert_eq!(
            CodexQuotaParser::default().parse(&HeaderMap::new(), b"{not-json"),
            Err(CodexQuotaError::InvalidJson)
        );
        assert_eq!(
            CodexQuotaParser::new(8)
                .parse_event(b"data: {\"error\":{\"code\":\"usage_limit_reached\"}}\n"),
            Err(CodexQuotaError::BodyTooLarge)
        );
    }

    #[test]
    fn device_poll_preserves_pending_states() {
        assert_eq!(
            parse_device_poll(br#"{"error":"authorization_pending"}"#).expect("pending"),
            CodexDevicePoll::AuthorizationPending
        );
        assert_eq!(
            parse_device_poll(br#"{"error":"slow_down"}"#).expect("slow down"),
            CodexDevicePoll::SlowDown
        );
        let authorized = parse_device_poll(
            br#"{"access_token":"device-access","refresh_token":"device-refresh","expires_in":60}"#,
        )
        .expect("authorized");
        assert!(matches!(authorized, CodexDevicePoll::Authorized(_)));
    }

    #[test]
    fn device_verification_uri_is_validated_and_redacted() {
        let valid = CodexDeviceAuthorization::from_json(
            br#"{"device_code":"device-secret","user_code":"ABCD","verification_uri":"https://auth.example.test/device","expires_in":600}"#,
        )
        .expect("device authorization");
        assert_eq!(valid.verification_uri(), "https://auth.example.test/device");
        let debug = format!("{valid:?}");
        assert!(!debug.contains("auth.example.test"));
        for uri in [
            "http://auth.example.test/device",
            "https://user:password@auth.example.test/device",
            "https://auth.example.test/device#fragment",
            "/relative/device",
        ] {
            let body = format!(
                r#"{{"device_code":"device","user_code":"ABCD","verification_uri":"{uri}","expires_in":600}}"#
            );
            assert!(CodexDeviceAuthorization::from_json(body.as_bytes()).is_err());
        }
    }

    #[tokio::test]
    async fn concurrent_refreshes_share_one_provider_operation() {
        let provider = provider();
        let calls = Arc::new(AtomicUsize::new(0));
        let credential = CredentialId::new("codex-refresh").expect("credential");
        let first_provider = provider.clone();
        let first_calls = calls.clone();
        let first_credential = credential.clone();
        let first = tokio::spawn(async move {
            first_provider
                .refresh_with(
                    first_credential,
                    SecretValue::new("refresh-secret"),
                    move |_refresh| {
                        first_calls.fetch_add(1, Ordering::SeqCst);
                        async {
                            tokio::task::yield_now().await;
                            CodexTokenResponse::from_json(
                                br#"{"access_token":"refreshed","expires_in":60}"#,
                            )
                        }
                    },
                )
                .await
        });
        let second_provider = provider.clone();
        let second_credential = credential;
        let second = tokio::spawn(async move {
            second_provider
                .refresh_with(
                    second_credential,
                    SecretValue::new("refresh-secret"),
                    |_refresh| async {
                        CodexTokenResponse::from_json(
                            br#"{"access_token":"unexpected","expires_in":60}"#,
                        )
                    },
                )
                .await
        });
        let (first, second) = tokio::join!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let first = first.expect("first task").expect("first refresh");
        let second = second.expect("second task").expect("second refresh");
        assert_eq!(first.access_token().expose_secret(), "refreshed");
        assert_eq!(
            first
                .refresh_token()
                .expect("refresh token")
                .expose_secret(),
            "refresh-secret"
        );
        assert_eq!(second.access_token().expose_secret(), "refreshed");
        assert_eq!(
            second
                .refresh_token()
                .expect("refresh token")
                .expose_secret(),
            "refresh-secret"
        );
        assert_eq!(provider.active_refresh_leases(), 0);
    }
}
