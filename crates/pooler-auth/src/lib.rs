//! Authentication primitives used by Pooler.
//!
//! The crate deliberately keeps secret acquisition behind explicit policy and
//! backend boundaries.  Parsing a [`SecretRef`] never reads a source, and the
//! default resolver will not execute commands, accept literals, or silently
//! use an OS keyring implementation unless the optional backend is enabled.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

pub use pooler_core::CredentialId;
use thiserror::Error;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
#[cfg(test)]
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

mod keyring_backend;
mod oauth;
mod provider_login;

pub use keyring_backend::{KeyringBackend, KeyringProvider, OsKeyringBackend};
pub use oauth::*;
pub use provider_login::*;

/// Authentication material selected for one configured account.
///
/// API keys remain external [`SecretRef`] values. OAuth credentials are held
/// in the encrypted token store and may represent subscription access.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthKind {
    /// Usage-based provider API key.
    ApiKey,
    /// OAuth bearer credential, including ChatGPT/Codex subscription access.
    OAuth,
}

impl AuthKind {
    /// Stable operator-facing spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::OAuth => "oauth",
        }
    }
}

impl fmt::Display for AuthKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A secret held in memory and zeroized when dropped.
///
/// `Debug` and `Display` are intentionally redacted.  Callers must opt into
/// [`SecretValue::expose_secret`] at the small boundary where a secret is
/// actually needed.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Construct a secret from UTF-8 text.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into().into_bytes()))
    }

    /// Construct a secret from bytes, rejecting invalid UTF-8.
    pub fn from_bytes(mut value: Vec<u8>) -> Result<Self, SecretValueError> {
        if std::str::from_utf8(&value).is_err() {
            value.zeroize();
            return Err(SecretValueError::InvalidUtf8);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Return the secret text for the outbound operation that needs it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        // `from_bytes` validates arbitrary input and `new` only accepts a
        // String, so this conversion cannot fail for a constructed value.
        std::str::from_utf8(&self.0).expect("SecretValue invariant: valid UTF-8")
    }

    /// Return the secret bytes for protocols that do not use text.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the secret contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of UTF-8 bytes in the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Errors constructing a secret value.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretValueError {
    /// Secret material was not valid UTF-8.
    #[error("secret is not valid UTF-8")]
    InvalidUtf8,
}

/// A source reference for a secret.
///
/// This enum contains references, not resolved values.  Its custom `Debug`
/// implementation redacts literals and never prints command arguments, since
/// command arguments can themselves contain sensitive values.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// An environment variable name.
    Env(String),
    /// An owner-only file path.
    File(PathBuf),
    /// A keyring service and account lookup.
    Keyring {
        /// OS keyring service name.
        service: String,
        /// OS keyring account name.
        account: String,
    },
    /// An explicitly configured command provider invocation.
    Command {
        /// Executable name or path.  No shell is implied.
        program: String,
        /// Arguments passed directly to the configured command provider.
        args: Vec<String>,
    },
    /// A literal development-only secret.
    Literal(SecretValue),
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => formatter.debug_tuple("Env").field(name).finish(),
            Self::File(path) => formatter.debug_tuple("File").field(path).finish(),
            Self::Keyring { service, account } => formatter
                .debug_struct("Keyring")
                .field("service", service)
                .field("account", account)
                .finish(),
            Self::Command { program, .. } => formatter
                .debug_struct("Command")
                .field("program", program)
                .field("args", &"[REDACTED]")
                .finish(),
            Self::Literal(_) => formatter.write_str("Literal([REDACTED])"),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => write!(formatter, "env:{name}"),
            Self::File(path) => write!(formatter, "file:{}", path.display()),
            Self::Keyring { service, account } => write!(formatter, "keyring:{service}/{account}"),
            Self::Command { program, .. } => write!(formatter, "command:{program} [REDACTED]"),
            Self::Literal(_) => formatter.write_str("literal:[REDACTED]"),
        }
    }
}

impl std::str::FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl SecretRef {
    /// Parse a source reference without accessing the referenced source.
    pub fn parse(value: &str) -> Result<Self, SecretRefError> {
        let (kind, payload) = value.split_once(':').ok_or(SecretRefError::MissingScheme)?;
        if payload.is_empty() {
            return Err(SecretRefError::EmptyReference);
        }

        match kind {
            "env" => {
                validate_env_name(payload)?;
                Ok(Self::Env(payload.to_owned()))
            }
            "file" => Ok(Self::File(PathBuf::from(payload))),
            "keyring" => parse_keyring(payload),
            "command" => parse_command(payload),
            "literal" => Ok(Self::Literal(SecretValue::new(payload))),
            _ => Err(SecretRefError::UnknownScheme),
        }
    }

    /// Return the source kind without exposing any source payload.
    #[must_use]
    pub fn kind(&self) -> SecretSourceKind {
        match self {
            Self::Env(_) => SecretSourceKind::Environment,
            Self::File(_) => SecretSourceKind::File,
            Self::Keyring { .. } => SecretSourceKind::Keyring,
            Self::Command { .. } => SecretSourceKind::Command,
            Self::Literal(_) => SecretSourceKind::Literal,
        }
    }

    /// Resolve with the default restrictive policy and optional OS keyring.
    pub fn resolve(&self) -> Result<SecretValue, SecretError> {
        self.resolve_with(
            &SecretResolveOptions::default(),
            &OsKeyringBackend::default(),
        )
    }

    /// Resolve with an explicit policy and backend.
    pub fn resolve_with(
        &self,
        options: &SecretResolveOptions,
        backend: &dyn SecretBackend,
    ) -> Result<SecretValue, SecretError> {
        match self {
            Self::Env(name) => resolve_environment(name),
            Self::File(path) => resolve_file(path, options),
            Self::Keyring { service, account } => backend
                .keyring(service, account)?
                .ok_or(SecretError::BackendUnavailable(
                    "keyring backend returned no secret",
                ))
                .and_then(non_empty),
            Self::Command { program, args } => {
                if !options.allow_command {
                    return Err(SecretError::CommandSourceDisabled);
                }
                backend
                    .command(program, args)?
                    .ok_or(SecretError::BackendUnavailable(
                        "command backend returned no secret",
                    ))
                    .and_then(non_empty)
            }
            Self::Literal(value) => {
                if !options.allow_literal {
                    return Err(SecretError::LiteralSourceDisabled);
                }
                Ok(value.clone())
            }
        }
    }

    /// Resolve with explicit policy and no external backend.
    pub fn resolve_with_options(
        &self,
        options: &SecretResolveOptions,
    ) -> Result<SecretValue, SecretError> {
        self.resolve_with(options, &OsKeyringBackend::default())
    }
}

fn validate_env_name(name: &str) -> Result<(), SecretRefError> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(SecretRefError::EmptyReference);
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || chars.any(|character| !(character == '_' || character.is_ascii_alphanumeric()))
    {
        return Err(SecretRefError::InvalidEnvironmentName);
    }
    Ok(())
}

fn parse_keyring(payload: &str) -> Result<SecretRef, SecretRefError> {
    let (service, account) = payload
        .split_once('/')
        .or_else(|| payload.split_once(':'))
        .ok_or(SecretRefError::InvalidKeyringReference)?;
    if service.is_empty() || account.is_empty() || account.contains('/') {
        return Err(SecretRefError::InvalidKeyringReference);
    }
    Ok(SecretRef::Keyring {
        service: service.to_owned(),
        account: account.to_owned(),
    })
}

fn parse_command(payload: &str) -> Result<SecretRef, SecretRefError> {
    let mut fields = payload.split_whitespace();
    let Some(program) = fields.next() else {
        return Err(SecretRefError::EmptyReference);
    };
    // Command references are intentionally not shell syntax.  This simple
    // tokenization keeps a future provider from accidentally invoking a shell.
    Ok(SecretRef::Command {
        program: program.to_owned(),
        args: fields.map(ToOwned::to_owned).collect(),
    })
}

fn resolve_environment(name: &str) -> Result<SecretValue, SecretError> {
    let value = std::env::var(name).map_err(|_| SecretError::EnvironmentUnavailable {
        name: name.to_owned(),
    })?;
    non_empty(SecretValue::new(value))
}

fn resolve_file(path: &Path, options: &SecretResolveOptions) -> Result<SecretValue, SecretError> {
    let mut file = open_secret_file(path)?;
    let metadata = file.metadata().map_err(|source| SecretError::Io {
        path: path.to_owned(),
        source,
    })?;
    validate_owner_only_metadata(path, &metadata)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| SecretError::Io {
            path: path.to_owned(),
            source,
        })?;
    if options.trim_file_newline {
        trim_one_newline(&mut bytes);
    }
    non_empty(SecretValue::from_bytes(bytes).map_err(SecretError::InvalidValue)?)
}

fn open_secret_file(path: &Path) -> Result<std::fs::File, SecretError> {
    #[cfg(unix)]
    let result = {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    };
    #[cfg(not(unix))]
    let result = std::fs::File::open(path);

    result.map_err(|source| SecretError::Io {
        path: path.to_owned(),
        source,
    })
}

fn trim_one_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

fn non_empty(value: SecretValue) -> Result<SecretValue, SecretError> {
    if value.is_empty() {
        Err(SecretError::EmptySecret)
    } else {
        Ok(value)
    }
}

/// Source categories accepted by [`SecretRef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSourceKind {
    /// Environment variable.
    Environment,
    /// Owner-only file.
    File,
    /// External OS keyring.
    Keyring,
    /// Explicit command provider.
    Command,
    /// Development-only literal.
    Literal,
}

/// Parsing failures for secret references.  Errors intentionally do not echo
/// the input, because a `literal:` reference is itself sensitive.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretRefError {
    /// The reference did not contain a `scheme:` prefix.
    #[error("secret reference is missing a scheme")]
    MissingScheme,
    /// The scheme payload was empty.
    #[error("secret reference is empty")]
    EmptyReference,
    /// The source scheme is unsupported.
    #[error("unknown secret reference scheme")]
    UnknownScheme,
    /// Environment names must be portable and shell-independent.
    #[error("invalid environment variable name")]
    InvalidEnvironmentName,
    /// Keyring references need `service/account` (or `service:account`).
    #[error("invalid keyring reference")]
    InvalidKeyringReference,
}

/// Runtime failures resolving a secret reference.
#[derive(Debug, Error)]
pub enum SecretError {
    /// Environment value was not present or was not valid Unicode.
    #[error("environment variable {name:?} is unavailable")]
    EnvironmentUnavailable { name: String },
    /// Command references are disabled unless explicitly enabled.
    #[error("command secret sources are disabled")]
    CommandSourceDisabled,
    /// Literal references are disabled unless explicitly enabled.
    #[error("literal secret sources are disabled")]
    LiteralSourceDisabled,
    /// Keyring or command resolution requires a configured backend.
    #[error("secret backend is unavailable: {0}")]
    BackendUnavailable(&'static str),
    /// The optional native OS keyring is disabled or could not be accessed.
    #[error("OS keyring is unavailable")]
    KeyringUnavailable,
    /// A source returned an empty value.
    #[error("secret source returned an empty value")]
    EmptySecret,
    /// File permissions or type were unsafe.
    #[error("secret file is not owner-only: {path}")]
    InsecureFilePermissions { path: PathBuf },
    /// The file was not a regular file.
    #[error("secret path is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    /// File or source I/O failed.
    #[error("could not read secret source {path}: {source}")]
    Io {
        /// Source path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Secret source bytes were not UTF-8.
    #[error("secret source is not valid UTF-8")]
    InvalidValue(SecretValueError),
}

/// Controls which potentially dangerous secret sources are enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretResolveOptions {
    /// Permit `command:` references when a backend is configured.
    pub allow_command: bool,
    /// Permit `literal:` references.  This should only be enabled in a
    /// development configuration with an explicit startup warning.
    pub allow_literal: bool,
    /// Remove one trailing CRLF/LF from file-backed secrets.
    pub trim_file_newline: bool,
}

impl Default for SecretResolveOptions {
    fn default() -> Self {
        Self {
            allow_command: false,
            allow_literal: false,
            trim_file_newline: true,
        }
    }
}

/// Explicit provider for sources that require an external integration.
///
/// Returning `Ok(None)` means that no value was found.  Implementations must
/// return a [`SecretValue`] so raw material remains redacted by default.
pub trait SecretBackend: Send + Sync {
    /// Resolve an OS keyring item.
    fn keyring(&self, _service: &str, _account: &str) -> Result<Option<SecretValue>, SecretError> {
        Ok(None)
    }

    /// Resolve a command source.  The implementation must not invoke a shell
    /// unless that is an explicit, separately reviewed product choice.
    fn command(
        &self,
        _program: &str,
        _args: &[String],
    ) -> Result<Option<SecretValue>, SecretError> {
        Ok(None)
    }
}

/// Check that a credential file is a regular owner-only file.
///
/// On Unix, all group and other permission bits must be clear (`0600`,
/// `0400`, and similarly restrictive modes are accepted).  Symlinks are
/// rejected to avoid validating one inode and opening another.  On platforms
/// without Unix mode bits, regular-file validation still applies.
pub fn validate_owner_only_file(path: impl AsRef<Path>) -> Result<(), SecretError> {
    let path = path.as_ref();
    let metadata = std::fs::symlink_metadata(path).map_err(|source| SecretError::Io {
        path: path.to_owned(),
        source,
    })?;
    validate_owner_only_metadata(path, &metadata)
}

fn validate_owner_only_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SecretError> {
    if !metadata.file_type().is_file() {
        return Err(SecretError::NotRegularFile {
            path: path.to_owned(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        let wrong_owner = metadata.uid() != rustix::process::geteuid().as_raw();
        if wrong_owner || mode & 0o077 != 0 || mode & 0o400 == 0 {
            return Err(SecretError::InsecureFilePermissions {
                path: path.to_owned(),
            });
        }
    }

    Ok(())
}

/// Alias emphasizing that this helper validates permissions, not file
/// contents.
pub fn validate_owner_only_permissions(path: impl AsRef<Path>) -> Result<(), SecretError> {
    validate_owner_only_file(path)
}

/// A credential handle carrying one secret for a bounded operation.
///
/// The handle's `Debug` output includes only its opaque identifier.  It does
/// not include the token, its length, or any other derived credential value.
pub struct CredentialHandle {
    id: CredentialId,
    secret: SecretValue,
}

impl CredentialHandle {
    /// Create a handle from secret text.
    #[must_use]
    pub fn new(id: CredentialId, secret: impl Into<String>) -> Self {
        Self {
            id,
            secret: SecretValue::new(secret),
        }
    }

    /// Create a handle from an already protected value.
    #[must_use]
    pub fn from_secret(id: CredentialId, secret: SecretValue) -> Self {
        Self { id, secret }
    }

    /// Opaque identifier associated with this credential.
    #[must_use]
    pub fn id(&self) -> CredentialId {
        self.id.clone()
    }

    /// Borrow secret material at an explicit outbound boundary.
    #[must_use]
    pub fn secret(&self) -> &SecretValue {
        &self.secret
    }

    /// Compare an incoming bearer token without allocating or exposing the
    /// expected token.
    #[must_use]
    pub fn bearer_matches(&self, provided: &str) -> bool {
        constant_time_eq(provided.as_bytes(), self.secret.expose_bytes())
    }

    /// Compare a complete `Authorization` header against this credential.
    #[must_use]
    pub fn authorization_matches(&self, header: &str) -> bool {
        bearer_authorization_matches(header, &self.secret)
    }
}

impl Clone for CredentialHandle {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            secret: self.secret.clone(),
        }
    }
}

impl fmt::Debug for CredentialHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialHandle")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Compare two byte strings using work proportional to their maximum length.
///
/// The length is necessarily observable, but the byte comparison does not
/// return early based on matching or mismatching secret bytes.  This function
/// is intentionally kept local so every bearer-auth call site uses the same
/// comparison behavior.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

/// Compare a bearer token against a `Bearer <token>` authorization header.
#[must_use]
pub fn bearer_authorization_matches(header: &str, expected: &SecretValue) -> bool {
    let Some((scheme, credentials)) = header.split_once(char::is_whitespace) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let credentials = credentials.trim_matches(|character: char| character.is_ascii_whitespace());
    if credentials.is_empty() {
        return false;
    }
    constant_time_eq(credentials.as_bytes(), expected.expose_bytes())
}

/// OAuth token material held in a redacting wrapper.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokens {
    access_token: SecretValue,
    refresh_token: Option<SecretValue>,
    expires_at: Option<SystemTime>,
    token_type: String,
}

impl OAuthTokens {
    /// Construct bearer tokens with the conventional `Bearer` token type.
    #[must_use]
    pub fn bearer(
        access_token: impl Into<String>,
        refresh_token: Option<impl Into<String>>,
        expires_at: Option<SystemTime>,
    ) -> Self {
        Self {
            access_token: SecretValue::new(access_token),
            refresh_token: refresh_token.map(|value| SecretValue::new(value.into())),
            expires_at,
            token_type: "Bearer".to_owned(),
        }
    }

    /// Construct tokens with an explicit OAuth token type.
    #[must_use]
    pub fn new(
        access_token: SecretValue,
        refresh_token: Option<SecretValue>,
        expires_at: Option<SystemTime>,
        token_type: impl Into<String>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
            token_type: token_type.into(),
        }
    }

    /// Access token for one outbound request.
    #[must_use]
    pub fn access_token(&self) -> &SecretValue {
        &self.access_token
    }

    /// Optional refresh token.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&SecretValue> {
        self.refresh_token.as_ref()
    }

    /// OAuth token type, such as `Bearer`.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Expiry supplied by the provider, if known.
    #[must_use]
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

impl fmt::Debug for OAuthTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokens")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// One imported or newly authenticated OAuth account profile.
///
/// The profile name is non-secret provider metadata. Token and identity
/// material remains protected and debug output reports presence only.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthCredentialProfile {
    provider_profile: String,
    tokens: OAuthTokens,
    id_token: Option<SecretValue>,
    account_id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    expired: bool,
    disabled: bool,
    last_refresh: Option<SystemTime>,
}

impl OAuthCredentialProfile {
    /// Create an active OAuth profile from protected tokens.
    #[must_use]
    pub fn new(provider_profile: impl Into<String>, tokens: OAuthTokens) -> Self {
        Self {
            provider_profile: provider_profile.into(),
            tokens,
            id_token: None,
            account_id: None,
            email: None,
            name: None,
            expired: false,
            disabled: false,
            last_refresh: None,
        }
    }

    /// Attach a provider identity returned by a documented identity endpoint.
    #[must_use]
    pub fn with_identity(mut self, identity: OAuthIdentity) -> Self {
        self.account_id = Some(identity.subject);
        self.email = identity.email;
        self.name = identity.name;
        self
    }

    /// Attach an explicitly verified provider account identifier.
    #[must_use]
    pub fn with_account_id(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = Some(account_id.into());
        self
    }

    /// Attach an optional encrypted ID token from an imported profile.
    #[must_use]
    pub fn with_id_token(mut self, id_token: Option<SecretValue>) -> Self {
        self.id_token = id_token;
        self
    }

    /// Attach optional non-secret account display metadata.
    #[must_use]
    pub fn with_email(mut self, email: Option<String>) -> Self {
        self.email = email;
        self
    }

    /// Retain imported lifecycle metadata.
    #[must_use]
    pub const fn with_lifecycle(
        mut self,
        expired: bool,
        disabled: bool,
        last_refresh: Option<SystemTime>,
    ) -> Self {
        self.expired = expired;
        self.disabled = disabled;
        self.last_refresh = last_refresh;
        self
    }

    /// Canonical provider login profile.
    #[must_use]
    pub fn provider_profile(&self) -> &str {
        &self.provider_profile
    }

    /// Protected OAuth token set.
    #[must_use]
    pub const fn tokens(&self) -> &OAuthTokens {
        &self.tokens
    }

    /// Consume the profile and return its token set.
    #[must_use]
    pub fn into_tokens(self) -> OAuthTokens {
        self.tokens
    }

    /// Optional imported ID token.
    #[must_use]
    pub const fn id_token(&self) -> Option<&SecretValue> {
        self.id_token.as_ref()
    }

    /// Provider-stable account identifier.
    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Optional provider email metadata.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Optional provider display name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Whether the imported source marked the token expired.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    /// Whether the imported source marked the account disabled.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Imported last-refresh timestamp.
    #[must_use]
    pub const fn last_refresh(&self) -> Option<SystemTime> {
        self.last_refresh
    }
}

impl fmt::Debug for OAuthCredentialProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthCredentialProfile")
            .field("provider_profile", &self.provider_profile)
            .field("tokens", &self.tokens)
            .field("has_id_token", &self.id_token.is_some())
            .field("has_account_id", &self.account_id.is_some())
            .field("has_email", &self.email.is_some())
            .field("has_name", &self.name.is_some())
            .field("expired", &self.expired)
            .field("disabled", &self.disabled)
            .field("last_refresh", &self.last_refresh)
            .finish()
    }
}

/// Refresh failures retain only safe categories and redacted diagnostics;
/// they never include a token or authorization header.
#[derive(Error, Clone, PartialEq, Eq)]
pub enum RefreshError {
    /// The provider rejected or failed the refresh operation.
    #[error("oauth refresh failed")]
    Failed(String),
    /// The leader task was cancelled before completing the refresh.
    #[error("oauth refresh was cancelled")]
    Cancelled,
    /// The provider rejected the grant and interactive login is required.
    #[error("oauth provider requires reauthorization")]
    NeedsReauth,
    /// A compare-and-swap token commit lost a generation race.
    #[error("oauth token generation changed during refresh")]
    GenerationConflict,
    /// A structured OAuth operation error, rendered without provider bodies.
    #[error("oauth refresh operation failed")]
    OAuth(oauth::OAuthError),
}

impl fmt::Debug for RefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
            Self::NeedsReauth => "needs_reauth",
            Self::GenerationConflict => "generation_conflict",
            Self::OAuth(_) => "oauth",
        };
        formatter
            .debug_struct("RefreshError")
            .field("kind", &kind)
            .finish()
    }
}

struct RefreshEntry {
    result: Mutex<Option<Result<OAuthTokens, RefreshError>>>,
    complete: Notify,
}

impl RefreshEntry {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            complete: Notify::new(),
        }
    }
}

struct CoordinatorState {
    entries: Mutex<HashMap<CredentialId, Arc<RefreshEntry>>>,
}

/// Coordinates at most one OAuth refresh operation per credential.
///
/// The coordinator uses a synchronous, short-held map lock so a dropped leader
/// can release its entry from `Drop`.  Waiters observe the same result and do
/// not start a second refresh.  Dropping a waiter has no effect on the leader;
/// dropping the leader publishes [`RefreshError::Cancelled`] and wakes any
/// remaining waiters.
#[derive(Clone)]
pub struct RefreshCoordinator {
    state: Arc<CoordinatorState>,
}

impl Default for RefreshCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshCoordinator {
    /// Create an empty coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(CoordinatorState {
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Number of currently active refresh leases.
    #[must_use]
    pub fn active_leases(&self) -> usize {
        lock_unpoisoned(&self.state.entries).len()
    }

    /// Run one refresh operation, sharing its result with concurrent callers.
    pub async fn refresh<F, Fut>(
        &self,
        credential: CredentialId,
        operation: F,
    ) -> Result<OAuthTokens, RefreshError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<OAuthTokens, RefreshError>>,
    {
        let (entry, leader) = {
            let mut entries = lock_unpoisoned(&self.state.entries);
            if let Some(entry) = entries.get(&credential) {
                (Arc::clone(entry), false)
            } else {
                let entry = Arc::new(RefreshEntry::new());
                entries.insert(credential.clone(), Arc::clone(&entry));
                (entry, true)
            }
        };

        if !leader {
            return wait_for_refresh(&entry).await;
        }

        let mut guard = LeaderGuard {
            coordinator: self.clone(),
            credential,
            entry: Arc::clone(&entry),
            completed: false,
        };
        let result = operation().await;
        guard.complete(result.clone());
        result
    }

    /// Run one refresh operation with cancellation-aware leader and waiter
    /// behavior.  Cancelling a waiter leaves the leader's lease untouched;
    /// cancelling the leader publishes a terminal cancellation result so no
    /// refresh lease remains stuck.
    pub async fn refresh_cancellable<F, Fut>(
        &self,
        credential: CredentialId,
        cancellation: CancellationToken,
        operation: F,
    ) -> Result<OAuthTokens, RefreshError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<OAuthTokens, RefreshError>>,
    {
        let (entry, leader) = {
            let mut entries = lock_unpoisoned(&self.state.entries);
            if let Some(entry) = entries.get(&credential) {
                (Arc::clone(entry), false)
            } else {
                let entry = Arc::new(RefreshEntry::new());
                entries.insert(credential.clone(), Arc::clone(&entry));
                (entry, true)
            }
        };

        if !leader {
            return tokio::select! {
                result = wait_for_refresh(&entry) => result,
                () = cancellation.cancelled() => Err(RefreshError::Cancelled),
            };
        }

        let mut guard = LeaderGuard {
            coordinator: self.clone(),
            credential,
            entry: Arc::clone(&entry),
            completed: false,
        };
        let result = tokio::select! {
            () = cancellation.cancelled() => Err(RefreshError::Cancelled),
            result = operation() => result,
        };
        guard.complete(result.clone());
        result
    }

    /// Alias for [`RefreshCoordinator::refresh`] that reads naturally at a
    /// call site obtaining a token for a request.
    pub async fn get_or_refresh<F, Fut>(
        &self,
        credential: CredentialId,
        operation: F,
    ) -> Result<OAuthTokens, RefreshError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<OAuthTokens, RefreshError>>,
    {
        self.refresh(credential, operation).await
    }
}

async fn wait_for_refresh(entry: &RefreshEntry) -> Result<OAuthTokens, RefreshError> {
    loop {
        let notified = entry.complete.notified();
        if let Some(result) = lock_unpoisoned(&entry.result).clone() {
            return result;
        }
        notified.await;
    }
}

struct LeaderGuard {
    coordinator: RefreshCoordinator,
    credential: CredentialId,
    entry: Arc<RefreshEntry>,
    completed: bool,
}

impl LeaderGuard {
    fn complete(&mut self, result: Result<OAuthTokens, RefreshError>) {
        *lock_unpoisoned(&self.entry.result) = Some(result);
        remove_entry(
            &self.coordinator.state.entries,
            &self.credential,
            &self.entry,
        );
        self.entry.complete.notify_waiters();
        self.completed = true;
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        *lock_unpoisoned(&self.entry.result) = Some(Err(RefreshError::Cancelled));
        remove_entry(
            &self.coordinator.state.entries,
            &self.credential,
            &self.entry,
        );
        self.entry.complete.notify_waiters();
    }
}

fn remove_entry(
    entries: &Mutex<HashMap<CredentialId, Arc<RefreshEntry>>>,
    credential: &CredentialId,
    expected: &Arc<RefreshEntry>,
) {
    let mut entries = lock_unpoisoned(entries);
    let should_remove = entries
        .get(credential)
        .is_some_and(|current| Arc::ptr_eq(current, expected));
    if should_remove {
        entries.remove(credential);
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// `Zeroizing<Vec<u8>>` already zeroizes the bytes.  This explicit impl keeps
// the invariant obvious if its representation changes in the future.
impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[test]
    fn parses_references_without_resolving_them() {
        assert_eq!(
            SecretRef::parse("env:POOLER_KEY").unwrap(),
            SecretRef::Env("POOLER_KEY".into())
        );
        assert_eq!(
            SecretRef::parse("file:/tmp/pooler-key").unwrap(),
            SecretRef::File(PathBuf::from("/tmp/pooler-key"))
        );
        assert_eq!(
            SecretRef::parse("keyring:pooler/account").unwrap(),
            SecretRef::Keyring {
                service: "pooler".into(),
                account: "account".into()
            }
        );
        let command = SecretRef::parse("command:provider --account acct").unwrap();
        assert!(matches!(command, SecretRef::Command { .. }));
        assert!(matches!(
            SecretRef::parse("literal:dev-only"),
            Ok(SecretRef::Literal(_))
        ));
    }

    #[test]
    fn command_and_literal_are_disabled_by_default() {
        let command = SecretRef::parse("command:provider").unwrap();
        assert!(matches!(
            command.resolve(),
            Err(SecretError::CommandSourceDisabled)
        ));
        let literal = SecretRef::parse("literal:dev-only").unwrap();
        assert!(matches!(
            literal.resolve(),
            Err(SecretError::LiteralSourceDisabled)
        ));
        let options = SecretResolveOptions {
            allow_literal: true,
            ..SecretResolveOptions::default()
        };
        assert_eq!(
            literal
                .resolve_with_options(&options)
                .unwrap()
                .expose_secret(),
            "dev-only"
        );
    }

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let value = SecretValue::new("super-secret");
        assert_eq!(format!("{value:?}"), "[REDACTED]");
        assert_eq!(value.to_string(), "[REDACTED]");
        let handle = CredentialHandle::new(
            CredentialId::new("credential-test").expect("valid credential ID"),
            "super-secret",
        );
        let rendered = format!("{handle:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(!format!("{handle:?}").contains("len"));
    }

    #[test]
    fn bearer_matching_is_scheme_aware_and_constant_time_api() {
        let expected = SecretValue::new("s3cret");
        assert!(constant_time_eq(b"s3cret", b"s3cret"));
        assert!(!constant_time_eq(b"s3cret", b"s3cret!"));
        assert!(bearer_authorization_matches("Bearer s3cret", &expected));
        assert!(bearer_authorization_matches("bearer   s3cret", &expected));
        assert!(!bearer_authorization_matches("Basic s3cret", &expected));
        assert!(!bearer_authorization_matches("Bearer wrong", &expected));
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_file_permissions_are_enforced() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("pooler-auth-{}", Uuid::new_v4()));
        std::fs::write(&path, "file-secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_owner_only_file(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            validate_owner_only_file(&path),
            Err(SecretError::InsecureFilePermissions { .. })
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_open_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let target = std::env::temp_dir().join(format!("pooler-auth-target-{}", Uuid::new_v4()));
        let path = std::env::temp_dir().join(format!("pooler-auth-link-{}", Uuid::new_v4()));
        std::fs::write(&target, "file-secret\n").unwrap();
        symlink(&target, &path).unwrap();

        assert!(open_secret_file(&path).is_err());
        assert!(SecretRef::File(path.clone()).resolve().is_err());

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    #[tokio::test]
    async fn concurrent_refreshes_share_one_result() {
        let coordinator = RefreshCoordinator::new();
        let id = CredentialId::new("credential-refresh").expect("valid credential ID");
        let calls = Arc::new(AtomicUsize::new(0));
        let (ready_tx, ready_rx) = oneshot::channel();
        let first_calls = Arc::clone(&calls);
        let first_id = id.clone();
        let first = {
            let coordinator = coordinator.clone();
            tokio::spawn(async move {
                coordinator
                    .refresh(first_id, || async move {
                        first_calls.fetch_add(1, Ordering::SeqCst);
                        let _ = ready_rx.await;
                        Ok(OAuthTokens::bearer("access", Some("refresh"), None))
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        let second_calls = Arc::clone(&calls);
        let second_id = id;
        let second = {
            let coordinator = coordinator.clone();
            tokio::spawn(async move {
                coordinator
                    .refresh(second_id, || async move {
                        second_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(OAuthTokens::bearer("wrong", None::<String>, None))
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(coordinator.active_leases(), 1);
        ready_tx.send(()).unwrap();
        let first_result = first.await.unwrap().unwrap();
        let second_result = second.await.unwrap().unwrap();
        assert_eq!(first_result.access_token().expose_secret(), "access");
        assert_eq!(second_result.access_token().expose_secret(), "access");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(coordinator.active_leases(), 0);
    }

    #[tokio::test]
    async fn cancelling_leader_releases_lease_and_wakes_waiter() {
        let coordinator = RefreshCoordinator::new();
        let id = CredentialId::new("credential-cancel").expect("valid credential ID");
        let (started_tx, started_rx) = oneshot::channel();
        let (_never_tx, never_rx) = oneshot::channel::<()>();
        let leader_id = id.clone();
        let leader = {
            let coordinator = coordinator.clone();
            tokio::spawn(async move {
                coordinator
                    .refresh(leader_id, || async move {
                        let _ = started_tx.send(());
                        let _ = never_rx.await;
                        Ok(OAuthTokens::bearer("never", None::<String>, None))
                    })
                    .await
            })
        };
        started_rx.await.unwrap();
        let waiter_id = id;
        let waiter = {
            let coordinator = coordinator.clone();
            tokio::spawn(async move {
                coordinator
                    .refresh(waiter_id, || async {
                        panic!("waiter must not become a refresh leader");
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(1)).await;
        leader.abort();
        let result = waiter.await.unwrap();
        assert!(matches!(result, Err(RefreshError::Cancelled)));
        assert_eq!(coordinator.active_leases(), 0);
    }

    #[tokio::test]
    async fn failed_refresh_result_is_shared_and_lease_is_released() {
        let coordinator = RefreshCoordinator::new();
        let id = CredentialId::new("credential-failure").expect("valid credential ID");
        let first = coordinator
            .refresh(id, || async { Err(RefreshError::Failed("denied".into())) })
            .await;
        assert_eq!(first, Err(RefreshError::Failed("denied".into())));
        assert_eq!(coordinator.active_leases(), 0);
    }
}
