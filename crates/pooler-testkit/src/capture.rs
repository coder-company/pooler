use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(unix))]
use std::fs::OpenOptions;

use pooler_observe::RedactionPolicy;
use ring::digest::{digest, SHA256};
#[cfg(unix)]
use rustix::fs as unix_fs;
#[cfg(target_os = "linux")]
use rustix::fs::RenameFlags;
#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Fixture, FixtureMetadata, Header, ScriptedChunk, ScriptedError, ScriptedRequest,
    ScriptedResponse, ScriptedResult,
};

/// The default upper bound for a body explicitly included in a capture.
pub const DEFAULT_MAX_CAPTURE_BODY_BYTES: usize = 64 * 1024;

/// Options controlling sanitized fixture capture.
///
/// Captures omit body content unless [`Self::with_bodies`] is selected.  Even
/// when bodies are enabled, only valid JSON bodies no larger than
/// `max_body_bytes` are retained, and all retained values pass through the
/// configured redaction policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureOptions {
    /// Include bounded, recursively sanitized body values.
    #[serde(default)]
    pub include_bodies: bool,
    /// Maximum size of a body whose content may be retained.
    #[serde(default = "default_max_capture_body_bytes")]
    pub max_body_bytes: usize,
    /// Policy used for headers, metadata, and retained JSON values.
    #[serde(default)]
    pub redaction: RedactionPolicy,
}

fn default_max_capture_body_bytes() -> usize {
    DEFAULT_MAX_CAPTURE_BODY_BYTES
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            include_bodies: false,
            max_body_bytes: DEFAULT_MAX_CAPTURE_BODY_BYTES,
            redaction: RedactionPolicy::default(),
        }
    }
}

impl CaptureOptions {
    /// Return options that explicitly retain bounded, sanitized JSON bodies.
    #[must_use]
    pub fn with_bodies() -> Self {
        Self {
            include_bodies: true,
            ..Self::default()
        }
    }

    /// Set the maximum body size retained by an opt-in capture.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Set the policy used to redact captured values.
    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionPolicy) -> Self {
        self.redaction = redaction;
        self
    }
}

/// A bounded body summary.  Body content is absent for default captures,
/// malformed data, and bodies exceeding the configured limit.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedBody {
    /// Number of bytes in the original body.
    pub length: usize,
    /// Lowercase SHA-256 digest of the original body.
    pub sha256: String,
    /// Recursively redacted JSON content, when explicitly retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// Whether content was omitted because the body exceeded the configured
    /// bound.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// Whether the body was not valid JSON and therefore is represented only
    /// by its length and digest.
    #[serde(default, skip_serializing_if = "is_false")]
    pub malformed: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A deterministic, sanitized request representation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub method: String,
    pub uri: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<CapturedBody>,
}

/// A deterministic, sanitized response representation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub chunks: Vec<CapturedChunk>,
}

/// A sanitized stream item.  Binary payloads use [`CapturedBody`] so a
/// default capture never writes raw bytes to disk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapturedChunk {
    Bytes {
        body: CapturedBody,
    },
    Text {
        body: CapturedBody,
    },
    Sse {
        event: Option<String>,
        body: CapturedBody,
    },
    Frame {
        opcode: u8,
        fin: bool,
        body: CapturedBody,
    },
    Connect {
        flags: u8,
        body: CapturedBody,
    },
    Delay {
        millis: u64,
    },
    Error {
        message: String,
    },
    End,
}

/// A sanitized scripted result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapturedResult {
    Response(CapturedResponse),
    Error {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<CapturedBody>,
    },
    Cancelled,
}

/// A complete sanitized fixture record suitable for an owner-private capture
/// file.  It is intentionally distinct from [`Fixture`]: default captures do
/// not pretend that omitted bodies can be replayed.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedFixture {
    pub metadata: FixtureMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downstream_request: Option<CapturedRequest>,
    #[serde(default)]
    pub extracted_fields: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_upstream_request: Option<CapturedRequest>,
    #[serde(default)]
    pub upstream_script: Vec<CapturedResult>,
    #[serde(default)]
    pub expected_downstream_chunks: Vec<CapturedChunk>,
    #[serde(default)]
    pub conversion_report: crate::ConversionReport,
    #[serde(default)]
    pub expected_health_mutation: crate::ExpectedHealthMutation,
}

/// Errors produced while serializing or writing a sanitized capture.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture body limit must be greater than zero")]
    InvalidBodyLimit,
    #[error("invalid capture path `{path}`")]
    InvalidPath { path: String },
    #[error("could not serialize sanitized capture: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("could not create capture directory {path}: {source}")]
    CreateDirectory {
        path: String,
        source: std::io::Error,
    },
    #[error("could not write capture file {path}: {source}")]
    WriteFile {
        path: String,
        source: std::io::Error,
    },
    #[error("capture directory `{path}` is not owner-private")]
    InsecureDirectory { path: String },
    #[error("capture destination `{path}` already exists or changed during publication")]
    DestinationExists { path: String },
    #[error("could not open capture directory {path}: {source}")]
    OpenDirectory {
        path: String,
        source: std::io::Error,
    },
    #[error("could not create temporary capture in {path}: {source}")]
    TemporaryFile {
        path: String,
        source: std::io::Error,
    },
    #[error("could not synchronize capture {path}: {source}")]
    Sync {
        path: String,
        source: std::io::Error,
    },
    #[error("could not publish capture {path}: {source}")]
    Publish {
        path: String,
        source: std::io::Error,
    },
    #[error("could not clean up temporary capture {path}: {source}")]
    Cleanup {
        path: String,
        source: std::io::Error,
    },
    #[error("could not set owner-only permissions on {path}: {source}")]
    Permissions {
        path: String,
        source: std::io::Error,
    },
}

/// Capture one body according to `options`.
#[must_use]
pub fn capture_body(body: &[u8], options: &CaptureOptions) -> CapturedBody {
    let mut captured = CapturedBody {
        length: body.len(),
        sha256: sha256_hex(body),
        ..CapturedBody::default()
    };

    if !options.include_bodies {
        return captured;
    }
    if body.len() > options.max_body_bytes {
        captured.truncated = true;
        return captured;
    }

    match serde_json::from_slice::<Value>(body) {
        Ok(value) => captured.value = Some(options.redaction.sanitize_json(&value)),
        Err(_) => captured.malformed = true,
    }
    captured
}

/// Capture one scripted request, omitting its body unless explicitly enabled.
#[must_use]
pub fn capture_request(request: &ScriptedRequest, options: &CaptureOptions) -> CapturedRequest {
    CapturedRequest {
        method: request.method.to_ascii_uppercase(),
        uri: options.redaction.sanitize_text(&request.uri),
        headers: capture_headers(&request.headers, options),
        body: options
            .include_bodies
            .then(|| capture_body(&request.body, options)),
    }
}

/// Capture one scripted response, applying the same bounded body policy to
/// every stream payload.
#[must_use]
pub fn capture_response(response: &ScriptedResponse, options: &CaptureOptions) -> CapturedResponse {
    CapturedResponse {
        status: response.status,
        headers: capture_headers(&response.headers, options),
        chunks: response
            .chunks
            .iter()
            .map(|chunk| capture_chunk(chunk, options))
            .collect(),
    }
}

/// Capture a complete fixture with deterministic field ordering and redaction.
#[must_use]
pub fn capture_fixture(fixture: &Fixture, options: &CaptureOptions) -> CapturedFixture {
    let metadata = FixtureMetadata {
        id: options.redaction.sanitize_text(&fixture.metadata.id),
        equivalence: fixture.metadata.equivalence,
        intentional_corrections: fixture
            .metadata
            .intentional_corrections
            .iter()
            .map(|value| options.redaction.sanitize_text(value))
            .collect(),
        notes: fixture
            .metadata
            .notes
            .as_deref()
            .map(|value| options.redaction.sanitize_text(value)),
    };
    let extracted_fields = fixture
        .extracted_fields
        .iter()
        .map(|(key, value)| {
            (
                options.redaction.sanitize_text(key),
                options.redaction.sanitize_text(value),
            )
        })
        .collect();

    CapturedFixture {
        metadata,
        downstream_request: fixture
            .downstream_request
            .as_ref()
            .map(|request| capture_request(request, options)),
        extracted_fields,
        expected_upstream_request: fixture
            .expected_upstream_request
            .as_ref()
            .map(|request| capture_request(request, options)),
        upstream_script: fixture
            .upstream_script
            .iter()
            .map(|result| capture_result(result, options))
            .collect(),
        expected_downstream_chunks: fixture
            .expected_downstream_chunks
            .iter()
            .map(|chunk| capture_chunk(chunk, options))
            .collect(),
        conversion_report: capture_conversion_report(&fixture.conversion_report, options),
        expected_health_mutation: capture_health_mutation(
            &fixture.expected_health_mutation,
            options,
        ),
    }
}

/// Serialize a sanitized fixture and write it to an owner-private file.
pub fn write_captured_fixture(
    path: impl AsRef<Path>,
    fixture: &CapturedFixture,
) -> Result<(), CaptureError> {
    let path = path.as_ref();
    let bytes = serde_json::to_vec_pretty(fixture)?;
    let target_name = path.file_name().ok_or_else(|| CaptureError::InvalidPath {
        path: path.display().to_string(),
    })?;
    if target_name == OsStr::new(".") || target_name == OsStr::new("..") {
        return Err(CaptureError::InvalidPath {
            path: path.display().to_string(),
        });
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_directory(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(CaptureError::DestinationExists {
            path: path.display().to_string(),
        });
    }

    #[cfg(unix)]
    {
        write_atomic_unix(parent, target_name, path, &bytes)
    }
    #[cfg(not(unix))]
    {
        write_atomic_portable(parent, target_name, path, &bytes)
    }
}

fn capture_headers(headers: &[Header], options: &CaptureOptions) -> Vec<Header> {
    let mut captured: Vec<_> = headers
        .iter()
        .map(|(name, value)| {
            let name = name.trim().to_ascii_lowercase();
            let value = if options.redaction.is_sensitive_header(&name)
                || !options.redaction.is_allowed_header(&name)
            {
                options.redaction.placeholder.clone()
            } else {
                options.redaction.sanitize_text(value)
            };
            (name, value)
        })
        .collect();
    captured.sort_unstable();
    captured
}

fn capture_chunk(chunk: &ScriptedChunk, options: &CaptureOptions) -> CapturedChunk {
    match chunk {
        ScriptedChunk::Bytes(body) => CapturedChunk::Bytes {
            body: capture_body(body, options),
        },
        ScriptedChunk::Text(body) => CapturedChunk::Text {
            body: capture_body(body.as_bytes(), options),
        },
        ScriptedChunk::Sse { event, data } => CapturedChunk::Sse {
            event: event
                .as_deref()
                .map(|value| options.redaction.sanitize_text(value)),
            body: capture_body(data.as_bytes(), options),
        },
        ScriptedChunk::Frame {
            opcode,
            fin,
            payload,
        } => CapturedChunk::Frame {
            opcode: *opcode,
            fin: *fin,
            body: capture_body(payload, options),
        },
        ScriptedChunk::Connect { flags, payload } => CapturedChunk::Connect {
            flags: *flags,
            body: capture_body(payload, options),
        },
        ScriptedChunk::Delay(duration) => CapturedChunk::Delay {
            millis: duration.as_millis().min(u128::from(u64::MAX)) as u64,
        },
        ScriptedChunk::Error(error) => CapturedChunk::Error {
            message: options.redaction.sanitize_text(&error.to_string()),
        },
        ScriptedChunk::End => CapturedChunk::End,
    }
}

fn capture_result(result: &ScriptedResult, options: &CaptureOptions) -> CapturedResult {
    match result {
        ScriptedResult::Response(response) => {
            CapturedResult::Response(capture_response(response, options))
        }
        ScriptedResult::Error(error) => CapturedResult::Error {
            message: options.redaction.sanitize_text(&error.to_string()),
            body: error_body(error, options),
        },
        ScriptedResult::Cancelled => CapturedResult::Cancelled,
    }
}

fn error_body(error: &ScriptedError, options: &CaptureOptions) -> Option<CapturedBody> {
    match error {
        ScriptedError::Status { body, .. } if options.include_bodies => {
            Some(capture_body(body, options))
        }
        _ => None,
    }
}

fn capture_conversion_report(
    report: &crate::ConversionReport,
    options: &CaptureOptions,
) -> crate::ConversionReport {
    let sanitize = |values: &[String]| {
        values
            .iter()
            .map(|value| options.redaction.sanitize_text(value))
            .collect()
    };
    crate::ConversionReport {
        preserved_capabilities: sanitize(&report.preserved_capabilities),
        degraded_fields: sanitize(&report.degraded_fields),
        dropped_optional_fields: sanitize(&report.dropped_optional_fields),
        unsupported_required_fields: sanitize(&report.unsupported_required_fields),
        preserved_extensions: sanitize(&report.preserved_extensions),
        rules_applied: sanitize(&report.rules_applied),
    }
}

fn capture_health_mutation(
    mutation: &crate::ExpectedHealthMutation,
    options: &CaptureOptions,
) -> crate::ExpectedHealthMutation {
    let text = |value: &str| options.redaction.sanitize_text(value);
    match mutation {
        crate::ExpectedHealthMutation::None => crate::ExpectedHealthMutation::None,
        crate::ExpectedHealthMutation::CredentialCooldown {
            credential,
            duration_ms,
        } => crate::ExpectedHealthMutation::CredentialCooldown {
            credential: text(credential),
            duration_ms: *duration_ms,
        },
        crate::ExpectedHealthMutation::ProviderCooldown {
            provider,
            duration_ms,
        } => crate::ExpectedHealthMutation::ProviderCooldown {
            provider: text(provider),
            duration_ms: *duration_ms,
        },
        crate::ExpectedHealthMutation::ModelCooldown { model, duration_ms } => {
            crate::ExpectedHealthMutation::ModelCooldown {
                model: text(model),
                duration_ms: *duration_ms,
            }
        }
        crate::ExpectedHealthMutation::Custom { scope, reason } => {
            crate::ExpectedHealthMutation::Custom {
                scope: text(scope),
                reason: text(reason),
            }
        }
    }
}

fn sha256_hex(body: &[u8]) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest(&SHA256, body).as_ref() {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[cfg(unix)]
static NEXT_CAPTURE_TEMP: AtomicU64 = AtomicU64::new(0);
const MAX_CAPTURE_TEMP_ATTEMPTS: usize = 64;

fn ensure_private_directory(path: &Path) -> Result<(), CaptureError> {
    let mut current = PathBuf::new();
    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {
                if current.as_os_str().is_empty() {
                    current.push(component.as_os_str());
                }
            }
            Component::ParentDir => {
                return Err(CaptureError::InvalidPath {
                    path: path.display().to_string(),
                });
            }
            Component::Normal(name) => {
                current.push(name);
                saw_component = true;
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(CaptureError::InsecureDirectory {
                                path: current.display().to_string(),
                            });
                        }
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                        fs::create_dir(&current).map_err(|source| {
                            if source.kind() == std::io::ErrorKind::AlreadyExists {
                                CaptureError::InsecureDirectory {
                                    path: current.display().to_string(),
                                }
                            } else {
                                CaptureError::CreateDirectory {
                                    path: current.display().to_string(),
                                    source,
                                }
                            }
                        })?;
                        set_owner_only_directory(&current)?;
                    }
                    Err(source) => {
                        return Err(CaptureError::CreateDirectory {
                            path: current.display().to_string(),
                            source,
                        });
                    }
                }
            }
        }
    }

    if !saw_component && current.as_os_str().is_empty() {
        current.push(".");
    }
    let metadata =
        fs::symlink_metadata(&current).map_err(|source| CaptureError::CreateDirectory {
            path: path.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || !is_private_directory(&metadata) {
        return Err(CaptureError::InsecureDirectory {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn is_private_directory(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

#[cfg(unix)]
fn open_private_directory(path: &Path) -> Result<File, CaptureError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let descriptor = unix_fs::open(path, flags, Mode::empty()).map_err(|source| {
        CaptureError::OpenDirectory {
            path: path.display().to_string(),
            source: source.into(),
        }
    })?;
    Ok(File::from(descriptor))
}

#[cfg(unix)]
fn write_atomic_unix(
    parent: &Path,
    target_name: &OsStr,
    target_path: &Path,
    bytes: &[u8],
) -> Result<(), CaptureError> {
    let directory = open_private_directory(parent)?;
    let (mut temporary, temporary_name) = create_temporary_unix(&directory, target_path)?;
    let mut guard = TemporaryCaptureGuard {
        directory: &directory,
        name: temporary_name.clone(),
        active: true,
    };

    temporary
        .write_all(bytes)
        .map_err(|source| CaptureError::WriteFile {
            path: target_path.display().to_string(),
            source,
        })?;
    temporary.sync_all().map_err(|source| CaptureError::Sync {
        path: target_path.display().to_string(),
        source,
    })?;

    #[cfg(target_os = "linux")]
    {
        let result = unix_fs::renameat_with(
            &directory,
            temporary_name.as_str(),
            &directory,
            target_name,
            RenameFlags::NOREPLACE,
        );
        let result = result.map_err(std::io::Error::from);
        if let Err(source) = result {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(CaptureError::DestinationExists {
                    path: target_path.display().to_string(),
                });
            }
            return Err(CaptureError::Publish {
                path: target_path.display().to_string(),
                source,
            });
        }
        guard.active = false;
        sync_directory(&directory, target_path)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let result = unix_fs::linkat(
            &directory,
            temporary_name.as_str(),
            &directory,
            target_name,
            AtFlags::empty(),
        );
        let result = result.map_err(std::io::Error::from);
        if let Err(source) = result {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(CaptureError::DestinationExists {
                    path: target_path.display().to_string(),
                });
            }
            return Err(CaptureError::Publish {
                path: target_path.display().to_string(),
                source,
            });
        }
        sync_directory(&directory, target_path)?;
        unix_fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty()).map_err(
            |source| CaptureError::Cleanup {
                path: target_path.display().to_string(),
                source: source.into(),
            },
        )?;
        guard.active = false;
        sync_directory(&directory, target_path)
    }
}

#[cfg(unix)]
fn create_temporary_unix(
    directory: &File,
    target_path: &Path,
) -> Result<(File, String), CaptureError> {
    let target = target_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| CaptureError::InvalidPath {
            path: target_path.display().to_string(),
        })?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    for _ in 0..MAX_CAPTURE_TEMP_ATTEMPTS {
        let sequence = NEXT_CAPTURE_TEMP.fetch_add(1, Ordering::Relaxed);
        let name = format!(".{target}.tmp-{}-{sequence}", std::process::id());
        match unix_fs::openat(directory, name.as_str(), flags, Mode::from_raw_mode(0o600)) {
            Ok(descriptor) => return Ok((File::from(descriptor), name)),
            Err(source)
                if std::io::Error::from(source).kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(source) => {
                return Err(CaptureError::TemporaryFile {
                    path: target_path.display().to_string(),
                    source: source.into(),
                });
            }
        }
    }
    Err(CaptureError::TemporaryFile {
        path: target_path.display().to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temporary capture name exhausted",
        ),
    })
}

#[cfg(unix)]
fn sync_directory(directory: &File, target_path: &Path) -> Result<(), CaptureError> {
    unix_fs::fsync(directory).map_err(|source| CaptureError::Sync {
        path: target_path.display().to_string(),
        source: source.into(),
    })
}

#[cfg(unix)]
struct TemporaryCaptureGuard<'a> {
    directory: &'a File,
    name: String,
    active: bool,
}

#[cfg(unix)]
impl Drop for TemporaryCaptureGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = unix_fs::unlinkat(self.directory, self.name.as_str(), AtFlags::empty());
        }
    }
}

#[cfg(not(unix))]
fn write_atomic_portable(
    parent: &Path,
    target_name: &OsStr,
    target_path: &Path,
    bytes: &[u8],
) -> Result<(), CaptureError> {
    let target = target_name.to_string_lossy();
    let temporary_path = parent.join(format!(".{target}.tmp-{}", std::process::id()));
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|source| CaptureError::TemporaryFile {
            path: target_path.display().to_string(),
            source,
        })?;
    let result = (|| {
        temporary
            .write_all(bytes)
            .map_err(|source| CaptureError::WriteFile {
                path: target_path.display().to_string(),
                source,
            })?;
        temporary.sync_all().map_err(|source| CaptureError::Sync {
            path: target_path.display().to_string(),
            source,
        })?;
        fs::hard_link(&temporary_path, target_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                CaptureError::DestinationExists {
                    path: target_path.display().to_string(),
                }
            } else {
                CaptureError::Publish {
                    path: target_path.display().to_string(),
                    source,
                }
            }
        })?;
        fs::remove_file(&temporary_path).map_err(|source| CaptureError::Cleanup {
            path: target_path.display().to_string(),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn set_owner_only_directory(path: &Path) -> Result<(), CaptureError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            CaptureError::Permissions {
                path: path.display().to_string(),
                source,
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;
    use crate::{Equivalence, LeakCounters, ScriptedChunk, ScriptedRequest};

    #[test]
    fn default_capture_omits_body_content_and_redacts_headers() {
        let fixture = Fixture::new("capture", Equivalence::JsonStructural).with_downstream_request(
            ScriptedRequest::new("post", "/v1?token=sk-live-1234567890")
                .with_header("content-type", "application/json")
                .with_header("authorization", "Bearer secret")
                .with_body(br#"{"safe":true,"password":"secret"}"#.to_vec()),
        );

        let captured = capture_fixture(&fixture, &CaptureOptions::default());
        let request = captured.downstream_request.as_ref().expect("request");
        assert!(request.body.is_none());
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name == "authorization")
                .expect("authorization header")
                .1,
            "[REDACTED]"
        );
        let encoded = serde_json::to_string(&captured).expect("capture serializes");
        assert!(!encoded.contains("secret"));
    }

    #[test]
    fn explicit_capture_redacts_nested_json_and_reports_malformed_data() {
        let options = CaptureOptions::with_bodies().with_max_body_bytes(256);
        let body = capture_body(
            br#"{"safe":{"value":1},"items":[{"password":"secret"}]}"#,
            &options,
        );
        assert_eq!(
            body.value.as_ref().expect("retained JSON")["safe"]["value"],
            1
        );
        assert_eq!(
            body.value.as_ref().expect("retained JSON")["items"][0]["password"],
            "[REDACTED]"
        );

        let malformed = capture_body(b"not-json-secret", &options);
        assert!(malformed.value.is_none());
        assert!(malformed.malformed);
        assert_eq!(malformed.length, 15);
        assert!(!malformed.sha256.is_empty());
    }

    #[test]
    fn body_limit_keeps_only_length_and_digest() {
        let captured = capture_body(
            b"{\"value\":true}",
            &CaptureOptions::with_bodies().with_max_body_bytes(2),
        );
        assert!(captured.value.is_none());
        assert!(captured.truncated);
        assert!(!captured.sha256.is_empty());
    }

    #[test]
    fn stream_payloads_follow_body_policy() {
        let fixture = Fixture::new("stream", Equivalence::EventSemantic)
            .with_downstream_chunks([ScriptedChunk::sse(r#"{"token":"secret"}"#)]);
        let captured = capture_fixture(&fixture, &CaptureOptions::with_bodies());
        let CapturedChunk::Sse { body, .. } = &captured.expected_downstream_chunks[0] else {
            panic!("expected SSE capture")
        };
        assert_eq!(
            body.value.as_ref().expect("JSON body")["token"],
            "[REDACTED]"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_file_is_owner_private() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical temporary directory");
        let path = root.join("nested").join("capture.json");
        let fixture = capture_fixture(
            &Fixture::new("file", Equivalence::ByteLevel),
            &CaptureOptions::default(),
        );
        write_captured_fixture(&path, &fixture).expect("capture writes");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path)
                .expect("capture metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("nested"))
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(fs::read_dir(root.join("nested"))
            .expect("capture directory")
            .all(|entry| !entry
                .expect("capture entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")));
    }

    #[cfg(unix)]
    #[test]
    fn capture_rejects_symlink_destination_without_following_it() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical temporary directory");
        let parent = root.join("captures");
        fs::create_dir(&parent).expect("capture directory");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("private capture directory");
        let target = root.join("outside.json");
        fs::write(&target, b"do not replace").expect("outside target");
        let destination = parent.join("capture.json");
        symlink(&target, &destination).expect("destination symlink");
        let fixture = capture_fixture(
            &Fixture::new("symlink", Equivalence::ByteLevel),
            &CaptureOptions::default(),
        );

        let error = write_captured_fixture(&destination, &fixture)
            .expect_err("symlink destination must be rejected");
        assert!(matches!(error, CaptureError::DestinationExists { .. }));
        assert_eq!(
            fs::read(&target).expect("outside target"),
            b"do not replace"
        );
        assert!(fs::symlink_metadata(&destination)
            .expect("destination metadata")
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn capture_rejects_non_private_destination_directories() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical temporary directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("non-private directory");
        let fixture = capture_fixture(
            &Fixture::new("permissions", Equivalence::ByteLevel),
            &CaptureOptions::default(),
        );

        let error = write_captured_fixture(root.join("capture.json"), &fixture)
            .expect_err("non-private directory must be rejected");
        assert!(matches!(error, CaptureError::InsecureDirectory { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_publication_rejects_a_symlink_inserted_after_precheck() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("captures");
        fs::create_dir(&parent).expect("capture directory");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("private capture directory");
        let destination = parent.join("capture.json");
        let outside = directory.path().join("outside.json");
        fs::write(&outside, b"do not replace").expect("outside target");
        let handle = open_private_directory(&parent).expect("open capture directory");
        let (mut temporary, name) =
            create_temporary_unix(&handle, &destination).expect("temporary file");
        temporary.write_all(b"capture").expect("temporary body");
        temporary.sync_all().expect("temporary sync");
        let _guard = TemporaryCaptureGuard {
            directory: &handle,
            name: name.clone(),
            active: true,
        };
        symlink(&outside, &destination).expect("insert destination symlink");

        let error = unix_fs::renameat_with(
            &handle,
            name.as_str(),
            &handle,
            destination.file_name().expect("destination name"),
            RenameFlags::NOREPLACE,
        )
        .expect_err("no-replace publication must reject the race");
        assert_eq!(
            std::io::Error::from(error).kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(&outside).expect("outside target"),
            b"do not replace"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unpublished_capture_temp_file_is_removed_during_unwind() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("captures");
        fs::create_dir(&parent).expect("capture directory");
        set_owner_only_directory(&parent).expect("private capture directory");
        let handle = open_private_directory(&parent).expect("open capture directory");
        let target = parent.join("cancelled.json");
        let counters = LeakCounters::new();

        let result = catch_unwind(AssertUnwindSafe(|| {
            let (_file, name) = create_temporary_unix(&handle, &target).expect("temporary file");
            let _tracked = counters.temporary_file();
            let _guard = TemporaryCaptureGuard {
                directory: &handle,
                name: name.clone(),
                active: true,
            };
            panic!("simulate cancellation while capture is in flight");
        }));
        assert!(result.is_err());
        assert!(counters.assert_zero().is_ok());
        assert!(fs::read_dir(&parent)
            .expect("capture directory")
            .all(|entry| !entry
                .expect("capture entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")));
    }
}
