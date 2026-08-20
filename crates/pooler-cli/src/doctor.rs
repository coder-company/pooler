//! Read-only, redacted health checks for a Pooler installation.

use std::collections::BTreeSet;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pooler_config::{CompiledConfig, ConfigLoader, ExtensionPlan};
use pooler_extension::{
    ExtensionCapabilities, ExtensionCapability, ExtensionLimits, ExtensionRegistry, ExtensionSpec,
    WasmExtension,
};
use pooler_observe::RedactionPolicy;
use pooler_store::{SqliteStore, Store};
use serde::Serialize;

use crate::auth;

/// A single diagnostic result.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorCheck {
    /// Stable check identifier.
    pub name: String,
    /// `passed`, `warning`, `failed`, or `skipped`.
    pub status: &'static str,
    /// Safe diagnostic detail. Secret values are never included.
    pub detail: String,
}

/// Complete structured doctor output.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    /// Overall result. This is `failed` when any check failed.
    pub status: &'static str,
    /// Checks in deterministic order.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn new() -> Self {
        Self {
            status: "ok",
            checks: Vec::new(),
        }
    }

    fn check(&mut self, name: impl Into<String>, status: &'static str, detail: impl Into<String>) {
        if status == "failed" {
            self.status = "failed";
        }
        self.checks.push(DoctorCheck {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }

    fn failed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == "failed")
            .count()
    }
}

/// Run diagnostics and emit one redacted JSON document.
pub fn run(
    config_path: &Path,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    let report = diagnose(config_path, explicit_store_path, credential_key_ref);
    let rendered =
        serde_json::to_string_pretty(&report).context("could not serialize doctor report")?;
    println!("{rendered}");
    let failures = report.failed_count();
    if failures != 0 {
        bail!("doctor found {failures} failing checks")
    }
    Ok(())
}

/// Run diagnostics without writing files, opening listeners, or contacting a
/// provider. This function is public so tests and embedding callers can make
/// the same checks without parsing process output.
#[must_use]
pub fn diagnose(
    config_path: &Path,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
) -> DoctorReport {
    let mut report = DoctorReport::new();
    let policy = RedactionPolicy::strict();

    let loaded = match ConfigLoader::default().load_tracked(config_path) {
        Ok(loaded) => {
            match loaded.compile() {
                Ok(compiled) => {
                    report.check(
                        "config.compile",
                        "passed",
                        "configuration parsed and compiled",
                    );
                    check_binds(&mut report, &compiled);
                    check_provider_urls(&mut report, &compiled, &policy);
                    check_extensions(&mut report, &compiled, &policy);
                }
                Err(error) => report.check("config.compile", "failed", safe_detail(&policy, error)),
            }
            check_schema(&mut report);
            check_dependencies(&mut report, loaded.dependencies());
            Some(loaded)
        }
        Err(error) => {
            report.check("config.compile", "failed", safe_detail(&policy, error));
            check_schema(&mut report);
            None
        }
    };

    if loaded.is_none() {
        report.check(
            "config.dependencies",
            "skipped",
            "dependency checks require a valid configuration",
        );
        report.check(
            "listeners.bind",
            "skipped",
            "bind checks require a valid configuration",
        );
        report.check(
            "providers.tls",
            "skipped",
            "provider checks require a valid configuration",
        );
        report.check(
            "extensions.readiness",
            "skipped",
            "extension checks require a valid configuration",
        );
    }

    check_store(
        &mut report,
        explicit_store_path,
        credential_key_ref,
        &policy,
    );

    report
}

fn check_schema(report: &mut DoctorReport) {
    let rendered = pooler_config::render_config_schema();
    match serde_json::from_str::<serde_json::Value>(&rendered) {
        Ok(value)
            if value
                .get("$schema")
                .and_then(serde_json::Value::as_str)
                .is_some()
                && value
                    .get("$defs")
                    .and_then(serde_json::Value::as_object)
                    .is_some() =>
        {
            report.check(
                "config.schema",
                "passed",
                "configuration schema is valid JSON",
            );
        }
        Ok(_) => report.check(
            "config.schema",
            "failed",
            "configuration schema is missing required metadata",
        ),
        Err(error) => report.check(
            "config.schema",
            "failed",
            format!("configuration schema is invalid: {error}"),
        ),
    }
}

fn check_dependencies(report: &mut DoctorReport, dependencies: &[PathBuf]) {
    let mut failed = false;
    for dependency in dependencies {
        match fs::symlink_metadata(dependency) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                failed = true;
                report.check(
                    "config.dependencies",
                    "failed",
                    format!(
                        "configuration dependency is not a regular file: {}",
                        path_label(dependency)
                    ),
                );
            }
            Err(error) => {
                failed = true;
                report.check(
                    "config.dependencies",
                    "failed",
                    format!(
                        "configuration dependency is unavailable: {}",
                        safe_io(error)
                    ),
                );
            }
        }
    }
    if !failed {
        report.check(
            "config.dependencies",
            "passed",
            format!("{} configuration file(s) are available", dependencies.len()),
        );
    }
}

fn check_binds(report: &mut DoctorReport, config: &CompiledConfig) {
    let mut seen = BTreeSet::new();
    for listener in config.listeners().values() {
        check_bind(
            report,
            format!("listeners.bind.{}", listener.id()),
            listener.bind(),
            &mut seen,
        );
    }
    if let Some(management) = config.management() {
        check_bind(
            report,
            "management.bind".to_owned(),
            management.bind(),
            &mut seen,
        );
    }
    if config.listeners().is_empty() && config.management().is_none() {
        report.check("listeners.bind", "skipped", "no listeners are configured");
    }
}

fn check_bind(report: &mut DoctorReport, name: String, bind: &str, seen: &mut BTreeSet<String>) {
    let bind = bind.trim();
    if !seen.insert(bind.to_owned()) {
        report.check(name, "failed", "bind is duplicated by another listener");
        return;
    }
    if let Ok(address) = bind.parse::<SocketAddr>() {
        match TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                report.check(
                    name,
                    "passed",
                    "TCP bind is available for a preflight probe",
                );
            }
            Err(error) => report.check(
                name,
                "failed",
                format!("TCP bind is unavailable: {}", safe_io(error)),
            ),
        }
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::net::UnixStream;
        let path = bind.strip_prefix("unix:").unwrap_or(bind);
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_socket() => {
                report.check(name, "failed", "Unix bind path exists but is not a socket")
            }
            Ok(_) => match UnixStream::connect(path) {
                Ok(_) => report.check(name, "failed", "Unix bind is already in use"),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    report.check(name, "warning", "Unix bind has a stale socket path")
                }
                Err(error) => report.check(
                    name,
                    "failed",
                    format!("Unix bind is unavailable: {}", safe_io(error)),
                ),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                report.check(name, "passed", "Unix bind path is available")
            }
            Err(error) => report.check(
                name,
                "failed",
                format!("Unix bind path is unavailable: {}", safe_io(error)),
            ),
        }
    }
    #[cfg(not(unix))]
    report.check(
        name,
        "warning",
        "Unix bind diagnostics are unavailable on this platform",
    );
}

fn check_provider_urls(
    report: &mut DoctorReport,
    config: &CompiledConfig,
    policy: &RedactionPolicy,
) {
    if config.upstreams().is_empty() {
        report.check(
            "providers.tls",
            "skipped",
            "no upstream providers are configured",
        );
        return;
    }
    for (id, upstream) in config.upstreams() {
        let url = upstream.url();
        let scheme = url.scheme();
        let host = url.host_str().unwrap_or("<missing-host>");
        let detail = format!(
            "provider={} scheme={} host={}",
            safe_detail(policy, id),
            scheme,
            safe_detail(policy, host)
        );
        if scheme == "https" {
            report.check(
                format!("providers.tls.{}", safe_detail(policy, id)),
                "passed",
                format!("{detail}; TLS is required and URL credentials are absent"),
            );
        } else if is_loopback_host(host) {
            report.check(
                format!("providers.tls.{}", safe_detail(policy, id)),
                "warning",
                format!("{detail}; plaintext HTTP is limited to a loopback endpoint"),
            );
        } else {
            report.check(
                format!("providers.tls.{}", safe_detail(policy, id)),
                "failed",
                format!("{detail}; non-loopback provider URLs must use HTTPS"),
            );
        }
    }
}

fn check_extensions(report: &mut DoctorReport, config: &CompiledConfig, policy: &RedactionPolicy) {
    if config.extensions().is_empty() {
        report.check(
            "extensions.readiness",
            "skipped",
            "no external extensions are configured",
        );
        return;
    }

    let mut process_specs = Vec::new();
    for extension in config.extensions().values() {
        if let Some(path) = extension.command() {
            let path = Path::new(path);
            if let Err(detail) = executable_check(path) {
                report.check(
                    format!(
                        "extensions.readiness.{}",
                        safe_detail(policy, extension.id())
                    ),
                    "failed",
                    detail,
                );
                continue;
            }
            match extension_spec(extension) {
                Ok(spec) => process_specs.push(spec),
                Err(error) => report.check(
                    format!(
                        "extensions.readiness.{}",
                        safe_detail(policy, extension.id())
                    ),
                    "failed",
                    safe_detail(policy, error),
                ),
            }
        } else if let Some(path) = extension.wasm() {
            let name = format!(
                "extensions.readiness.{}",
                safe_detail(policy, extension.id())
            );
            match fs::read(path) {
                Ok(module) => match wasm_extension(extension, &module) {
                    Ok(_) => {
                        report.check(name, "passed", "WASM module compiled with no host imports")
                    }
                    Err(error) => report.check(name, "failed", safe_detail(policy, error)),
                },
                Err(error) => report.check(name, "failed", safe_io(error)),
            }
        }
    }
    if !process_specs.is_empty() {
        match ExtensionRegistry::from_specs(process_specs) {
            Ok(_) => report.check(
                "extensions.sandbox",
                "passed",
                "external extension sandbox probe succeeded",
            ),
            Err(error) => report.check("extensions.sandbox", "failed", safe_detail(policy, error)),
        }
    }
}

fn executable_check(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("extension executable is unavailable: {}", safe_io(error)))?;
    if !metadata.is_file() {
        return Err("extension executable is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("extension executable has no execute permission".to_owned());
        }
    }
    Ok(())
}

fn extension_spec(extension: &ExtensionPlan) -> Result<ExtensionSpec, String> {
    let capabilities = extension_capabilities(extension)?;
    ExtensionSpec::new(
        extension.id(),
        PathBuf::from(extension.command().expect("command extension")),
        extension.args().iter().map(|arg| arg.to_string().into()),
        capabilities,
        extension_limits(extension),
    )
    .map_err(|error| error.to_string())
}

fn wasm_extension(extension: &ExtensionPlan, module: &[u8]) -> Result<WasmExtension, String> {
    WasmExtension::new(
        extension.id(),
        module,
        extension_capabilities(extension)?,
        extension_limits(extension),
    )
    .map_err(|error| error.to_string())
}

fn extension_capabilities(extension: &ExtensionPlan) -> Result<ExtensionCapabilities, String> {
    let values = extension
        .capabilities()
        .iter()
        .filter_map(|value| match value.as_ref() {
            "inspect" => Some(ExtensionCapability::Inspect),
            "transform" => Some(ExtensionCapability::Transform),
            _ => None,
        });
    Ok(ExtensionCapabilities::from_capabilities(values))
}

fn extension_limits(extension: &ExtensionPlan) -> ExtensionLimits {
    let limits = extension.limits();
    ExtensionLimits {
        max_input_bytes: usize::try_from(limits.max_input_bytes()).unwrap_or(usize::MAX),
        max_output_bytes: usize::try_from(limits.max_output_bytes()).unwrap_or(usize::MAX),
        timeout: limits.timeout(),
        max_memory_bytes: limits.max_memory_bytes(),
        max_concurrency: usize::try_from(limits.max_concurrency()).unwrap_or(usize::MAX),
    }
}

fn check_store(
    report: &mut DoctorReport,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
    policy: &RedactionPolicy,
) {
    let configured = explicit_store_path.is_some()
        || credential_key_ref.is_some()
        || std::env::var_os("POOLER_CREDENTIAL_STORE").is_some();
    if !configured {
        report.check(
            "store",
            "skipped",
            "credential store is not configured for this invocation",
        );
        return;
    }

    let path = match auth::credential_store_path(explicit_store_path) {
        Ok(path) => path,
        Err(error) => {
            report.check("store.path", "failed", safe_detail(policy, error));
            return;
        }
    };
    check_store_permissions(report, &path);
    if !path.is_file() {
        report.check("store", "failed", "credential store file is not available");
        if credential_key_ref.is_none() {
            report.check(
                "store.key",
                "failed",
                "credential store key reference is required",
            );
        }
        return;
    }

    let key = match credential_key_ref {
        Some(reference) => match auth::load_master_key(Some(reference)) {
            Ok(key) => {
                report.check("store.key", "passed", "credential-store key resolved");
                Some(key)
            }
            Err(error) => {
                report.check("store.key", "failed", safe_detail(policy, error));
                None
            }
        },
        None => None,
    };

    let store = match key {
        Some(key) => SqliteStore::open_encrypted(&path, key),
        None => SqliteStore::open(&path),
    };
    let store = match store {
        Ok(store) => store,
        Err(error) => {
            report.check("store.open", "failed", safe_detail(policy, error));
            return;
        }
    };
    match store.journal_mode() {
        Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
            report.check("store.wal", "passed", "SQLite WAL mode is enabled")
        }
        Ok(mode) => report.check(
            "store.wal",
            "failed",
            format!("SQLite journal mode is `{mode}`, expected WAL"),
        ),
        Err(error) => report.check("store.wal", "failed", safe_detail(policy, error)),
    }
    match store.integrity_check() {
        Ok(()) => report.check("store.integrity", "passed", "SQLite integrity check passed"),
        Err(error) => report.check("store.integrity", "failed", safe_detail(policy, error)),
    }

    let payload_count = match store.credential_payload_count() {
        Ok(count) => count,
        Err(error) => {
            report.check("store.payloads", "failed", safe_detail(policy, error));
            return;
        }
    };
    if credential_key_ref.is_none() {
        if payload_count == 0 {
            report.check(
                "store.decrypt",
                "warning",
                "store has no encrypted payloads; no key reference was supplied",
            );
        } else {
            report.check(
                "store.decrypt",
                "failed",
                "encrypted credential payloads exist but no key reference was supplied",
            );
        }
        return;
    }

    let mut decrypted = 0usize;
    match store.credential_states() {
        Ok(states) => {
            for state in states {
                match store.credential_payload(&state.credential_id) {
                    Ok(Some(_payload)) => decrypted += 1,
                    Ok(None) => {}
                    Err(error) => {
                        report.check("store.decrypt", "failed", safe_detail(policy, error));
                        return;
                    }
                }
            }
        }
        Err(error) => {
            report.check("store.decrypt", "failed", safe_detail(policy, error));
            return;
        }
    }
    if decrypted == payload_count {
        report.check(
            "store.decrypt",
            "passed",
            format!("authenticated {decrypted} encrypted credential payload(s)"),
        );
    } else {
        report.check(
            "store.decrypt",
            "failed",
            "encrypted payload rows do not match credential metadata",
        );
    }
}

fn check_store_permissions(report: &mut DoctorReport, path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.permissions().mode() & 0o077 != 0 {
                    report.check(
                        "store.permissions",
                        "failed",
                        "credential store permissions grant access to group or other users",
                    );
                } else if metadata.uid() != rustix::process::geteuid().as_raw() {
                    report.check(
                        "store.permissions",
                        "failed",
                        "credential store is not owned by the current user",
                    );
                } else {
                    report.check(
                        "store.permissions",
                        "passed",
                        "credential store is owner-private",
                    );
                }
                for suffix in ["-wal", "-shm"] {
                    let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
                    if let Ok(metadata) = fs::symlink_metadata(&sidecar) {
                        if metadata.permissions().mode() & 0o077 != 0 {
                            report.check(
                                "store.permissions",
                                "failed",
                                "SQLite sidecar permissions grant access to group or other users",
                            );
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            report.check(
                "store.permissions",
                "passed",
                "credential store permissions are platform-managed",
            );
        }
        Err(error) => report.check(
            "store.permissions",
            "failed",
            format!(
                "credential store metadata is unavailable: {}",
                safe_io(error)
            ),
        ),
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn path_label(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "<configuration-file>".to_owned(), ToOwned::to_owned)
}

fn safe_io(error: std::io::Error) -> String {
    format!("I/O error ({})", error.kind())
}

fn safe_detail(policy: &RedactionPolicy, error: impl std::fmt::Display) -> String {
    policy.sanitize_text(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn config(text: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("pooler.yaml");
        fs::write(&path, text).expect("configuration");
        (directory, path)
    }

    #[test]
    fn valid_config_reports_structured_success_without_store() {
        let (_directory, path) = config("version: 1\nlisteners: {}\nupstreams: {}\nroutes: []\n");
        let report = diagnose(&path, None, None);
        assert_eq!(report.status, "ok");
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "config.compile" && check.status == "passed"));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "config.schema" && check.status == "passed"));
    }

    #[test]
    fn invalid_config_is_a_failure_and_secret_text_is_not_reported() {
        let (_directory, path) =
            config("version: 1\nupstreams: {x: {url: 'http://user:super-secret@example.test'}}\n");
        let report = diagnose(&path, None, None);
        assert_eq!(report.status, "failed");
        let encoded = serde_json::to_string(&report).expect("report JSON");
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn duplicate_binds_are_reported_without_leaving_a_listener() {
        let (_directory, path) = config(
            "version: 1\nlisteners: {one: {bind: '127.0.0.1:0'}, two: {bind: '127.0.0.1:0'}}\nroutes: []\n",
        );
        let report = diagnose(&path, None, None);
        assert_eq!(report.status, "failed");
        assert!(report
            .checks
            .iter()
            .any(|check| check.detail.contains("duplicated")));
    }
}
