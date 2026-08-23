//! Bounded, value-free migration from the pinned CLIProxyAPI configuration shape.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use url::Url;

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const SOURCE_REVISION: &str = "CLIProxyAPI Plus 7.2.125 (2e6b1d83)";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LegacyConfig {
    #[serde(default)]
    api_keys: Vec<IgnoredAny>,
    #[serde(default)]
    openai_compatibility: Vec<CompatibleProvider>,
    #[serde(default)]
    gemini_api_key: Vec<IgnoredAny>,
    #[serde(default)]
    interactions_api_key: Vec<IgnoredAny>,
    #[serde(default)]
    codex_api_key: Vec<IgnoredAny>,
    #[serde(default)]
    xai_api_key: Vec<IgnoredAny>,
    #[serde(default)]
    claude_api_key: Vec<IgnoredAny>,
    #[serde(default)]
    vertex_api_key: Vec<IgnoredAny>,
    #[serde(flatten)]
    other: BTreeMap<String, IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CompatibleProvider {
    name: String,
    #[serde(default)]
    disabled: bool,
    base_url: String,
    #[serde(default)]
    api_key_entries: Vec<IgnoredAny>,
    #[serde(default)]
    models: Vec<LegacyModel>,
    #[serde(flatten)]
    other: BTreeMap<String, IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LegacyModel {
    #[serde(rename = "name")]
    _name: String,
    alias: String,
    #[serde(flatten)]
    other: BTreeMap<String, IgnoredAny>,
}

#[derive(Debug, Serialize)]
struct MigrationReport {
    schema_version: u32,
    source_revision: &'static str,
    dry_run: bool,
    wrote_files: bool,
    downstream_api_keys_found: usize,
    compatible_providers_found: usize,
    compatible_providers_translated: usize,
    provider_credentials_requiring_reentry: usize,
    unsupported_native_credentials: BTreeMap<&'static str, usize>,
    unsupported_settings: Vec<String>,
    unsupported_model_aliases: usize,
    generated_secret_references: Vec<String>,
    proposed_config: Option<String>,
    output: Option<PathBuf>,
}

pub(crate) fn cliproxy(input: &Path, dry_run: bool, output: Option<&Path>) -> Result<()> {
    let file = File::open(input)
        .with_context(|| format!("open CLIProxyAPI config {}", input.display()))?;
    let mut bytes = Vec::with_capacity(MAX_SOURCE_BYTES as usize + 1);
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read CLIProxyAPI config {}", input.display()))?;
    if bytes.len() > MAX_SOURCE_BYTES as usize {
        return Err(anyhow!(
            "CLIProxyAPI config exceeds the 1 MiB migration bound"
        ));
    }
    let source =
        String::from_utf8(bytes).map_err(|_| anyhow!("CLIProxyAPI config is not valid UTF-8"))?;
    let legacy: LegacyConfig = serde_yml::from_str(&source).map_err(|_| {
        anyhow!("CLIProxyAPI config does not match the supported pinned YAML shape")
    })?;
    let (proposed_config, secret_refs, translated, unsupported_aliases) = translate(&legacy)?;

    let mut unsupported_native_credentials = BTreeMap::new();
    for (kind, count) in [
        ("gemini-api-key", legacy.gemini_api_key.len()),
        ("interactions-api-key", legacy.interactions_api_key.len()),
        ("codex-api-key", legacy.codex_api_key.len()),
        ("xai-api-key", legacy.xai_api_key.len()),
        ("claude-api-key", legacy.claude_api_key.len()),
        ("vertex-api-key", legacy.vertex_api_key.len()),
    ] {
        if count > 0 {
            unsupported_native_credentials.insert(kind, count);
        }
    }

    let mut wrote_files = false;
    if dry_run {
        if let Some(config) = proposed_config.as_deref() {
            validate_generated_config(input, output, config.as_bytes())?;
        }
    } else {
        let destination = output.ok_or_else(|| anyhow!("non-dry migration requires --output"))?;
        let config = proposed_config.as_deref().ok_or_else(|| {
            anyhow!("no safely translatable OpenAI-compatible providers were found")
        })?;
        write_validated_new(destination, config.as_bytes())?;
        wrote_files = true;
    }

    let provider_credentials_requiring_reentry = legacy
        .openai_compatibility
        .iter()
        .map(|provider| provider.api_key_entries.len())
        .sum::<usize>()
        + unsupported_native_credentials.values().sum::<usize>();
    let mut unsupported_settings = legacy.other.keys().cloned().collect::<Vec<_>>();
    for provider in &legacy.openai_compatibility {
        unsupported_settings.extend(
            provider
                .other
                .keys()
                .map(|key| format!("openai-compatibility.{}.{}", safe_id(&provider.name), key)),
        );
        for model in &provider.models {
            unsupported_settings.extend(model.other.keys().map(|key| {
                format!(
                    "openai-compatibility.{}.models.{}.{}",
                    safe_id(&provider.name),
                    safe_id(&model.alias),
                    key
                )
            }));
        }
    }
    unsupported_settings.sort();
    unsupported_settings.dedup();

    let report = MigrationReport {
        schema_version: 1,
        source_revision: SOURCE_REVISION,
        dry_run,
        wrote_files,
        downstream_api_keys_found: legacy.api_keys.len(),
        compatible_providers_found: legacy.openai_compatibility.len(),
        compatible_providers_translated: translated,
        provider_credentials_requiring_reentry,
        unsupported_native_credentials,
        unsupported_settings,
        unsupported_model_aliases: unsupported_aliases,
        generated_secret_references: secret_refs,
        proposed_config,
        output: if dry_run {
            None
        } else {
            output.map(Path::to_path_buf)
        },
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn translate(config: &LegacyConfig) -> Result<(Option<String>, Vec<String>, usize, usize)> {
    let mut imports = Vec::new();
    let mut secret_refs = Vec::new();
    let mut aliases = 0;
    let env_names = migrated_env_names(config)?;
    for (index, provider) in config.openai_compatibility.iter().enumerate() {
        aliases += provider.models.len();
        if provider.disabled {
            continue;
        }
        let base = validate_base_url(&provider.base_url)?;
        let id = safe_id(&provider.name);
        if id.is_empty() {
            return Err(anyhow!(
                "compatible provider name cannot form a Pooler identifier"
            ));
        }
        let env_name = env_names[index]
            .as_deref()
            .expect("active providers always have a generated environment name");
        let secret_ref = format!("env:{env_name}");
        secret_refs.push(secret_ref.clone());
        imports.push(format!(
            "  - preset: gateway\n    as: migrated-{id}-{index}\n    with:\n      bind: 127.0.0.1:{}\n      upstream_url: {}\n      websocket_url: {}\n      secret: {}\n",
            8400_u16.checked_add(index as u16).ok_or_else(|| anyhow!("too many providers"))?,
            yaml_string(base.as_str()),
            yaml_string(&websocket_url(&base)?),
            yaml_string(&secret_ref),
        ));
    }
    if imports.is_empty() {
        return Ok((None, secret_refs, 0, aliases));
    }
    let translated = imports.len();
    Ok((
        Some(format!("imports:\n{}\nversion: 1\n", imports.concat())),
        secret_refs,
        translated,
        aliases,
    ))
}

/// Generate valid, deterministic environment names for active providers and
/// reject names whose normalization would alias one another.
fn migrated_env_names(config: &LegacyConfig) -> Result<Vec<Option<String>>> {
    let mut seen = BTreeMap::<String, (usize, String)>::new();
    let mut names = Vec::with_capacity(config.openai_compatibility.len());
    for (index, provider) in config.openai_compatibility.iter().enumerate() {
        if provider.disabled {
            names.push(None);
            continue;
        }
        let id = normalize_env_id(&provider.name)?;
        let env_name = format!("POOLER_MIGRATED_{id}_KEY");
        if let Some((other_index, other_name)) =
            seen.insert(env_name.clone(), (index, provider.name.clone()))
        {
            return Err(anyhow!(
                "compatible provider names {:?} (index {}) and {:?} (index {}) normalize to the same environment variable {:?}",
                other_name,
                other_index,
                provider.name,
                index,
                env_name,
            ));
        }
        names.push(Some(env_name));
    }
    Ok(names)
}

fn normalize_env_id(value: &str) -> Result<String> {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_uppercase());
        } else if !normalized.ends_with('_') {
            normalized.push('_');
        }
    }
    let normalized = normalized.trim_matches('_');
    if normalized.is_empty() {
        return Err(anyhow!(
            "compatible provider name cannot form an environment variable identifier"
        ));
    }
    Ok(normalized.to_owned())
}

fn validate_base_url(value: &str) -> Result<Url> {
    let url =
        Url::parse(value).map_err(|_| anyhow!("compatible provider has an invalid base URL"))?;
    let loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if (url.scheme() != "https" && !loopback_http)
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(anyhow!(
            "compatible provider base URL violates the migration trust boundary"
        ));
    }
    Ok(url)
}

fn websocket_url(base: &Url) -> Result<String> {
    let mut url = base.clone();
    let scheme = if base.scheme() == "https" {
        "wss"
    } else {
        "ws"
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow!("could not derive compatible WebSocket URL"))?;
    Ok(url.into())
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

fn publish_new_without_replace(temporary: &Path, destination: &Path) -> Result<()> {
    std::fs::hard_link(temporary, destination)
        .context("publish validated migration output without replacing an existing path")?;
    std::fs::remove_file(temporary).context("remove published migration temporary link")
}

fn write_validated_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(anyhow!("migration output already exists"));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("migration output needs a UTF-8 file name"))?;
    let temporary = parent.join(format!(
        ".{file_name}.pooler-migrate-{}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create migration output beside {}", path.display()))?;
        file.write_all(bytes).context("write migration output")?;
        file.sync_all().context("sync migration output")?;
        pooler_config::load_path(&temporary)
            .and_then(|config| config.compile())
            .context("translated Pooler configuration failed validation")?;
        publish_new_without_replace(&temporary, path)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync migration output directory")
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn validate_generated_config(input: &Path, output: Option<&Path>, bytes: &[u8]) -> Result<()> {
    let anchor = output.unwrap_or(input);
    let parent = anchor.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create dry-run validation file beside {}", anchor.display()))?;
    temporary
        .write_all(bytes)
        .context("write dry-run validation file")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync dry-run validation file")?;
    pooler_config::load_path(temporary.path())
        .and_then(|config| config.compile())
        .map(|_| ())
        .context("translated Pooler configuration failed validation")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &str = r#"
host: 127.0.0.1
port: 8317
api-keys: [downstream-secret]
openai-compatibility:
  - name: openrouter
    base-url: https://openrouter.ai/api/v1
    api-key-entries:
      - api-key: provider-secret
    models:
      - name: vendor/model
        alias: public-model
"#;

    #[test]
    fn translation_retains_no_legacy_secret_values() {
        let legacy: LegacyConfig = serde_yml::from_str(LEGACY).expect("legacy config");
        let (config, references, translated, aliases) = translate(&legacy).expect("translation");
        let config = config.expect("proposed config");
        assert_eq!(translated, 1);
        assert_eq!(aliases, 1);
        assert_eq!(references, ["env:POOLER_MIGRATED_OPENROUTER_KEY"]);
        assert!(!config.contains("downstream-secret"));
        assert!(!config.contains("provider-secret"));
        let directory = tempfile::tempdir().expect("directory");
        let output = directory.path().join("pooler.yaml");
        write_validated_new(&output, config.as_bytes()).expect("generated config compiles");
    }

    #[test]
    fn dry_run_writes_no_file_even_when_output_is_supplied() {
        let directory = tempfile::tempdir().expect("directory");
        let input = directory.path().join("cliproxy.yaml");
        let output = directory.path().join("pooler.yaml");
        std::fs::write(&input, LEGACY).expect("legacy config");
        cliproxy(&input, true, Some(&output)).expect("dry run");
        assert!(!output.exists());
        assert!(!directory
            .path()
            .join(format!(
                ".pooler-migrate-dry-run-{}.tmp",
                std::process::id()
            ))
            .exists());
    }

    #[test]
    fn migration_normalizes_provider_names_for_environment_references() {
        let legacy: LegacyConfig =
            serde_yml::from_str(&LEGACY.replace("openrouter", "foo-bar")).expect("legacy config");
        let (_, references, _, _) = translate(&legacy).expect("translation");
        assert_eq!(references, ["env:POOLER_MIGRATED_FOO_BAR_KEY"]);
    }

    #[test]
    fn migration_rejects_colliding_normalized_environment_references() {
        let legacy: LegacyConfig = serde_yml::from_str(
            r#"
openai-compatibility:
  - name: foo-bar
    base-url: https://example.com/v1
  - name: foo bar
    base-url: https://example.org/v1
"#,
        )
        .expect("legacy config");
        let error = translate(&legacy).expect_err("colliding names rejected");
        assert!(error.to_string().contains(
            "normalize to the same environment variable \"POOLER_MIGRATED_FOO_BAR_KEY\""
        ));
    }

    #[test]
    fn migration_rejects_names_without_identifier_characters() {
        let legacy: LegacyConfig = serde_yml::from_str(
            r#"
openai-compatibility:
  - name: "---"
    base-url: https://example.com/v1
"#,
        )
        .expect("legacy config");
        let error = translate(&legacy).expect_err("invalid name rejected");
        assert!(error
            .to_string()
            .contains("cannot form an environment variable identifier"));
    }

    #[test]
    fn dry_run_validation_rejects_invalid_expanded_configuration() {
        let directory = tempfile::tempdir().expect("directory");
        let input = directory.path().join("cliproxy.yaml");
        let error = validate_generated_config(
            &input,
            None,
            b"imports:\n  - preset: unsupported\nversion: 1\n",
        )
        .expect_err("invalid preset rejected");
        assert!(error
            .to_string()
            .contains("translated Pooler configuration"));
        assert!(!directory
            .path()
            .join(format!(
                ".pooler-migrate-dry-run-{}.tmp",
                std::process::id()
            ))
            .exists());
    }

    #[test]
    fn dry_run_validation_never_removes_a_preexisting_predictable_path() {
        let directory = tempfile::tempdir().expect("directory");
        let input = directory.path().join("cliproxy.yaml");
        let sentinel = directory.path().join(format!(
            ".pooler-migrate-dry-run-{}.tmp",
            std::process::id()
        ));
        std::fs::write(&sentinel, b"operator-owned").expect("sentinel");

        validate_generated_config(
            &input,
            None,
            b"version: 1\nlisteners: {local: {bind: 127.0.0.1:0}}\n",
        )
        .expect("validation succeeds beside sentinel");

        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel remains"),
            b"operator-owned"
        );
    }

    #[test]
    fn migration_reads_through_the_one_mebibyte_bound() {
        let directory = tempfile::tempdir().expect("directory");
        let input = directory.path().join("oversized.yaml");
        std::fs::write(&input, vec![b'a'; MAX_SOURCE_BYTES as usize + 1]).expect("oversized input");
        let error = cliproxy(&input, true, None).expect_err("oversized input rejected");
        assert!(error
            .to_string()
            .contains("exceeds the 1 MiB migration bound"));
    }

    #[test]
    fn migration_publication_never_replaces_a_concurrently_created_destination() {
        let directory = tempfile::tempdir().expect("directory");
        let temporary = directory.path().join("temporary.yaml");
        let destination = directory.path().join("destination.yaml");
        std::fs::write(&temporary, b"candidate").expect("temporary");
        std::fs::write(&destination, b"operator file").expect("destination");
        assert!(publish_new_without_replace(&temporary, &destination).is_err());
        assert_eq!(
            std::fs::read(&destination).expect("destination remains"),
            b"operator file"
        );
    }

    #[test]
    fn migration_rejects_credential_bearing_or_cleartext_remote_urls() {
        for url in [
            "https://user:secret@example.com/v1",
            "http://example.com/v1",
        ] {
            assert!(validate_base_url(url).is_err(), "accepted {url}");
        }
    }
}
