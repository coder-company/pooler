//! Secure, non-destructive first-run bootstrap.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::Serialize;

const CONFIG_NAME: &str = "pooler.yaml";
const MANAGEMENT_TOKEN_NAME: &str = "management.token";
const STORE_KEY_NAME: &str = "store.key";
const PROVIDER_KEY_NAME: &str = "provider.key";
const CREDENTIAL_STORE_NAME: &str = "credentials.sqlite3";

#[derive(Debug, Serialize)]
pub(crate) struct InitReport {
    pub schema_version: u32,
    pub directory: PathBuf,
    pub config: PathBuf,
    pub credential_store: PathBuf,
    pub management_url: String,
    pub credential_key_ref: String,
    pub provider_secret_ref: String,
    pub next_steps: Vec<String>,
}

pub(crate) fn init(output: &Path) -> Result<InitReport> {
    if output.exists() {
        return Err(anyhow!(
            "bootstrap destination already exists; choose a new directory"
        ));
    }
    create_private_directory(output)?;
    let result = initialize_private_directory(output);
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

fn initialize_private_directory(output: &Path) -> Result<InitReport> {
    let directory = output
        .canonicalize()
        .with_context(|| format!("canonicalize bootstrap directory {}", output.display()))?;
    let config = directory.join(CONFIG_NAME);
    let management_token = directory.join(MANAGEMENT_TOKEN_NAME);
    let store_key = directory.join(STORE_KEY_NAME);
    let provider_key = directory.join(PROVIDER_KEY_NAME);
    let credential_store = directory.join(CREDENTIAL_STORE_NAME);

    write_private_new(&management_token, &random_secret(32)?)?;
    write_private_new(&store_key, &random_secret(32)?)?;
    write_private_new(&provider_key, b"")?;

    let provider_secret_ref = file_reference(&provider_key);
    let management_secret_ref = file_reference(&management_token);
    let credential_key_ref = file_reference(&store_key);
    let yaml = format!(
        "imports:\n  - preset: gateway\n    as: gateway\n    with:\n      bind: 127.0.0.1:8400\n      upstream_url: https://api.openai.com\n      websocket_url: wss://api.openai.com\n      secret: {}\n\nversion: 1\nmanagement:\n  bind: 127.0.0.1:18477\n  auth:\n    secret: {}\n",
        yaml_string(&provider_secret_ref),
        yaml_string(&management_secret_ref),
    );
    write_private_new(&config, yaml.as_bytes())?;
    pooler_config::load_path(&config)
        .and_then(|config| config.compile())
        .context("generated starter configuration did not compile")?;
    sync_directory(&directory)?;

    Ok(InitReport {
        schema_version: 1,
        directory,
        config: config.clone(),
        credential_store: credential_store.clone(),
        management_url: "http://127.0.0.1:18477/management/ui/".to_owned(),
        credential_key_ref: credential_key_ref.clone(),
        provider_secret_ref,
        next_steps: vec![
            shell_note().to_owned(),
            format!(
                "write the provider API key to {}",
                shell_quote_path(&provider_key)
            ),
            format!("pooler check --config {}", shell_quote_path(&config)),
            format!(
                "pooler --config {} --credential-store {} --credential-key-ref {} serve",
                shell_quote_path(&config),
                shell_quote_path(&credential_store),
                shell_quote(&credential_key_ref),
            ),
            format!("pooler --config {} dashboard", shell_quote_path(&config)),
        ],
    })
}

fn random_secret(bytes: usize) -> Result<Vec<u8>> {
    let mut value = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow!("operating-system randomness is unavailable"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(value)
        .into_bytes())
}

fn file_reference(path: &Path) -> String {
    format!("file:{}", path.display())
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize as JSON/YAML scalars")
}

#[cfg(not(windows))]
/// Quote one value for a POSIX shell command printed as a copy/paste step.
///
/// Paths are generated from the filesystem and can contain whitespace,
/// shell metacharacters, or single quotes. Single-quoted shell strings are
/// inert, with an embedded quote represented by the standard close/escape/
/// reopen sequence.
fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(windows)]
/// Quote one value for a cmd.exe command.
///
/// Double quotes both preserve whitespace and make cmd.exe metacharacters
/// ordinary argument characters. Backslashes are doubled where required by
/// the Windows command-line parser, especially before embedded or closing
/// double quotes.
fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                quoted.push('\\');
            }
            quoted.push('"');
        } else {
            for _ in 0..backslashes {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        backslashes = 0;
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

#[cfg(not(windows))]
fn shell_note() -> &'static str {
    "The commands below use POSIX shell quoting (sh/bash/zsh/WSL); adapt quoting for Windows cmd or PowerShell."
}

#[cfg(windows)]
fn shell_note() -> &'static str {
    "The commands below use cmd.exe quoting; PowerShell users should adapt the quoting."
}

fn shell_quote_path(path: &Path) -> String {
    shell_quote(&path.to_string_lossy())
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create private bootstrap directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)
        .with_context(|| format!("create private bootstrap directory {}", path.display()))?;
    Ok(())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create private bootstrap file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write bootstrap file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync bootstrap file {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync bootstrap directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_valid_owner_private_secret_references() {
        let parent = tempfile::tempdir().expect("parent");
        let destination = parent.path().join("starter");
        let report = init(&destination).expect("bootstrap");
        let yaml = fs::read_to_string(&report.config).expect("starter YAML");
        let token = fs::read_to_string(destination.join(MANAGEMENT_TOKEN_NAME)).expect("token");
        assert!(!yaml.contains(&token));
        assert!(yaml.contains("file:"));
        pooler_config::load_path(&report.config)
            .and_then(|config| config.compile())
            .expect("compiled starter");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&destination)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for name in [
                CONFIG_NAME,
                MANAGEMENT_TOKEN_NAME,
                STORE_KEY_NAME,
                PROVIDER_KEY_NAME,
            ] {
                let permissions = fs::metadata(destination.join(name))
                    .expect("metadata")
                    .permissions();
                assert_eq!(permissions.mode() & 0o777, 0o600);
            }
        }
    }

    #[test]
    fn init_refuses_to_modify_an_existing_destination() {
        let destination = tempfile::tempdir().expect("destination");
        let sentinel = destination.path().join("keep");
        fs::write(&sentinel, "unchanged").expect("sentinel");
        assert!(init(destination.path()).is_err());
        assert_eq!(fs::read_to_string(sentinel).expect("sentinel"), "unchanged");
    }

    #[test]
    fn init_steps_quote_paths_and_pin_the_credential_store_to_the_deployment() {
        let parent = tempfile::tempdir().expect("parent");
        let destination = parent.path().join("starter with 'quotes'");
        let report = init(&destination).expect("bootstrap");
        let config = shell_quote_path(&report.config);
        let store = shell_quote_path(&report.credential_store);
        let key = shell_quote(&report.credential_key_ref);

        assert!(report.next_steps[0].contains("quoting"));
        assert!(report
            .next_steps
            .iter()
            .any(|step| step == &format!("pooler check --config {config}")));
        assert!(report.next_steps.iter().any(|step| {
            step == &format!(
                "pooler --config {config} --credential-store {store} --credential-key-ref {key} serve"
            )
        }));
        assert!(report
            .next_steps
            .iter()
            .any(|step| step == &format!("pooler --config {config} dashboard")));
        assert!(report.credential_store.ends_with(CREDENTIAL_STORE_NAME));
    }

    #[cfg(not(windows))]
    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a path/'quoted'"), "'a path/'\\''quoted'\\'''");
    }

    #[cfg(windows)]
    #[test]
    fn shell_quote_uses_cmd_double_quotes_for_spaces_and_metacharacters() {
        assert_eq!(
            shell_quote(r#"C:\Pooler & data\store.key"#),
            r#""C:\Pooler & data\store.key""#
        );
        assert_eq!(
            shell_quote(r#"C:\Pooler ^ data\store.key"#),
            r#""C:\Pooler ^ data\store.key""#
        );
        assert!(shell_note().contains("cmd.exe"));
    }
}
