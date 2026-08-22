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

#[derive(Debug, Serialize)]
pub(crate) struct InitReport {
    pub schema_version: u32,
    pub directory: PathBuf,
    pub config: PathBuf,
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
        management_url: "http://127.0.0.1:18477/management/ui/".to_owned(),
        credential_key_ref: credential_key_ref.clone(),
        provider_secret_ref,
        next_steps: vec![
            format!("write the provider API key to {}", provider_key.display()),
            format!("pooler check --config {}", config.display()),
            format!(
                "pooler --config {} --credential-key-ref {} serve",
                config.display(),
                credential_key_ref
            ),
            "pooler dashboard --config <path-to-pooler.yaml>".to_owned(),
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
}
