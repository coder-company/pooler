use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use pooler_store::{MasterKey, SqliteStore, Store};

const CONFIG: &str = r#"
version: 1
upstreams:
  xai:
    url: https://api.x.ai
    native: {kind: xai}
accounts:
  work: {provider: xai, auth_kind: api_key, secret: env:XAI_WORK_KEY}
  personal: {provider: xai, auth_kind: api_key, secret: env:XAI_PERSONAL_KEY}
"#;

fn invoke(
    config_path: &Path,
    store_path: &Path,
    key_reference: Option<&str>,
    operation: &str,
    account: &str,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pooler"));
    command
        .args(["--config", config_path.to_str().expect("UTF-8 config path")])
        .args([
            "--credential-store",
            store_path.to_str().expect("UTF-8 store path"),
        ]);
    if let Some(key_reference) = key_reference {
        command.args(["--credential-key-ref", key_reference]);
    }
    command
        .args(["auth", operation, account])
        .output()
        .expect("pooler process")
}

#[test]
fn account_mutations_use_the_global_encryption_key_and_fail_closed_without_it() {
    let directory = tempfile::tempdir().expect("temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(directory.path())
            .expect("temporary directory metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(directory.path(), permissions)
            .expect("owner-private temporary directory");
    }
    let config_path = directory.path().join("pooler.yaml");
    let store_path = directory.path().join("credentials.sqlite3");
    let key_path = directory.path().join("store-key");
    fs::write(&config_path, CONFIG).expect("config");
    fs::write(&key_path, b"process-auth-mutation-key").expect("key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&key_path).expect("key metadata").permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&key_path, permissions).expect("private key file");
    }
    let key_reference = format!("file:{}", key_path.display());
    SqliteStore::open_encrypted(
        &store_path,
        MasterKey::from_bytes(b"process-auth-mutation-key").expect("master key"),
    )
    .expect("encrypted store");

    for (operation, account) in [
        ("switch", "personal"),
        ("enable", "work"),
        ("disable", "personal"),
    ] {
        let output = invoke(&config_path, &store_path, None, operation, account);
        assert!(
            !output.status.success(),
            "{operation} unexpectedly succeeded"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("encryption key"), "{operation}: {stderr}");
    }

    for (operation, account) in [
        ("switch", "personal"),
        ("enable", "work"),
        ("disable", "personal"),
    ] {
        let output = invoke(
            &config_path,
            &store_path,
            Some(&key_reference),
            operation,
            account,
        );
        assert!(
            output.status.success(),
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let store = SqliteStore::open_encrypted(
        &store_path,
        MasterKey::from_bytes(b"process-auth-mutation-key").expect("master key"),
    )
    .expect("reopen encrypted store");
    assert!(
        store
            .credential_state("work")
            .expect("work state")
            .expect("work account")
            .enabled
    );
    assert!(
        !store
            .credential_state("personal")
            .expect("personal state")
            .expect("personal account")
            .enabled
    );
}
