use std::fs;

use pooler_cli::{migrate_pooler_v1 as migrate, MigrationOptions};
use pooler_store::{CredentialPayload, CredentialState, MasterKey, SqliteStore, Store};

fn private_file(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("fixture mode");
    }
}

fn fixture(
    directory: &tempfile::TempDir,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture directory mode");
    }
    let config = directory.path().join("v1.yaml");
    let store = directory.path().join("v1.sqlite3");
    let key = directory.path().join("v1.key");
    let output_config = directory.path().join("v2.yaml");
    let output_store = directory.path().join("v2.sqlite3");
    let output_key = directory.path().join("v2.key");
    private_file(
        &config,
        br#"version: 1
listeners:
  local:
    bind: 127.0.0.1:18400
upstreams:
  provider:
    url: https://example.invalid/v1
accounts:
  account:
    provider: provider
    auth_kind: api_key
policies:
  default:
    selection:
      strategy: fill_first
routes: []
models:
  - id: public-model
    targets:
      - provider: provider
        account: account
        upstream_model: vendor/model
"#,
    );
    private_file(&key, b"migration-test-key");
    let store_key = MasterKey::from_bytes(b"migration-test-key").expect("master key");
    let store_instance = SqliteStore::open_encrypted(&store, store_key).expect("store");
    store_instance
        .upsert_credential_state(CredentialState::new("account", "provider", true, 1))
        .expect("credential metadata");
    store_instance
        .upsert_credential_payload(
            "account",
            &CredentialPayload::new(b"secret-token").expect("payload"),
            1,
        )
        .expect("credential payload");
    (config, store, key, output_config, output_store, output_key)
}

#[test]
fn dry_run_does_not_create_destinations_or_print_secret_values() {
    let directory = tempfile::tempdir().expect("directory");
    let (config, store, key, output_config, output_store, output_key) = fixture(&directory);
    let options = MigrationOptions {
        source_config: config,
        source_store: store,
        source_key: key,
        destination_config: output_config.clone(),
        destination_store: output_store.clone(),
        destination_key: output_key.clone(),
        transaction_dir: Some(directory.path().join("transaction")),
        dry_run: true,
        quiesced: true,
        replace_existing: false,
        fail_after: None,
    };
    let report = migrate(&options).expect("dry-run migration");
    let rendered = serde_json::to_string(&report).expect("report");
    assert!(!rendered.contains("secret-token"));
    assert!(!output_config.exists());
    assert!(!output_store.exists());
    assert!(!output_key.exists());
}

#[test]
fn real_migration_reencrypts_payload_and_purges_legacy_affinity_namespace() {
    let directory = tempfile::tempdir().expect("directory");
    let (config, store, key, output_config, output_store, output_key) = fixture(&directory);
    let options = MigrationOptions {
        source_config: config,
        source_store: store,
        source_key: key,
        destination_config: output_config.clone(),
        destination_store: output_store.clone(),
        destination_key: output_key,
        transaction_dir: Some(directory.path().join("transaction")),
        dry_run: false,
        quiesced: true,
        replace_existing: false,
        fail_after: None,
    };
    let report = migrate(&options).expect("migration");
    assert_eq!(report.phase, "committed");
    let rendered = fs::read_to_string(output_config).expect("v2 config");
    pooler_config::Config::from_yaml("migrated.yaml", &rendered)
        .expect("v2 parse")
        .compile()
        .expect("v2 compile");
    let migrated = SqliteStore::open_encrypted(
        output_store,
        MasterKey::from_bytes(b"migration-test-key").expect("master key"),
    )
    .expect("migrated store");
    let state = migrated
        .credential_state("account")
        .expect("state")
        .expect("account state");
    assert!(!state.configuration_fingerprint.is_empty());
    assert_eq!(
        migrated
            .credential_payload("account")
            .expect("payload")
            .expect("payload")
            .as_bytes(),
        b"secret-token"
    );
    assert_eq!(migrated.len().expect("lengths").affinities, 0);
}

#[test]
fn migration_requires_explicit_quiescence_and_rejects_ambiguous_model_binding() {
    let directory = tempfile::tempdir().expect("directory");
    let (config, store, key, output_config, output_store, output_key) = fixture(&directory);
    let mut options = MigrationOptions {
        source_config: config.clone(),
        source_store: store.clone(),
        source_key: key.clone(),
        destination_config: output_config.clone(),
        destination_store: output_store,
        destination_key: output_key,
        transaction_dir: Some(directory.path().join("transaction-no-quiesce")),
        dry_run: true,
        quiesced: false,
        replace_existing: false,
        fail_after: None,
    };
    assert!(migrate(&options).is_err());
    let ambiguous = fs::read_to_string(config)
        .expect("config")
        .replace(
            "  account:\n    provider: provider\n    auth_kind: api_key\n",
            "  account:\n    provider: provider\n    auth_kind: api_key\n  second:\n    provider: provider\n    auth_kind: api_key\n",
        )
        .replace("        account: account\n", "");
    private_file(&options.source_config, ambiguous.as_bytes());
    options.transaction_dir = Some(directory.path().join("transaction-ambiguous"));
    options.quiesced = true;
    assert!(migrate(&options).is_err());
    assert!(!output_config.exists());
}
