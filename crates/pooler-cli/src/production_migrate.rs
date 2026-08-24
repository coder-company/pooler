//! One-shot migration from the retired Pooler-v1 layout.
//!
//! This module is deliberately separate from the CLIProxyAPI translator. A
//! Pooler-v1 migration has a stronger contract: the source must be quiesced,
//! SQLite is copied with its backup API, credential payloads are authenticated
//! under their exact legacy AAD and immediately re-encrypted under the v2
//! identity, and promotion never replaces an input file.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use pooler_config::{Config, SecretRef};
use pooler_store::{
    credential_configuration_fingerprint, CredentialFingerprintInput, MasterKey, SqliteStore, Store,
};
use ring::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MANIFEST_VERSION: u32 = 1;
const OPERATION: &str = "pooler-v1-to-v2";
const STAGED_CONFIG: &str = "pooler.yaml";
const STAGED_STORE: &str = "credentials.sqlite3";
const STAGED_KEY: &str = "store.key";
const STAGED_COMPACT_STORE: &str = "credentials.compact.sqlite3";

/// Inputs and destinations for one production migration.
#[derive(Clone, Debug)]
pub struct MigrationOptions {
    /// Retired v1 source configuration.
    pub source_config: PathBuf,
    /// Retired v1 encrypted SQLite store.
    pub source_store: PathBuf,
    /// Raw owner-private bytes used as the v1 store key.
    pub source_key: PathBuf,
    /// New canonical v2 configuration path.
    pub destination_config: PathBuf,
    /// New canonical v2 encrypted SQLite store path.
    pub destination_store: PathBuf,
    /// New canonical v2 store-key path.
    pub destination_key: PathBuf,
    /// Private transaction directory. A deterministic sibling is used when
    /// omitted.
    pub transaction_dir: Option<PathBuf>,
    /// Validate and stage without checkpointing or promoting anything.
    pub dry_run: bool,
    /// The caller has stopped all source writers and accepts the exclusive
    /// SQLite backup boundary.
    pub quiesced: bool,
    /// Permit replacing existing destinations after each one is copied into
    /// the private transaction backup set. The default is idempotent refusal.
    pub replace_existing: bool,
    /// Test-only promotion interruption hook. It is ignored unless supplied
    /// by an embedding caller; the CLI keeps this unset.
    pub fail_after: Option<usize>,
}

impl MigrationOptions {
    /// Construct options for callers that want explicit paths in code/tests.
    #[must_use]
    pub fn new(
        source_config: impl Into<PathBuf>,
        source_store: impl Into<PathBuf>,
        source_key: impl Into<PathBuf>,
        destination_config: impl Into<PathBuf>,
        destination_store: impl Into<PathBuf>,
        destination_key: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source_config: source_config.into(),
            source_store: source_store.into(),
            source_key: source_key.into(),
            destination_config: destination_config.into(),
            destination_store: destination_store.into(),
            destination_key: destination_key.into(),
            transaction_dir: None,
            dry_run: false,
            quiesced: false,
            replace_existing: false,
            fail_after: None,
        }
    }
}

/// Redacted migration result. It contains paths, counts, phases, and digests,
/// never key bytes, credential payloads, or provider response bodies.
#[derive(Clone, Debug, Serialize)]
pub struct MigrationReport {
    pub operation: &'static str,
    pub dry_run: bool,
    pub phase: String,
    pub transaction_dir: PathBuf,
    pub manifest: PathBuf,
    pub providers: usize,
    pub accounts: usize,
    pub models: usize,
    pub credentials_reencrypted: usize,
    pub legacy_affinities_purged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileFact {
    role: String,
    path: String,
    exists: bool,
    size: u64,
    mode: Option<u32>,
    owner_uid: Option<u32>,
    owner_gid: Option<u32>,
    sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    manifest_version: u32,
    operation: String,
    phase: String,
    source: Vec<FileFact>,
    source_after: Vec<FileFact>,
    wal_checkpointed: bool,
    staged: Vec<FileFact>,
    destinations: Vec<FileFact>,
    promoted: Vec<String>,
    backups: Vec<BackupEntry>,
    providers: usize,
    accounts: usize,
    models: usize,
    credentials_reencrypted: usize,
    legacy_affinities_purged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BackupEntry {
    destination: String,
    backup: String,
}

#[derive(Clone, Debug)]
struct MigratedConfig {
    yaml: String,
    providers: usize,
    accounts: usize,
    models: usize,
}

/// Execute one Pooler-v1 migration.
pub fn migrate(options: &MigrationOptions) -> Result<MigrationReport> {
    if !options.quiesced {
        bail!("Pooler-v1 migration requires an explicitly quiesced source store");
    }
    if !options.replace_existing {
        reject_existing_destination(&options.destination_config)?;
        reject_existing_destination(&options.destination_store)?;
        reject_existing_destination(&options.destination_key)?;
    }
    ensure_distinct_paths(options)?;

    let source_config_fact = file_fact("config", &options.source_config, true)?;
    let source_key_fact = file_fact("key", &options.source_key, true)?;
    let source_store_fact = file_fact("store", &options.source_store, true)?;
    let source_wal_fact = file_fact("store-wal", &sidecar(&options.source_store, "-wal"), false)?;
    let source_shm_fact = file_fact("store-shm", &sidecar(&options.source_store, "-shm"), false)?;
    let source_facts = vec![
        source_config_fact,
        source_key_fact,
        source_store_fact,
        source_wal_fact,
        source_shm_fact,
    ];

    let source_config = read_config_source(&options.source_config)?;
    let migrated = translate_v1_config(&source_config)?;
    Config::from_yaml("<pooler-v1-migration>", &migrated.yaml)
        .and_then(|config| config.compile())
        .map_err(|_| anyhow!("translated Pooler configuration failed validation"))?;

    let transaction_dir = transaction_dir(options)?;
    create_transaction_dir(&transaction_dir)?;
    let stage_dir = transaction_dir.join("stage");
    create_private_directory(&stage_dir)?;
    let manifest_path = transaction_dir.join("manifest.json");
    if manifest_path.exists() {
        bail!("migration transaction already exists; use --recover before retrying");
    }

    let mut manifest = Manifest {
        manifest_version: MANIFEST_VERSION,
        operation: OPERATION.to_owned(),
        phase: "prepared".to_owned(),
        source: source_facts,
        source_after: Vec::new(),
        wal_checkpointed: false,
        staged: Vec::new(),
        destinations: destination_facts(options)?,
        promoted: Vec::new(),
        backups: Vec::new(),
        providers: migrated.providers,
        accounts: migrated.accounts,
        models: migrated.models,
        credentials_reencrypted: 0,
        legacy_affinities_purged: false,
    };
    write_manifest(&manifest_path, &manifest)?;

    let staged_config = stage_dir.join(STAGED_CONFIG);
    write_private_new(
        &staged_config,
        migrated.yaml.as_bytes(),
        source_mode(&manifest.source, "config")?,
    )?;
    let key_bytes = Zeroizing::new(read_private_bytes(&options.source_key, "store key")?);
    let master_key = MasterKey::from_bytes(key_bytes.as_slice())
        .map_err(|_| anyhow!("source store key could not be resolved"))?;
    manifest.staged = vec![file_fact("staged-config", &staged_config, true)?];
    write_manifest(&manifest_path, &manifest)?;

    if options.dry_run {
        manifest.phase = "dry_run_validated".to_owned();
        write_manifest(&manifest_path, &manifest)?;
        return Ok(report_from_manifest(
            &manifest,
            transaction_dir,
            manifest_path,
        ));
    }

    let staged_key = stage_dir.join(STAGED_KEY);
    write_private_new(
        &staged_key,
        key_bytes.as_slice(),
        source_mode(&manifest.source, "key")?,
    )?;
    manifest
        .staged
        .push(file_fact("staged-key", &staged_key, true)?);
    write_manifest(&manifest_path, &manifest)?;

    let staged_store = stage_dir.join(STAGED_STORE);
    SqliteStore::checkpoint_and_backup_quiesced(&options.source_store, &staged_store)
        .map_err(|error| anyhow!("quiesced SQLite backup failed: {error}"))?;
    set_file_mode(&staged_store, source_mode(&manifest.source, "store")?)?;
    let source_store = read_only_integrity(&options.source_store)?;
    if !source_store {
        bail!("source SQLite integrity check failed");
    }
    manifest.source_after = vec![
        file_fact("config", &options.source_config, true)?,
        file_fact("key", &options.source_key, true)?,
        file_fact("store", &options.source_store, true)?,
        file_fact("store-wal", &sidecar(&options.source_store, "-wal"), false)?,
        file_fact("store-shm", &sidecar(&options.source_store, "-shm"), false)?,
    ];
    for role in ["config", "key"] {
        let before = manifest
            .source
            .iter()
            .find(|fact| fact.role == role)
            .and_then(|fact| fact.sha256.as_deref());
        let after = manifest
            .source_after
            .iter()
            .find(|fact| fact.role == role)
            .and_then(|fact| fact.sha256.as_deref());
        if before != after {
            bail!("Pooler-v1 source changed during migration");
        }
    }
    manifest.wal_checkpointed = true;
    write_manifest(&manifest_path, &manifest)?;

    let store = SqliteStore::open_encrypted(&staged_store, master_key)
        .map_err(|_| anyhow!("staged SQLite store could not be opened with the source key"))?;
    store
        .integrity_check()
        .map_err(|_| anyhow!("staged SQLite integrity check failed"))?;
    let states = store
        .credential_states()
        .map_err(|_| anyhow!("staged credential metadata could not be read"))?;
    let account_facts = account_fingerprints(&source_config)?;
    for state in states {
        let Some(facts) = account_facts.get(&state.credential_id) else {
            bail!("credential metadata has no unambiguous v1 account mapping");
        };
        if facts.provider_id != state.provider_id {
            bail!("credential metadata provider does not match the v1 account");
        }
        let fingerprint = credential_configuration_fingerprint(&facts.input)
            .map_err(|_| anyhow!("v1 account identity could not be fingerprinted"))?;
        if state.configuration_fingerprint.is_empty() {
            store
                .adopt_credential_fingerprint(
                    &state.credential_id,
                    "",
                    &fingerprint,
                    state.updated_at.max(1),
                )
                .map_err(|_| anyhow!("legacy credential payload could not be re-encrypted"))?;
            manifest.credentials_reencrypted += 1;
        } else if state.configuration_fingerprint != fingerprint {
            bail!("credential identity fingerprint conflict");
        }
    }
    manifest.legacy_affinities_purged = true;
    drop(store);

    let compact_store = stage_dir.join(STAGED_COMPACT_STORE);
    SqliteStore::checkpoint_and_backup_quiesced(&staged_store, &compact_store)
        .map_err(|_| anyhow!("staged SQLite checkpoint failed"))?;
    set_file_mode(&compact_store, source_mode(&manifest.source, "store")?)?;
    fs::remove_file(&staged_store).context("replace staged SQLite backup")?;
    fs::rename(&compact_store, &staged_store).context("publish compact staged SQLite backup")?;
    remove_sidecars(&staged_store)?;
    sync_directory(&stage_dir)?;
    manifest.staged = staged_facts(&stage_dir)?;
    manifest.phase = "staged".to_owned();
    write_manifest(&manifest_path, &manifest)?;

    promote(&transaction_dir, &manifest_path, &mut manifest, options)?;
    Ok(report_from_manifest(
        &manifest,
        transaction_dir,
        manifest_path,
    ))
}

/// Recover a transaction left in the prepared/staged/promoting phases.
pub fn recover_transaction(transaction_dir: &Path) -> Result<MigrationReport> {
    let manifest_path = transaction_dir.join("manifest.json");
    let mut manifest: Manifest = read_json(&manifest_path)?;
    if manifest.operation != OPERATION || manifest.manifest_version != MANIFEST_VERSION {
        bail!("migration transaction manifest is unsupported");
    }
    match manifest.phase.as_str() {
        "committed" | "rolled_back" | "dry_run_validated" => {}
        "prepared" | "staged" | "promoting" => {
            rollback_promoted(&mut manifest)?;
            manifest.phase = "rolled_back".to_owned();
            write_manifest(&manifest_path, &manifest)?;
        }
        _ => bail!("migration transaction phase is unknown"),
    }
    Ok(report_from_manifest(
        &manifest,
        transaction_dir.to_owned(),
        manifest_path,
    ))
}

/// CLI entry point. Output is a redacted JSON report only.
pub fn run(options: MigrationOptions, recover: Option<PathBuf>) -> Result<()> {
    let report = if let Some(transaction_dir) = recover {
        recover_transaction(&transaction_dir)?
    } else {
        migrate(&options)?
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize migration report")?
    );
    Ok(())
}

fn translate_v1_config(source: &str) -> Result<MigratedConfig> {
    reject_literal_secret_values(source)?;
    let mut root: Value = serde_yml::from_str(source)
        .map_err(|_| anyhow!("Pooler-v1 configuration is not valid YAML"))?;
    let object = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("Pooler-v1 configuration root must be a mapping"))?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Pooler-v1 configuration version is missing"))?;
    if version != 1 {
        bail!("Pooler-v1 migration accepts only version 1 input");
    }
    reject_unknown_root_fields(object)?;
    object.insert("version".to_owned(), Value::from(2_u64));

    let upstreams = object_map(object, "upstreams")?;
    let upstream_snapshot = upstreams.clone();
    let providers = upstreams.len();
    let accounts = normalize_accounts(object, &upstream_snapshot)?;
    let account_ids = accounts.keys().cloned().collect::<Vec<_>>();
    let account_providers = accounts
        .iter()
        .filter_map(|(id, value)| {
            value
                .get("provider")
                .and_then(Value::as_str)
                .map(|p| (id, p))
        })
        .map(|(id, provider)| (id.clone(), provider.to_owned()))
        .collect::<BTreeMap<_, _>>();
    let pools = normalize_singleton_pools(object, &account_providers)?;
    if pools.is_empty() && !account_ids.is_empty() {
        bail!("v1 account pool mapping is ambiguous");
    }
    normalize_policies(object, &account_providers)?;
    let models = normalize_models(object, &accounts, &pools)?;
    let model_count = models.as_array().map_or(0, Vec::len);
    object.insert("models".to_owned(), models);
    let yaml =
        serde_yml::to_string(&root).map_err(|_| anyhow!("could not render v2 configuration"))?;
    Ok(MigratedConfig {
        yaml,
        providers,
        accounts: accounts.len(),
        models: model_count,
    })
}

fn reject_unknown_root_fields(object: &Map<String, Value>) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "version",
        "listeners",
        "management",
        "upstreams",
        "models",
        "catalog",
        "usage_price_book",
        "accounts",
        "account_pools",
        "policies",
        "routes",
        "extensions",
        "imports",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        bail!("Pooler-v1 configuration contains an unsupported top-level field");
    }
    Ok(())
}

fn normalize_accounts(
    object: &mut Map<String, Value>,
    upstreams: &Map<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let accounts = object_map_mut(object, "accounts")?;
    let mut normalized = BTreeMap::new();
    for (id, value) in accounts.iter_mut() {
        let account = value
            .as_object_mut()
            .ok_or_else(|| anyhow!("v1 account declaration must be a mapping"))?;
        let provider = account
            .get("provider")
            .or_else(|| account.get("upstream"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("v1 account provider mapping is ambiguous"))?
            .to_owned();
        account.insert("provider".to_owned(), Value::String(provider.clone()));
        account.remove("upstream");
        if !account.contains_key("auth_kind") {
            let inferred_codex = upstreams
                .get(&provider)
                .and_then(Value::as_object)
                .and_then(|upstream| upstream.get("native"))
                .and_then(Value::as_object)
                .and_then(|native| native.get("kind"))
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("codex"));
            if account.contains_key("oauth") || inferred_codex {
                account.insert("auth_kind".to_owned(), Value::String("oauth".to_owned()));
            } else {
                account.insert("auth_kind".to_owned(), Value::String("api_key".to_owned()));
            }
        }
        if account.get("auth_kind").and_then(Value::as_str) == Some("api_key")
            && !account.contains_key("secret")
        {
            account.insert("secret".to_owned(), Value::String(format!("managed:{id}")));
        }
        account.remove("oauth");
        normalized.insert(id.clone(), value.clone());
    }
    Ok(normalized)
}

fn normalize_singleton_pools(
    object: &mut Map<String, Value>,
    account_providers: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Value>> {
    let pools = object
        .entry("account_pools".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let pools = pools
        .as_object_mut()
        .ok_or_else(|| anyhow!("v1 account pools must be a mapping"))?;
    for (account, provider) in account_providers {
        let pool_id = singleton_pool_id(account);
        if let Some(existing) = pools.get(&pool_id) {
            let existing_accounts = existing
                .get("accounts")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("v1 account pool mapping is ambiguous"))?;
            if existing_accounts.len() != 1
                || existing_accounts.first().and_then(Value::as_str) != Some(account)
            {
                bail!("v1 account pool ID normalization is ambiguous");
            }
        }
        let entry = pools
            .entry(pool_id)
            .or_insert_with(|| Value::Object(Map::new()));
        let pool = entry
            .as_object_mut()
            .ok_or_else(|| anyhow!("v1 account pool declaration must be a mapping"))?;
        pool.insert("provider".to_owned(), Value::String(provider.clone()));
        pool.insert(
            "accounts".to_owned(),
            Value::Array(vec![Value::String(account.clone())]),
        );
        pool.entry("strategy".to_owned())
            .or_insert_with(|| Value::String("fill_first".to_owned()));
    }
    Ok(pools.clone().into_iter().collect())
}

fn normalize_policies(
    object: &mut Map<String, Value>,
    account_providers: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(policies) = object.get_mut("policies") else {
        return Ok(());
    };
    let policies = policies
        .as_object_mut()
        .ok_or_else(|| anyhow!("v1 policies must be a mapping"))?;
    for value in policies.values_mut() {
        let policy = value
            .as_object_mut()
            .ok_or_else(|| anyhow!("v1 policy declaration must be a mapping"))?;
        if let Some(selection) = policy.get_mut("selection") {
            let selection = selection
                .as_object_mut()
                .ok_or_else(|| anyhow!("v1 selection declaration must be a mapping"))?;
            if let Some(accounts) = selection.get("accounts") {
                let accounts = accounts
                    .as_array()
                    .ok_or_else(|| anyhow!("v1 policy accounts must be a list"))?;
                let mut providers = BTreeMap::new();
                for account in accounts {
                    let account = account
                        .as_str()
                        .ok_or_else(|| anyhow!("v1 policy account mapping is ambiguous"))?;
                    let provider = account_providers
                        .get(account)
                        .ok_or_else(|| anyhow!("v1 policy references an unknown account"))?;
                    providers.insert(provider, ());
                }
                if providers.len() > 1 {
                    bail!("v1 policy account mapping crosses providers");
                }
            }
            // Account membership now belongs to explicit model targets and
            // pools. Removing the retired field prevents a silent v1 policy
            // compatibility path from surviving in the v2 compiler.
            selection.remove("accounts");
            selection.remove("account");
            selection.remove("account_pool");
        }
    }
    Ok(())
}

fn normalize_models(
    object: &Map<String, Value>,
    accounts: &BTreeMap<String, Value>,
    pools: &BTreeMap<String, Value>,
) -> Result<Value> {
    let Some(value) = object.get("models") else {
        return Ok(Value::Array(Vec::new()));
    };
    let mut models = Vec::new();
    match value {
        Value::Array(entries) => {
            for (ordinal, entry) in entries.iter().enumerate() {
                models.push(normalize_model(entry, ordinal, accounts, pools)?);
            }
        }
        Value::Object(entries) => {
            for (ordinal, (id, entry)) in entries.iter().enumerate() {
                let mut model = entry.clone();
                if let Some(model_object) = model.as_object_mut() {
                    model_object
                        .entry("id".to_owned())
                        .or_insert_with(|| Value::String(id.clone()));
                } else {
                    model = Value::Object(Map::from_iter([
                        ("id".to_owned(), Value::String(id.clone())),
                        (
                            "targets".to_owned(),
                            Value::Array(vec![Value::String(id.clone())]),
                        ),
                    ]));
                }
                models.push(normalize_model(&model, ordinal, accounts, pools)?);
            }
        }
        _ => bail!("v1 models must be a list or mapping"),
    }
    Ok(Value::Array(models))
}

fn normalize_model(
    value: &Value,
    _model_ordinal: usize,
    accounts: &BTreeMap<String, Value>,
    pools: &BTreeMap<String, Value>,
) -> Result<Value> {
    let source = value
        .as_object()
        .ok_or_else(|| anyhow!("v1 model declaration must be a mapping"))?;
    let id = source
        .get("id")
        .or_else(|| source.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("v1 model ID is missing"))?
        .to_owned();
    let raw_targets = source
        .get("targets")
        .or_else(|| source.get("providers"))
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![Value::String(id.clone())]));
    let targets = match raw_targets {
        Value::Array(entries) => entries,
        Value::Object(entries) => entries
            .into_iter()
            .map(|(provider, mut target)| {
                if let Some(target) = target.as_object_mut() {
                    target
                        .entry("provider".to_owned())
                        .or_insert_with(|| Value::String(provider.clone()));
                }
                target
            })
            .collect(),
        Value::String(provider) => vec![Value::String(provider)],
        _ => return Err(anyhow!("v1 model targets must be a list or mapping")),
    };
    if targets.is_empty() {
        bail!("v1 model has no targets");
    }
    let normalized_targets = targets
        .iter()
        .enumerate()
        .map(|(target_ordinal, target)| {
            normalize_target(target, &id, _model_ordinal, target_ordinal, accounts, pools)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Value::Object(Map::from_iter([
        ("id".to_owned(), Value::String(id)),
        ("targets".to_owned(), Value::Array(normalized_targets)),
    ])))
}

fn normalize_target(
    value: &Value,
    model_id: &str,
    _model_ordinal: usize,
    target_ordinal: usize,
    accounts: &BTreeMap<String, Value>,
    pools: &BTreeMap<String, Value>,
) -> Result<Value> {
    let source = match value {
        Value::String(provider) => {
            Map::from_iter([("provider".to_owned(), Value::String(provider.clone()))])
        }
        Value::Object(object) => object.clone(),
        _ => return Err(anyhow!("v1 model target must be a mapping or provider ID")),
    };
    let provider = source
        .get("provider")
        .or_else(|| source.get("upstream"))
        .or_else(|| source.get("provider_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("v1 model target provider is missing"))?
        .to_owned();
    let upstream_model = source
        .get("upstream_model")
        .or_else(|| source.get("model"))
        .or_else(|| source.get("name"))
        .and_then(Value::as_str)
        .unwrap_or(model_id)
        .to_owned();
    let selected_account = source
        .get("account")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let selected_pool = source
        .get("account_pool")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if selected_account.is_some() && selected_pool.is_some() {
        bail!("v1 model target has ambiguous account binding");
    }
    let account_pool = if let Some(account) = selected_account {
        let Some(account_value) = accounts.get(&account) else {
            bail!("v1 model target references an unknown account");
        };
        let account_provider = account_value
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("v1 account provider mapping is ambiguous"))?;
        if account_provider != provider {
            bail!("v1 model target crosses provider/account boundaries");
        }
        Some(singleton_pool_id(&account))
    } else if let Some(pool) = selected_pool {
        let Some(pool_value) = pools.get(&pool) else {
            bail!("v1 model target references an unknown account pool");
        };
        let pool_provider = pool_value
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("v1 account pool provider mapping is ambiguous"))?;
        if pool_provider != provider {
            bail!("v1 model target crosses provider/pool boundaries");
        }
        Some(pool)
    } else {
        let matches = accounts
            .iter()
            .filter(|(_, account)| {
                account.get("provider").and_then(Value::as_str) == Some(provider.as_str())
            })
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [account] => Some(singleton_pool_id(account)),
            [] => bail!("v1 model target has no account for its provider"),
            _ => bail!("v1 model target has an ambiguous account mapping"),
        }
    };
    let target_id = source
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            deterministic_target_id(model_id, &provider, &upstream_model, target_ordinal)
        });
    let priority = source
        .get("priority")
        .and_then(Value::as_u64)
        .unwrap_or((target_ordinal + 1) as u64);
    if priority == 0 || priority > u64::from(u32::MAX) {
        bail!("v1 model target priority is invalid");
    }
    let mut target = Map::new();
    target.insert("id".to_owned(), Value::String(target_id));
    target.insert("provider".to_owned(), Value::String(provider));
    target.insert(
        "account_pool".to_owned(),
        Value::String(account_pool.ok_or_else(|| anyhow!("v1 account pool mapping is ambiguous"))?),
    );
    target.insert("priority".to_owned(), Value::from(priority));
    target.insert("upstream_model".to_owned(), Value::String(upstream_model));
    target.insert(
        "capabilities".to_owned(),
        source
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
    );
    target.insert(
        "codecs".to_owned(),
        source
            .get("codecs")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
    );
    target.insert(
        "wire_family".to_owned(),
        source
            .get("wire_family")
            .or_else(|| source.get("endpoint_family"))
            .cloned()
            .unwrap_or_else(|| Value::String("openai".to_owned())),
    );
    if let Some(weight) = source.get("weight") {
        target.insert("weight".to_owned(), weight.clone());
    }
    Ok(Value::Object(target))
}

fn account_fingerprints(source: &str) -> Result<BTreeMap<String, AccountFacts>> {
    let root: Value = serde_yml::from_str(source)
        .map_err(|_| anyhow!("Pooler-v1 configuration is not valid YAML"))?;
    let object = root
        .as_object()
        .ok_or_else(|| anyhow!("Pooler-v1 configuration root must be a mapping"))?;
    let upstreams = object
        .get("upstreams")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("v1 upstream mapping is missing"))?;
    let accounts = object
        .get("accounts")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("v1 account mapping is missing"))?;
    let mut result = BTreeMap::new();
    for (account_id, account) in accounts {
        let account = account
            .as_object()
            .ok_or_else(|| anyhow!("v1 account declaration must be a mapping"))?;
        let provider_id = account
            .get("provider")
            .or_else(|| account.get("upstream"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("v1 account provider mapping is ambiguous"))?;
        let upstream = upstreams
            .get(provider_id)
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("v1 account references an unknown provider"))?;
        let origin = upstream_origin(provider_id, upstream)?;
        let native_profile = upstream
            .get("native")
            .and_then(Value::as_object)
            .and_then(|native| native.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("generic");
        let auth_kind = account
            .get("auth_kind")
            .and_then(Value::as_str)
            .unwrap_or("api_key");
        let oauth = upstream.get("oauth").and_then(Value::as_object);
        let input = CredentialFingerprintInput {
            account_id: account_id.clone(),
            provider_instance_id: provider_id.to_owned(),
            provider_origin: origin,
            auth_kind: auth_kind.to_owned(),
            provider_profile: native_profile.to_owned(),
            oauth_client_id: oauth
                .and_then(|value| value.get("client_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            oauth_grant_type: oauth
                .and_then(|value| value.get("grant_type"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            authorization_endpoint: oauth
                .and_then(|value| value.get("authorization_endpoint"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            token_endpoint: oauth
                .and_then(|value| value.get("token_endpoint"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            auth_placement: "account".to_owned(),
        };
        if result
            .insert(
                account_id.clone(),
                AccountFacts {
                    provider_id: provider_id.to_owned(),
                    input,
                },
            )
            .is_some()
        {
            bail!("v1 account mapping is ambiguous");
        }
    }
    Ok(result)
}

#[derive(Clone, Debug)]
struct AccountFacts {
    provider_id: String,
    input: CredentialFingerprintInput,
}

fn upstream_origin(provider_id: &str, upstream: &Map<String, Value>) -> Result<String> {
    if let Some(url) = upstream
        .get("url")
        .or_else(|| upstream.get("base_url"))
        .and_then(Value::as_str)
    {
        return Ok(url.to_owned());
    }
    if let Some(transport) = upstream.get("transport").and_then(Value::as_object) {
        if let Some(url) = transport.get("base_url").and_then(Value::as_str) {
            return Ok(url.to_owned());
        }
    }
    if upstream
        .get("native")
        .and_then(Value::as_object)
        .and_then(|native| native.get("kind"))
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("codex"))
    {
        return Ok("https://chatgpt.com".to_owned());
    }
    bail!("v1 provider origin for `{provider_id}` is ambiguous")
}

fn reject_literal_secret_values(source: &str) -> Result<()> {
    let root: Value = serde_yml::from_str(source)
        .map_err(|_| anyhow!("Pooler-v1 configuration is not valid YAML"))?;
    fn visit(value: &Value, secret_context: bool) -> Result<()> {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let key_context = secret_context
                        || key.to_ascii_lowercase().contains("secret")
                        || key.to_ascii_lowercase().contains("token")
                        || key.to_ascii_lowercase().contains("password")
                        || key.to_ascii_lowercase().contains("api_key")
                        || key.eq_ignore_ascii_case("authorization");
                    visit(value, key_context)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, secret_context)?;
                }
            }
            Value::String(value) if secret_context => {
                if SecretRef::parse(value).is_err() {
                    bail!("Pooler-v1 contains an inline secret value; use an external reference");
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(&root, false)
}

fn object_map<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>> {
    object
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("v1 `{key}` must be a mapping"))
}

fn object_map_mut<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>> {
    object_map(object, key)
}

fn singleton_pool_id(account: &str) -> String {
    format!("pool-{}", slug(account))
}

fn deterministic_target_id(
    model: &str,
    provider: &str,
    upstream_model: &str,
    ordinal: usize,
) -> String {
    format!(
        "target-{}-{}-{}-{}",
        slug(model),
        slug(provider),
        slug(upstream_model),
        ordinal + 1
    )
}

fn slug(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            result.push(character.to_ascii_lowercase());
        } else if !result.ends_with('-') {
            result.push('-');
        }
    }
    let result = result.trim_matches('-');
    if result.is_empty() {
        "legacy".to_owned()
    } else {
        result.chars().take(96).collect()
    }
}

fn transaction_dir(options: &MigrationOptions) -> Result<PathBuf> {
    if let Some(path) = &options.transaction_dir {
        return Ok(path.clone());
    }
    let parent = options
        .destination_config
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".pooler-v1-migration-{}", std::process::id())))
}

fn create_transaction_dir(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("migration transaction directory already exists");
    }
    create_private_directory(path)
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create private migration directory `{}`", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))
}

fn source_mode(facts: &[FileFact], role: &str) -> Result<Option<u32>> {
    facts
        .iter()
        .find(|fact| fact.role == role)
        .and_then(|fact| fact.mode)
        .ok_or_else(|| anyhow!("source file fact is missing"))
        .map(Some)
}

fn file_fact(role: &str, path: &Path, required: bool) -> Result<FileFact> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(FileFact {
                role: role.to_owned(),
                path: path.display().to_string(),
                exists: false,
                size: 0,
                mode: None,
                owner_uid: None,
                owner_gid: None,
                sha256: None,
            });
        }
        Err(error) => return Err(error).with_context(|| format!("stat `{}`", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("migration input must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("migration input must be owner-private");
        }
        Ok(FileFact {
            role: role.to_owned(),
            path: path.display().to_string(),
            exists: true,
            size: metadata.len(),
            mode: Some(metadata.permissions().mode() & 0o7777),
            owner_uid: Some(metadata.uid()),
            owner_gid: Some(metadata.gid()),
            sha256: Some(file_digest(path)?),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileFact {
            role: role.to_owned(),
            path: path.display().to_string(),
            exists: true,
            size: metadata.len(),
            mode: None,
            owner_uid: None,
            owner_gid: None,
            sha256: Some(file_digest(path)?),
        })
    }
}

fn destination_facts(options: &MigrationOptions) -> Result<Vec<FileFact>> {
    Ok(vec![
        file_fact("destination-config", &options.destination_config, false)?,
        file_fact("destination-store", &options.destination_store, false)?,
        file_fact("destination-key", &options.destination_key, false)?,
    ])
}

fn staged_facts(stage_dir: &Path) -> Result<Vec<FileFact>> {
    Ok(vec![
        file_fact("staged-config", &stage_dir.join(STAGED_CONFIG), true)?,
        file_fact("staged-store", &stage_dir.join(STAGED_STORE), true)?,
        file_fact("staged-key", &stage_dir.join(STAGED_KEY), true)?,
    ])
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_config_source(path: &Path) -> Result<String> {
    let bytes = read_bounded(path, MAX_CONFIG_BYTES, "Pooler-v1 configuration")?;
    String::from_utf8(bytes).map_err(|_| anyhow!("Pooler-v1 configuration is not UTF-8"))
}

fn read_private_bytes(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = read_bounded(path, 1024 * 1024, label)?;
    if bytes.is_empty() {
        bail!("{label} is empty");
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_context(|| format!("open {label}"))?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{label} exceeds its migration size bound");
    }
    Ok(bytes)
}

fn file_digest(path: &Path) -> Result<String> {
    let mut file = File::open(path).context("open migration input for digest")?;
    let mut context = DigestContext::new(&SHA256);
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if bytes_read > 64 * 1024 * 1024 {
            bail!("migration input exceeds its digest size bound");
        }
        context.update(&buffer[..read]);
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn write_private_new(path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
    if path.exists() {
        bail!("staged migration file already exists");
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("migration file name is invalid"))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    #[cfg(not(unix))]
    let _ = mode;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(mode.unwrap_or(0o600));
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("manifest"),
        std::process::id()
    ));
    write_private_new(&temporary, &bytes, Some(0o600))?;
    fs::rename(&temporary, path)?;
    sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = read_bounded(path, 4 * 1024 * 1024, "migration manifest")?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("migration manifest is invalid"))
}

fn read_only_integrity(path: &Path) -> Result<bool> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result: String =
        connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    Ok(result.eq_ignore_ascii_case("ok"))
}

fn promote(
    transaction_dir: &Path,
    manifest_path: &Path,
    manifest: &mut Manifest,
    options: &MigrationOptions,
) -> Result<()> {
    manifest.phase = "promoting".to_owned();
    write_manifest(manifest_path, manifest)?;
    let stage_dir = transaction_dir.join("stage");
    let entries = [
        (STAGED_CONFIG, &options.destination_config, "config"),
        (STAGED_STORE, &options.destination_store, "store"),
        (STAGED_KEY, &options.destination_key, "key"),
    ];
    let backup_dir = transaction_dir.join("backups");
    create_private_directory(&backup_dir)?;
    for (index, (staged, destination, role)) in entries.iter().enumerate() {
        if fail_after(options, index + 1) {
            rollback_promoted(manifest)?;
            manifest.phase = "rolled_back".to_owned();
            write_manifest(manifest_path, manifest)?;
            bail!("migration promotion was interrupted after {role}");
        }
        if options.replace_existing {
            if fs::symlink_metadata(destination.as_path()).is_ok() {
                let backup = backup_dir.join(format!("{index}-{role}.bak"));
                copy_existing_file(destination.as_path(), &backup)?;
                manifest.backups.push(BackupEntry {
                    destination: destination.display().to_string(),
                    backup: backup.display().to_string(),
                });
            }
            if *role == "store" {
                for suffix in ["-wal", "-shm"] {
                    let sidecar = sidecar(destination.as_path(), suffix);
                    if fs::symlink_metadata(&sidecar).is_ok() {
                        let backup = backup_dir.join(format!("{index}-{role}{suffix}.bak"));
                        copy_existing_file(&sidecar, &backup)?;
                        manifest.backups.push(BackupEntry {
                            destination: sidecar.display().to_string(),
                            backup: backup.display().to_string(),
                        });
                    }
                }
            }
            write_manifest(manifest_path, manifest)?;
        }
        if *role == "store" {
            if let Err(error) = remove_sidecars(destination.as_path()) {
                rollback_promoted(manifest)?;
                manifest.phase = "rolled_back".to_owned();
                write_manifest(manifest_path, manifest)?;
                return Err(error);
            }
        }
        manifest.promoted.push(destination.display().to_string());
        write_manifest(manifest_path, manifest)?;
        if let Err(error) = publish_file(
            &stage_dir.join(*staged),
            destination.as_path(),
            options.replace_existing,
        ) {
            rollback_promoted(manifest)?;
            manifest.phase = "rolled_back".to_owned();
            write_manifest(manifest_path, manifest)?;
            return Err(error);
        }
        write_manifest(manifest_path, manifest)?;
    }
    sync_directory(transaction_dir)?;
    manifest.destinations = destination_facts(options)?;
    manifest.phase = "committed".to_owned();
    write_manifest(manifest_path, manifest)?;
    Ok(())
}

fn fail_after(options: &MigrationOptions, step: usize) -> bool {
    options.fail_after.or_else(|| {
        std::env::var("POOLER_MIGRATION_FAIL_AFTER")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
    }) == Some(step)
}

fn publish_file(source: &Path, destination: &Path, replace_existing: bool) -> Result<()> {
    if fs::symlink_metadata(destination).is_ok() && !replace_existing {
        bail!("migration destination already exists");
    }
    let source_metadata = fs::symlink_metadata(source)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        bail!("staged migration input is not a regular file");
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("migration destination parent is not a directory");
    }
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("migration destination file name is invalid"))?;
    let temporary = parent.join(format!(".{name}.pooler-migrate-{}.tmp", std::process::id()));
    let bytes = read_bounded(source, 64 * 1024 * 1024, "staged migration file")?;
    write_private_new(
        &temporary,
        &bytes,
        source_mode_from_metadata(&source_metadata)?,
    )?;
    fs::rename(&temporary, destination).inspect_err(|_error| {
        let _ = fs::remove_file(&temporary);
    })?;
    sync_directory(parent)
}

fn source_mode_from_metadata(metadata: &fs::Metadata) -> Result<Option<u32>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(Some(metadata.permissions().mode() & 0o7777))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(None)
    }
}

fn set_file_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let _ = (path, mode);
    Ok(())
}

fn rollback_promoted(manifest: &mut Manifest) -> Result<()> {
    let promoted = manifest.promoted.clone();
    for path in manifest.promoted.iter().rev() {
        let path = Path::new(path);
        if let Some(backup) = manifest
            .backups
            .iter()
            .find(|entry| entry.destination == path.display().to_string())
        {
            publish_file(Path::new(&backup.backup), path, true)?;
        } else if path.exists() {
            fs::remove_file(path)?;
            sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))?;
        }
    }
    for backup in &manifest.backups {
        if !promoted.iter().any(|path| path == &backup.destination)
            && fs::symlink_metadata(&backup.backup).is_ok()
        {
            publish_file(
                Path::new(&backup.backup),
                Path::new(&backup.destination),
                true,
            )?;
        }
    }
    manifest.promoted.clear();
    Ok(())
}

fn copy_existing_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("migration rollback source is not a regular file");
    }
    let bytes = read_bounded(source, 64 * 1024 * 1024, "migration rollback file")?;
    write_private_new(destination, &bytes, source_mode_from_metadata(&metadata)?)
}

fn ensure_distinct_paths(options: &MigrationOptions) -> Result<()> {
    let sources = [
        &options.source_config,
        &options.source_store,
        &options.source_key,
    ];
    let destinations = [
        &options.destination_config,
        &options.destination_store,
        &options.destination_key,
    ];
    for source in sources {
        for destination in destinations {
            if source == destination {
                bail!("migration source and destination paths must be distinct");
            }
        }
    }
    Ok(())
}

fn remove_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = sidecar(path, suffix);
        if fs::symlink_metadata(&sidecar).is_ok() {
            fs::remove_file(&sidecar)?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("sync migration directory `{}`", path.display()))
}

fn reject_existing_destination(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        bail!("migration destination already exists; refusing an idempotent overwrite");
    }
    Ok(())
}

fn report_from_manifest(
    manifest: &Manifest,
    transaction_dir: PathBuf,
    manifest_path: PathBuf,
) -> MigrationReport {
    MigrationReport {
        operation: OPERATION,
        dry_run: manifest.phase == "dry_run_validated",
        phase: manifest.phase.clone(),
        transaction_dir,
        manifest: manifest_path,
        providers: manifest.providers,
        accounts: manifest.accounts,
        models: manifest.models,
        credentials_reencrypted: manifest.credentials_reencrypted,
        legacy_affinities_purged: manifest.legacy_affinities_purged,
    }
}
