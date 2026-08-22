//! Bounded typed configuration drafts and durable managed-file persistence.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use pooler_config::{Config, ConfigLoader};
use ring::digest::{digest, SHA256};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

const MAX_DRAFTS: usize = 8;
const MAX_PATCHES: usize = 128;
const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const DRAFT_TTL: Duration = Duration::from_secs(30 * 60);
const GENERATED_HEADER: &[u8] =
    b"# Generated and exclusively managed by Pooler. Do not edit by hand.\n";
const RECOVERY_MARKER: &[u8] = b"pooler-managed-config-transaction-v1\n";

#[cfg(test)]
thread_local! {
    static FAIL_WRITE_AFTER_RENAME: Cell<bool> = const { Cell::new(false) };
}

/// A section-scoped mutation. Arbitrary JSON pointers and unrestricted YAML are
/// deliberately unsupported; the compiler remains the final type authority.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TypedConfigPatch {
    Upsert {
        section: String,
        id: String,
        value: Value,
    },
    Remove {
        section: String,
        id: String,
    },
    Replace {
        section: String,
        value: Value,
    },
}

struct Draft {
    id: u64,
    base_generation: u64,
    base: Value,
    document: Value,
    etag: String,
    patches: usize,
    created_at: SystemTime,
    confirmation: Option<String>,
}

struct PendingCommit {
    request_id: u64,
    managed_path: PathBuf,
    persistence: PersistenceState,
    previous_source: PathBuf,
}

struct PersistenceState {
    previous_managed: Option<Vec<u8>>,
    previous_backup: Option<Vec<u8>>,
}

struct State {
    active_source: PathBuf,
    drafts: VecDeque<Draft>,
    pending: BTreeMap<u64, PendingCommit>,
    commit_in_progress: bool,
    unmanaged_reload_in_progress: bool,
}

/// Process-local draft coordinator. Persisted output is always an explicitly
/// named generated sidecar; operator-authored source is never rewritten.
pub(crate) struct ConfigManagement {
    managed_path: PathBuf,
    next_id: AtomicU64,
    state: Mutex<State>,
}

#[derive(Debug, Error)]
pub(crate) enum ConfigManagementError {
    #[error("configuration draft was not found")]
    NotFound,
    #[error("configuration draft has expired")]
    Expired,
    #[error("configuration draft precondition failed")]
    Precondition,
    #[error("configuration patch is not supported")]
    UnsupportedPatch,
    #[error("configuration patch limit reached")]
    PatchLimit,
    #[error("configuration document exceeds the managed limit")]
    TooLarge,
    #[error("configuration candidate is invalid: {0}")]
    Invalid(String),
    #[error("configuration confirmation is invalid")]
    Confirmation,
    #[error("configuration persistence failed")]
    Persistence,
    #[error("configuration persistence restoration failed; operator recovery is required")]
    RecoveryRequired,
}

pub(crate) fn serving_source(source: impl AsRef<Path>) -> Result<PathBuf, ConfigManagementError> {
    let (original, managed) = managed_paths(source.as_ref())?;
    ensure_no_recovery_marker(&managed)?;
    if validate_existing_managed(&managed)? {
        Ok(managed)
    } else {
        Ok(original)
    }
}

impl ConfigManagement {
    pub(crate) fn new(source: impl AsRef<Path>) -> Result<Self, ConfigManagementError> {
        let (original_source, managed_path) = managed_paths(source.as_ref())?;
        ensure_no_recovery_marker(&managed_path)?;
        let active_source = if validate_existing_managed(&managed_path)? {
            managed_path.clone()
        } else {
            original_source.clone()
        };
        Ok(Self {
            managed_path,
            next_id: AtomicU64::new(0),
            state: Mutex::new(State {
                active_source,
                drafts: VecDeque::new(),
                pending: BTreeMap::new(),
                commit_in_progress: false,
                unmanaged_reload_in_progress: false,
            }),
        })
    }

    pub(crate) fn try_begin_unmanaged_reload(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        if state.commit_in_progress
            || !state.pending.is_empty()
            || state.unmanaged_reload_in_progress
        {
            return false;
        }
        state.unmanaged_reload_in_progress = true;
        true
    }

    pub(crate) fn finish_unmanaged_reload(&self) {
        self.state
            .lock()
            .expect("configuration draft lock poisoned")
            .unmanaged_reload_in_progress = false;
    }

    pub(crate) fn create(&self, base_generation: u64) -> Result<Value, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        prune(&mut state.drafts);
        while state.drafts.len() >= MAX_DRAFTS {
            state.drafts.pop_front();
        }
        let rendered = ConfigLoader::default()
            .render(&state.active_source)
            .map_err(|error| ConfigManagementError::Invalid(error.to_string()))?;
        if rendered.len() > MAX_DOCUMENT_BYTES {
            return Err(ConfigManagementError::TooLarge);
        }
        let yaml: serde_yml::Value = serde_yml::from_str(&rendered)
            .map_err(|error| ConfigManagementError::Invalid(error.to_string()))?;
        let document = serde_json::to_value(yaml)
            .map_err(|_| ConfigManagementError::Invalid("candidate is not JSON-shaped".into()))?;
        let id = self
            .next_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let etag = document_etag(&document)?;
        state.drafts.push_back(Draft {
            id,
            base_generation,
            base: document.clone(),
            document,
            etag: etag.clone(),
            patches: 0,
            created_at: SystemTime::now(),
            confirmation: None,
        });
        Ok(json!({
            "draft_id": id,
            "base_generation": base_generation,
            "etag": etag,
            "patch_count": 0,
            "status": "draft"
        }))
    }

    pub(crate) fn view(&self, id: u64) -> Result<Value, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let draft = draft_mut(&mut state.drafts, id)?;
        Ok(draft_view(draft))
    }

    pub(crate) fn apply(
        &self,
        id: u64,
        if_match: &str,
        patch: TypedConfigPatch,
    ) -> Result<Value, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let draft = draft_mut(&mut state.drafts, id)?;
        require_etag(draft, if_match)?;
        if draft.patches >= MAX_PATCHES {
            return Err(ConfigManagementError::PatchLimit);
        }
        let mut candidate = draft.document.clone();
        apply_patch(&mut candidate, patch)?;
        if serde_json::to_vec(&candidate)
            .map_err(|_| ConfigManagementError::UnsupportedPatch)?
            .len()
            > MAX_DOCUMENT_BYTES
        {
            return Err(ConfigManagementError::TooLarge);
        }
        let etag = document_etag(&candidate)?;
        draft.document = candidate;
        draft.patches += 1;
        draft.etag = etag;
        draft.confirmation = None;
        Ok(draft_view(draft))
    }

    pub(crate) fn validate(&self, id: u64, if_match: &str) -> Result<Value, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let draft = draft_mut(&mut state.drafts, id)?;
        require_etag(draft, if_match)?;
        compile_document(&draft.document, draft.base_generation.saturating_add(1))?;
        let changes = semantic_diff(&draft.base, &draft.document);
        let confirmation = confirmation_token(draft, &changes)?;
        draft.confirmation = Some(confirmation.clone());
        Ok(json!({
            "draft_id": draft.id,
            "base_generation": draft.base_generation,
            "etag": draft.etag,
            "valid": true,
            "semantic_diff": changes,
            "confirmation_token": confirmation
        }))
    }

    pub(crate) fn diff(&self, id: u64) -> Result<Value, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let draft = draft_mut(&mut state.drafts, id)?;
        Ok(json!({
            "draft_id": draft.id,
            "base_generation": draft.base_generation,
            "etag": draft.etag,
            "semantic_diff": semantic_diff(&draft.base, &draft.document)
        }))
    }

    pub(crate) fn commit(
        &self,
        id: u64,
        if_match: &str,
        active_generation: u64,
        confirmation: &str,
    ) -> Result<PreparedCommit, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        if state.commit_in_progress
            || !state.pending.is_empty()
            || state.unmanaged_reload_in_progress
        {
            return Err(ConfigManagementError::Precondition);
        }
        let position = state
            .drafts
            .iter()
            .position(|draft| draft.id == id)
            .ok_or(ConfigManagementError::NotFound)?;
        let draft = state.drafts.get(position).expect("position was found");
        require_live(draft)?;
        require_etag(draft, if_match)?;
        if draft.base_generation != active_generation {
            return Err(ConfigManagementError::Precondition);
        }
        if draft.confirmation.as_deref() != Some(confirmation) {
            return Err(ConfigManagementError::Confirmation);
        }
        compile_document(&draft.document, active_generation.saturating_add(1))?;
        let encoded = generated_document(&draft.document)?;
        let previous_source = state.active_source.clone();
        let persistence = match persist_atomic(&self.managed_path, &encoded) {
            Ok(persistence) => persistence,
            Err(error) => {
                state.commit_in_progress = matches!(error, ConfigManagementError::RecoveryRequired);
                return Err(error);
            }
        };
        state.active_source = self.managed_path.clone();
        state.drafts.remove(position);
        state.commit_in_progress = true;
        Ok(PreparedCommit {
            base_generation: active_generation,
            managed_path: self.managed_path.clone(),
            persistence,
            previous_source,
        })
    }

    pub(crate) fn register_commit(&self, request_id: u64, commit: PreparedCommit) {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        state.commit_in_progress = false;
        state.pending.insert(
            request_id,
            PendingCommit {
                request_id,
                managed_path: commit.managed_path,
                persistence: commit.persistence,
                previous_source: commit.previous_source,
            },
        );
    }

    pub(crate) fn complete_commit(
        &self,
        request_id: u64,
        succeeded: bool,
    ) -> Result<(), ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let Some(pending) = state.pending.remove(&request_id) else {
            return Ok(());
        };
        debug_assert_eq!(pending.request_id, request_id);
        let completion = if succeeded {
            clear_recovery_marker(&pending.managed_path)
        } else {
            restore_persistence(&pending.managed_path, &pending.persistence)
                .and_then(|()| verify_persistence(&pending.managed_path, &pending.persistence))
                .and_then(|()| clear_recovery_marker(&pending.managed_path))
        };
        if completion.is_err() {
            state.pending.insert(request_id, pending);
            return Err(ConfigManagementError::RecoveryRequired);
        }
        if !succeeded {
            state.active_source = pending.previous_source;
        }
        Ok(())
    }

    pub(crate) fn rollback(
        &self,
        active_generation: u64,
    ) -> Result<PreparedCommit, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        if state.commit_in_progress
            || !state.pending.is_empty()
            || state.unmanaged_reload_in_progress
        {
            return Err(ConfigManagementError::Precondition);
        }
        if let Err(error) = acquire_recovery_marker(&self.managed_path) {
            state.commit_in_progress = matches!(error, ConfigManagementError::RecoveryRequired);
            return Err(error);
        }
        let backup = backup_path(&self.managed_path);
        let prepared = (|| {
            let prior = read_existing_managed(&backup)?.ok_or(ConfigManagementError::NotFound)?;
            let prior_text = std::str::from_utf8(&prior)
                .map_err(|_| ConfigManagementError::Invalid("rollback is not UTF-8".into()))?;
            Config::from_yaml(backup.display().to_string(), prior_text)
                .and_then(|config| {
                    config.compile_with_generation(active_generation.saturating_add(1))
                })
                .map_err(|error| ConfigManagementError::Invalid(error.to_string()))?;
            Ok(prior)
        })();
        let prior = match prepared {
            Ok(prior) => prior,
            Err(error) => {
                let error = clear_marker_or_recovery_required(&self.managed_path, error);
                state.commit_in_progress = matches!(error, ConfigManagementError::RecoveryRequired);
                return Err(error);
            }
        };
        let previous_source = state.active_source.clone();
        let persistence = match persist_atomic_marked(&self.managed_path, &prior) {
            Ok(persistence) => persistence,
            Err(error) => {
                state.commit_in_progress = matches!(error, ConfigManagementError::RecoveryRequired);
                return Err(error);
            }
        };
        state.commit_in_progress = true;
        Ok(PreparedCommit {
            base_generation: active_generation,
            managed_path: self.managed_path.clone(),
            persistence,
            previous_source,
        })
    }
}

pub(crate) struct PreparedCommit {
    pub(crate) base_generation: u64,
    pub(crate) managed_path: PathBuf,
    persistence: PersistenceState,
    previous_source: PathBuf,
}

fn draft_view(draft: &Draft) -> Value {
    json!({
        "draft_id": draft.id,
        "base_generation": draft.base_generation,
        "etag": draft.etag,
        "patch_count": draft.patches,
        "status": if draft.confirmation.is_some() { "validated" } else { "draft" }
    })
}

fn draft_mut(drafts: &mut VecDeque<Draft>, id: u64) -> Result<&mut Draft, ConfigManagementError> {
    let draft = drafts
        .iter_mut()
        .find(|draft| draft.id == id)
        .ok_or(ConfigManagementError::NotFound)?;
    require_live(draft)?;
    Ok(draft)
}

fn require_live(draft: &Draft) -> Result<(), ConfigManagementError> {
    if draft.created_at.elapsed().unwrap_or(DRAFT_TTL) >= DRAFT_TTL {
        Err(ConfigManagementError::Expired)
    } else {
        Ok(())
    }
}

fn require_etag(draft: &Draft, if_match: &str) -> Result<(), ConfigManagementError> {
    if if_match.trim_matches('"') == draft.etag {
        Ok(())
    } else {
        Err(ConfigManagementError::Precondition)
    }
}

fn prune(drafts: &mut VecDeque<Draft>) {
    drafts.retain(|draft| require_live(draft).is_ok());
}

fn apply_patch(document: &mut Value, patch: TypedConfigPatch) -> Result<(), ConfigManagementError> {
    match patch {
        TypedConfigPatch::Upsert { section, id, value } => {
            validate_id(&id)?;
            if map_section(&section) {
                let map = section_object_mut(document, &section)?;
                map.insert(id, value);
                Ok(())
            } else if list_section(&section) {
                let list = section_array_mut(document, &section)?;
                let object = value
                    .as_object()
                    .ok_or(ConfigManagementError::UnsupportedPatch)?;
                if object.get("id").and_then(Value::as_str) != Some(id.as_str()) {
                    return Err(ConfigManagementError::UnsupportedPatch);
                }
                if let Some(existing) = list
                    .iter()
                    .position(|entry| entry.get("id").and_then(Value::as_str) == Some(id.as_str()))
                {
                    list[existing] = value;
                } else {
                    list.push(value);
                }
                Ok(())
            } else {
                Err(ConfigManagementError::UnsupportedPatch)
            }
        }
        TypedConfigPatch::Remove { section, id } => {
            validate_id(&id)?;
            if map_section(&section) {
                section_object_mut(document, &section)?.remove(&id);
                Ok(())
            } else if list_section(&section) {
                section_array_mut(document, &section)?
                    .retain(|entry| entry.get("id").and_then(Value::as_str) != Some(id.as_str()));
                Ok(())
            } else {
                Err(ConfigManagementError::UnsupportedPatch)
            }
        }
        TypedConfigPatch::Replace { section, value } => {
            if !matches!(
                section.as_str(),
                "catalog" | "management" | "usage_price_book"
            ) {
                return Err(ConfigManagementError::UnsupportedPatch);
            }
            document
                .as_object_mut()
                .ok_or(ConfigManagementError::UnsupportedPatch)?
                .insert(section, value);
            Ok(())
        }
    }
}

fn map_section(section: &str) -> bool {
    matches!(
        section,
        "listeners"
            | "upstreams"
            | "accounts"
            | "credentials"
            | "account_pools"
            | "policies"
            | "extensions"
    )
}

fn list_section(section: &str) -> bool {
    matches!(section, "models" | "routes")
}

fn validate_id(id: &str) -> Result<(), ConfigManagementError> {
    if !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(ConfigManagementError::UnsupportedPatch)
    }
}

fn section_object_mut<'a>(
    document: &'a mut Value,
    section: &str,
) -> Result<&'a mut Map<String, Value>, ConfigManagementError> {
    let root = document
        .as_object_mut()
        .ok_or(ConfigManagementError::UnsupportedPatch)?;
    root.entry(section).or_insert_with(|| json!({}));
    root.get_mut(section)
        .and_then(Value::as_object_mut)
        .ok_or(ConfigManagementError::UnsupportedPatch)
}

fn section_array_mut<'a>(
    document: &'a mut Value,
    section: &str,
) -> Result<&'a mut Vec<Value>, ConfigManagementError> {
    let root = document
        .as_object_mut()
        .ok_or(ConfigManagementError::UnsupportedPatch)?;
    root.entry(section).or_insert_with(|| json!([]));
    root.get_mut(section)
        .and_then(Value::as_array_mut)
        .ok_or(ConfigManagementError::UnsupportedPatch)
}

fn compile_document(document: &Value, generation: u64) -> Result<(), ConfigManagementError> {
    let encoded = serde_json::to_string(document)
        .map_err(|_| ConfigManagementError::Invalid("candidate serialization failed".into()))?;
    Config::from_yaml("<managed-config-draft>", &encoded)
        .and_then(|config| config.compile_with_generation(generation))
        .map(|_| ())
        .map_err(|error| ConfigManagementError::Invalid(error.to_string()))
}

fn document_etag(document: &Value) -> Result<String, ConfigManagementError> {
    let encoded = serde_json::to_vec(document)
        .map_err(|_| ConfigManagementError::Invalid("candidate serialization failed".into()))?;
    Ok(hex(digest(&SHA256, &encoded).as_ref()))
}

fn confirmation_token(draft: &Draft, changes: &Value) -> Result<String, ConfigManagementError> {
    let encoded = serde_json::to_vec(&json!({
        "draft": draft.id,
        "generation": draft.base_generation,
        "etag": draft.etag,
        "diff": changes
    }))
    .map_err(|_| ConfigManagementError::Confirmation)?;
    Ok(hex(digest(&SHA256, &encoded).as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn semantic_diff(base: &Value, candidate: &Value) -> Value {
    let mut changes = Vec::new();
    for section in [
        "listeners",
        "upstreams",
        "accounts",
        "credentials",
        "account_pools",
        "policies",
        "extensions",
    ] {
        let before = base.get(section).and_then(Value::as_object);
        let after = candidate.get(section).and_then(Value::as_object);
        let mut ids = std::collections::BTreeSet::new();
        ids.extend(before.into_iter().flat_map(|map| map.keys().cloned()));
        ids.extend(after.into_iter().flat_map(|map| map.keys().cloned()));
        for id in ids {
            let old = before.and_then(|map| map.get(&id));
            let new = after.and_then(|map| map.get(&id));
            if old != new {
                changes.push(json!({
                    "section": section,
                    "id": id,
                    "change": match (old, new) {
                        (None, Some(_)) => "added",
                        (Some(_), None) => "removed",
                        _ => "changed",
                    }
                }));
            }
        }
    }
    for section in ["models", "routes"] {
        let indexed = |value: Option<&Value>| {
            value
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    entry
                        .get("id")
                        .and_then(Value::as_str)
                        .map(|id| (id.to_owned(), entry.clone()))
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before = indexed(base.get(section));
        let after = indexed(candidate.get(section));
        let mut ids = std::collections::BTreeSet::new();
        ids.extend(before.keys().cloned());
        ids.extend(after.keys().cloned());
        for id in ids {
            let old = before.get(&id);
            let new = after.get(&id);
            if old != new {
                changes.push(json!({
                    "section": section,
                    "id": id,
                    "change": match (old, new) {
                        (None, Some(_)) => "added",
                        (Some(_), None) => "removed",
                        _ => "changed",
                    }
                }));
            }
        }
    }
    for section in ["catalog", "management", "usage_price_book"] {
        if base.get(section) != candidate.get(section) {
            changes.push(json!({"section": section, "change": "changed"}));
        }
    }
    Value::Array(changes)
}

fn generated_document(document: &Value) -> Result<Vec<u8>, ConfigManagementError> {
    let encoded = serde_yml::to_string(document)
        .map_err(|_| ConfigManagementError::Invalid("candidate serialization failed".into()))?;
    let mut output = GENERATED_HEADER.to_vec();
    output.extend_from_slice(encoded.as_bytes());
    if output.len() > MAX_DOCUMENT_BYTES {
        return Err(ConfigManagementError::TooLarge);
    }
    Ok(output)
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("backup.yaml")
}

fn recovery_marker_path(path: &Path) -> PathBuf {
    path.with_extension("recovery-required")
}

fn completed_recovery_marker_path(path: &Path) -> PathBuf {
    path.with_extension("recovery-completed")
}

fn ensure_no_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    cleanup_completed_recovery_marker(path)?;
    if validate_existing_recovery_marker(&recovery_marker_path(path))? {
        Err(ConfigManagementError::RecoveryRequired)
    } else {
        Ok(())
    }
}

fn cleanup_completed_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    let completed = completed_recovery_marker_path(path);
    if !validate_existing_recovery_marker(&completed)? {
        return Ok(());
    }
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    remove_file_synced(parent, &completed)
}

fn validate_existing_recovery_marker(path: &Path) -> Result<bool, ConfigManagementError> {
    let Some(mut file) = open_validated_file(path, true)? else {
        return Ok(false);
    };
    let metadata = file
        .metadata()
        .map_err(|_| ConfigManagementError::Persistence)?;
    if metadata.len() != RECOVERY_MARKER.len() as u64 {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let mut bytes = Vec::with_capacity(RECOVERY_MARKER.len());
    file.read_to_end(&mut bytes)
        .map_err(|_| ConfigManagementError::Persistence)?;
    if bytes == RECOVERY_MARKER {
        Ok(true)
    } else {
        Err(ConfigManagementError::RecoveryRequired)
    }
}

fn acquire_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    ensure_no_recovery_marker(path)?;
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    let marker = recovery_marker_path(path);
    for _ in 0..3 {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(&marker) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if validate_existing_recovery_marker(&marker)? {
                    return Err(ConfigManagementError::RecoveryRequired);
                }
                continue;
            }
            Err(_) => return Err(ConfigManagementError::Persistence),
        };
        let result = (|| -> io::Result<()> {
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file() {
                return Err(io::Error::other("recovery marker is not a regular file"));
            }
            #[cfg(unix)]
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(io::Error::other("recovery marker is not owner-private"));
            }
            file.write_all(RECOVERY_MARKER)?;
            file.sync_all()?;
            File::open(parent)?.sync_all()
        })();
        return result.map_err(|_| ConfigManagementError::RecoveryRequired);
    }
    Err(ConfigManagementError::Persistence)
}

fn clear_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    cleanup_completed_recovery_marker(path)?;
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    let marker = recovery_marker_path(path);
    let completed = completed_recovery_marker_path(path);
    if !validate_existing_recovery_marker(&marker)? {
        return Err(ConfigManagementError::Persistence);
    }
    fs::rename(&marker, &completed).map_err(|_| ConfigManagementError::Persistence)?;
    if File::open(parent)
        .and_then(|directory| directory.sync_all())
        .is_err()
    {
        let _ = fs::rename(&completed, &marker);
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        return Err(ConfigManagementError::RecoveryRequired);
    }
    // The durable rename records completed recovery. Removing that completion
    // marker is only cleanup: either its presence or absence is safe at restart.
    let _ = remove_file_synced(parent, &completed);
    Ok(())
}

fn clear_marker_or_recovery_required(
    path: &Path,
    original: ConfigManagementError,
) -> ConfigManagementError {
    if clear_recovery_marker(path).is_ok() {
        original
    } else {
        ConfigManagementError::RecoveryRequired
    }
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<PersistenceState, ConfigManagementError> {
    acquire_recovery_marker(path)?;
    persist_atomic_marked(path, bytes)
}

fn persist_atomic_marked(
    path: &Path,
    bytes: &[u8],
) -> Result<PersistenceState, ConfigManagementError> {
    let parent = match path.parent().and_then(|parent| parent.canonicalize().ok()) {
        Some(parent) => parent,
        None => {
            return Err(clear_marker_or_recovery_required(
                path,
                ConfigManagementError::Persistence,
            ));
        }
    };
    let backup = backup_path(path);
    let previous_managed = read_optional_managed(path)
        .map_err(|error| clear_marker_or_recovery_required(path, error))?;
    let previous_backup = read_optional_managed(&backup)
        .map_err(|error| clear_marker_or_recovery_required(path, error))?;
    let persistence = PersistenceState {
        previous_managed,
        previous_backup,
    };

    let mutation = (|| {
        if let Some(previous) = persistence.previous_managed.as_deref() {
            write_atomic(&parent, &backup, previous)?;
        }
        write_atomic(&parent, path, bytes)
    })();
    if mutation.is_err() {
        return match restore_persistence(path, &persistence)
            .and_then(|()| verify_persistence(path, &persistence))
            .and_then(|()| clear_recovery_marker(path))
        {
            Ok(()) => Err(ConfigManagementError::Persistence),
            Err(_) => Err(ConfigManagementError::RecoveryRequired),
        };
    }
    Ok(persistence)
}

fn read_optional_managed(path: &Path) -> Result<Option<Vec<u8>>, ConfigManagementError> {
    read_existing_managed(path)
}

fn restore_persistence(
    path: &Path,
    persistence: &PersistenceState,
) -> Result<(), ConfigManagementError> {
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    if let Some(previous) = persistence.previous_managed.as_deref() {
        write_atomic(parent, path, previous)?;
    } else {
        remove_file_synced(parent, path)?;
    }

    let backup = backup_path(path);
    if let Some(previous) = persistence.previous_backup.as_deref() {
        write_atomic(parent, &backup, previous)
    } else {
        remove_file_synced(parent, &backup)
    }
}

fn verify_persistence(
    path: &Path,
    persistence: &PersistenceState,
) -> Result<(), ConfigManagementError> {
    if read_optional_managed(path)? != persistence.previous_managed {
        return Err(ConfigManagementError::Persistence);
    }
    if read_optional_managed(&backup_path(path))? != persistence.previous_backup {
        return Err(ConfigManagementError::Persistence);
    }
    Ok(())
}

fn remove_file_synced(parent: &Path, path: &Path) -> Result<(), ConfigManagementError> {
    match fs::remove_file(path) {
        Ok(()) => File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ConfigManagementError::Persistence),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ConfigManagementError::Persistence),
    }
}

fn write_atomic(parent: &Path, path: &Path, bytes: &[u8]) -> Result<(), ConfigManagementError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ConfigManagementError::Persistence)?;
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(test)]
        if FAIL_WRITE_AFTER_RENAME.replace(false) {
            return Err(io::Error::other("injected failure after atomic rename"));
        }
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(ConfigManagementError::Persistence);
    }
    Ok(())
}

fn managed_paths(source: &Path) -> Result<(PathBuf, PathBuf), ConfigManagementError> {
    let source_metadata =
        fs::symlink_metadata(source).map_err(|_| ConfigManagementError::Persistence)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.file_type().is_file() {
        return Err(ConfigManagementError::Persistence);
    }
    let original = source
        .canonicalize()
        .map_err(|_| ConfigManagementError::Persistence)?;
    validate_source_file(&original)?;
    validate_parent_directory(
        original
            .parent()
            .ok_or(ConfigManagementError::Persistence)?,
    )?;
    let file_name = original
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or(ConfigManagementError::Persistence)?;
    let managed = original.with_file_name(format!("{file_name}.managed.yaml"));
    Ok((original, managed))
}

fn validate_source_file(path: &Path) -> Result<(), ConfigManagementError> {
    open_validated_file(path, false)?
        .map(|_| ())
        .ok_or(ConfigManagementError::Persistence)
}

fn validate_existing_managed(path: &Path) -> Result<bool, ConfigManagementError> {
    Ok(read_existing_managed(path)?.is_some())
}

fn read_existing_managed(path: &Path) -> Result<Option<Vec<u8>>, ConfigManagementError> {
    let Some(mut file) = open_validated_file(path, true)? else {
        return Ok(None);
    };
    if file
        .metadata()
        .map_err(|_| ConfigManagementError::Persistence)?
        .len()
        > MAX_DOCUMENT_BYTES as u64
    {
        return Err(ConfigManagementError::TooLarge);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigManagementError::Persistence)?;
    if bytes.len() > MAX_DOCUMENT_BYTES || !bytes.starts_with(GENERATED_HEADER) {
        return Err(ConfigManagementError::Persistence);
    }
    Ok(Some(bytes))
}

fn open_validated_file(
    path: &Path,
    owner_private: bool,
) -> Result<Option<File>, ConfigManagementError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ConfigManagementError::Persistence),
    };
    let metadata = file
        .metadata()
        .map_err(|_| ConfigManagementError::Persistence)?;
    if !metadata.file_type().is_file() {
        return Err(ConfigManagementError::Persistence);
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || if owner_private {
            metadata.mode() & 0o077 != 0
        } else {
            metadata.mode() & 0o022 != 0
        }
    {
        return Err(ConfigManagementError::Persistence);
    }
    Ok(Some(file))
}

fn validate_parent_directory(path: &Path) -> Result<(), ConfigManagementError> {
    let mut current = path;
    let mut immediate = true;
    loop {
        let metadata = fs::metadata(current).map_err(|_| ConfigManagementError::Persistence)?;
        if !metadata.is_dir() {
            return Err(ConfigManagementError::Persistence);
        }
        #[cfg(unix)]
        {
            let owner = metadata.uid();
            let effective = rustix::process::geteuid().as_raw();
            let root_owned_sticky = !immediate && owner == 0 && metadata.mode() & 0o1000 != 0;
            let trusted_owner = owner == effective || (!immediate && owner == 0);
            if !trusted_owner || (metadata.mode() & 0o022 != 0 && !root_owned_sticky) {
                return Err(ConfigManagementError::Persistence);
            }
        }
        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
        immediate = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn source() -> (tempfile::TempDir, PathBuf) {
        let directory = tempdir().expect("tempdir");
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private configuration directory");
        let path = directory.path().join("pooler.yaml");
        fs::write(
            &path,
            "version: 1\nlisteners: {}\nupstreams: {}\nmodels: []\naccounts: {}\naccount_pools: {}\npolicies: {}\nroutes: []\nextensions: {}\nmanagement: {}\n",
        )
        .expect("source");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private configuration source");
        (directory, path)
    }

    #[test]
    fn draft_patch_validation_diff_and_atomic_persistence_are_bounded() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let created = manager.create(7).expect("draft");
        let id = created["draft_id"].as_u64().expect("id");
        let etag = created["etag"].as_str().expect("etag");
        let patched = manager
            .apply(
                id,
                etag,
                TypedConfigPatch::Upsert {
                    section: "listeners".into(),
                    id: "local".into(),
                    value: json!({"bind": "127.0.0.1:0"}),
                },
            )
            .expect("patch");
        let etag = patched["etag"].as_str().expect("etag");
        let validated = manager.validate(id, etag).expect("validate");
        assert_eq!(validated["valid"], true);
        assert_eq!(validated["semantic_diff"][0]["id"], "local");
        let token = validated["confirmation_token"].as_str().expect("token");
        let commit = manager.commit(id, etag, 7, token).expect("commit");
        assert!(commit.managed_path.is_file());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&commit.managed_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn successful_commits_create_a_reversible_owner_private_backup() {
        let (_directory, path) = source();
        assert_eq!(
            serving_source(&path).expect("original selected"),
            path.canonicalize().expect("canonical source")
        );
        let manager = ConfigManagement::new(&path).expect("manager");

        let commit_listener = |generation: u64, bind: &str| {
            let created = manager.create(generation).expect("draft");
            let id = created["draft_id"].as_u64().expect("id");
            let patched = manager
                .apply(
                    id,
                    created["etag"].as_str().expect("etag"),
                    TypedConfigPatch::Upsert {
                        section: "listeners".into(),
                        id: "local".into(),
                        value: json!({"bind": bind}),
                    },
                )
                .expect("patch");
            let etag = patched["etag"].as_str().expect("patched etag");
            let validated = manager.validate(id, etag).expect("validate");
            manager
                .commit(
                    id,
                    etag,
                    generation,
                    validated["confirmation_token"]
                        .as_str()
                        .expect("confirmation"),
                )
                .expect("commit")
        };

        let first = commit_listener(1, "127.0.0.1:1001");
        let managed = first.managed_path.clone();
        let marker = recovery_marker_path(&managed);
        manager.register_commit(1, first);
        assert!(marker.is_file());
        assert!(matches!(
            serving_source(&path),
            Err(ConfigManagementError::RecoveryRequired)
        ));
        assert!(matches!(
            ConfigManagement::new(&path),
            Err(ConfigManagementError::RecoveryRequired)
        ));
        manager.complete_commit(1, true).expect("first completion");
        assert!(!marker.exists());
        assert_eq!(
            serving_source(&path).expect("managed source selected after restart"),
            managed
        );
        assert!(fs::read_to_string(&managed)
            .expect("first managed file")
            .contains("1001"));

        let second = commit_listener(2, "127.0.0.1:1002");
        manager.register_commit(2, second);
        manager.complete_commit(2, true).expect("second completion");
        assert!(fs::read_to_string(&managed)
            .expect("second managed file")
            .contains("1002"));
        let backup = backup_path(&managed);
        assert!(fs::read_to_string(&backup)
            .expect("first backup")
            .contains("1001"));

        let rollback = manager.rollback(3).expect("rollback");
        manager.register_commit(3, rollback);
        manager
            .complete_commit(3, true)
            .expect("rollback completion");
        assert!(fs::read_to_string(&managed)
            .expect("rolled back managed file")
            .contains("1001"));
        assert!(fs::read_to_string(&backup)
            .expect("reversible backup")
            .contains("1002"));
        let failed = commit_listener(4, "127.0.0.1:1003");
        manager.register_commit(4, failed);
        manager
            .complete_commit(4, false)
            .expect("failed commit restoration");
        assert!(!marker.exists());
        assert_eq!(
            manager.state.lock().expect("state lock").active_source,
            managed
        );
        assert!(fs::read_to_string(&managed)
            .expect("restored managed file")
            .contains("1001"));
        assert!(fs::read_to_string(&backup)
            .expect("restored rollback backup")
            .contains("1002"));

        let failed_rollback = manager.rollback(5).expect("failed rollback candidate");
        manager.register_commit(5, failed_rollback);
        manager
            .complete_commit(5, false)
            .expect("failed rollback restoration");
        assert!(fs::read_to_string(&managed)
            .expect("managed file after failed rollback")
            .contains("1001"));
        assert!(fs::read_to_string(&backup)
            .expect("backup after failed rollback")
            .contains("1002"));

        let injected = manager.create(6).expect("injected draft");
        let injected_id = injected["draft_id"].as_u64().expect("injected id");
        let injected_patch = manager
            .apply(
                injected_id,
                injected["etag"].as_str().expect("injected etag"),
                TypedConfigPatch::Upsert {
                    section: "listeners".into(),
                    id: "local".into(),
                    value: json!({"bind": "127.0.0.1:1004"}),
                },
            )
            .expect("injected patch");
        let injected_etag = injected_patch["etag"]
            .as_str()
            .expect("injected patched etag");
        let injected_validation = manager
            .validate(injected_id, injected_etag)
            .expect("injected validation");
        FAIL_WRITE_AFTER_RENAME.set(true);
        assert!(matches!(
            manager.commit(
                injected_id,
                injected_etag,
                6,
                injected_validation["confirmation_token"]
                    .as_str()
                    .expect("injected confirmation"),
            ),
            Err(ConfigManagementError::Persistence)
        ));
        assert!(!manager.state.lock().expect("state lock").commit_in_progress);
        assert!(fs::read_to_string(&managed)
            .expect("managed file after injected commit failure")
            .contains("1001"));
        assert!(fs::read_to_string(&backup)
            .expect("backup after injected commit failure")
            .contains("1002"));

        assert!(matches!(
            manager.commit(injected_id, injected_etag, 6, "wrong-confirmation"),
            Err(ConfigManagementError::Confirmation)
        ));
        FAIL_WRITE_AFTER_RENAME.set(true);
        assert!(matches!(
            manager.rollback(7),
            Err(ConfigManagementError::Persistence)
        ));
        assert!(fs::read_to_string(&managed)
            .expect("managed file after injected rollback failure")
            .contains("1001"));
        assert!(fs::read_to_string(&backup)
            .expect("backup after injected rollback failure")
            .contains("1002"));

        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&backup)
                .expect("backup metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn unmanaged_reload_lease_blocks_managed_commit_until_released() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let created = manager.create(1).expect("draft");
        let id = created["draft_id"].as_u64().expect("id");
        let patched = manager
            .apply(
                id,
                created["etag"].as_str().expect("etag"),
                TypedConfigPatch::Upsert {
                    section: "listeners".into(),
                    id: "local".into(),
                    value: json!({"bind": "127.0.0.1:1001"}),
                },
            )
            .expect("patch");
        let etag = patched["etag"].as_str().expect("patched etag");
        let validated = manager.validate(id, etag).expect("validate");
        let token = validated["confirmation_token"]
            .as_str()
            .expect("confirmation");
        assert!(manager.try_begin_unmanaged_reload());
        assert!(matches!(
            manager.commit(id, etag, 1, token),
            Err(ConfigManagementError::Precondition)
        ));
        manager.finish_unmanaged_reload();
        let commit = manager
            .commit(id, etag, 1, token)
            .expect("commit after lease release");
        manager.register_commit(1, commit);
        manager
            .complete_commit(1, false)
            .expect("leased commit restoration");
    }

    #[test]
    fn rollback_recovery_marker_blocks_all_reload_classes() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let marker = recovery_marker_path(&manager.managed_path);
        fs::write(&marker, RECOVERY_MARKER).expect("recovery marker");
        #[cfg(unix)]
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("private recovery marker");

        assert!(matches!(
            manager.rollback(1),
            Err(ConfigManagementError::RecoveryRequired)
        ));
        assert!(!manager.try_begin_unmanaged_reload());
    }

    #[cfg(unix)]
    #[test]
    fn source_and_managed_destination_symlinks_fail_closed() {
        use std::os::unix::fs::symlink;

        let (_directory, path) = source();
        let linked_source = path.with_file_name("linked.yaml");
        symlink(&path, &linked_source).expect("source symlink");
        assert!(matches!(
            ConfigManagement::new(&linked_source),
            Err(ConfigManagementError::Persistence)
        ));

        let managed = path.with_file_name("pooler.managed.yaml");
        symlink(&path, &managed).expect("managed destination symlink");
        assert!(matches!(
            ConfigManagement::new(&path),
            Err(ConfigManagementError::Persistence)
        ));
        fs::remove_file(&managed).expect("managed symlink removed");
        fs::write(&managed, b"version: 1\n").expect("unmarked managed file");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o600))
            .expect("unmarked file made private");
        assert!(matches!(
            serving_source(&path),
            Err(ConfigManagementError::Persistence)
        ));
        fs::remove_file(&managed).expect("unmarked managed file removed");

        let marker = recovery_marker_path(&managed);
        let completed = completed_recovery_marker_path(&managed);
        fs::write(&completed, RECOVERY_MARKER).expect("completed marker written");
        fs::set_permissions(&completed, fs::Permissions::from_mode(0o600))
            .expect("completed marker made private");
        assert_eq!(
            serving_source(&path).expect("completed transaction marker is safe"),
            path.canonicalize().expect("canonical source")
        );
        assert!(!completed.exists());

        symlink(&path, &marker).expect("recovery marker symlink");
        assert!(matches!(
            serving_source(&path),
            Err(ConfigManagementError::Persistence)
        ));
        fs::remove_file(&marker).expect("marker symlink removed");
        fs::write(&marker, RECOVERY_MARKER).expect("recovery marker written");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))
            .expect("marker permissions changed");
        assert!(matches!(
            ConfigManagement::new(&path),
            Err(ConfigManagementError::Persistence)
        ));
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("marker made private");
        let marked = ConfigManagement::new(&path);
        assert!(
            matches!(marked, Err(ConfigManagementError::RecoveryRequired)),
            "unexpected marked-source result: {:?}",
            marked.err()
        );
        fs::remove_file(&marker).expect("valid marker removed");
        let linked_marker = marker.with_extension("linked");
        fs::write(&linked_marker, RECOVERY_MARKER).expect("hard-link source written");
        fs::set_permissions(&linked_marker, fs::Permissions::from_mode(0o600))
            .expect("hard-link source made private");
        fs::hard_link(&linked_marker, &marker).expect("marker hard link");
        assert!(matches!(
            serving_source(&path),
            Err(ConfigManagementError::Persistence)
        ));

        let (_writable_source_directory, writable_source) = source();
        fs::set_permissions(&writable_source, fs::Permissions::from_mode(0o666))
            .expect("source made writable");
        assert!(matches!(
            ConfigManagement::new(&writable_source),
            Err(ConfigManagementError::Persistence)
        ));

        let (writable_directory, writable_source) = source();
        fs::set_permissions(writable_directory.path(), fs::Permissions::from_mode(0o777))
            .expect("source parent made writable");
        assert!(matches!(
            ConfigManagement::new(&writable_source),
            Err(ConfigManagementError::Persistence)
        ));
    }

    #[test]
    fn versioned_usage_price_book_is_a_compiler_validated_typed_section() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let created = manager.create(1).expect("draft");
        let id = created["draft_id"].as_u64().expect("id");
        let patched = manager
            .apply(
                id,
                created["etag"].as_str().expect("etag"),
                TypedConfigPatch::Upsert {
                    section: "upstreams".into(),
                    id: "provider".into(),
                    value: json!({"url": "http://127.0.0.1:1"}),
                },
            )
            .expect("provider patch");
        let patched = manager
            .apply(
                id,
                patched["etag"].as_str().expect("etag"),
                TypedConfigPatch::Replace {
                    section: "usage_price_book".into(),
                    value: json!({
                        "version": "operator-v1",
                        "entries": [{
                            "provider": "provider",
                            "model": "model",
                            "input_per_million_usd_ticks": 1
                        }]
                    }),
                },
            )
            .expect("price book patch");
        let validated = manager
            .validate(id, patched["etag"].as_str().expect("etag"))
            .expect("compiled price book draft");
        assert!(
            validated["semantic_diff"]
                .as_array()
                .expect("diff")
                .iter()
                .any(|change| change["section"] == "usage_price_book"
                    && change["change"] == "changed")
        );
        assert!(!validated.to_string().contains("operator-v1"));
    }

    #[test]
    fn stale_etags_and_literal_secrets_fail_closed() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let created = manager.create(1).expect("draft");
        let id = created["draft_id"].as_u64().expect("id");
        assert!(matches!(
            manager.apply(
                id,
                "stale",
                TypedConfigPatch::Replace {
                    section: "management".into(),
                    value: json!({})
                }
            ),
            Err(ConfigManagementError::Precondition)
        ));

        let etag = created["etag"].as_str().expect("etag");
        let before = manager.view(id).expect("draft before oversized patch");
        assert!(matches!(
            manager.apply(
                id,
                etag,
                TypedConfigPatch::Replace {
                    section: "management".into(),
                    value: json!({"padding": "x".repeat(MAX_DOCUMENT_BYTES)}),
                },
            ),
            Err(ConfigManagementError::TooLarge)
        ));
        let after = manager.view(id).expect("draft after oversized patch");
        assert_eq!(after["etag"], before["etag"]);
        assert_eq!(after["patch_count"], before["patch_count"]);

        let patched = manager
            .apply(
                id,
                etag,
                TypedConfigPatch::Upsert {
                    section: "upstreams".into(),
                    id: "bad".into(),
                    value: json!({
                        "base_url": "https://example.invalid",
                        "auth": {"kind": "bearer", "secret": "literal-secret"}
                    }),
                },
            )
            .expect("structural patch");
        let etag = patched["etag"].as_str().expect("etag");
        assert!(matches!(
            manager.validate(id, etag),
            Err(ConfigManagementError::Invalid(_))
        ));
    }
}
