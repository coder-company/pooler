//! Bounded typed drafts and one canonical configuration-file transaction.
//!
//! File preparation and runtime publication are deliberately separate. This
//! module validates a candidate, durably stages it, and hands the staged
//! candidate to the runtime owner. The configured path remains the only live
//! configuration path.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use pooler_config::{CompiledConfig, Config, ConfigLoader, MAX_CONFIG_FILE_BYTES};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::ManagementState;
use pooler_store::DraftRecord;

const MAX_DRAFTS: usize = 8;
const MAX_PATCHES: usize = 128;
const MAX_DOCUMENT_BYTES: usize = MAX_CONFIG_FILE_BYTES as usize;
const DRAFT_TTL: Duration = Duration::from_secs(30 * 60);
const GENERATED_HEADER: &[u8] =
    b"# Generated and exclusively managed by Pooler. Do not edit by hand.\n";
const RECOVERY_MARKER: &[u8] = b"pooler-config-transaction-v2\n";
const RECOVERY_MARKER_MAX_BYTES: usize = 64 * 1024;
const RECOVERY_RECORD_VERSION: u8 = 2;

#[cfg(test)]
thread_local! {
    static FAILURE_HOOK: Cell<Option<FileTransactionStage>> = const { Cell::new(None) };
}

/// A section-scoped mutation. Arbitrary JSON pointers and unrestricted YAML
/// are deliberately unsupported; the compiler remains the final type
/// authority.
#[derive(Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableDraftPayload {
    base: Value,
    document: Value,
    patches: usize,
    confirmation: Option<String>,
}

struct PendingActivation {
    request_id: u64,
    activation: PreparedActivation,
}

struct State {
    drafts: VecDeque<Draft>,
    pending: BTreeMap<u64, PendingActivation>,
    commit_in_progress: bool,
    external_reload_in_progress: bool,
}

/// Process-local draft coordinator for the canonical configuration path.
pub(crate) struct ConfigManagement {
    canonical_path: PathBuf,
    next_id: AtomicU64,
    state: Mutex<State>,
    durable: Option<std::sync::Arc<ManagementState>>,
}

#[derive(Debug, Error)]
pub enum ConfigManagementError {
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryRecord {
    version: u8,
    operation: String,
    canonical: String,
    staged: String,
    backup: String,
    rollback: String,
    generation: u64,
    prior_sha256: String,
    next_sha256: String,
    prior_backup_sha256: Option<String>,
}

#[derive(Clone, Debug)]
enum RecoveryMarker {
    Legacy,
    Record(Box<RecoveryRecord>),
}

/// Return the one configured path after regular-file and marker validation.
///
/// The caller must load this exact path. No alternate generated path is
/// selected when a recovery marker or an unsafe file is present.
pub(crate) fn configured_source(
    source: impl AsRef<Path>,
) -> Result<PathBuf, ConfigManagementError> {
    let canonical = canonical_config_path(source.as_ref())?;
    ensure_no_recovery_marker(&canonical)?;
    Ok(canonical)
}

impl ConfigManagement {
    pub(crate) fn new(source: impl AsRef<Path>) -> Result<Self, ConfigManagementError> {
        let canonical_path = canonical_config_path(source.as_ref())?;
        ensure_no_recovery_marker(&canonical_path)?;
        Ok(Self {
            canonical_path,
            next_id: AtomicU64::new(0),
            state: Mutex::new(State {
                drafts: VecDeque::new(),
                pending: BTreeMap::new(),
                commit_in_progress: false,
                external_reload_in_progress: false,
            }),
            durable: None,
        })
    }

    pub(crate) fn new_with_state(
        source: impl AsRef<Path>,
        durable: std::sync::Arc<ManagementState>,
    ) -> Result<Self, ConfigManagementError> {
        let mut manager = Self::new(source)?;
        manager.durable = Some(durable);
        Ok(manager)
    }

    fn render_document(&self) -> Result<Value, ConfigManagementError> {
        let rendered = ConfigLoader::default()
            .render(&self.canonical_path)
            .map_err(|error| ConfigManagementError::Invalid(error.to_string()))?;
        if rendered.len() > MAX_DOCUMENT_BYTES {
            return Err(ConfigManagementError::TooLarge);
        }
        let yaml: serde_yml::Value = serde_yml::from_str(&rendered)
            .map_err(|error| ConfigManagementError::Invalid(error.to_string()))?;
        serde_json::to_value(yaml)
            .map_err(|_| ConfigManagementError::Invalid("candidate is not JSON-shaped".into()))
    }

    /// Serialize an external watcher with a prepared canonical activation.
    ///
    /// The method name remains a narrow compatibility seam for the current
    /// management caller; it does not select or serve another file.
    pub(crate) fn try_begin_unmanaged_reload(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        if state.commit_in_progress
            || !state.pending.is_empty()
            || state.external_reload_in_progress
        {
            return false;
        }
        state.external_reload_in_progress = true;
        true
    }

    pub(crate) fn finish_unmanaged_reload(&self) {
        self.state
            .lock()
            .expect("configuration draft lock poisoned")
            .external_reload_in_progress = false;
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
            .render(&self.canonical_path)
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

    pub(crate) fn create_owned(
        &self,
        owner_id: &str,
        base_generation: u64,
    ) -> Result<Value, ConfigManagementError> {
        let Some(durable) = self.durable.as_ref() else {
            return self.create(base_generation);
        };
        let document = self.render_document()?;
        let payload = DurableDraftPayload {
            base: document.clone(),
            document,
            patches: 0,
            confirmation: None,
        };
        let now = management_timestamp_ms();
        let record = durable
            .create_draft(DraftRecord::new(
                owner_id,
                "configuration",
                base_generation,
                encode_durable_draft(&payload)?,
                now,
                now.saturating_add(u64::try_from(DRAFT_TTL.as_millis()).unwrap_or(u64::MAX)),
            ))
            .map_err(map_store_error)?;
        durable_draft_view(&record, &payload)
    }

    pub(crate) fn view(&self, id: u64) -> Result<Value, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let draft = draft_mut(&mut state.drafts, id)?;
        Ok(draft_view(draft))
    }

    pub(crate) fn view_owned(
        &self,
        owner_id: &str,
        id: u64,
    ) -> Result<Value, ConfigManagementError> {
        let Some(durable) = self.durable.as_ref() else {
            return self.view(id);
        };
        let record = durable
            .draft(id, owner_id, management_timestamp_ms())
            .map_err(map_store_error)?
            .ok_or(ConfigManagementError::NotFound)?;
        let payload = decode_durable_draft(&record.payload)?;
        durable_draft_view(&record, &payload)
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

    pub(crate) fn apply_owned(
        &self,
        owner_id: &str,
        id: u64,
        if_match: &str,
        patch: TypedConfigPatch,
    ) -> Result<Value, ConfigManagementError> {
        let Some(durable) = self.durable.as_ref() else {
            return self.apply(id, if_match, patch);
        };
        let record = durable
            .draft(id, owner_id, management_timestamp_ms())
            .map_err(map_store_error)?
            .ok_or(ConfigManagementError::NotFound)?;
        let mut payload = decode_durable_draft(&record.payload)?;
        if document_etag(&payload.document)? != if_match.trim_matches('"') {
            return Err(ConfigManagementError::Precondition);
        }
        if payload.patches >= MAX_PATCHES {
            return Err(ConfigManagementError::PatchLimit);
        }
        let mut candidate = payload.document.clone();
        apply_patch(&mut candidate, patch)?;
        if serde_json::to_vec(&candidate)
            .map_err(|_| ConfigManagementError::UnsupportedPatch)?
            .len()
            > MAX_DOCUMENT_BYTES
        {
            return Err(ConfigManagementError::TooLarge);
        }
        payload.document = candidate;
        payload.patches += 1;
        payload.confirmation = None;
        let next = durable
            .update_draft(
                id,
                owner_id,
                record.revision,
                &record.etag,
                encode_durable_draft(&payload)?,
                management_timestamp_ms(),
            )
            .map_err(map_store_error)?;
        durable_draft_view(&next, &payload)
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

    pub(crate) fn validate_owned(
        &self,
        owner_id: &str,
        id: u64,
        if_match: &str,
    ) -> Result<Value, ConfigManagementError> {
        let Some(durable) = self.durable.as_ref() else {
            return self.validate(id, if_match);
        };
        let record = durable
            .draft(id, owner_id, management_timestamp_ms())
            .map_err(map_store_error)?
            .ok_or(ConfigManagementError::NotFound)?;
        let mut payload = decode_durable_draft(&record.payload)?;
        if document_etag(&payload.document)? != if_match.trim_matches('"') {
            return Err(ConfigManagementError::Precondition);
        }
        compile_document(&payload.document, record.base_generation.saturating_add(1))?;
        let changes = semantic_diff(&payload.base, &payload.document);
        let confirmation = confirmation_token_for(
            record.draft_id,
            record.base_generation,
            if_match.trim_matches('"'),
            &changes,
        )?;
        payload.confirmation = Some(confirmation.clone());
        let next = durable
            .update_draft(
                id,
                owner_id,
                record.revision,
                &record.etag,
                encode_durable_draft(&payload)?,
                management_timestamp_ms(),
            )
            .map_err(map_store_error)?;
        Ok(json!({
            "draft_id": next.draft_id,
            "base_generation": next.base_generation,
            "etag": document_etag(&payload.document)?,
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

    pub(crate) fn diff_owned(
        &self,
        owner_id: &str,
        id: u64,
    ) -> Result<Value, ConfigManagementError> {
        let Some(durable) = self.durable.as_ref() else {
            return self.diff(id);
        };
        let record = durable
            .draft(id, owner_id, management_timestamp_ms())
            .map_err(map_store_error)?
            .ok_or(ConfigManagementError::NotFound)?;
        let payload = decode_durable_draft(&record.payload)?;
        durable_draft_diff(&record, &payload)
    }

    /// Validate and stage a candidate without claiming runtime activation.
    pub(crate) fn commit(
        &self,
        id: u64,
        if_match: &str,
        active_generation: u64,
        confirmation: &str,
    ) -> Result<PreparedActivation, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        if state.commit_in_progress
            || !state.pending.is_empty()
            || state.external_reload_in_progress
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
        let target_generation = active_generation.saturating_add(1);
        let compiled = compile_document(&draft.document, target_generation)?;
        let encoded = generated_document(&draft.document)?;
        let activation = match prepare_activation(
            &self.canonical_path,
            encoded,
            compiled,
            active_generation,
            target_generation,
            "commit",
        ) {
            Ok(activation) => activation,
            Err(error) => {
                state.commit_in_progress =
                    matches!(&error, ConfigManagementError::RecoveryRequired);
                return Err(error);
            }
        };
        state.drafts.remove(position);
        state.commit_in_progress = true;
        Ok(activation)
    }

    pub(crate) fn commit_owned(
        &self,
        owner_id: &str,
        id: u64,
        if_match: &str,
        active_generation: u64,
        confirmation: &str,
    ) -> Result<PreparedActivation, ConfigManagementError> {
        let Some(durable) = self.durable.as_ref() else {
            return self.commit(id, if_match, active_generation, confirmation);
        };
        {
            let state = self
                .state
                .lock()
                .expect("configuration draft lock poisoned");
            if state.commit_in_progress
                || !state.pending.is_empty()
                || state.external_reload_in_progress
            {
                return Err(ConfigManagementError::Precondition);
            }
        }
        let record = durable
            .draft(id, owner_id, management_timestamp_ms())
            .map_err(map_store_error)?
            .ok_or(ConfigManagementError::NotFound)?;
        let payload = decode_durable_draft(&record.payload)?;
        if document_etag(&payload.document)? != if_match.trim_matches('"') {
            return Err(ConfigManagementError::Precondition);
        }
        if record.base_generation != active_generation {
            return Err(ConfigManagementError::Precondition);
        }
        if payload.confirmation.as_deref() != Some(confirmation) {
            return Err(ConfigManagementError::Confirmation);
        }
        let target_generation = active_generation.saturating_add(1);
        let compiled = compile_document(&payload.document, target_generation)?;
        let encoded = generated_document(&payload.document)?;
        let activation = match prepare_activation(
            &self.canonical_path,
            encoded,
            compiled,
            active_generation,
            target_generation,
            "commit",
        ) {
            Ok(activation) => activation,
            Err(error) => {
                self.state
                    .lock()
                    .expect("configuration draft lock poisoned")
                    .commit_in_progress = matches!(&error, ConfigManagementError::RecoveryRequired);
                return Err(error);
            }
        };
        match durable.remove_draft(id, owner_id) {
            Ok(true) => {
                self.state
                    .lock()
                    .expect("configuration draft lock poisoned")
                    .commit_in_progress = true;
                Ok(activation)
            }
            Ok(false) | Err(_) => {
                let mut activation = activation;
                let _ = rollback_activation(&mut activation);
                Err(ConfigManagementError::Persistence)
            }
        }
    }

    /// Register the handoff before the runtime starts its off-path work.
    pub(crate) fn register_commit(&self, request_id: u64, activation: PreparedActivation) {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        state.commit_in_progress = false;
        state.pending.insert(
            request_id,
            PendingActivation {
                request_id,
                activation,
            },
        );
    }

    /// Promote a prepared candidate after the runtime has accepted it.
    #[cfg(test)]
    pub(crate) fn promote_file(
        &self,
        activation: &mut PreparedActivation,
    ) -> Result<(), ConfigManagementError> {
        if activation.candidate.canonical_path != self.canonical_path
            || !activation.rollback_guard.active
        {
            return Err(ConfigManagementError::Precondition);
        }
        let result = promote_staged(&activation.candidate);
        if let Err(error) = result {
            return match rollback_activation(activation) {
                Ok(()) => Err(error),
                Err(_) => Err(ConfigManagementError::RecoveryRequired),
            };
        }
        activation.promoted = true;
        Ok(())
    }

    /// Promote one registered handoff after runtime preparation succeeds.
    pub(crate) fn promote_commit(&self, request_id: u64) -> Result<(), ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        let pending = state
            .pending
            .get_mut(&request_id)
            .ok_or(ConfigManagementError::NotFound)?;
        if pending.activation.candidate.canonical_path != self.canonical_path
            || !pending.activation.rollback_guard.active
        {
            return Err(ConfigManagementError::Precondition);
        }
        let result = promote_staged(&pending.activation.candidate);
        if let Err(error) = result {
            return match rollback_activation(&mut pending.activation) {
                Ok(()) => Err(error),
                Err(_) => Err(ConfigManagementError::RecoveryRequired),
            };
        }
        pending.activation.promoted = true;
        Ok(())
    }

    /// Complete or roll back a registered file handoff.
    #[cfg(test)]
    pub(crate) fn complete(
        &self,
        request_id: u64,
        succeeded: bool,
    ) -> Result<(), ConfigManagementError> {
        self.complete_commit(request_id, succeeded)
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
        let Some(mut pending) = state.pending.remove(&request_id) else {
            return Ok(());
        };
        debug_assert_eq!(pending.request_id, request_id);
        let completion = if succeeded {
            complete_activation(&mut pending.activation)
        } else {
            rollback_activation(&mut pending.activation)
        };
        if let Err(error) = completion {
            state.pending.insert(request_id, pending);
            return Err(error);
        }
        Ok(())
    }

    /// Cancel an unregistered handoff and restore the exact prior file state.
    #[cfg(test)]
    pub(crate) fn cancel_activation(
        &self,
        mut activation: PreparedActivation,
    ) -> Result<(), ConfigManagementError> {
        let handoff_failure = fail_hook(FileTransactionStage::HandoffCancellation);
        let rollback_result = rollback_activation(&mut activation);
        let rollback_ok = rollback_result.is_ok();
        let result = match (handoff_failure, rollback_result) {
            (Ok(()), result) => result,
            (Err(error), Ok(())) => Err(error),
            (Err(_), Err(_)) => Err(ConfigManagementError::RecoveryRequired),
        };
        if rollback_ok {
            self.state
                .lock()
                .expect("configuration draft lock poisoned")
                .commit_in_progress = false;
        }
        result
    }

    /// Stage the prior canonical revision as an explicit rollback activation.
    pub(crate) fn rollback(
        &self,
        active_generation: u64,
    ) -> Result<PreparedActivation, ConfigManagementError> {
        let mut state = self
            .state
            .lock()
            .expect("configuration draft lock poisoned");
        if state.commit_in_progress
            || !state.pending.is_empty()
            || state.external_reload_in_progress
        {
            return Err(ConfigManagementError::Precondition);
        }
        ensure_no_recovery_marker(&self.canonical_path)?;
        let backup = backup_path(&self.canonical_path);
        let prior = read_existing_file(&backup, true)?.ok_or(ConfigManagementError::NotFound)?;
        let compiled =
            compile_generated_bytes(&backup, &prior, active_generation.saturating_add(1))?;
        let activation = match prepare_activation(
            &self.canonical_path,
            prior,
            compiled,
            active_generation,
            active_generation.saturating_add(1),
            "rollback",
        ) {
            Ok(activation) => activation,
            Err(error) => {
                state.commit_in_progress =
                    matches!(&error, ConfigManagementError::RecoveryRequired);
                return Err(error);
            }
        };
        state.commit_in_progress = true;
        Ok(activation)
    }

    /// Redacted file state for management/status consumers.
    #[allow(dead_code)] // Exposed by the structured control-plane graph in Task 14.
    pub(crate) fn active_status(&self, generation: u64) -> Result<Value, ConfigManagementError> {
        let bytes = read_existing_file(&self.canonical_path, false)?
            .ok_or(ConfigManagementError::Persistence)?;
        Ok(json!({
            "path": self.canonical_path,
            "sha256": bytes_digest(&bytes),
            "generation": generation,
        }))
    }
}

/// The immutable candidate passed from file management to runtime activation.
#[derive(Clone)]
pub(crate) struct ActivationCandidate {
    pub(crate) base_generation: u64,
    pub(crate) target_generation: u64,
    pub(crate) compiled: CompiledConfig,
    pub(crate) canonical_path: PathBuf,
    pub(crate) staged_path: PathBuf,
    pub(crate) backup_path: PathBuf,
    pub(crate) rollback_path: PathBuf,
    #[allow(dead_code)] // Surfaced by the structured activation graph in Task 14.
    pub(crate) prior_digest: String,
    pub(crate) next_digest: String,
    pub(crate) bytes: Vec<u8>,
}

/// A prepared candidate with an exact-file rollback guard.
pub(crate) struct PreparedActivation {
    pub(crate) candidate: ActivationCandidate,
    rollback_guard: RollbackGuard,
    promoted: bool,
}

struct RollbackGuard {
    persistence: PersistenceState,
    active: bool,
}

/// Compatibility type name for the current management caller. The value is
/// already a prepared activation and no file is promoted by this alias.
pub(crate) type PreparedCommit = PreparedActivation;

struct PersistenceState {
    previous_canonical: Vec<u8>,
    previous_backup: Option<Vec<u8>>,
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

fn management_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn encode_durable_draft(payload: &DurableDraftPayload) -> Result<Vec<u8>, ConfigManagementError> {
    serde_json::to_vec(payload).map_err(|_| ConfigManagementError::Persistence)
}

fn decode_durable_draft(bytes: &[u8]) -> Result<DurableDraftPayload, ConfigManagementError> {
    serde_json::from_slice(bytes).map_err(|_| ConfigManagementError::Persistence)
}

fn durable_draft_view(
    record: &DraftRecord,
    payload: &DurableDraftPayload,
) -> Result<Value, ConfigManagementError> {
    Ok(json!({
        "draft_id": record.draft_id,
        "base_generation": record.base_generation,
        "etag": document_etag(&payload.document)?,
        "patch_count": payload.patches,
        "status": if payload.confirmation.is_some() { "validated" } else { "draft" }
    }))
}

fn durable_draft_diff(
    record: &DraftRecord,
    payload: &DurableDraftPayload,
) -> Result<Value, ConfigManagementError> {
    Ok(json!({
        "draft_id": record.draft_id,
        "base_generation": record.base_generation,
        "etag": document_etag(&payload.document)?,
        "semantic_diff": semantic_diff(&payload.base, &payload.document)
    }))
}

fn confirmation_token_for(
    draft_id: u64,
    base_generation: u64,
    etag: &str,
    changes: &Value,
) -> Result<String, ConfigManagementError> {
    let encoded = serde_json::to_vec(&json!({
        "draft": draft_id,
        "generation": base_generation,
        "etag": etag,
        "diff": changes
    }))
    .map_err(|_| ConfigManagementError::Confirmation)?;
    Ok(hex(digest(&SHA256, &encoded).as_ref()))
}

fn map_store_error(error: pooler_store::StoreError) -> ConfigManagementError {
    match error {
        pooler_store::StoreError::OwnerMismatch
        | pooler_store::StoreError::ManagementRevisionConflict => {
            ConfigManagementError::Precondition
        }
        pooler_store::StoreError::RecordExpired => ConfigManagementError::Expired,
        pooler_store::StoreError::ManagementCapacity => ConfigManagementError::PatchLimit,
        _ => ConfigManagementError::Persistence,
    }
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
            if matches!(section.as_str(), "accounts" | "upstreams") {
                reject_external_secret_references(&value)?;
            }
            if map_section(&section) {
                section_object_mut(document, &section)?.insert(id, value);
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

fn reject_external_secret_references(value: &Value) -> Result<(), ConfigManagementError> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (key, child) in object {
        if matches!(
            key.as_str(),
            "secret" | "client_secret" | "secret_value" | "access_token" | "refresh_token"
        ) {
            let Some(reference) = child.as_str() else {
                return Err(ConfigManagementError::UnsupportedPatch);
            };
            if !reference.starts_with("managed:") {
                return Err(ConfigManagementError::UnsupportedPatch);
            }
        }
        if child.is_object() {
            reject_external_secret_references(child)?;
        } else if let Some(values) = child.as_array() {
            for value in values {
                if value.is_object() {
                    reject_external_secret_references(value)?;
                }
            }
        }
    }
    Ok(())
}

fn map_section(section: &str) -> bool {
    matches!(
        section,
        "listeners" | "upstreams" | "accounts" | "account_pools" | "policies" | "extensions"
    )
}

fn list_section(section: &str) -> bool {
    section == "models" || section == "routes"
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

fn compile_document(
    document: &Value,
    generation: u64,
) -> Result<CompiledConfig, ConfigManagementError> {
    let encoded = serde_json::to_string(document)
        .map_err(|_| ConfigManagementError::Invalid("candidate serialization failed".into()))?;
    Config::from_yaml("<canonical-config-draft>", &encoded)
        .and_then(|config| config.compile_with_generation(generation))
        .map_err(|error| ConfigManagementError::Invalid(error.to_string()))
}

fn compile_generated_bytes(
    path: &Path,
    bytes: &[u8],
    generation: u64,
) -> Result<CompiledConfig, ConfigManagementError> {
    let body = bytes.strip_prefix(GENERATED_HEADER).unwrap_or(bytes);
    let text = std::str::from_utf8(body)
        .map_err(|_| ConfigManagementError::Invalid("configuration is not UTF-8".into()))?;
    Config::from_yaml(path.display().to_string(), text)
        .and_then(|config| config.compile_with_generation(generation))
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

fn bytes_digest(bytes: &[u8]) -> String {
    hex(digest(&SHA256, bytes).as_ref())
}

fn semantic_diff(base: &Value, candidate: &Value) -> Value {
    let mut changes = Vec::new();
    for section in [
        "listeners",
        "upstreams",
        "accounts",
        "account_pools",
        "policies",
        "extensions",
    ] {
        let before = base.get(section).and_then(Value::as_object);
        let after = candidate.get(section).and_then(Value::as_object);
        let mut ids = BTreeSet::new();
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
        let mut ids = BTreeSet::new();
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

fn canonical_config_path(path: &Path) -> Result<PathBuf, ConfigManagementError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigManagementError::Persistence)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ConfigManagementError::Persistence);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| ConfigManagementError::Persistence)?;
    validate_source_file(&canonical)?;
    validate_parent_directory(
        canonical
            .parent()
            .ok_or(ConfigManagementError::Persistence)?,
    )?;
    Ok(canonical)
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("backup.yaml")
}

fn rollback_path(path: &Path) -> PathBuf {
    path.with_extension("rollback.yaml")
}

fn recovery_marker_path(path: &Path) -> PathBuf {
    path.with_extension("recovery-required")
}

fn completed_recovery_marker_path(path: &Path) -> PathBuf {
    path.with_extension("recovery-completed")
}

fn staged_path(path: &Path) -> PathBuf {
    let parent = path.parent().expect("canonical path has a parent");
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(".{name}.{}.{}.stage", std::process::id(), nonce))
}

fn ensure_no_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    cleanup_completed_recovery_marker(path)?;
    if read_recovery_marker(&recovery_marker_path(path))?.is_some() {
        Err(ConfigManagementError::RecoveryRequired)
    } else {
        Ok(())
    }
}

fn cleanup_completed_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    let completed = completed_recovery_marker_path(path);
    if !path_exists(&completed)? {
        return Ok(());
    }
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    remove_file_synced(parent, &completed)
}

fn path_exists(path: &Path) -> Result<bool, ConfigManagementError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ConfigManagementError::Persistence),
    }
}

fn read_recovery_marker(path: &Path) -> Result<Option<RecoveryMarker>, ConfigManagementError> {
    let Some(mut file) = open_validated_file(path, true)? else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|_| ConfigManagementError::Persistence)?;
    if metadata.len() > RECOVERY_MARKER_MAX_BYTES as u64 {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| ConfigManagementError::Persistence)?;
    if bytes == RECOVERY_MARKER {
        return Ok(Some(RecoveryMarker::Legacy));
    }
    let Some(payload) = bytes.strip_prefix(RECOVERY_MARKER) else {
        return Err(ConfigManagementError::RecoveryRequired);
    };
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let record: RecoveryRecord =
        serde_json::from_slice(payload).map_err(|_| ConfigManagementError::RecoveryRequired)?;
    if record.version != RECOVERY_RECORD_VERSION {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    Ok(Some(RecoveryMarker::Record(Box::new(record))))
}

fn acquire_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    ensure_no_recovery_marker(path)?;
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    let marker = recovery_marker_path(path);
    fail_hook(FileTransactionStage::MarkerCreate)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&marker)
        .map_err(|_| ConfigManagementError::Persistence)?;
    let result = (|| -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::other("transaction marker is not a regular file"));
        }
        #[cfg(unix)]
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::other("transaction marker is not owner-private"));
        }
        file.write_all(RECOVERY_MARKER)?;
        file.sync_all()?;
        sync_directory(parent)
            .map_err(|_| io::Error::other("transaction marker directory sync"))?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(&marker);
        let _ = sync_directory_io(parent);
        return Err(ConfigManagementError::Persistence);
    }
    Ok(())
}

fn write_recovery_record(
    path: &Path,
    record: &RecoveryRecord,
) -> Result<(), ConfigManagementError> {
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    let marker = recovery_marker_path(path);
    let mut bytes = RECOVERY_MARKER.to_vec();
    bytes.extend(serde_json::to_vec(record).map_err(|_| ConfigManagementError::RecoveryRequired)?);
    bytes.push(b'\n');
    if bytes.len() > RECOVERY_MARKER_MAX_BYTES {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let mut options = OpenOptions::new();
    options.write(true).truncate(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(&marker)
        .map_err(|_| ConfigManagementError::RecoveryRequired)?;
    file.set_len(0)
        .and_then(|_| file.write_all(&bytes))
        .and_then(|_| file.sync_all())
        .and_then(|_| sync_directory_io(parent))
        .map_err(|_| ConfigManagementError::RecoveryRequired)
}

fn clear_recovery_marker(path: &Path) -> Result<(), ConfigManagementError> {
    let parent = path.parent().ok_or(ConfigManagementError::Persistence)?;
    let marker = recovery_marker_path(path);
    let completed = completed_recovery_marker_path(path);
    if !path_exists(&marker)? {
        return Err(ConfigManagementError::Persistence);
    }
    fail_hook(FileTransactionStage::CompletionMarkerWrite)?;
    fs::rename(&marker, &completed).map_err(|_| ConfigManagementError::Persistence)?;
    if sync_directory(parent).is_err() {
        let _ = fs::rename(&completed, &marker);
        let _ = sync_directory_io(parent);
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let _ = remove_file_synced(parent, &completed);
    Ok(())
}

fn clear_recovery_marker_if_present(path: &Path) -> Result<(), ConfigManagementError> {
    if path_exists(&recovery_marker_path(path))? {
        clear_recovery_marker(path)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)] // Every path/digest component is part of the durable record.
fn recovery_record(
    path: &Path,
    staged: &Path,
    backup: &Path,
    rollback: &Path,
    bytes: &[u8],
    generation: u64,
    operation: &str,
    persistence: &PersistenceState,
) -> RecoveryRecord {
    RecoveryRecord {
        version: RECOVERY_RECORD_VERSION,
        operation: operation.to_owned(),
        canonical: path.display().to_string(),
        staged: staged.display().to_string(),
        backup: backup.display().to_string(),
        rollback: rollback.display().to_string(),
        generation,
        prior_sha256: bytes_digest(&persistence.previous_canonical),
        next_sha256: bytes_digest(bytes),
        prior_backup_sha256: persistence.previous_backup.as_deref().map(bytes_digest),
    }
}

fn prepare_activation(
    canonical: &Path,
    bytes: Vec<u8>,
    compiled: CompiledConfig,
    base_generation: u64,
    target_generation: u64,
    operation: &str,
) -> Result<PreparedActivation, ConfigManagementError> {
    acquire_recovery_marker(canonical)?;
    let backup = backup_path(canonical);
    let rollback = rollback_path(canonical);
    let staged = staged_path(canonical);
    let persistence = match persistence_snapshot(canonical) {
        Ok(persistence) => persistence,
        Err(error) => {
            return Err(abort_preparation(
                canonical, &backup, &staged, &rollback, None, error,
            ))
        }
    };
    let record = recovery_record(
        canonical,
        &staged,
        &backup,
        &rollback,
        &bytes,
        target_generation,
        operation,
        &persistence,
    );
    let preparation = (|| {
        write_recovery_record(canonical, &record)?;
        if let Some(previous_backup) = persistence.previous_backup.as_deref() {
            write_atomic(
                canonical
                    .parent()
                    .ok_or(ConfigManagementError::Persistence)?,
                &rollback,
                previous_backup,
                AtomicWriteKind::Backup,
            )?;
        }
        write_atomic(
            canonical
                .parent()
                .ok_or(ConfigManagementError::Persistence)?,
            &backup,
            &persistence.previous_canonical,
            AtomicWriteKind::Backup,
        )?;
        write_atomic(
            canonical
                .parent()
                .ok_or(ConfigManagementError::Persistence)?,
            &staged,
            &bytes,
            AtomicWriteKind::Staged,
        )?;
        Ok(())
    })();
    if let Err(error) = preparation {
        return Err(abort_preparation(
            canonical,
            &backup,
            &staged,
            &rollback,
            Some(&persistence),
            error,
        ));
    }
    let prior_digest = bytes_digest(&persistence.previous_canonical);
    let next_digest = bytes_digest(&bytes);
    Ok(PreparedActivation {
        candidate: ActivationCandidate {
            base_generation,
            target_generation,
            compiled,
            canonical_path: canonical.to_owned(),
            staged_path: staged,
            backup_path: backup,
            rollback_path: rollback,
            prior_digest,
            next_digest,
            bytes,
        },
        rollback_guard: RollbackGuard {
            persistence,
            active: true,
        },
        promoted: false,
    })
}

fn abort_preparation(
    canonical: &Path,
    backup: &Path,
    staged: &Path,
    rollback: &Path,
    persistence: Option<&PersistenceState>,
    original: ConfigManagementError,
) -> ConfigManagementError {
    let restored = (if let Some(persistence) = persistence {
        restore_preparation_state(canonical, backup, staged, rollback, persistence)
    } else {
        Ok(())
    })
    .and_then(|_| clear_recovery_marker_if_present(canonical));
    if restored.is_ok() {
        original
    } else {
        ConfigManagementError::RecoveryRequired
    }
}

fn restore_preparation_state(
    canonical: &Path,
    backup: &Path,
    staged: &Path,
    rollback: &Path,
    persistence: &PersistenceState,
) -> Result<(), ConfigManagementError> {
    let parent = canonical
        .parent()
        .ok_or(ConfigManagementError::Persistence)?;
    if let Some(previous_backup) = persistence.previous_backup.as_deref() {
        write_atomic(parent, backup, previous_backup, AtomicWriteKind::Rollback)?;
    } else {
        remove_file_synced(parent, backup)?;
    }
    remove_file_synced(parent, staged)?;
    remove_file_synced(parent, rollback)?;
    Ok(())
}

fn persistence_snapshot(path: &Path) -> Result<PersistenceState, ConfigManagementError> {
    let previous_canonical =
        read_existing_file(path, false)?.ok_or(ConfigManagementError::Persistence)?;
    let backup = backup_path(path);
    let previous_backup = read_existing_file(&backup, true)?;
    let rollback = rollback_path(path);
    if path_exists(&rollback)? {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    Ok(PersistenceState {
        previous_canonical,
        previous_backup,
    })
}

fn restore_file_state(
    canonical: &Path,
    backup: &Path,
    staged: &Path,
    rollback: &Path,
    persistence: &PersistenceState,
) -> Result<(), ConfigManagementError> {
    let parent = canonical
        .parent()
        .ok_or(ConfigManagementError::Persistence)?;
    write_atomic(
        parent,
        canonical,
        &persistence.previous_canonical,
        AtomicWriteKind::Rollback,
    )?;
    if let Some(previous_backup) = persistence.previous_backup.as_deref() {
        write_atomic(parent, backup, previous_backup, AtomicWriteKind::Rollback)?;
    } else {
        remove_file_synced(parent, backup)?;
    }
    remove_file_synced(parent, staged)?;
    remove_file_synced(parent, rollback)?;
    fail_hook(FileTransactionStage::RollbackFsync)?;
    sync_directory(parent)
}

fn restore_exact(
    candidate: &ActivationCandidate,
    persistence: &PersistenceState,
) -> Result<(), ConfigManagementError> {
    restore_file_state(
        &candidate.canonical_path,
        &candidate.backup_path,
        &candidate.staged_path,
        &candidate.rollback_path,
        persistence,
    )
}

fn rollback_activation(activation: &mut PreparedActivation) -> Result<(), ConfigManagementError> {
    if !activation.rollback_guard.active {
        return Ok(());
    }
    restore_exact(
        &activation.candidate,
        &activation.rollback_guard.persistence,
    )?;
    clear_recovery_marker(&activation.candidate.canonical_path)?;
    activation.rollback_guard.active = false;
    activation.promoted = false;
    Ok(())
}

fn promote_staged(candidate: &ActivationCandidate) -> Result<(), ConfigManagementError> {
    let staged = read_existing_file(&candidate.staged_path, true)?
        .ok_or(ConfigManagementError::Persistence)?;
    if bytes_digest(&staged) != candidate.next_digest {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let parent = candidate
        .canonical_path
        .parent()
        .ok_or(ConfigManagementError::Persistence)?;
    fail_hook(FileTransactionStage::Rename)?;
    fs::rename(&candidate.staged_path, &candidate.canonical_path)
        .map_err(|_| ConfigManagementError::Persistence)?;
    sync_directory(parent)?;
    Ok(())
}

fn complete_activation(activation: &mut PreparedActivation) -> Result<(), ConfigManagementError> {
    if !activation.rollback_guard.active || !activation.promoted {
        return Err(ConfigManagementError::Precondition);
    }
    let parent = activation
        .candidate
        .canonical_path
        .parent()
        .ok_or(ConfigManagementError::Persistence)?;
    remove_file_synced(parent, &activation.candidate.staged_path)?;
    remove_file_synced(parent, &activation.candidate.rollback_path)?;
    clear_recovery_marker(&activation.candidate.canonical_path)?;
    activation.rollback_guard.active = false;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomicWriteKind {
    Backup,
    Staged,
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileTransactionStage {
    MarkerCreate,
    BackupWrite,
    BackupFsync,
    TempWrite,
    TempFsync,
    Rename,
    DirectoryFsync,
    #[cfg(test)]
    HandoffCancellation,
    CompletionMarkerWrite,
    RollbackFsync,
}

fn fail_hook(_stage: FileTransactionStage) -> Result<(), ConfigManagementError> {
    #[cfg(test)]
    {
        if FAILURE_HOOK.with(|hook| hook.get() == Some(_stage)) {
            FAILURE_HOOK.with(|hook| hook.set(None));
            return Err(ConfigManagementError::Persistence);
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ConfigManagementError> {
    fail_hook(FileTransactionStage::DirectoryFsync)?;
    sync_directory_io(path).map_err(|_| ConfigManagementError::Persistence)
}

fn sync_directory_io(path: &Path) -> io::Result<()> {
    File::open(path).and_then(|directory| directory.sync_all())
}

fn write_atomic(
    parent: &Path,
    path: &Path,
    bytes: &[u8],
    kind: AtomicWriteKind,
) -> Result<(), ConfigManagementError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ConfigManagementError::Persistence)?;
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let write_stage = match kind {
        AtomicWriteKind::Backup => FileTransactionStage::BackupWrite,
        AtomicWriteKind::Staged | AtomicWriteKind::Rollback => FileTransactionStage::TempWrite,
    };
    let sync_stage = match kind {
        AtomicWriteKind::Backup => FileTransactionStage::BackupFsync,
        AtomicWriteKind::Staged | AtomicWriteKind::Rollback => FileTransactionStage::TempFsync,
    };
    fail_hook(write_stage)?;
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
        fail_hook(sync_stage).map_err(|_| io::Error::other("transaction sync hook"))?;
        file.sync_all()?;
        fail_hook(FileTransactionStage::Rename)
            .map_err(|_| io::Error::other("transaction rename hook"))?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        fail_hook(FileTransactionStage::DirectoryFsync)
            .map_err(|_| io::Error::other("transaction directory sync hook"))?;
        sync_directory_io(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(ConfigManagementError::Persistence);
    }
    Ok(())
}

fn remove_file_synced(parent: &Path, path: &Path) -> Result<(), ConfigManagementError> {
    match fs::remove_file(path) {
        Ok(()) => sync_directory(parent),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ConfigManagementError::Persistence),
    }
}

fn validate_source_file(path: &Path) -> Result<(), ConfigManagementError> {
    open_validated_file(path, false)?
        .map(|_| ())
        .ok_or(ConfigManagementError::Persistence)
}

fn read_existing_file(
    path: &Path,
    owner_private: bool,
) -> Result<Option<Vec<u8>>, ConfigManagementError> {
    let Some(mut file) = open_validated_file(path, owner_private)? else {
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
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ConfigManagementError::TooLarge);
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

#[derive(Default)]
struct RecoveryFileInspection {
    present: bool,
    regular: bool,
    owner_private: bool,
    bytes: Option<Vec<u8>>,
    digest: Option<String>,
    generated: bool,
    config_valid: bool,
    error: Option<String>,
}

struct RecoveryMarkerInspection {
    present: bool,
    valid: bool,
    digest: Option<String>,
    marker: Option<RecoveryMarker>,
    error: Option<String>,
}

fn inspect_recovery_file(
    path: &Path,
    generation: u64,
    require_generated: bool,
    owner_private: bool,
) -> RecoveryFileInspection {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return RecoveryFileInspection::default()
        }
        Err(error) => {
            return RecoveryFileInspection {
                present: true,
                error: Some(error.to_string()),
                ..RecoveryFileInspection::default()
            }
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return RecoveryFileInspection {
            present: true,
            error: Some("path is not a regular file".into()),
            ..RecoveryFileInspection::default()
        };
    }
    let bytes = match read_existing_file(path, owner_private) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return RecoveryFileInspection {
                present: true,
                error: Some("file disappeared during inspection".into()),
                ..RecoveryFileInspection::default()
            }
        }
        Err(error) => {
            return RecoveryFileInspection {
                present: true,
                regular: true,
                error: Some(error.to_string()),
                ..RecoveryFileInspection::default()
            }
        }
    };
    let digest = bytes_digest(&bytes);
    let generated = bytes.starts_with(GENERATED_HEADER);
    let config_bytes = if generated {
        &bytes[GENERATED_HEADER.len()..]
    } else {
        &bytes[..]
    };
    let (config_valid, error) = if require_generated && !generated {
        (
            false,
            Some("file is missing Pooler's generated-file marker".into()),
        )
    } else {
        match std::str::from_utf8(config_bytes) {
            Ok(body) => match Config::from_yaml(path.display().to_string(), body)
                .and_then(|config| config.compile_with_generation(generation))
            {
                Ok(_) => (true, None),
                Err(error) => (false, Some(error.to_string())),
            },
            Err(error) => (false, Some(error.to_string())),
        }
    };
    RecoveryFileInspection {
        present: true,
        regular: true,
        owner_private: !owner_private || is_owner_private(path),
        bytes: Some(bytes),
        digest: Some(digest),
        generated,
        config_valid,
        error,
    }
}

fn is_owner_private(path: &Path) -> bool {
    #[cfg(unix)]
    {
        fs::metadata(path)
            .map(|metadata| {
                metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o077 == 0
            })
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

fn inspect_recovery_marker(path: &Path) -> RecoveryMarkerInspection {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return RecoveryMarkerInspection {
                present: false,
                valid: true,
                digest: None,
                marker: None,
                error: None,
            }
        }
        Err(error) => {
            return RecoveryMarkerInspection {
                present: true,
                valid: false,
                digest: None,
                marker: None,
                error: Some(error.to_string()),
            }
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return RecoveryMarkerInspection {
            present: true,
            valid: false,
            digest: None,
            marker: None,
            error: Some("transaction marker is not a regular file".into()),
        };
    }
    let Some(bytes) = (match read_existing_file(path, true) {
        Ok(bytes) => bytes,
        Err(error) => {
            return RecoveryMarkerInspection {
                present: true,
                valid: false,
                digest: None,
                marker: None,
                error: Some(error.to_string()),
            }
        }
    }) else {
        return RecoveryMarkerInspection {
            present: true,
            valid: false,
            digest: None,
            marker: None,
            error: Some("transaction marker disappeared during inspection".into()),
        };
    };
    let digest = Some(bytes_digest(&bytes));
    if bytes.len() > RECOVERY_MARKER_MAX_BYTES {
        return RecoveryMarkerInspection {
            present: true,
            valid: false,
            digest,
            marker: None,
            error: Some("transaction marker is too large".into()),
        };
    }
    if bytes == RECOVERY_MARKER {
        return RecoveryMarkerInspection {
            present: true,
            valid: true,
            digest,
            marker: Some(RecoveryMarker::Legacy),
            error: None,
        };
    }
    let Some(payload) = bytes.strip_prefix(RECOVERY_MARKER) else {
        return RecoveryMarkerInspection {
            present: true,
            valid: false,
            digest,
            marker: None,
            error: Some("transaction marker has an unknown format".into()),
        };
    };
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let record = serde_json::from_slice::<RecoveryRecord>(payload).ok();
    let valid = record
        .as_ref()
        .is_some_and(|record| record.version == RECOVERY_RECORD_VERSION);
    RecoveryMarkerInspection {
        present: true,
        valid,
        digest,
        marker: record.map(|record| RecoveryMarker::Record(Box::new(record))),
        error: if valid {
            None
        } else {
            Some("transaction marker record is invalid".into())
        },
    }
}

fn recovery_file_value(file: &RecoveryFileInspection) -> Value {
    json!({
        "present": file.present,
        "regular": file.regular,
        "owner_private": file.owner_private,
        "bytes": file.bytes.as_ref().map(Vec::len),
        "sha256": file.digest,
        "generated": file.generated,
        "config_valid": file.config_valid,
        "error": file.error,
    })
}

fn recovery_marker_value(marker: &RecoveryMarkerInspection) -> Value {
    let (format, record) = match marker.marker.as_ref() {
        Some(RecoveryMarker::Legacy) => (Some("legacy"), None),
        Some(RecoveryMarker::Record(record)) => (Some("v2"), Some(record)),
        None => (None, None),
    };
    json!({
        "present": marker.present,
        "valid": marker.valid,
        "format": format,
        "sha256": marker.digest,
        "record": record.map(|record| json!({
            "version": record.version,
            "operation": record.operation,
            "canonical": record.canonical,
            "staged": record.staged,
            "backup": record.backup,
            "rollback": record.rollback,
            "generation": record.generation,
            "prior_sha256": record.prior_sha256,
            "next_sha256": record.next_sha256,
            "prior_backup_sha256": record.prior_backup_sha256,
        })),
        "error": marker.error,
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn optional_digest_matches(file: &RecoveryFileInspection, expected: Option<&str>) -> bool {
    match expected {
        Some(expected) => file.digest.as_deref() == Some(expected),
        None => !file.present,
    }
}

fn record_path_matches(
    record: &RecoveryRecord,
    canonical: &Path,
    staged: &Path,
    backup: &Path,
    rollback: &Path,
) -> bool {
    record.version == RECOVERY_RECORD_VERSION
        && !record.operation.is_empty()
        && canonical.display().to_string() == record.canonical
        && staged.display().to_string() == record.staged
        && backup.display().to_string() == record.backup
        && rollback.display().to_string() == record.rollback
        && record.generation > 0
        && valid_digest(&record.prior_sha256)
        && valid_digest(&record.next_sha256)
        && record
            .prior_backup_sha256
            .as_deref()
            .is_none_or(valid_digest)
}

fn inspect_recovery(source: impl AsRef<Path>) -> Result<Value, ConfigManagementError> {
    let canonical = canonical_config_path(source.as_ref())?;
    let backup = backup_path(&canonical);
    let rollback = rollback_path(&canonical);
    let marker_path = recovery_marker_path(&canonical);
    let marker = inspect_recovery_marker(&marker_path);
    let generation = marker.marker.as_ref().and_then(|marker| match marker {
        RecoveryMarker::Legacy => None,
        RecoveryMarker::Record(record) => Some(record.generation),
    });
    let generation_for_compile = generation.unwrap_or(1);
    let canonical_file = inspect_recovery_file(&canonical, generation_for_compile, false, false);
    let staged_path = marker
        .marker
        .as_ref()
        .and_then(|marker| match marker {
            RecoveryMarker::Record(record) => Some(PathBuf::from(&record.staged)),
            RecoveryMarker::Legacy => None,
        })
        .unwrap_or_else(|| canonical.with_file_name(".pooler-config-stage"));
    let staged_file = inspect_recovery_file(&staged_path, generation_for_compile, true, true);
    let backup_file = inspect_recovery_file(&backup, generation_for_compile, false, true);
    let rollback_file = inspect_recovery_file(&rollback, generation_for_compile, false, true);
    let mut verified = !marker.present && canonical_file.config_valid;
    let mut can_resume = false;
    let mut can_abort = false;
    let mut state = if marker.present { "blocked" } else { "clear" };
    let mut reason = marker.error.clone();
    if let Some(RecoveryMarker::Record(record)) = marker.marker.as_ref() {
        let paths_match = record_path_matches(record, &canonical, &staged_path, &backup, &rollback);
        let files_safe = canonical_file.config_valid
            && (!staged_file.present || (staged_file.owner_private && staged_file.config_valid))
            && (!backup_file.present || (backup_file.owner_private && backup_file.config_valid))
            && (!rollback_file.present
                || (rollback_file.owner_private && rollback_file.config_valid));
        let prior_canonical =
            canonical_file.digest.as_deref() == Some(record.prior_sha256.as_str());
        let next_canonical = canonical_file.digest.as_deref() == Some(record.next_sha256.as_str());
        let staged_next = staged_file.digest.as_deref() == Some(record.next_sha256.as_str());
        let backup_prior = backup_file.digest.as_deref() == Some(record.prior_sha256.as_str());
        let prior_backup =
            optional_digest_matches(&rollback_file, record.prior_backup_sha256.as_deref());
        let prepared = prior_canonical && staged_next && backup_prior && prior_backup;
        let promoted = next_canonical && !staged_file.present && backup_prior && prior_backup;
        let untouched = prior_canonical
            && !staged_file.present
            && optional_digest_matches(&backup_file, record.prior_backup_sha256.as_deref());
        verified = paths_match && files_safe && (prepared || promoted || untouched);
        can_resume = verified && (prepared || promoted);
        can_abort = verified && (prepared || promoted);
        if !paths_match {
            reason = Some("transaction marker paths, generation, or digests are invalid".into());
        } else if !files_safe {
            reason = Some("canonical transaction file failed identity or compiler checks".into());
        } else if promoted {
            state = "ready-to-complete";
        } else if prepared {
            state = "ready-to-promote";
        } else if untouched {
            state = "no-op-recovery";
        } else {
            state = "requires-operator";
            reason = Some("transaction files do not describe a known state".into());
        }
    } else if matches!(marker.marker, Some(RecoveryMarker::Legacy)) {
        state = "legacy-marker";
        reason = Some(
            "legacy transaction marker has no durable file digests or generation; refusing mutation"
                .into(),
        );
    }
    Ok(json!({
        "state": state,
        "verified": verified,
        "safe_to_resume": can_resume,
        "safe_to_abort": can_abort,
        "generation": generation,
        "active": {
            "path": canonical,
            "sha256": canonical_file.digest,
            "generation": generation,
        },
        "paths": {
            "canonical": canonical,
            "staged": staged_path,
            "backup": backup,
            "rollback": rollback,
            "recovery_marker": marker_path,
        },
        "marker": recovery_marker_value(&marker),
        "canonical_file": recovery_file_value(&canonical_file),
        "staged_file": recovery_file_value(&staged_file),
        "backup": recovery_file_value(&backup_file),
        "rollback": recovery_file_value(&rollback_file),
        "reason": reason,
    }))
}

fn require_verified_recovery(status: &Value) -> Result<(), ConfigManagementError> {
    if status.get("verified").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(ConfigManagementError::RecoveryRequired)
    }
}

pub(crate) fn recovery_status(source: impl AsRef<Path>) -> Result<Value, ConfigManagementError> {
    inspect_recovery(source)
}

pub(crate) fn verify_recovery(source: impl AsRef<Path>) -> Result<Value, ConfigManagementError> {
    let status = inspect_recovery(source)?;
    require_verified_recovery(&status)?;
    Ok(status)
}

pub(crate) fn resume_recovery(source: impl AsRef<Path>) -> Result<Value, ConfigManagementError> {
    let source = source.as_ref();
    let status = inspect_recovery(source)?;
    if status.get("safe_to_resume").and_then(Value::as_bool) != Some(true) {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let canonical = status["paths"]["canonical"]
        .as_str()
        .map(PathBuf::from)
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    let staged = status["paths"]["staged"]
        .as_str()
        .map(PathBuf::from)
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    let marker = inspect_recovery_marker(&recovery_marker_path(&canonical));
    if let Some(RecoveryMarker::Record(record)) = marker.marker {
        let canonical_file = inspect_recovery_file(&canonical, record.generation, false, false);
        if canonical_file.digest.as_deref() != Some(record.next_sha256.as_str()) {
            let staged_bytes = read_existing_file(&staged, true)?
                .ok_or(ConfigManagementError::RecoveryRequired)?;
            if bytes_digest(&staged_bytes) != record.next_sha256 {
                return Err(ConfigManagementError::RecoveryRequired);
            }
            fail_hook(FileTransactionStage::Rename)?;
            fs::rename(&staged, &canonical).map_err(|_| ConfigManagementError::RecoveryRequired)?;
            sync_directory(
                canonical
                    .parent()
                    .ok_or(ConfigManagementError::RecoveryRequired)?,
            )?;
        }
        clear_recovery_marker(&canonical)?;
    } else {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let mut resumed = inspect_recovery(source)?;
    resumed["action"] = Value::String("resumed".into());
    Ok(resumed)
}

pub(crate) fn abort_recovery(source: impl AsRef<Path>) -> Result<Value, ConfigManagementError> {
    let source = source.as_ref();
    let status = inspect_recovery(source)?;
    if status.get("safe_to_abort").and_then(Value::as_bool) != Some(true) {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let canonical = status["paths"]["canonical"]
        .as_str()
        .map(PathBuf::from)
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    let staged = status["paths"]["staged"]
        .as_str()
        .map(PathBuf::from)
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    let backup = status["paths"]["backup"]
        .as_str()
        .map(PathBuf::from)
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    let rollback = status["paths"]["rollback"]
        .as_str()
        .map(PathBuf::from)
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    let marker = inspect_recovery_marker(&recovery_marker_path(&canonical));
    let Some(RecoveryMarker::Record(record)) = marker.marker else {
        return Err(ConfigManagementError::RecoveryRequired);
    };
    let backup_bytes =
        read_existing_file(&backup, true)?.ok_or(ConfigManagementError::RecoveryRequired)?;
    if bytes_digest(&backup_bytes) != record.prior_sha256 {
        return Err(ConfigManagementError::RecoveryRequired);
    }
    let parent = canonical
        .parent()
        .ok_or(ConfigManagementError::RecoveryRequired)?;
    write_atomic(parent, &canonical, &backup_bytes, AtomicWriteKind::Rollback)?;
    if let Some(previous_backup) = record.prior_backup_sha256.as_deref() {
        let previous =
            read_existing_file(&rollback, true)?.ok_or(ConfigManagementError::RecoveryRequired)?;
        if bytes_digest(&previous) != previous_backup {
            return Err(ConfigManagementError::RecoveryRequired);
        }
        write_atomic(parent, &backup, &previous, AtomicWriteKind::Rollback)?;
    } else {
        remove_file_synced(parent, &backup)?;
    }
    remove_file_synced(parent, &staged)?;
    remove_file_synced(parent, &rollback)?;
    fail_hook(FileTransactionStage::RollbackFsync)?;
    sync_directory(parent)?;
    clear_recovery_marker(&canonical)?;
    let mut aborted = inspect_recovery(source)?;
    aborted["action"] = Value::String("aborted".into());
    Ok(aborted)
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
            "version: 2\nlisteners: {}\nupstreams: {}\nmodels: []\naccounts: {}\naccount_pools: {}\npolicies: {}\nroutes: []\nextensions: {}\nmanagement: {}\n",
        )
        .expect("source");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private configuration source");
        (directory, path)
    }

    fn candidate(manager: &ConfigManagement, generation: u64, bind: &str) -> PreparedActivation {
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
        let validated = manager
            .validate(id, patched["etag"].as_str().expect("etag"))
            .expect("validate");
        manager
            .commit(
                id,
                patched["etag"].as_str().expect("etag"),
                generation,
                validated["confirmation_token"].as_str().expect("token"),
            )
            .expect("prepare")
    }

    #[test]
    fn canonical_config_transaction_activates_exact_candidate() {
        let (_directory, path) = source();
        let canonical = path.canonicalize().expect("canonical path");
        let prior = fs::read(&canonical).expect("prior bytes");
        let manager = ConfigManagement::new(&path).expect("manager");
        let mut activation = candidate(&manager, 1, "127.0.0.1:1001");

        assert_eq!(activation.candidate.canonical_path, canonical);
        assert_eq!(activation.candidate.base_generation, 1);
        assert_eq!(activation.candidate.target_generation, 2);
        assert_eq!(
            bytes_digest(&activation.candidate.bytes),
            activation.candidate.next_digest
        );
        assert_eq!(
            fs::read(&canonical).expect("canonical remains prior"),
            prior
        );
        assert_eq!(
            fs::read(&activation.candidate.backup_path).expect("backup"),
            prior
        );
        assert!(activation.candidate.staged_path.is_file());

        manager
            .promote_file(&mut activation)
            .expect("promote candidate");
        assert_eq!(
            fs::read(&canonical).expect("promoted canonical"),
            activation.candidate.bytes
        );
        assert!(!activation.candidate.staged_path.exists());
        manager.register_commit(9, activation);
        manager.complete(9, true).expect("complete");
        assert!(!recovery_marker_path(&canonical).exists());
        assert!(!rollback_path(&canonical).exists());
        assert_eq!(
            configured_source(&path).expect("configured path"),
            canonical
        );
    }

    #[test]
    fn canonical_config_transaction_rolls_back_file_hooks() {
        let stages = [
            FileTransactionStage::MarkerCreate,
            FileTransactionStage::BackupWrite,
            FileTransactionStage::BackupFsync,
            FileTransactionStage::TempWrite,
            FileTransactionStage::TempFsync,
            FileTransactionStage::Rename,
            FileTransactionStage::DirectoryFsync,
        ];
        for stage in stages {
            let (_directory, path) = source();
            let canonical = path.canonicalize().expect("canonical path");
            let prior = fs::read(&canonical).expect("prior bytes");
            let manager = ConfigManagement::new(&path).expect("manager");
            FAILURE_HOOK.with(|hook| hook.set(Some(stage)));
            let result = {
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
                let validated = manager
                    .validate(id, patched["etag"].as_str().expect("etag"))
                    .expect("validate");
                manager.commit(
                    id,
                    patched["etag"].as_str().expect("etag"),
                    1,
                    validated["confirmation_token"].as_str().expect("token"),
                )
            };
            assert!(result.is_err(), "hook should fail: {stage:?}");
            assert_eq!(fs::read(&canonical).expect("prior restored"), prior);
            assert!(
                !recovery_marker_path(&canonical).exists(),
                "recovery marker remains after {stage:?}"
            );
            assert!(!rollback_path(&canonical).exists());
        }

        let (_directory, path) = source();
        let canonical = path.canonicalize().expect("canonical path");
        let prior = fs::read(&canonical).expect("prior bytes");
        let manager = ConfigManagement::new(&path).expect("manager");
        let activation = candidate(&manager, 1, "127.0.0.1:1001");
        FAILURE_HOOK.with(|hook| hook.set(Some(FileTransactionStage::HandoffCancellation)));
        assert!(manager.cancel_activation(activation).is_err());
        assert_eq!(
            fs::read(&canonical).expect("prior after cancellation"),
            prior
        );
        FAILURE_HOOK.with(|hook| hook.set(None));
        let mut activation = candidate(&manager, 1, "127.0.0.1:1002");
        manager.promote_file(&mut activation).expect("promote");
        manager.register_commit(11, activation);
        FAILURE_HOOK.with(|hook| hook.set(Some(FileTransactionStage::CompletionMarkerWrite)));
        assert!(manager.complete(11, true).is_err());
        FAILURE_HOOK.with(|hook| hook.set(None));
        manager.complete(11, true).expect("retry complete");

        let mut activation = candidate(&manager, 2, "127.0.0.1:1003");
        manager.promote_file(&mut activation).expect("promote");
        manager.register_commit(12, activation);
        FAILURE_HOOK.with(|hook| hook.set(Some(FileTransactionStage::RollbackFsync)));
        assert!(manager.complete(12, false).is_err());
        FAILURE_HOOK.with(|hook| hook.set(None));
        manager.complete(12, false).expect("retry rollback");
    }

    #[test]
    fn canonical_config_transaction_preserves_etag_and_generation_guards() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let created = manager.create(7).expect("draft");
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
        let validated = manager
            .validate(id, patched["etag"].as_str().expect("etag"))
            .expect("validate");
        assert!(matches!(
            manager.commit(
                id,
                patched["etag"].as_str().expect("etag"),
                8,
                validated["confirmation_token"].as_str().expect("token")
            ),
            Err(ConfigManagementError::Precondition)
        ));
    }

    #[test]
    fn recovery_status_exposes_only_canonical_transaction_paths() {
        let (_directory, path) = source();
        let manager = ConfigManagement::new(&path).expect("manager");
        let activation = candidate(&manager, 1, "127.0.0.1:1001");
        let status = recovery_status(&path).expect("status");
        assert_eq!(status["state"], "ready-to-promote");
        assert_eq!(
            status["paths"]["canonical"],
            path.canonicalize()
                .expect("canonical")
                .to_string_lossy()
                .as_ref()
        );
        assert!(status["paths"].get("staged").is_some());
        assert!(status["paths"].get("backup").is_some());
        assert!(status["paths"].get("rollback").is_some());
        manager.cancel_activation(activation).expect("cancel");
        assert_eq!(recovery_status(&path).expect("clear")["state"], "clear");
    }

    #[cfg(unix)]
    #[test]
    fn canonical_config_rejects_symlink_and_shared_writable_paths() {
        use std::os::unix::fs::symlink;

        let (_directory, path) = source();
        let linked = path.with_file_name("linked.yaml");
        symlink(&path, &linked).expect("symlink");
        assert!(matches!(
            ConfigManagement::new(&linked),
            Err(ConfigManagementError::Persistence)
        ));
        let (writable_directory, writable_source) = source();
        fs::set_permissions(writable_directory.path(), fs::Permissions::from_mode(0o777))
            .expect("writable directory");
        assert!(matches!(
            ConfigManagement::new(&writable_source),
            Err(ConfigManagementError::Persistence)
        ));
    }
}
