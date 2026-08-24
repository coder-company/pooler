//! Durable management control-plane state.
//!
//! The management HTTP layer owns request policy and presentation.  This
//! module owns the small persistence seam that keeps browser sessions,
//! drafts, operation records, and OAuth correlation metadata out of that
//! layer.  A configured SQLite store is the production path; the bounded
//! in-memory implementation keeps existing embedders and unit fixtures
//! usable when they do not provide a control-plane store.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use pooler_store::{
    AuditRecord, DraftRecord, ManagedSecretRecord, ManagementSessionRecord, OAuthFlowRecord,
    OAuthFlowStatus, ReloadRecord, SecretPayload, SqliteStore, StoreError, StoreResult,
};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

const MAX_EPHEMERAL_SESSIONS: usize = 1_024;
const MAX_EPHEMERAL_DRAFTS: usize = 1_024;
const MAX_EPHEMERAL_AUDIT: usize = 16_384;
const MAX_EPHEMERAL_RELOADS: usize = 4_096;
const MAX_EPHEMERAL_OAUTH: usize = 1_024;

/// Stable administrative identity used by direct bearer callers.
pub(crate) const BEARER_ADMIN_ACTOR: &str = "bearer-admin";

/// One authenticated management principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagementActor {
    pub(crate) actor_id: String,
    pub(crate) session_id: Option<String>,
}

#[derive(Default)]
struct EphemeralState {
    sessions: BTreeMap<String, (ManagementSessionRecord, [u8; 32])>,
    drafts: BTreeMap<u64, DraftRecord>,
    audit: VecDeque<AuditRecord>,
    reloads: VecDeque<ReloadRecord>,
    oauth: BTreeMap<String, EphemeralOAuth>,
}

struct EphemeralOAuth {
    record: OAuthFlowRecord,
    state_hash: [u8; 32],
    pkce: Option<SecretPayload>,
}

/// Bounded management persistence backed by the encrypted Task-2 store.
pub(crate) struct ManagementState {
    sqlite: Option<Arc<SqliteStore>>,
    ephemeral: Mutex<EphemeralState>,
    random: SystemRandom,
}

impl std::fmt::Debug for ManagementState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementState")
            .field("durable", &self.sqlite.is_some())
            .finish_non_exhaustive()
    }
}

impl ManagementState {
    /// Construct bounded state using an optional encrypted SQLite store.
    pub(crate) fn new(sqlite: Option<Arc<SqliteStore>>) -> Self {
        Self {
            sqlite,
            ephemeral: Mutex::new(EphemeralState::default()),
            random: SystemRandom::new(),
        }
    }

    /// Return a process-local state for legacy embedders and fixtures.
    pub(crate) fn ephemeral() -> Self {
        Self::new(None)
    }

    /// Generate an opaque cookie/session identifier. Raw bytes are returned
    /// only to the caller that immediately emits the cookie and persists its
    /// keyed digest.
    pub(crate) fn random_secret(&self) -> Result<Vec<u8>, StoreError> {
        let mut bytes = [0_u8; 32];
        self.random
            .fill(&mut bytes)
            .map_err(|_| StoreError::EncryptionFailed)?;
        Ok(hex(&bytes).into_bytes())
    }

    pub(crate) fn random_id(&self, prefix: &str) -> Result<String, StoreError> {
        let secret = self.random_secret()?;
        Ok(format!("{prefix}-{}", String::from_utf8_lossy(&secret)))
    }

    /// Ingest one transient secret directly into encrypted managed storage.
    ///
    /// The caller owns the plaintext only until this method returns. An
    /// ephemeral, unencrypted management state intentionally rejects the
    /// operation so the dashboard can never silently downgrade protection.
    pub(crate) fn put_managed_secret(
        &self,
        owner_id: &str,
        kind: &str,
        payload: &SecretPayload,
    ) -> StoreResult<ManagedSecretRecord> {
        let Some(sqlite) = &self.sqlite else {
            return Err(StoreError::ManagedSecretEncryptionRequired);
        };
        let now = management_timestamp_ms();
        let secret_id = self.random_id("managed")?;
        sqlite.put_managed_secret(
            ManagedSecretRecord::new(secret_id, owner_id, kind, now, None),
            payload,
            None,
        )
    }

    pub(crate) fn create_session(
        &self,
        record: ManagementSessionRecord,
        cookie_secret: &[u8],
    ) -> StoreResult<ManagementSessionRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.create_management_session(record, cookie_secret);
        }
        let hash = digest(&SHA256, cookie_secret);
        let mut cookie_hash = [0_u8; 32];
        cookie_hash.copy_from_slice(hash.as_ref());
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        state
            .sessions
            .retain(|_, (session, _)| session.active_at(record.created_at));
        if state.sessions.len() >= MAX_EPHEMERAL_SESSIONS {
            return Err(StoreError::ManagementCapacity);
        }
        if state.sessions.values().any(|(session, existing)| {
            session.session_id == record.session_id || existing == &cookie_hash
        }) {
            return Err(StoreError::ManagementSessionAlreadyExists);
        }
        let mut created = record;
        created.revision = 1;
        state
            .sessions
            .insert(created.session_id.clone(), (created.clone(), cookie_hash));
        Ok(created)
    }

    pub(crate) fn session_by_cookie(
        &self,
        cookie_secret: &[u8],
        now: u64,
    ) -> StoreResult<Option<ManagementSessionRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.management_session_by_cookie(cookie_secret, now);
        }
        let hash = digest(&SHA256, cookie_secret);
        let state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        Ok(state
            .sessions
            .values()
            .find(|(session, existing)| {
                session.active_at(now) && existing.as_slice() == hash.as_ref()
            })
            .map(|(session, _)| session.clone()))
    }

    pub(crate) fn revoke_session(
        &self,
        session_id: &str,
        expected_revision: u64,
        revoked_at: u64,
    ) -> StoreResult<ManagementSessionRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.revoke_management_session(session_id, expected_revision, revoked_at);
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let Some((session, _)) = state.sessions.get_mut(session_id) else {
            return Err(StoreError::OwnerMismatch);
        };
        if session.revision != expected_revision {
            return Err(StoreError::ManagementRevisionConflict);
        }
        session.revision = session.revision.saturating_add(1);
        session.revoked_at = Some(revoked_at);
        Ok(session.clone())
    }

    pub(crate) fn create_draft(&self, draft: DraftRecord) -> StoreResult<DraftRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.create_draft(draft);
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        if state.drafts.len() >= MAX_EPHEMERAL_DRAFTS {
            return Err(StoreError::ManagementCapacity);
        }
        let id = state
            .drafts
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        let mut draft = draft;
        draft.draft_id = id;
        draft.revision = 1;
        draft.etag = format!("ephemeral-{id}-{}", draft.payload.len());
        state.drafts.insert(id, draft.clone());
        Ok(draft)
    }

    pub(crate) fn update_draft(
        &self,
        draft_id: u64,
        owner_id: &str,
        expected_revision: u64,
        expected_etag: &str,
        payload: Vec<u8>,
        updated_at: u64,
    ) -> StoreResult<DraftRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.update_draft(
                draft_id,
                owner_id,
                expected_revision,
                expected_etag,
                payload,
                updated_at,
            );
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let Some(current) = state.drafts.get(&draft_id).cloned() else {
            return Err(StoreError::RecordExpired);
        };
        if current.owner_id != owner_id {
            return Err(StoreError::OwnerMismatch);
        }
        if current.revision != expected_revision || current.etag != expected_etag {
            return Err(StoreError::ManagementRevisionConflict);
        }
        if !current.active_at(updated_at) {
            return Err(StoreError::RecordExpired);
        }
        let next = DraftRecord {
            etag: format!("ephemeral-{draft_id}-{}", payload.len()),
            revision: current.revision.saturating_add(1),
            payload,
            updated_at,
            ..current
        };
        state.drafts.insert(draft_id, next.clone());
        Ok(next)
    }

    pub(crate) fn draft(
        &self,
        draft_id: u64,
        owner_id: &str,
        now: u64,
    ) -> StoreResult<Option<DraftRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.draft(draft_id, owner_id, now);
        }
        let state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        match state.drafts.get(&draft_id) {
            Some(draft) if draft.owner_id != owner_id => Err(StoreError::OwnerMismatch),
            Some(draft) if !draft.active_at(now) => Err(StoreError::RecordExpired),
            value => Ok(value.cloned()),
        }
    }

    pub(crate) fn remove_draft(&self, draft_id: u64, owner_id: &str) -> StoreResult<bool> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.remove_draft(draft_id, owner_id);
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        if let Some(draft) = state.drafts.get(&draft_id) {
            if draft.owner_id != owner_id {
                return Err(StoreError::OwnerMismatch);
            }
        }
        Ok(state.drafts.remove(&draft_id).is_some())
    }

    pub(crate) fn append_audit(&self, record: AuditRecord) -> StoreResult<AuditRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.append_audit_record(record);
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut record = record;
        record.id = state
            .audit
            .back()
            .map_or(0, |existing| existing.id)
            .saturating_add(1);
        state.audit.push_back(record.clone());
        while state.audit.len() > MAX_EPHEMERAL_AUDIT {
            state.audit.pop_front();
        }
        Ok(record)
    }

    pub(crate) fn audit(&self) -> StoreResult<Vec<AuditRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.audit_records();
        }
        Ok(self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .audit
            .iter()
            .cloned()
            .collect())
    }

    pub(crate) fn append_reload(&self, record: ReloadRecord) -> StoreResult<ReloadRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.append_reload_record(record);
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut record = record;
        record.id = state
            .reloads
            .back()
            .map_or(0, |existing| existing.id)
            .saturating_add(1);
        record.revision = 1;
        state.reloads.push_back(record.clone());
        while state.reloads.len() > MAX_EPHEMERAL_RELOADS {
            state.reloads.pop_front();
        }
        Ok(record)
    }

    pub(crate) fn update_reload(
        &self,
        record_id: u64,
        expected_revision: u64,
        status: &str,
        error_code: Option<&str>,
        completed_at: Option<u64>,
        completed_generation: Option<u64>,
    ) -> StoreResult<ReloadRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.update_reload_record(
                record_id,
                expected_revision,
                status,
                error_code,
                completed_at,
                completed_generation,
            );
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let Some(current) = state
            .reloads
            .iter_mut()
            .find(|record| record.id == record_id)
        else {
            return Err(StoreError::ManagementRevisionConflict);
        };
        if current.revision != expected_revision {
            return Err(StoreError::ManagementRevisionConflict);
        }
        current.revision = current.revision.saturating_add(1);
        current.status = status.to_owned();
        current.error_code = error_code.map(ToOwned::to_owned);
        current.completed_at = completed_at;
        current.completed_generation = completed_generation;
        Ok(current.clone())
    }

    pub(crate) fn reloads(&self) -> StoreResult<Vec<ReloadRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.reload_records();
        }
        Ok(self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .reloads
            .iter()
            .cloned()
            .collect())
    }

    pub(crate) fn begin_oauth(
        &self,
        record: OAuthFlowRecord,
        state_value: &[u8],
        pkce: Option<&SecretPayload>,
    ) -> StoreResult<OAuthFlowRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.begin_oauth_flow(record, state_value, pkce);
        }
        let state_hash = digest(&SHA256, state_value);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(state_hash.as_ref());
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        if state.oauth.len() >= MAX_EPHEMERAL_OAUTH
            || state.oauth.values().any(|flow| {
                flow.record.status == OAuthFlowStatus::Pending
                    && flow.record.provider_id == record.provider_id
                    && flow.record.account_id == record.account_id
            })
            || state.oauth.values().any(|flow| flow.state_hash == hash)
        {
            return Err(StoreError::OAuthFlowAlreadyExists);
        }
        let mut record = record;
        record.revision = 1;
        state.oauth.insert(
            record.flow_id.clone(),
            EphemeralOAuth {
                record: record.clone(),
                state_hash: hash,
                pkce: pkce.cloned(),
            },
        );
        Ok(record)
    }

    pub(crate) fn consume_oauth(
        &self,
        state_value: &[u8],
        now: u64,
    ) -> StoreResult<Option<OAuthFlowRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.consume_oauth_state(state_value, now);
        }
        let hash = digest(&SHA256, state_value);
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let Some(flow) = state.oauth.values_mut().find(|flow| {
            flow.state_hash.as_slice() == hash.as_ref()
                && flow.record.state_consumed_at.is_none()
                && flow.record.active_at(now)
        }) else {
            return Ok(None);
        };
        flow.record.state_consumed_at = Some(now);
        flow.record.revision = flow.record.revision.saturating_add(1);
        Ok(Some(flow.record.clone()))
    }

    pub(crate) fn oauth_by_state(
        &self,
        state_value: &[u8],
        now: u64,
    ) -> StoreResult<Option<OAuthFlowRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.oauth_flow_by_state(state_value, now);
        }
        let hash = digest(&SHA256, state_value);
        Ok(self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .oauth
            .values()
            .find(|flow| {
                flow.state_hash.as_slice() == hash.as_ref()
                    && flow.record.state_consumed_at.is_none()
                    && flow.record.active_at(now)
            })
            .map(|flow| flow.record.clone()))
    }

    #[allow(dead_code)]
    pub(crate) fn oauth_pkce(&self, flow_id: &str) -> StoreResult<Option<SecretPayload>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.oauth_flow_pkce_verifier(flow_id);
        }
        Ok(self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .oauth
            .get(flow_id)
            .and_then(|flow| flow.pkce.clone()))
    }

    pub(crate) fn update_oauth(
        &self,
        flow_id: &str,
        owner_id: &str,
        expected_revision: u64,
        status: OAuthFlowStatus,
        error_code: Option<&str>,
        completed_at: Option<u64>,
    ) -> StoreResult<OAuthFlowRecord> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.update_oauth_flow(
                flow_id,
                owner_id,
                expected_revision,
                status,
                error_code,
                completed_at,
            );
        }
        let mut state = self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let Some(flow) = state.oauth.get_mut(flow_id) else {
            return Err(StoreError::OAuthFlowNotFound);
        };
        if flow.record.owner_id != owner_id {
            return Err(StoreError::OwnerMismatch);
        }
        if flow.record.revision != expected_revision {
            return Err(StoreError::ManagementRevisionConflict);
        }
        flow.record.revision = flow.record.revision.saturating_add(1);
        flow.record.status = status;
        flow.record.error_code = error_code.map(ToOwned::to_owned);
        flow.record.completed_at = completed_at;
        Ok(flow.record.clone())
    }

    pub(crate) fn oauth(&self, flow_id: &str) -> StoreResult<Option<OAuthFlowRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.oauth_flow(flow_id);
        }
        Ok(self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .oauth
            .get(flow_id)
            .map(|flow| flow.record.clone()))
    }

    pub(crate) fn oauth_for_owner(&self, owner_id: &str) -> StoreResult<Vec<OAuthFlowRecord>> {
        if let Some(sqlite) = &self.sqlite {
            return sqlite.oauth_flows_for_owner(owner_id);
        }
        Ok(self
            .ephemeral
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .oauth
            .values()
            .filter(|flow| flow.record.owner_id == owner_id)
            .map(|flow| flow.record.clone())
            .collect())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn management_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_sessions_store_only_a_digest_and_revoke() {
        let state = ManagementState::ephemeral();
        let cookie = b"opaque-cookie-value";
        let record = state
            .create_session(
                ManagementSessionRecord::new("session-1", "actor-1", 10, 100),
                cookie,
            )
            .expect("session");
        assert_eq!(
            state.session_by_cookie(cookie, 20).expect("lookup"),
            Some(record.clone())
        );
        assert!(state
            .session_by_cookie(b"wrong-cookie", 20)
            .expect("lookup")
            .is_none());
        state
            .revoke_session(&record.session_id, record.revision, 21)
            .expect("revoke");
        assert!(state
            .session_by_cookie(cookie, 22)
            .expect("lookup")
            .is_none());
    }

    #[test]
    fn ephemeral_oauth_state_is_one_time_and_owner_fenced() {
        let state = ManagementState::ephemeral();
        let flow = state
            .begin_oauth(
                OAuthFlowRecord::new(
                    "flow-1", "owner-1", "provider", "account", "browser", 1, 100,
                ),
                b"state-value",
                None,
            )
            .expect("flow");
        let consumed = state
            .consume_oauth(b"state-value", 2)
            .expect("consume")
            .expect("matching flow");
        assert_eq!(consumed.owner_id, "owner-1");
        assert!(state
            .consume_oauth(b"state-value", 3)
            .expect("replay")
            .is_none());
        assert!(matches!(
            state.update_oauth(
                &flow.flow_id,
                "other-owner",
                consumed.revision,
                OAuthFlowStatus::Failed,
                Some("denied"),
                Some(4),
            ),
            Err(StoreError::OwnerMismatch)
        ));
    }
}
