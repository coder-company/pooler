//! SQLite-backed implementation of the mutable Pooler state store.
//!
//! The connection is deliberately kept behind one mutex.  Pooler state
//! updates are small, and serializing them here makes each operation's
//! transaction boundary explicit while still allowing callers to share the
//! store safely across worker threads.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::{
    encrypted::{CredentialCipher, CredentialPayload},
    non_empty, CooldownState, CredentialHealthState, CredentialHealthStatus, CredentialState,
    DecisionRecord, MasterKey, MemoryStore, PruneReport, RequestEvent, RetentionPolicy,
    SecretPayload, SessionAffinity, Store, StoreError, StoreLengths, StoreResult, Timestamp,
    UsageRecord, MAX_REQUEST_EVENTS_PER_REQUEST,
};

const MAX_COOLDOWNS: usize = 4_096;
const LATEST_SCHEMA_VERSION: i64 = 7;
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("migrations/001_initial.sql")),
    (2, include_str!("migrations/002_health_and_cooldowns.sql")),
    (3, include_str!("migrations/003_credential_payloads.sql")),
    (4, include_str!("migrations/004_request_events.sql")),
    (5, include_str!("migrations/005_usage_ledger.sql")),
    (6, include_str!("migrations/006_request_event_indexes.sql")),
    (7, include_str!("migrations/007_encryption_fence.sql")),
];

/// A transactional, WAL-backed SQLite [`Store`].
#[derive(Clone)]
pub struct SqliteStore {
    retention: RetentionPolicy,
    connection: Arc<Mutex<Connection>>,
    path: Option<PathBuf>,
    encryption: Arc<RwLock<Option<Arc<CredentialCipher>>>>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteStore")
            .field("retention", &self.retention)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Open or create a private on-disk database using the default retention.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        Self::open_with_retention(path, RetentionPolicy::default())
    }

    /// Open or create a private on-disk database with explicit retention.
    pub fn open_with_retention(
        path: impl AsRef<Path>,
        retention: RetentionPolicy,
    ) -> StoreResult<Self> {
        let path = prepare_database_path(path.as_ref())?;
        ensure_private_sidecars(&path)?;
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        initialize_connection(connection, false, retention, Some(path), None)
    }

    /// Open or create a private database whose credential payloads are
    /// encrypted with `master_key`.
    pub fn open_encrypted(path: impl AsRef<Path>, master_key: MasterKey) -> StoreResult<Self> {
        Self::open_encrypted_with_retention(path, RetentionPolicy::default(), master_key)
    }

    /// Open or create an encrypted database with explicit retention limits.
    pub fn open_encrypted_with_retention(
        path: impl AsRef<Path>,
        retention: RetentionPolicy,
        master_key: MasterKey,
    ) -> StoreResult<Self> {
        let path = prepare_database_path(path.as_ref())?;
        ensure_private_sidecars(&path)?;
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        initialize_connection(connection, false, retention, Some(path), Some(master_key))
    }

    /// Open an in-memory database.  This is intended for tests and ephemeral
    /// deployments; file privacy checks do not apply to it.
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::open_in_memory_with_retention(RetentionPolicy::default())
    }

    /// Open an in-memory database with explicit retention.
    pub fn open_in_memory_with_retention(retention: RetentionPolicy) -> StoreResult<Self> {
        let connection = Connection::open_in_memory().map_err(sqlite_error)?;
        initialize_connection(connection, true, retention, None, None)
    }

    /// Open an encrypted in-memory database for ephemeral use and tests.
    pub fn open_in_memory_encrypted(master_key: MasterKey) -> StoreResult<Self> {
        Self::open_in_memory_encrypted_with_retention(RetentionPolicy::default(), master_key)
    }

    /// Open an encrypted in-memory database with explicit retention limits.
    pub fn open_in_memory_encrypted_with_retention(
        retention: RetentionPolicy,
        master_key: MasterKey,
    ) -> StoreResult<Self> {
        let connection = Connection::open_in_memory().map_err(sqlite_error)?;
        initialize_connection(connection, true, retention, None, Some(master_key))
    }

    /// Return the on-disk path, if this store is file-backed.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Return collection lengths.  Health and cooldown rows are auxiliary to
    /// the three retained collections and are intentionally not included in
    /// this compatibility count.
    pub fn len(&self) -> StoreResult<StoreLengths> {
        let connection = self.connection()?;
        let credentials = count_rows(&connection, "credentials")?;
        let affinities = count_rows(&connection, "affinities")?;
        let decisions = count_rows(&connection, "decisions")?;
        let request_events = count_rows(&connection, "request_events")?;
        let usage_records = count_rows(&connection, "usage_records")?;
        Ok(StoreLengths {
            credentials,
            affinities,
            decisions,
            request_events,
            usage_records,
        })
    }

    /// Return whether all retained collections are empty.
    pub fn is_empty(&self) -> StoreResult<bool> {
        Ok(self.len()?.is_empty())
    }

    /// Return the configured SQLite journal mode.
    pub fn journal_mode(&self) -> StoreResult<String> {
        let connection = self.connection()?;
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(sqlite_error)
    }

    /// Verify the SQLite database without changing its contents.
    ///
    /// SQLite's built-in integrity check is intentionally exposed as a small
    /// diagnostic operation. It does not open a transaction or checkpoint the
    /// WAL, so callers can run it while another process owns the database.
    pub fn integrity_check(&self) -> StoreResult<()> {
        let connection = self.connection()?;
        let result: String = connection
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .map_err(sqlite_error)?;
        if result.eq_ignore_ascii_case("ok") {
            Ok(())
        } else {
            Err(StoreError::Sqlite(format!(
                "SQLite integrity check reported `{result}`"
            )))
        }
    }

    /// Return the number of encrypted credential payload rows.
    ///
    /// This metadata-only query lets diagnostics distinguish an unencrypted
    /// empty store from a store whose payloads require a missing key.
    pub fn credential_payload_count(&self) -> StoreResult<usize> {
        let connection = self.connection()?;
        count_rows(&connection, "credential_payloads")
    }

    /// Persist one encrypted credential payload.
    ///
    /// The credential metadata row must already exist.  This ordering keeps a
    /// payload from becoming an unowned secret blob and lets the metadata
    /// retention path remove its payload through the foreign key.
    pub fn upsert_credential_payload(
        &self,
        credential_id: &str,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<()> {
        non_empty("credential_id", credential_id)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let envelope = cipher.seal_for(payload, credential_id.as_bytes())?;
        self.with_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let exists = transaction
                .query_row(
                    "SELECT 1 FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            if exists.is_none() {
                return Err(StoreError::CredentialNotFound(credential_id.to_owned()));
            }
            transaction
                .execute(
                    "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       envelope = excluded.envelope,
                       updated_at = excluded.updated_at",
                    params![credential_id, envelope, updated_at],
                )
                .map_err(sqlite_error)?;
            Ok(())
        })
    }

    /// Atomically replace an encrypted credential payload and advance its
    /// metadata revision when the caller still owns `expected_revision`.
    ///
    /// The compare-and-swap and payload write share one transaction. This is
    /// important for OAuth rotation: a process crash cannot leave a new
    /// revision pointing at an old payload, and concurrent refreshers cannot
    /// overwrite one another after the initial revision check.
    pub fn compare_and_swap_credential_payload(
        &self,
        credential_id: &str,
        expected_revision: u64,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        non_empty("credential_id", credential_id)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let current: CredentialState = transaction
                .query_row(
                    "SELECT credential_id, provider_id, enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
            if current.revision != expected_revision {
                return Err(StoreError::CredentialRevisionConflict);
            }
            if let Some(existing_envelope) = transaction
                .query_row(
                    "SELECT envelope FROM credential_payloads WHERE credential_id = ?1",
                    [credential_id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(sqlite_error)?
            {
                // Authenticate the old value before changing either the
                // metadata revision or the encrypted payload. A wrong key
                // must fail closed rather than overwrite an unreadable token.
                cipher.open_for(&existing_envelope, credential_id.as_bytes())?;
            }
            let envelope = cipher.seal_for(payload, credential_id.as_bytes())?;
            let revision = current.revision.saturating_add(1);
            let changed = transaction
                .execute(
                    "UPDATE credentials SET updated_at = ?1, revision = ?2
                     WHERE credential_id = ?3 AND revision = ?4",
                    params![
                        updated_at,
                        i64::try_from(revision).unwrap_or(i64::MAX),
                        credential_id,
                        i64::try_from(expected_revision).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            transaction
                .execute(
                    "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       envelope = excluded.envelope,
                       updated_at = excluded.updated_at",
                    params![credential_id, envelope, updated_at],
                )
                .map_err(sqlite_error)?;
            Ok(CredentialState {
                updated_at,
                revision,
                ..current
            })
        })
    }

    /// Alias for [`Self::upsert_credential_payload`].
    pub fn put_credential_payload(
        &self,
        credential_id: &str,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<()> {
        self.upsert_credential_payload(credential_id, payload, updated_at)
    }

    /// Load and authenticate one encrypted credential payload.
    pub fn credential_payload(
        &self,
        credential_id: &str,
    ) -> StoreResult<Option<CredentialPayload>> {
        non_empty("credential_id", credential_id)?;
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, cipher)?;
        let envelope = connection
            .query_row(
                "SELECT envelope FROM credential_payloads WHERE credential_id = ?1",
                [credential_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        envelope
            .map(|value| cipher.open_for(&value, credential_id.as_bytes()))
            .transpose()
    }

    /// Load credential metadata and its encrypted payload under one SQLite
    /// connection lock. This prevents an OAuth reader from pairing a newer
    /// revision with an older payload while a refresh transaction commits.
    pub fn credential_payload_with_state(
        &self,
        credential_id: &str,
    ) -> StoreResult<Option<(CredentialState, Option<CredentialPayload>)>> {
        non_empty("credential_id", credential_id)?;
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, cipher)?;
        let row = connection
            .query_row(
                "SELECT c.credential_id, c.provider_id, c.enabled, c.updated_at,
                        c.revision, p.envelope
                 FROM credentials AS c
                 LEFT JOIN credential_payloads AS p
                   ON p.credential_id = c.credential_id
                 WHERE c.credential_id = ?1",
                [credential_id],
                |row| {
                    let state = CredentialState {
                        credential_id: row.get(0)?,
                        provider_id: row.get(1)?,
                        enabled: row.get::<_, i64>(2)? != 0,
                        updated_at: row.get(3)?,
                        revision: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(u64::MAX),
                    };
                    let envelope = row.get::<_, Option<Vec<u8>>>(5)?;
                    Ok((state, envelope))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(state, envelope)| {
            envelope
                .map(|value| cipher.open_for(&value, credential_id.as_bytes()))
                .transpose()
                .map(|payload| (state, payload))
        })
        .transpose()
    }

    /// Alias for [`Self::credential_payload`].
    pub fn load_credential_payload(
        &self,
        credential_id: &str,
    ) -> StoreResult<Option<CredentialPayload>> {
        self.credential_payload(credential_id)
    }

    /// Remove one encrypted credential payload and advance its revision.
    ///
    /// Advancing the generation turns revocation into a tombstone for any
    /// in-flight refresh that still holds the removed payload's snapshot.
    pub fn remove_credential_payload(&self, credential_id: &str) -> StoreResult<bool> {
        non_empty("credential_id", credential_id)?;
        if self.encryption_read()?.is_none() {
            return Err(StoreError::EncryptionRequired);
        }
        self.with_transaction(|transaction| {
            let current_revision: Option<i64> = transaction
                .query_row(
                    "SELECT revision FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            let Some(current_revision) = current_revision else {
                return Ok(false);
            };
            let next_revision = current_revision
                .checked_add(1)
                .ok_or(StoreError::CredentialRevisionConflict)?;
            let removed = transaction
                .execute(
                    "DELETE FROM credential_payloads WHERE credential_id = ?1",
                    [credential_id],
                )
                .map_err(sqlite_error)?;
            let advanced = transaction
                .execute(
                    "UPDATE credentials SET revision = ?1
                     WHERE credential_id = ?2 AND revision = ?3",
                    params![next_revision, credential_id, current_revision],
                )
                .map_err(sqlite_error)?;
            if advanced != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            Ok(removed != 0)
        })
    }

    /// Re-encrypt every encrypted record in one transaction with a new master
    /// key.
    ///
    /// Any authentication or encryption failure aborts the transaction and
    /// leaves both the database and the active key unchanged.
    pub fn rotate_master_key(&self, master_key: MasterKey) -> StoreResult<usize> {
        let mut encryption = self.encryption_write()?;
        let current = encryption
            .as_ref()
            .cloned()
            .ok_or(StoreError::EncryptionRequired)?;
        let next = Arc::new(CredentialCipher::new(master_key));
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        assert_cipher_current_transaction(&transaction, &current)?;
        let credential_rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT credential_id, envelope
                     FROM credential_payloads ORDER BY credential_id ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        let mut rotated = 0_usize;
        for (credential_id, envelope) in credential_rows {
            let payload = current.open_for(&envelope, credential_id.as_bytes())?;
            let replacement = next.seal_for(&payload, credential_id.as_bytes())?;
            transaction
                .execute(
                    "UPDATE credential_payloads SET envelope = ?1 WHERE credential_id = ?2",
                    params![replacement, credential_id],
                )
                .map_err(sqlite_error)?;
            rotated += 1;
        }

        // Request IDs remain encrypted inside the event envelope. Rebuild the
        // keyed index from the authenticated plaintext as well as rotating
        // the envelope; otherwise request_events_for would look under the new
        // key and find no rows after a successful rotation.
        let request_rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT id, envelope
                     FROM request_events ORDER BY id ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        for (id, envelope) in request_rows {
            let event = decrypt_request_event(&current, id, &envelope)?;
            let request_index = next.request_index(&event.request_id);
            let replacement = encrypt_request_event(&next, &event)?;
            transaction
                .execute(
                    "UPDATE request_events
                     SET envelope = ?1, request_index = ?2, event_index = ?3
                     WHERE id = ?4",
                    params![replacement, request_index.as_slice(), event.event_index, id],
                )
                .map_err(sqlite_error)?;
            rotated += 1;
        }

        let usage_rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT id, envelope
                     FROM usage_records ORDER BY id ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        for (id, envelope) in usage_rows {
            let record = decrypt_usage_record(&current, id, &envelope)?;
            let replacement = encrypt_usage_record(&next, &record)?;
            transaction
                .execute(
                    "UPDATE usage_records SET envelope = ?1 WHERE id = ?2",
                    params![replacement, id],
                )
                .map_err(sqlite_error)?;
            rotated += 1;
        }
        let current_key_id = current.key_id();
        let next_key_id = next.key_id();
        let fenced = transaction
            .execute(
                "UPDATE encryption_fence SET key_id = ?1
                 WHERE id = 1 AND key_id = ?2",
                params![next_key_id.as_slice(), current_key_id.as_slice()],
            )
            .map_err(sqlite_error)?;
        if fenced != 1 {
            return Err(StoreError::WrongMasterKey);
        }
        transaction.commit().map_err(sqlite_error)?;
        *encryption = Some(Arc::clone(&next));
        self.ensure_private_sidecars()?;
        Ok(rotated)
    }

    /// Alias for [`Self::rotate_master_key`].
    pub fn rotate_credential_payloads(&self, master_key: MasterKey) -> StoreResult<usize> {
        self.rotate_master_key(master_key)
    }

    /// Atomically enable one credential and disable its configured siblings.
    pub fn switch_credential(
        &self,
        selected: &str,
        siblings: &[String],
        updated_at: Timestamp,
    ) -> StoreResult<Vec<CredentialState>> {
        non_empty("selected", selected)?;
        for sibling in siblings {
            non_empty("sibling", sibling)?;
        }
        self.with_immediate_transaction(|transaction| {
            let mut states = Vec::with_capacity(siblings.len().saturating_add(1));
            states.push(set_credential_enabled_tx(
                transaction,
                selected,
                true,
                updated_at,
            )?);
            for sibling in siblings
                .iter()
                .filter(|sibling| sibling.as_str() != selected)
            {
                states.push(set_credential_enabled_tx(
                    transaction,
                    sibling,
                    false,
                    updated_at,
                )?);
            }
            Ok(states)
        })
    }

    fn connection(&self) -> StoreResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StoreError::LockPoisoned)
    }

    fn encryption_read(&self) -> StoreResult<RwLockReadGuard<'_, Option<Arc<CredentialCipher>>>> {
        self.encryption.read().map_err(|_| StoreError::LockPoisoned)
    }

    fn encryption_write(&self) -> StoreResult<RwLockWriteGuard<'_, Option<Arc<CredentialCipher>>>> {
        self.encryption
            .write()
            .map_err(|_| StoreError::LockPoisoned)
    }

    fn ensure_private_sidecars(&self) -> StoreResult<()> {
        if let Some(path) = &self.path {
            ensure_private_sidecars(path)?;
        }
        Ok(())
    }

    fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let cipher = self.encryption_read()?.clone();
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        assert_mutation_authorized_transaction(&transaction, cipher.as_deref())?;
        let value = operation(&transaction)?;
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_private_sidecars()?;
        Ok(value)
    }

    fn with_immediate_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let cipher = self.encryption_read()?.clone();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        assert_mutation_authorized_transaction(&transaction, cipher.as_deref())?;
        let value = operation(&transaction)?;
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_private_sidecars()?;
        Ok(value)
    }
}

fn initialize_connection(
    mut connection: Connection,
    in_memory: bool,
    retention: RetentionPolicy,
    path: Option<PathBuf>,
    master_key: Option<MasterKey>,
) -> StoreResult<SqliteStore> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(sqlite_error)?;
    if !in_memory {
        let mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(sqlite_error)?;
        if !mode.eq_ignore_ascii_case("wal") {
            let mode: String = connection
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
                .map_err(sqlite_error)?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::Sqlite(format!(
                    "SQLite did not enable WAL mode (reported `{mode}`)"
                )));
            }
        }
        connection
            .pragma_update(None, "synchronous", "NORMAL")
            .map_err(sqlite_error)?;
    }
    migrate(&mut connection)?;
    if let Some(path) = &path {
        ensure_private_sidecars(path)?;
    }
    let encryption = master_key.map(|key| Arc::new(CredentialCipher::new(key)));
    if let Some(cipher) = encryption.as_ref() {
        initialize_encryption_fence(&mut connection, cipher)?;
    }
    Ok(SqliteStore {
        retention,
        connection: Arc::new(Mutex::new(connection)),
        path,
        encryption: Arc::new(RwLock::new(encryption)),
    })
}

fn migrate(connection: &mut Connection) -> StoreResult<()> {
    let current: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sqlite_error)?;
    if current > LATEST_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchemaVersion(current));
    }
    for &(version, sql) in MIGRATIONS.iter().filter(|(version, _)| *version > current) {
        let transaction = connection.transaction().map_err(sqlite_error)?;
        if let Err(error) = apply_migration(&transaction, version, sql) {
            return Err(StoreError::Migration {
                version,
                message: error.to_string(),
            });
        }
        transaction.commit().map_err(sqlite_error)?;
    }
    Ok(())
}

fn apply_migration(
    transaction: &Transaction<'_>,
    version: i64,
    sql: &str,
) -> Result<(), rusqlite::Error> {
    transaction.execute_batch(sql)?;
    transaction.pragma_update(None, "user_version", version)
}

fn initialize_encryption_fence(
    connection: &mut Connection,
    cipher: &CredentialCipher,
) -> StoreResult<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO encryption_fence (id, key_id)
             VALUES (1, NULL)",
            [],
        )
        .map_err(sqlite_error)?;
    let stored: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT key_id FROM encryption_fence WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let expected = cipher.key_id();
    if stored.is_none() {
        // A v6 database has no fence metadata yet. Authenticate every
        // existing encrypted row before allowing this candidate key to claim
        // the fence; otherwise a wrong-key first open could permanently lock
        // the real key out without ever proving possession of it.
        validate_existing_encrypted_rows(&transaction, cipher)?;
        let key_id = cipher.key_id();
        transaction
            .execute(
                "UPDATE encryption_fence SET key_id = ?1
                 WHERE id = 1 AND key_id IS NULL",
                [key_id.as_slice()],
            )
            .map_err(sqlite_error)?;
        backfill_legacy_request_indexes(&transaction, cipher)?;
    } else if stored.as_deref() == Some(expected.as_slice()) {
        // Existing v6 rows are authenticated under the current key before
        // their encrypted request identifiers become queryable metadata.
        backfill_legacy_request_indexes(&transaction, cipher)?;
    } else {
        return Err(StoreError::WrongMasterKey);
    }
    transaction.commit().map_err(sqlite_error)
}

fn validate_existing_encrypted_rows(
    transaction: &Transaction<'_>,
    cipher: &CredentialCipher,
) -> StoreResult<()> {
    let credential_rows = {
        let mut statement = transaction
            .prepare(
                "SELECT credential_id, envelope
                 FROM credential_payloads ORDER BY credential_id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (credential_id, envelope) in credential_rows {
        cipher.open_for(&envelope, credential_id.as_bytes())?;
    }

    let request_rows = {
        let mut statement = transaction
            .prepare("SELECT id, envelope FROM request_events ORDER BY id ASC")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (id, envelope) in request_rows {
        decrypt_request_event(cipher, id, &envelope)?;
    }

    let usage_rows = {
        let mut statement = transaction
            .prepare("SELECT id, envelope FROM usage_records ORDER BY id ASC")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (id, envelope) in usage_rows {
        decrypt_usage_record(cipher, id, &envelope)?;
    }
    Ok(())
}

fn backfill_legacy_request_indexes(
    transaction: &Transaction<'_>,
    cipher: &CredentialCipher,
) -> StoreResult<()> {
    let rows = {
        let mut statement = transaction
            .prepare(
                "SELECT id, envelope FROM request_events
                 WHERE request_index IS NULL ORDER BY id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (id, envelope) in rows {
        let event = decrypt_request_event(cipher, id, &envelope)?;
        let request_index = cipher.request_index(&event.request_id);
        transaction
            .execute(
                "UPDATE request_events SET request_index = ?1, event_index = ?2
                 WHERE id = ?3 AND request_index IS NULL",
                params![request_index.as_slice(), event.event_index, id],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn assert_cipher_current_transaction(
    transaction: &Transaction<'_>,
    cipher: &CredentialCipher,
) -> StoreResult<()> {
    assert_cipher_current_connection(transaction, cipher)
}

fn assert_cipher_current_connection(
    connection: &Connection,
    cipher: &CredentialCipher,
) -> StoreResult<()> {
    let stored = encryption_fence_key_id(connection)?;
    let expected = cipher.key_id();
    if stored.as_deref() == Some(expected.as_slice()) {
        Ok(())
    } else {
        Err(StoreError::WrongMasterKey)
    }
}

fn assert_mutation_authorized_transaction(
    transaction: &Transaction<'_>,
    cipher: Option<&CredentialCipher>,
) -> StoreResult<()> {
    if let Some(cipher) = cipher {
        return assert_cipher_current_transaction(transaction, cipher);
    }
    if encryption_fence_key_id(transaction)?.is_some()
        || transaction
            .query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM credential_payloads
                     UNION ALL SELECT 1 FROM request_events
                     UNION ALL SELECT 1 FROM usage_records
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?
            != 0
    {
        Err(StoreError::EncryptionRequired)
    } else {
        Ok(())
    }
}

fn encryption_fence_key_id(connection: &Connection) -> StoreResult<Option<Vec<u8>>> {
    connection
        .query_row(
            "SELECT key_id FROM encryption_fence WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn prepare_database_path(path: &Path) -> StoreResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(StoreError::InvalidPath("database path is empty".to_owned()));
    }
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(io_error)?;
        if metadata.file_type().is_symlink() {
            return Err(StoreError::UnsafePath(
                "database path must not be a symbolic link".to_owned(),
            ));
        }
        if !metadata.is_file() {
            return Err(StoreError::InvalidPath(
                "database path is not a regular file".to_owned(),
            ));
        }
        ensure_private_file(path)?;
    } else {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let parent = parent.ok_or_else(|| {
            StoreError::UnsafePath(
                "database path must be inside an owner-private directory".to_owned(),
            )
        })?;
        ensure_private_directory(parent)?;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path).map_err(io_error)?;
        drop(file);
        ensure_private_file(path)?;
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_directory(parent)?;
    }
    Ok(path.to_path_buf())
}

fn ensure_private_sidecars(path: &Path) -> StoreResult<()> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar_name = path.as_os_str().to_owned();
        sidecar_name.push(suffix);
        let sidecar = PathBuf::from(sidecar_name);
        let metadata = match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(StoreError::UnsafePath(format!(
                "SQLite sidecar `{}` must not be a symbolic link",
                sidecar.display()
            )));
        }
        if !metadata.is_file() {
            return Err(StoreError::InvalidPath(format!(
                "SQLite sidecar `{}` is not a regular file",
                sidecar.display()
            )));
        }
        ensure_private_file(&sidecar)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    if !path.exists() {
        fs::create_dir_all(path).map_err(io_error)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() {
        return Err(StoreError::InvalidPath(format!(
            "database parent `{}` is not a directory",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::UnsafePath(format!(
            "database parent `{}` is not owner-private",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(path: &Path) -> StoreResult<()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(io_error)?;
    }
    if !path.is_dir() {
        return Err(StoreError::InvalidPath(format!(
            "database parent `{}` is not a directory",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_file(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(StoreError::InvalidPath(format!(
            "database path `{}` is not a regular file",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::UnsafePath(format!(
            "database `{}` is not owner-private",
            path.display()
        )));
    }
    // Mode checks prevent other users from reading or replacing the database.
    // Ownership is deliberately left to the host filesystem policy: portable
    // containers can map the process UID while retaining owner-only modes.
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_file(path: &Path) -> StoreResult<()> {
    if !path.is_file() {
        return Err(StoreError::InvalidPath(format!(
            "database path `{}` is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

fn sqlite_error(error: rusqlite::Error) -> StoreError {
    StoreError::Sqlite(error.to_string())
}

fn count_rows(connection: &Connection, table: &str) -> StoreResult<usize> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection
        .query_row(&query, [], |row| row.get(0))
        .map_err(sqlite_error)?;
    usize::try_from(count).map_err(|_| StoreError::Sqlite("row count overflow".to_owned()))
}

fn credential_from_row(row: &Row<'_>) -> rusqlite::Result<CredentialState> {
    let revision: i64 = row.get(4)?;
    Ok(CredentialState {
        credential_id: row.get(0)?,
        provider_id: row.get(1)?,
        enabled: row.get::<_, i64>(2)? != 0,
        updated_at: row.get(3)?,
        revision: u64::try_from(revision).unwrap_or(u64::MAX),
    })
}

fn affinity_from_row(row: &Row<'_>) -> rusqlite::Result<SessionAffinity> {
    Ok(SessionAffinity {
        key: row.get(0)?,
        provider_id: row.get(1)?,
        credential_id: row.get(2)?,
        upstream_model: row.get(3)?,
        created_at: row.get(4)?,
        last_used_at: row.get(5)?,
        expires_at: row.get(6)?,
    })
}

fn health_from_row(row: &Row<'_>) -> rusqlite::Result<CredentialHealthState> {
    let status: String = row.get(1)?;
    let status = CredentialHealthStatus::parse(&status).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid credential health status",
            )),
        )
    })?;
    let failure_count: i64 = row.get(2)?;
    Ok(CredentialHealthState {
        credential_id: row.get(0)?,
        status,
        failure_count: u64::try_from(failure_count).unwrap_or(u64::MAX),
        cooldown_until: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn cooldown_from_row(row: &Row<'_>) -> rusqlite::Result<CooldownState> {
    Ok(CooldownState {
        scope: row.get(0)?,
        key: row.get(1)?,
        until: row.get(2)?,
        reason: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn decision_from_row(row: &Row<'_>) -> StoreResult<DecisionRecord> {
    let id: i64 = row.get(0).map_err(sqlite_error)?;
    let candidates_json: String = row.get(4).map_err(sqlite_error)?;
    let candidates = serde_json::from_str(&candidates_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(DecisionRecord {
        id: u64::try_from(id).map_err(|_| StoreError::DecisionIdExhausted)?,
        request_id: row.get(1).map_err(sqlite_error)?,
        route_id: row.get(2).map_err(sqlite_error)?,
        model: row.get(3).map_err(sqlite_error)?,
        candidates,
        selected_provider: row.get(5).map_err(sqlite_error)?,
        selected_credential: row.get(6).map_err(sqlite_error)?,
        upstream_model: row.get(7).map_err(sqlite_error)?,
        attempt: row
            .get::<_, i64>(8)
            .map_err(sqlite_error)
            .and_then(|value| {
                u32::try_from(value).map_err(|_| StoreError::Sqlite("attempt overflow".to_owned()))
            })?,
        configuration_generation: row
            .get::<_, i64>(9)
            .map_err(sqlite_error)
            .and_then(|value| {
                u64::try_from(value)
                    .map_err(|_| StoreError::Sqlite("generation overflow".to_owned()))
            })?,
        reason: row.get(10).map_err(sqlite_error)?,
        recorded_at: row.get(11).map_err(sqlite_error)?,
    })
}

fn delete_credential_dependents(
    transaction: &Transaction<'_>,
    credential_id: &str,
) -> StoreResult<()> {
    // `credential_health` predates the credential foreign key and therefore
    // needs explicit cleanup. Affinities and credential-scoped cooldowns are
    // also references to the removed account, not independent retained state.
    transaction
        .execute(
            "DELETE FROM credential_health WHERE credential_id = ?1",
            [credential_id],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM affinities WHERE credential_id = ?1",
            [credential_id],
        )
        .map_err(sqlite_error)?;
    let cooldowns = {
        let mut statement = transaction
            .prepare(
                "SELECT scope, scope_key FROM cooldowns
                 WHERE scope IN ('credential', 'credential_model')",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (scope, key) in cooldowns {
        if cooldown_belongs_to_credential(&scope, &key, credential_id) {
            transaction
                .execute(
                    "DELETE FROM cooldowns WHERE scope = ?1 AND scope_key = ?2",
                    params![scope, key],
                )
                .map_err(sqlite_error)?;
        }
    }
    Ok(())
}

fn require_credential(transaction: &Transaction<'_>, credential_id: &str) -> StoreResult<()> {
    let exists: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM credentials WHERE credential_id = ?1",
            [credential_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(StoreError::CredentialNotFound(credential_id.to_owned()))
    }
}

fn decode_compound_cooldown_key(key: &str) -> Option<(String, String)> {
    let value = key.strip_prefix("v2:")?;
    let (left_length, value) = value.split_once(':')?;
    let (right_length, value) = value.split_once(':')?;
    let left_length = left_length.parse::<usize>().ok()?;
    let right_length = right_length.parse::<usize>().ok()?;
    let bytes = value.as_bytes();
    let total = left_length.checked_add(right_length)?;
    if bytes.len() != total {
        return None;
    }
    Some((
        String::from_utf8(bytes[..left_length].to_vec()).ok()?,
        String::from_utf8(bytes[left_length..].to_vec()).ok()?,
    ))
}

fn cooldown_credential_id(scope: &str, key: &str) -> Option<String> {
    match scope {
        "credential" => Some(key.to_owned()),
        "credential_model" => decode_compound_cooldown_key(key)
            .map(|(credential_id, _)| credential_id)
            .or_else(|| {
                (key.matches(':').count() == 1)
                    .then(|| {
                        key.split_once(':')
                            .map(|(credential_id, _)| credential_id.to_owned())
                    })
                    .flatten()
            }),
        _ => None,
    }
}

fn cooldown_belongs_to_credential(scope: &str, key: &str, credential_id: &str) -> bool {
    cooldown_credential_id(scope, key).as_deref() == Some(credential_id)
}

fn require_cooldown_credential(
    transaction: &Transaction<'_>,
    scope: &str,
    key: &str,
) -> StoreResult<()> {
    if let Some(credential_id) = cooldown_credential_id(scope, key) {
        require_credential(transaction, &credential_id)?;
    } else if matches!(scope, "credential" | "credential_model") {
        return Err(StoreError::CredentialNotFound(key.to_owned()));
    }
    Ok(())
}

fn evict_credentials(transaction: &Transaction<'_>, limit: usize) -> StoreResult<usize> {
    let limit =
        i64::try_from(limit).map_err(|_| StoreError::Sqlite("retention overflow".to_owned()))?;
    let candidates = {
        let mut statement = transaction
            .prepare(
                "SELECT credential_id FROM credentials
                 ORDER BY updated_at ASC, credential_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM credentials) - ?1, 0)",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([limit], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    let mut removed = 0_usize;
    for credential_id in candidates {
        let deleted = transaction
            .execute(
                "DELETE FROM credentials WHERE credential_id = ?1",
                [&credential_id],
            )
            .map_err(sqlite_error)?;
        if deleted != 0 {
            delete_credential_dependents(transaction, &credential_id)?;
            removed = removed.saturating_add(deleted);
        }
    }
    Ok(removed)
}

fn evict_affinities(transaction: &Transaction<'_>, limit: usize) -> StoreResult<usize> {
    let limit =
        i64::try_from(limit).map_err(|_| StoreError::Sqlite("retention overflow".to_owned()))?;
    transaction
        .execute(
            "DELETE FROM affinities WHERE key IN (
                 SELECT key FROM affinities
                 ORDER BY last_used_at ASC, created_at ASC, key ASC
                 LIMIT MAX((SELECT COUNT(*) FROM affinities) - ?1, 0)
             )",
            [limit],
        )
        .map_err(sqlite_error)
}

fn evict_decisions(transaction: &Transaction<'_>, limit: usize) -> StoreResult<usize> {
    let limit =
        i64::try_from(limit).map_err(|_| StoreError::Sqlite("retention overflow".to_owned()))?;
    transaction
        .execute(
            "DELETE FROM decisions WHERE id IN (
                 SELECT id FROM decisions ORDER BY id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM decisions) - ?1, 0)
             )",
            [limit],
        )
        .map_err(sqlite_error)
}

fn set_credential_enabled_tx(
    transaction: &Transaction<'_>,
    credential_id: &str,
    enabled: bool,
    updated_at: Timestamp,
) -> StoreResult<CredentialState> {
    let old = transaction
        .query_row(
            "SELECT credential_id, provider_id, enabled, updated_at, revision
             FROM credentials WHERE credential_id = ?1",
            [credential_id],
            credential_from_row,
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
    if old.enabled == enabled {
        return Ok(old);
    }
    let revision = old.revision.saturating_add(1);
    transaction
        .execute(
            "UPDATE credentials SET enabled = ?1, updated_at = ?2, revision = ?3
             WHERE credential_id = ?4",
            params![
                i64::from(enabled),
                updated_at,
                i64::try_from(revision).unwrap_or(i64::MAX),
                credential_id
            ],
        )
        .map_err(sqlite_error)?;
    if enabled {
        transaction
            .execute(
                "UPDATE credential_health SET status = 'healthy', cooldown_until = NULL,
                 updated_at = ?1 WHERE credential_id = ?2 AND status = 'disabled'",
                params![updated_at, credential_id],
            )
            .map_err(sqlite_error)?;
    } else {
        transaction
            .execute(
                "INSERT INTO credential_health
                 (credential_id, status, failure_count, cooldown_until, updated_at)
                 VALUES (?1, 'disabled', 0, NULL, ?2)
                 ON CONFLICT(credential_id) DO UPDATE SET
                   status = 'disabled', cooldown_until = NULL, updated_at = excluded.updated_at",
                params![credential_id, updated_at],
            )
            .map_err(sqlite_error)?;
    }
    Ok(CredentialState {
        enabled,
        updated_at,
        revision,
        ..old
    })
}

fn request_event_aad(id: u64) -> Vec<u8> {
    format!("pooler-request-event:v1:{id}").into_bytes()
}

fn encrypt_request_event(cipher: &CredentialCipher, event: &RequestEvent) -> StoreResult<Vec<u8>> {
    let bytes =
        serde_json::to_vec(event).map_err(|error| StoreError::Serialization(error.to_string()))?;
    if bytes.len() > 16 * 1024 {
        return Err(StoreError::Serialization(
            "request event exceeds encrypted record bound".to_owned(),
        ));
    }
    let payload = SecretPayload::from_bytes(bytes)?;
    cipher.seal_for(&payload, &request_event_aad(event.id))
}

fn decrypt_request_event(
    cipher: &CredentialCipher,
    id: u64,
    envelope: &[u8],
) -> StoreResult<RequestEvent> {
    let payload = cipher.open_for(envelope, &request_event_aad(id))?;
    let event: RequestEvent = serde_json::from_slice(payload.expose_bytes())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if event.id != id {
        return Err(StoreError::CredentialEnvelopeAuthenticationFailed);
    }
    Ok(event)
}

fn usage_record_aad(id: u64) -> Vec<u8> {
    format!("pooler-usage-record:v1:{id}").into_bytes()
}

fn encrypt_usage_record(cipher: &CredentialCipher, record: &UsageRecord) -> StoreResult<Vec<u8>> {
    let bytes =
        serde_json::to_vec(record).map_err(|error| StoreError::Serialization(error.to_string()))?;
    if bytes.len() > 16 * 1024 {
        return Err(StoreError::Serialization(
            "usage record exceeds encrypted record bound".to_owned(),
        ));
    }
    cipher.seal_for(
        &SecretPayload::from_bytes(bytes)?,
        &usage_record_aad(record.id),
    )
}

fn decrypt_usage_record(
    cipher: &CredentialCipher,
    id: u64,
    envelope: &[u8],
) -> StoreResult<UsageRecord> {
    let payload = cipher.open_for(envelope, &usage_record_aad(id))?;
    let record: UsageRecord = serde_json::from_slice(payload.expose_bytes())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if record.id != id {
        return Err(StoreError::CredentialEnvelopeAuthenticationFailed);
    }
    Ok(record)
}

fn evict_cooldowns(transaction: &Transaction<'_>) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM cooldowns WHERE rowid IN (
                 SELECT rowid FROM cooldowns
                 ORDER BY updated_at ASC, scope ASC, scope_key ASC
                 LIMIT MAX((SELECT COUNT(*) FROM cooldowns) - ?1, 0)
             )",
            [i64::try_from(MAX_COOLDOWNS).expect("constant fits in i64")],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn evict_request_events_for_transaction(
    transaction: &Transaction<'_>,
    cipher: &CredentialCipher,
    request_id: &str,
    request_index: &[u8],
) -> StoreResult<()> {
    let has_legacy_rows: i64 = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM request_events WHERE request_index IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if has_legacy_rows == 0 {
        transaction
            .execute(
                "DELETE FROM request_events
                 WHERE request_index = ?1 AND id NOT IN (
                     SELECT id FROM request_events
                     WHERE request_index = ?1
                     ORDER BY event_index DESC, id DESC LIMIT ?2
                 )",
                params![
                    request_index,
                    i64::try_from(MAX_REQUEST_EVENTS_PER_REQUEST)
                        .map_err(|_| StoreError::InvalidRetention)?
                ],
            )
            .map_err(sqlite_error)?;
        return Ok(());
    }

    let indexed_rows = {
        let mut statement = transaction
            .prepare(
                "SELECT id, envelope FROM request_events
                 WHERE request_index = ?1",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([request_index], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    let legacy_rows = {
        let mut statement = transaction
            .prepare(
                "SELECT id, envelope FROM request_events
                 WHERE request_index IS NULL",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    let mut matching = Vec::with_capacity(indexed_rows.len() + legacy_rows.len());
    for (id, envelope) in indexed_rows.into_iter().chain(legacy_rows) {
        let event = decrypt_request_event(cipher, id, &envelope)?;
        if event.request_id == request_id {
            matching.push((id, event.event_index));
        }
    }
    if matching.len() <= MAX_REQUEST_EVENTS_PER_REQUEST {
        return Ok(());
    }
    let mut retained = matching.clone();
    retained.sort_unstable_by(|left, right| (right.1, right.0).cmp(&(left.1, left.0)));
    retained.truncate(MAX_REQUEST_EVENTS_PER_REQUEST);
    let retained_ids = retained.into_iter().map(|(id, _)| id).collect::<Vec<_>>();
    for (id, _) in matching {
        if !retained_ids.contains(&id) {
            transaction
                .execute("DELETE FROM request_events WHERE id = ?1", [id])
                .map_err(sqlite_error)?;
        }
    }
    Ok(())
}

impl Store for SqliteStore {
    fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    fn upsert_credential_state(&self, state: CredentialState) -> StoreResult<CredentialState> {
        non_empty("credential_id", &state.credential_id)?;
        non_empty("provider_id", &state.provider_id)?;
        let revision = self.with_transaction(|transaction| {
            let existing: Option<i64> = transaction
                .query_row(
                    "SELECT revision FROM credentials WHERE credential_id = ?1",
                    [&state.credential_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            let revision = existing
                .map(|value| u64::try_from(value).unwrap_or(u64::MAX).saturating_add(1))
                .unwrap_or(1);
            let revision_i64 = i64::try_from(revision).unwrap_or(i64::MAX);
            transaction
                .execute(
                    "INSERT INTO credentials (credential_id, provider_id, enabled, updated_at, revision)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       provider_id = excluded.provider_id,
                       enabled = excluded.enabled,
                       updated_at = excluded.updated_at,
                       revision = excluded.revision",
                    params![
                        &state.credential_id,
                        &state.provider_id,
                        i64::from(state.enabled),
                        state.updated_at,
                        revision_i64,
                    ],
                )
                .map_err(sqlite_error)?;
            evict_credentials(transaction, self.retention.max_credentials)?;
            Ok(revision)
        })?;
        Ok(CredentialState { revision, ..state })
    }

    fn credential_state(&self, credential_id: &str) -> StoreResult<Option<CredentialState>> {
        non_empty("credential_id", credential_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT credential_id, provider_id, enabled, updated_at, revision
                 FROM credentials WHERE credential_id = ?1",
                [credential_id],
                credential_from_row,
            )
            .optional()
            .map_err(sqlite_error)
    }

    fn credential_states(&self) -> StoreResult<Vec<CredentialState>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT credential_id, provider_id, enabled, updated_at, revision
                 FROM credentials ORDER BY credential_id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], credential_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    fn set_credential_enabled(
        &self,
        credential_id: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        non_empty("credential_id", credential_id)?;
        self.with_transaction(|transaction| {
            set_credential_enabled_tx(transaction, credential_id, enabled, updated_at)
        })
    }

    fn switch_credential(
        &self,
        selected: &str,
        siblings: &[String],
        updated_at: Timestamp,
    ) -> StoreResult<Vec<CredentialState>> {
        SqliteStore::switch_credential(self, selected, siblings, updated_at)
    }

    fn remove_credential_state(&self, credential_id: &str) -> StoreResult<bool> {
        non_empty("credential_id", credential_id)?;
        self.with_transaction(|transaction| {
            let removed = transaction
                .execute(
                    "DELETE FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                )
                .map_err(sqlite_error)?;
            delete_credential_dependents(transaction, credential_id)?;
            Ok(removed != 0)
        })
    }

    fn upsert_credential_health(
        &self,
        state: CredentialHealthState,
    ) -> StoreResult<CredentialHealthState> {
        non_empty("credential_id", &state.credential_id)?;
        self.with_immediate_transaction(|transaction| {
            require_credential(transaction, &state.credential_id)?;
            transaction
                .execute(
                    "INSERT INTO credential_health
                 (credential_id, status, failure_count, cooldown_until, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(credential_id) DO UPDATE SET
                   status = excluded.status,
                   failure_count = excluded.failure_count,
                   cooldown_until = excluded.cooldown_until,
                   updated_at = excluded.updated_at",
                    params![
                        &state.credential_id,
                        state.status.as_str(),
                        i64::try_from(state.failure_count).unwrap_or(i64::MAX),
                        state.cooldown_until,
                        state.updated_at,
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(())
        })?;
        Ok(state)
    }

    fn credential_health(&self, credential_id: &str) -> StoreResult<Option<CredentialHealthState>> {
        non_empty("credential_id", credential_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT credential_id, status, failure_count, cooldown_until, updated_at
                 FROM credential_health WHERE credential_id = ?1",
                [credential_id],
                health_from_row,
            )
            .optional()
            .map_err(sqlite_error)
            .and_then(|value| value.map_or(Ok(None), |state| Ok(Some(state))))
    }

    fn credential_health_states(&self) -> StoreResult<Vec<CredentialHealthState>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT credential_id, status, failure_count, cooldown_until, updated_at
                 FROM credential_health ORDER BY credential_id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], health_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    fn upsert_cooldown(&self, state: CooldownState) -> StoreResult<CooldownState> {
        non_empty("scope", &state.scope)?;
        non_empty("key", &state.key)?;
        self.with_transaction(|transaction| {
            require_cooldown_credential(transaction, &state.scope, &state.key)?;
            transaction
                .execute(
                    "INSERT INTO cooldowns (scope, scope_key, until_at, reason, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(scope, scope_key) DO UPDATE SET
                       until_at = MAX(cooldowns.until_at, excluded.until_at),
                       reason = excluded.reason,
                       updated_at = excluded.updated_at",
                    params![
                        &state.scope,
                        &state.key,
                        state.until,
                        &state.reason,
                        state.updated_at,
                    ],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    "DELETE FROM cooldowns WHERE until_at <= ?1",
                    [state.updated_at],
                )
                .map_err(sqlite_error)?;
            evict_cooldowns(transaction)
        })?;
        Ok(state)
    }

    fn cooldown(
        &self,
        scope: &str,
        key: &str,
        now: Timestamp,
    ) -> StoreResult<Option<CooldownState>> {
        non_empty("scope", scope)?;
        non_empty("key", key)?;
        self.with_transaction(|transaction| {
            transaction
                .execute("DELETE FROM cooldowns WHERE until_at <= ?1", [now])
                .map_err(sqlite_error)?;
            transaction
                .query_row(
                    "SELECT scope, scope_key, until_at, reason, updated_at
                     FROM cooldowns WHERE scope = ?1 AND scope_key = ?2",
                    params![scope, key],
                    cooldown_from_row,
                )
                .optional()
                .map_err(sqlite_error)
        })
    }

    fn cooldowns(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>> {
        self.with_transaction(|transaction| {
            transaction
                .execute("DELETE FROM cooldowns WHERE until_at <= ?1", [now])
                .map_err(sqlite_error)?;
            let mut statement = transaction
                .prepare(
                    "SELECT scope, scope_key, until_at, reason, updated_at
                     FROM cooldowns ORDER BY scope ASC, scope_key ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], cooldown_from_row)
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
        })
    }

    fn remove_cooldown(&self, scope: &str, key: &str) -> StoreResult<bool> {
        non_empty("scope", scope)?;
        non_empty("key", key)?;
        self.with_transaction(|transaction| {
            let removed = transaction
                .execute(
                    "DELETE FROM cooldowns WHERE scope = ?1 AND scope_key = ?2",
                    params![scope, key],
                )
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    fn upsert_session_affinity(&self, affinity: SessionAffinity) -> StoreResult<SessionAffinity> {
        non_empty("key", &affinity.key)?;
        non_empty("provider_id", &affinity.provider_id)?;
        non_empty("credential_id", &affinity.credential_id)?;
        non_empty("upstream_model", &affinity.upstream_model)?;
        self.with_transaction(|transaction| {
            require_credential(transaction, &affinity.credential_id)?;
            transaction
                .execute(
                    "DELETE FROM affinities WHERE expires_at <= ?1",
                    [affinity.created_at],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    "INSERT INTO affinities
                     (key, provider_id, credential_id, upstream_model, created_at, last_used_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
                     ON CONFLICT(key) DO UPDATE SET
                       provider_id = excluded.provider_id,
                       credential_id = excluded.credential_id,
                       upstream_model = excluded.upstream_model,
                       created_at = excluded.created_at,
                       last_used_at = excluded.last_used_at,
                       expires_at = excluded.expires_at",
                    params![
                        &affinity.key,
                        &affinity.provider_id,
                        &affinity.credential_id,
                        &affinity.upstream_model,
                        affinity.created_at,
                        affinity.expires_at,
                    ],
                )
                .map_err(sqlite_error)?;
            evict_affinities(transaction, self.retention.max_affinities).map(|_| ())
        })?;
        Ok(affinity)
    }

    fn session_affinity(&self, key: &str, now: Timestamp) -> StoreResult<Option<SessionAffinity>> {
        non_empty("key", key)?;
        self.with_transaction(|transaction| {
            transaction
                .execute("DELETE FROM affinities WHERE expires_at <= ?1", [now])
                .map_err(sqlite_error)?;
            let value = transaction
                .query_row(
                    "SELECT key, provider_id, credential_id, upstream_model, created_at, last_used_at, expires_at
                     FROM affinities WHERE key = ?1",
                    [key],
                    affinity_from_row,
                )
                .optional()
                .map_err(sqlite_error)?;
            if value.is_some() {
                transaction
                    .execute(
                        "UPDATE affinities SET last_used_at = MAX(last_used_at, ?1) WHERE key = ?2",
                        params![now, key],
                    )
                    .map_err(sqlite_error)?;
            }
            Ok(value.map(|mut affinity| {
                affinity.last_used_at = affinity.last_used_at.max(now);
                affinity
            }))
        })
    }

    fn session_affinities(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>> {
        self.with_transaction(|transaction| {
            transaction
                .execute("DELETE FROM affinities WHERE expires_at <= ?1", [now])
                .map_err(sqlite_error)?;
            let mut statement = transaction
                .prepare(
                    "SELECT key, provider_id, credential_id, upstream_model, created_at, last_used_at, expires_at
                     FROM affinities ORDER BY key ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], affinity_from_row)
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
        })
    }

    fn remove_session_affinity(&self, key: &str) -> StoreResult<bool> {
        non_empty("key", key)?;
        self.with_transaction(|transaction| {
            let removed = transaction
                .execute("DELETE FROM affinities WHERE key = ?1", [key])
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    fn append_decision(&self, record: DecisionRecord) -> StoreResult<DecisionRecord> {
        non_empty("request_id", &record.request_id)?;
        non_empty("route_id", &record.route_id)?;
        non_empty("model", &record.model)?;
        let candidates = serde_json::to_string(&record.candidates)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let id = self.with_transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO decisions
                     (request_id, route_id, model, candidates_json, selected_provider,
                      selected_credential, upstream_model, attempt, configuration_generation,
                      reason, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        &record.request_id,
                        &record.route_id,
                        &record.model,
                        candidates,
                        &record.selected_provider,
                        &record.selected_credential,
                        &record.upstream_model,
                        i64::from(record.attempt),
                        i64::try_from(record.configuration_generation).unwrap_or(i64::MAX),
                        &record.reason,
                        record.recorded_at,
                    ],
                )
                .map_err(sqlite_error)?;
            let id = transaction.last_insert_rowid();
            if id <= 0 {
                return Err(StoreError::DecisionIdExhausted);
            }
            evict_decisions(transaction, self.retention.max_decisions)?;
            Ok(id)
        })?;
        Ok(DecisionRecord {
            id: u64::try_from(id).map_err(|_| StoreError::DecisionIdExhausted)?,
            ..record
        })
    }

    fn decisions(&self) -> StoreResult<Vec<DecisionRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, request_id, route_id, model, candidates_json, selected_provider,
                 selected_credential, upstream_model, attempt, configuration_generation,
                 reason, recorded_at FROM decisions ORDER BY id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                decision_from_row(row)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
            })
            .map_err(sqlite_error)?;
        rows.map(|row| row.map_err(sqlite_error)).collect()
    }

    fn recent_decisions(&self, limit: usize) -> StoreResult<Vec<DecisionRecord>> {
        let limit =
            i64::try_from(limit).map_err(|_| StoreError::Sqlite("limit overflow".to_owned()))?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, request_id, route_id, model, candidates_json, selected_provider,
                 selected_credential, upstream_model, attempt, configuration_generation,
                 reason, recorded_at FROM decisions ORDER BY id DESC LIMIT ?1",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([limit], |row| {
                decision_from_row(row)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
            })
            .map_err(sqlite_error)?;
        rows.map(|row| row.map_err(sqlite_error)).collect()
    }

    fn append_request_event(&self, mut event: RequestEvent) -> StoreResult<RequestEvent> {
        MemoryStore::validate_request_event(&event)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let request_index = cipher.request_index(&event.request_id);
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            transaction
                .execute(
                    "INSERT INTO request_events
                     (recorded_at, envelope, request_index, event_index)
                     VALUES (?1, X'00', ?2, ?3)",
                    params![
                        event.recorded_at,
                        request_index.as_slice(),
                        event.event_index
                    ],
                )
                .map_err(sqlite_error)?;
            let id = transaction.last_insert_rowid();
            if id <= 0 {
                return Err(StoreError::RequestEventIdExhausted);
            }
            event.id = u64::try_from(id).map_err(|_| StoreError::RequestEventIdExhausted)?;
            let envelope = encrypt_request_event(&cipher, &event)?;
            transaction
                .execute(
                    "UPDATE request_events SET envelope = ?1 WHERE id = ?2",
                    params![envelope, id],
                )
                .map_err(sqlite_error)?;

            let cutoff = event
                .recorded_at
                .saturating_sub(self.retention.request_history_ttl_ms);
            transaction
                .execute(
                    "DELETE FROM request_events WHERE recorded_at < ?1",
                    [cutoff],
                )
                .map_err(sqlite_error)?;
            evict_request_events_for_transaction(
                transaction,
                &cipher,
                &event.request_id,
                request_index.as_slice(),
            )?;
            transaction
                .execute(
                    "DELETE FROM request_events
                     WHERE id <= (
                         SELECT id FROM request_events
                         ORDER BY id DESC LIMIT 1 OFFSET ?1
                     )",
                    [i64::try_from(self.retention.max_request_events)
                        .map_err(|_| StoreError::InvalidRetention)?],
                )
                .map_err(sqlite_error)?;
            Ok(event.clone())
        })
    }

    fn request_events(&self) -> StoreResult<Vec<RequestEvent>> {
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, &cipher)?;
        let mut statement = connection
            .prepare("SELECT id, envelope FROM request_events ORDER BY id ASC")
            .map_err(sqlite_error)?;
        let encrypted = statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        encrypted
            .into_iter()
            .map(|(id, envelope)| decrypt_request_event(&cipher, id, &envelope))
            .collect()
    }

    fn request_events_for(&self, request_id: &str) -> StoreResult<Vec<RequestEvent>> {
        non_empty("request_id", request_id)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let request_index = cipher.request_index(request_id);
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, &cipher)?;
        let mut statement = connection
            .prepare(
                "SELECT id, envelope FROM request_events
                 WHERE request_index = ?1 ORDER BY event_index ASC, id ASC",
            )
            .map_err(sqlite_error)?;
        let encrypted = statement
            .query_map([request_index.as_slice()], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        let mut events = encrypted
            .into_iter()
            .map(|(id, envelope)| decrypt_request_event(&cipher, id, &envelope))
            .collect::<StoreResult<Vec<_>>>()?
            .into_iter()
            .filter(|event| event.request_id == request_id)
            .collect::<Vec<_>>();
        // Rows written before migration 006 have no index metadata. Merge
        // those authenticated legacy rows with indexed rows rather than
        // replacing the indexed result with a full-table read. This keeps a
        // timeline spanning the migration complete while preserving the
        // indexed fast path for all-new rows.
        let mut legacy_statement = connection
            .prepare(
                "SELECT id, envelope FROM request_events
                 WHERE request_index IS NULL ORDER BY id ASC",
            )
            .map_err(sqlite_error)?;
        let legacy_rows = legacy_statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(legacy_statement);
        for (id, envelope) in &legacy_rows {
            let event = decrypt_request_event(&cipher, *id, envelope)?;
            if event.request_id == request_id {
                events.push(event);
            }
        }
        events.sort_by_key(|event| (event.event_index, event.id));
        Ok(events)
    }

    fn append_usage_record(&self, mut record: UsageRecord) -> StoreResult<UsageRecord> {
        record.validate()?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            transaction
                .execute(
                    "INSERT INTO usage_records (recorded_at, envelope) VALUES (?1, X'00')",
                    [record.recorded_at],
                )
                .map_err(sqlite_error)?;
            let id = transaction.last_insert_rowid();
            if id <= 0 {
                return Err(StoreError::UsageRecordIdExhausted);
            }
            record.id = u64::try_from(id).map_err(|_| StoreError::UsageRecordIdExhausted)?;
            let envelope = encrypt_usage_record(&cipher, &record)?;
            transaction
                .execute(
                    "UPDATE usage_records SET envelope = ?1 WHERE id = ?2",
                    params![envelope, id],
                )
                .map_err(sqlite_error)?;
            let newest_recorded_at: u64 = transaction
                .query_row(
                    "SELECT COALESCE(MAX(recorded_at), 0) FROM usage_records",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    "DELETE FROM usage_records WHERE recorded_at < ?1",
                    [newest_recorded_at.saturating_sub(self.retention.usage_history_ttl_ms)],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    "DELETE FROM usage_records WHERE id IN (
                         SELECT id FROM usage_records ORDER BY id ASC
                         LIMIT MAX((SELECT COUNT(*) FROM usage_records) - ?1, 0)
                     )",
                    [i64::try_from(self.retention.max_usage_records)
                        .map_err(|_| StoreError::InvalidRetention)?],
                )
                .map_err(sqlite_error)?;
            Ok(record.clone())
        })
    }

    fn usage_records(&self) -> StoreResult<Vec<UsageRecord>> {
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, &cipher)?;
        let mut statement = connection
            .prepare("SELECT id, envelope FROM usage_records ORDER BY id ASC")
            .map_err(sqlite_error)?;
        let encrypted = statement
            .query_map([], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        encrypted
            .into_iter()
            .map(|(id, envelope)| decrypt_usage_record(&cipher, id, &envelope))
            .collect()
    }

    fn prune(&self, now: Timestamp) -> StoreResult<PruneReport> {
        self.with_transaction(|transaction| {
            let expired_affinities = transaction
                .execute("DELETE FROM affinities WHERE expires_at <= ?1", [now])
                .map_err(sqlite_error)?;
            transaction
                .execute("DELETE FROM cooldowns WHERE until_at <= ?1", [now])
                .map_err(sqlite_error)?;
            let evicted_credentials =
                evict_credentials(transaction, self.retention.max_credentials)?;
            let evicted_affinities = evict_affinities(transaction, self.retention.max_affinities)?;
            let evicted_decisions = evict_decisions(transaction, self.retention.max_decisions)?;
            let evicted_request_events = transaction
                .execute(
                    "DELETE FROM request_events WHERE recorded_at < ?1",
                    [now.saturating_sub(self.retention.request_history_ttl_ms)],
                )
                .map_err(sqlite_error)?;
            let mut evicted_usage_records = transaction
                .execute(
                    "DELETE FROM usage_records WHERE recorded_at < ?1",
                    [now.saturating_sub(self.retention.usage_history_ttl_ms)],
                )
                .map_err(sqlite_error)?;
            evicted_usage_records = evicted_usage_records.saturating_add(
                transaction
                    .execute(
                        "DELETE FROM usage_records WHERE id IN (
                             SELECT id FROM usage_records ORDER BY id ASC
                             LIMIT MAX((SELECT COUNT(*) FROM usage_records) - ?1, 0)
                         )",
                        [i64::try_from(self.retention.max_usage_records)
                            .map_err(|_| StoreError::InvalidRetention)?],
                    )
                    .map_err(sqlite_error)?,
            );
            Ok(PruneReport {
                expired_affinities,
                evicted_credentials,
                evicted_affinities,
                evicted_decisions,
                evicted_request_events,
                evicted_usage_records,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use tempfile::tempdir;

    use super::*;
    use crate::{CredentialHealthStatus, DecisionCandidate, RequestEventKind};

    fn policy(credentials: usize, affinities: usize, decisions: usize) -> RetentionPolicy {
        RetentionPolicy::new(credentials, affinities, decisions).expect("valid policy")
    }

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempdir().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("set directory permissions");
        }
        directory
    }

    fn affinity(key: &str, created_at: Timestamp, expires_at: Timestamp) -> SessionAffinity {
        SessionAffinity::new(
            key,
            "provider",
            "credential",
            "model",
            created_at,
            expires_at,
        )
    }

    #[test]
    fn account_switch_is_atomic_and_survives_reopen() {
        let directory = private_tempdir();
        let path = directory.path().join("switch.sqlite");
        {
            let store = SqliteStore::open(&path).expect("open store");
            store
                .upsert_credential_state(CredentialState::new("primary", "provider", false, 1))
                .expect("primary");
            store
                .upsert_credential_state(CredentialState::new("backup", "provider", true, 1))
                .expect("backup");
            store
                .switch_credential("primary", &["backup".to_owned()], 2)
                .expect("switch");
        }
        let reopened = SqliteStore::open(&path).expect("reopen store");
        assert!(
            reopened
                .credential_state("primary")
                .expect("primary state")
                .expect("primary exists")
                .enabled
        );
        assert!(
            !reopened
                .credential_state("backup")
                .expect("backup state")
                .expect("backup exists")
                .enabled
        );
    }

    #[test]
    fn account_switch_rolls_back_when_any_sibling_is_missing() {
        let store = SqliteStore::open_in_memory().expect("store");
        store
            .upsert_credential_state(CredentialState::new("primary", "provider", false, 1))
            .expect("primary");
        store
            .upsert_credential_state(CredentialState::new("backup", "provider", true, 1))
            .expect("backup");
        let error = store
            .switch_credential("primary", &["backup".to_owned(), "missing".to_owned()], 2)
            .expect_err("missing sibling must roll back");
        assert_eq!(error, StoreError::CredentialNotFound("missing".to_owned()));
        assert!(
            !store
                .credential_state("primary")
                .expect("primary state")
                .expect("primary exists")
                .enabled
        );
        assert!(
            store
                .credential_state("backup")
                .expect("backup state")
                .expect("backup exists")
                .enabled
        );
    }

    #[test]
    fn sqlite_round_trip_preserves_all_non_secret_state() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        {
            let store =
                SqliteStore::open_with_retention(&path, policy(8, 8, 8)).expect("open store");
            assert_eq!(store.journal_mode().expect("journal mode"), "wal");
            store
                .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
                .expect("credential");
            store
                .upsert_credential_health(CredentialHealthState {
                    credential_id: "credential".to_owned(),
                    status: CredentialHealthStatus::CoolingDown,
                    failure_count: 3,
                    cooldown_until: Some(100),
                    updated_at: 2,
                })
                .expect("health");
            store
                .upsert_cooldown(CooldownState {
                    scope: "credential".to_owned(),
                    key: "credential".to_owned(),
                    until: 100,
                    reason: Some("quota".to_owned()),
                    updated_at: 2,
                })
                .expect("cooldown");
            store
                .upsert_session_affinity(affinity("session", 1, 100))
                .expect("affinity");
            let mut decision = DecisionRecord::new("request", "route", "model", 2);
            decision.candidates.push(DecisionCandidate {
                provider_id: "provider".to_owned(),
                credential_id: Some("credential-pseudonym".to_owned()),
                score: 10,
                eligible: true,
                reason: None,
            });
            store.append_decision(decision).expect("decision");
        }

        let store = SqliteStore::open_with_retention(&path, policy(8, 8, 8)).expect("reopen");
        assert!(
            store
                .credential_state("credential")
                .expect("credential lookup")
                .unwrap()
                .enabled
        );
        assert_eq!(
            store
                .credential_health("credential")
                .expect("health lookup")
                .expect("health")
                .failure_count,
            3
        );
        assert_eq!(
            store
                .cooldown("credential", "credential", 2)
                .expect("cooldown lookup")
                .expect("cooldown")
                .until,
            100
        );
        assert!(store
            .session_affinity("session", 2)
            .expect("affinity lookup")
            .is_some());
        assert_eq!(
            store.recent_decisions(1).expect("decision lookup")[0].request_id,
            "request"
        );
    }

    #[test]
    fn credential_deletion_and_retention_remove_dependent_state() {
        let store = SqliteStore::open_in_memory_with_retention(policy(1, 8, 8)).expect("store");
        store
            .upsert_credential_state(CredentialState::new("old", "provider", true, 1))
            .expect("old credential");
        store
            .upsert_credential_health(CredentialHealthState::new(
                "old",
                CredentialHealthStatus::CoolingDown,
                2,
            ))
            .expect("old health");
        store
            .upsert_session_affinity(SessionAffinity::new(
                "old-session",
                "provider",
                "old",
                "model",
                1,
                100,
            ))
            .expect("old affinity");
        store
            .upsert_cooldown(CooldownState::new("credential", "old", 100, 2))
            .expect("old cooldown");
        store
            .upsert_cooldown(CooldownState::new("credential_model", "old:model", 100, 2))
            .expect("old model cooldown");
        store
            .upsert_cooldown(CooldownState::new("provider", "provider", 100, 2))
            .expect("provider cooldown");

        // Credential retention uses the same dependency cleanup as explicit
        // deletion.
        store
            .upsert_credential_state(CredentialState::new("new", "provider", true, 2))
            .expect("new credential");
        assert!(store.credential_state("old").expect("old state").is_none());
        assert!(store
            .credential_health("old")
            .expect("old health")
            .is_none());
        assert!(store
            .session_affinity("old-session", 2)
            .expect("old affinity")
            .is_none());
        assert!(store
            .cooldown("credential", "old", 2)
            .expect("cooldown")
            .is_none());
        assert!(store
            .cooldown("credential_model", "old:model", 2)
            .expect("model cooldown")
            .is_none());
        assert!(store
            .cooldown("provider", "provider", 2)
            .expect("provider cooldown")
            .is_some());

        store
            .upsert_credential_health(CredentialHealthState::new(
                "new",
                CredentialHealthStatus::Healthy,
                3,
            ))
            .expect("new health");
        store
            .upsert_session_affinity(SessionAffinity::new(
                "new-session",
                "provider",
                "new",
                "model",
                3,
                100,
            ))
            .expect("new affinity");
        store
            .upsert_cooldown(CooldownState::new("credential", "new", 100, 3))
            .expect("new cooldown");
        assert!(store
            .remove_credential_state("new")
            .expect("remove credential"));
        assert!(store
            .credential_health("new")
            .expect("new health")
            .is_none());
        assert!(store
            .session_affinity("new-session", 3)
            .expect("new affinity")
            .is_none());
        assert!(store
            .cooldown("credential", "new", 3)
            .expect("new cooldown")
            .is_none());
        assert_eq!(
            store.upsert_credential_health(CredentialHealthState::new(
                "new",
                CredentialHealthStatus::Healthy,
                4,
            )),
            Err(StoreError::CredentialNotFound("new".to_owned()))
        );
        assert_eq!(
            store.upsert_cooldown(CooldownState::new("credential", "new", 100, 4)),
            Err(StoreError::CredentialNotFound("new".to_owned()))
        );
        assert_eq!(
            store.upsert_session_affinity(SessionAffinity::new(
                "late-session",
                "provider",
                "new",
                "model",
                4,
                100,
            )),
            Err(StoreError::CredentialNotFound("new".to_owned()))
        );

        let collision_store = SqliteStore::open_in_memory().expect("collision store");
        collision_store
            .upsert_credential_state(CredentialState::new("a", "provider", true, 1))
            .expect("short credential");
        collision_store
            .upsert_credential_state(CredentialState::new("a:b", "provider", true, 1))
            .expect("long credential");
        collision_store
            .upsert_cooldown(CooldownState::new(
                "credential_model",
                "v2:3:5:a:bmodel",
                100,
                1,
            ))
            .expect("long credential cooldown");
        collision_store
            .remove_credential_state("a")
            .expect("remove short credential");
        assert!(collision_store
            .cooldown("credential_model", "v2:3:5:a:bmodel", 2)
            .expect("long cooldown lookup")
            .is_some());
        collision_store
            .remove_credential_state("a:b")
            .expect("remove long credential");
        assert!(collision_store
            .cooldown("credential_model", "v2:3:5:a:bmodel", 2)
            .expect("removed cooldown lookup")
            .is_none());
    }

    #[test]
    fn sqlite_expiry_is_applied_after_restart() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let store = SqliteStore::open(&path).expect("open store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_cooldown(CooldownState::new("provider", "provider", 10, 1))
            .expect("cooldown");
        store
            .upsert_session_affinity(affinity("session", 1, 10))
            .expect("affinity");
        drop(store);
        let store = SqliteStore::open(&path).expect("reopen");
        assert!(store
            .cooldown("provider", "provider", 10)
            .expect("lookup")
            .is_none());
        assert!(store
            .session_affinity("session", 10)
            .expect("lookup")
            .is_none());
    }

    #[test]
    fn encrypted_payload_is_opaque_and_survives_restart() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let key = MasterKey::from_bytes(b"persisted master key").expect("master key");
        let payload = CredentialPayload::new(b"refresh-token-value").expect("payload");
        {
            let store = SqliteStore::open_encrypted(&path, key.clone()).expect("open store");
            store
                .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
                .expect("credential");
            store
                .upsert_credential_payload("credential", &payload, 2)
                .expect("payload");
        }

        let raw = Connection::open(&path).expect("raw database");
        let envelope: Vec<u8> = raw
            .query_row(
                "SELECT envelope FROM credential_payloads WHERE credential_id = 'credential'",
                [],
                |row| row.get(0),
            )
            .expect("envelope");
        assert!(!envelope
            .windows(b"refresh-token-value".len())
            .any(|window| window == b"refresh-token-value"));
        drop(raw);

        let store = SqliteStore::open_encrypted(&path, key).expect("restart");
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("load")
                .expect("payload"),
            payload
        );
    }

    #[test]
    fn encrypted_payload_rotation_is_atomic_and_rejects_old_key() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let old_key = MasterKey::from_bytes(b"old persisted key").expect("old key");
        let new_key = MasterKey::from_bytes(b"new persisted key").expect("new key");
        let store = SqliteStore::open_encrypted(&path, old_key.clone()).expect("open store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_credential_payload(
                "credential",
                &CredentialPayload::new(b"refresh-token-value").expect("payload"),
                2,
            )
            .expect("payload");
        assert_eq!(store.rotate_master_key(new_key.clone()).expect("rotate"), 1);
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("load after rotate")
                .expect("payload")
                .as_bytes(),
            b"refresh-token-value"
        );
        drop(store);

        assert!(matches!(
            SqliteStore::open_encrypted(&path, old_key),
            Err(StoreError::WrongMasterKey)
        ));
        let new_store = SqliteStore::open_encrypted(&path, new_key).expect("new open");
        assert!(new_store
            .credential_payload("credential")
            .expect("new load")
            .is_some());
    }

    #[test]
    fn master_key_rotation_reencrypts_all_encrypted_ledgers_and_rebuilds_indexes() {
        let directory = private_tempdir();
        let path = directory.path().join("all-encrypted.sqlite");
        let old_key = MasterKey::from_bytes(b"all-ledger-old-key").expect("old key");
        let new_key = MasterKey::from_bytes(b"all-ledger-new-key").expect("new key");
        let store = SqliteStore::open_encrypted(&path, old_key.clone()).expect("open store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        let payload = CredentialPayload::new(b"refresh-token-value").expect("payload");
        store
            .upsert_credential_payload("credential", &payload, 2)
            .expect("credential payload");
        let event = store
            .append_request_event(RequestEvent::new(
                "request-before-rotation",
                0,
                RequestEventKind::Completion,
                "listener",
                "route",
                3,
            ))
            .expect("request event");
        let usage = store
            .append_usage_record(UsageRecord::new(
                4,
                "request-before-rotation",
                "route",
                "success",
            ))
            .expect("usage record");

        assert_eq!(store.rotate_master_key(new_key.clone()).expect("rotate"), 3);
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("credential after rotation")
                .expect("credential payload"),
            payload
        );
        assert_eq!(
            store
                .request_events_for("request-before-rotation")
                .expect("request timeline after rotation"),
            vec![event.clone()]
        );
        assert_eq!(
            store.usage_records().expect("usage after rotation"),
            vec![usage.clone()]
        );
        drop(store);

        assert!(matches!(
            SqliteStore::open_encrypted(&path, old_key),
            Err(StoreError::WrongMasterKey)
        ));

        let reopened = SqliteStore::open_encrypted(&path, new_key).expect("new-key reopen");
        assert_eq!(
            reopened
                .request_events_for("request-before-rotation")
                .expect("request timeline after restart"),
            vec![event]
        );
        assert_eq!(
            reopened.usage_records().expect("usage after restart"),
            vec![usage]
        );
    }

    #[test]
    fn master_key_rotation_rolls_back_before_switching_active_key() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"atomic-rotation-old-key").expect("old key"),
        )
        .expect("store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_credential_payload(
                "credential",
                &CredentialPayload::new(b"credential-token").expect("payload"),
                1,
            )
            .expect("credential payload");
        store
            .append_request_event(RequestEvent::new(
                "request",
                0,
                RequestEventKind::Attempt,
                "listener",
                "route",
                1,
            ))
            .expect("request event");
        store
            .append_usage_record(UsageRecord::new(1, "request", "route", "success"))
            .expect("usage record");
        {
            let connection = store.connection.lock().expect("connection");
            connection
                .execute("UPDATE usage_records SET envelope = X'00' WHERE id = 1", [])
                .expect("tamper usage row");
        }

        assert_eq!(
            store.rotate_master_key(
                MasterKey::from_bytes(b"atomic-rotation-new-key").expect("new key")
            ),
            Err(StoreError::InvalidCredentialEnvelope)
        );
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("credential remains under old key")
                .expect("payload")
                .as_bytes(),
            b"credential-token"
        );
        assert!(matches!(
            store.request_events(),
            Ok(events) if events.len() == 1
        ));
    }

    #[test]
    fn stale_sqlite_instance_is_fenced_after_rotation() {
        let directory = private_tempdir();
        let path = directory.path().join("rotation-fence.sqlite");
        let old_key = MasterKey::from_bytes(b"rotation-fence-old-key").expect("old key");
        let new_key = MasterKey::from_bytes(b"rotation-fence-new-key").expect("new key");
        {
            let store = SqliteStore::open_encrypted(&path, old_key.clone()).expect("store");
            store
                .append_request_event(RequestEvent::new(
                    "before-rotation",
                    0,
                    RequestEventKind::Admission,
                    "listener",
                    "route",
                    1,
                ))
                .expect("request event");
            store
                .append_usage_record(UsageRecord::new(1, "before-rotation", "route", "success"))
                .expect("usage record");
        }

        let rotating = SqliteStore::open_encrypted(&path, old_key.clone()).expect("rotating");
        let stale = SqliteStore::open_encrypted(&path, old_key).expect("stale");
        rotating.rotate_master_key(new_key.clone()).expect("rotate");

        assert_eq!(
            stale.append_request_event(RequestEvent::new(
                "after-rotation",
                0,
                RequestEventKind::Admission,
                "listener",
                "route",
                2,
            )),
            Err(StoreError::WrongMasterKey)
        );
        assert_eq!(
            stale.append_usage_record(UsageRecord::new(2, "after-rotation", "route", "success")),
            Err(StoreError::WrongMasterKey)
        );
        assert_eq!(stale.request_events(), Err(StoreError::WrongMasterKey));
        assert_eq!(stale.usage_records(), Err(StoreError::WrongMasterKey));

        let current = SqliteStore::open_encrypted(&path, new_key).expect("current");
        assert_eq!(current.request_events().expect("events").len(), 1);
        assert_eq!(current.usage_records().expect("usage").len(), 1);
    }

    fn assert_mutations_are_fenced(store: &SqliteStore, expected: StoreError) {
        assert_eq!(
            store.upsert_credential_state(CredentialState::new(
                "attacker-credential",
                "provider",
                true,
                200,
            )),
            Err(expected.clone())
        );
        assert_eq!(
            store.set_credential_enabled("victim", false, 200),
            Err(expected.clone())
        );
        assert_eq!(
            store.switch_credential("victim", &["sibling".to_owned()], 200),
            Err(expected.clone())
        );
        assert_eq!(
            store.remove_credential_state("victim"),
            Err(expected.clone())
        );
        assert_eq!(
            store.upsert_credential_health(CredentialHealthState::new(
                "victim",
                CredentialHealthStatus::Disabled,
                200,
            )),
            Err(expected.clone())
        );
        assert_eq!(
            store.upsert_cooldown(CooldownState::new("provider", "provider", 300, 200,)),
            Err(expected.clone())
        );
        assert_eq!(
            store.cooldown("provider", "provider", 200),
            Err(expected.clone())
        );
        assert_eq!(store.cooldowns(200), Err(expected.clone()));
        assert_eq!(
            store.remove_cooldown("provider", "provider"),
            Err(expected.clone())
        );
        assert_eq!(
            store.upsert_session_affinity(SessionAffinity::new(
                "attacker-session",
                "provider",
                "victim",
                "model",
                200,
                300,
            )),
            Err(expected.clone())
        );
        assert_eq!(
            store.session_affinity("protected-session", 200),
            Err(expected.clone())
        );
        assert_eq!(store.session_affinities(200), Err(expected.clone()));
        assert_eq!(
            store.remove_session_affinity("protected-session"),
            Err(expected.clone())
        );
        assert_eq!(
            store.append_decision(DecisionRecord::new(
                "attacker-decision",
                "route",
                "model",
                200,
            )),
            Err(expected.clone())
        );
        assert_eq!(
            store.upsert_credential_payload(
                "victim",
                &CredentialPayload::new(b"attacker-token").expect("payload"),
                200,
            ),
            Err(expected.clone())
        );
        assert_eq!(
            store.compare_and_swap_credential_payload(
                "victim",
                1,
                &CredentialPayload::new(b"attacker-token").expect("payload"),
                200,
            ),
            Err(expected.clone())
        );
        assert_eq!(
            store.remove_credential_payload("victim"),
            Err(expected.clone())
        );
        assert_eq!(
            store.append_request_event(RequestEvent::new(
                "attacker-request",
                0,
                RequestEventKind::Admission,
                "listener",
                "route",
                200,
            )),
            Err(expected.clone())
        );
        assert_eq!(
            store.append_usage_record(UsageRecord::new(
                200,
                "attacker-request",
                "route",
                "success",
            )),
            Err(expected.clone())
        );
        assert_eq!(store.prune(200), Err(expected.clone()));
        assert_eq!(
            store.rotate_master_key(
                MasterKey::from_bytes(b"attacker-rotation-key").expect("master key")
            ),
            Err(expected)
        );
    }

    #[test]
    fn encrypted_store_fences_every_mutation_after_key_rotation() {
        let directory = private_tempdir();
        let path = directory.path().join("all-mutation-fence.sqlite");
        let retention = policy(2, 1, 1)
            .with_request_history(1, 100)
            .expect("request retention")
            .with_usage_history(1, 100)
            .expect("usage retention");
        let old_key = MasterKey::from_bytes(b"all-mutation-old-key").expect("old key");
        let new_key = MasterKey::from_bytes(b"all-mutation-new-key").expect("new key");
        let rotating =
            SqliteStore::open_encrypted_with_retention(&path, retention, old_key.clone())
                .expect("rotating store");
        rotating
            .upsert_credential_state(CredentialState::new("victim", "provider", true, 1))
            .expect("victim credential");
        rotating
            .upsert_credential_payload(
                "victim",
                &CredentialPayload::new(b"protected-token").expect("payload"),
                1,
            )
            .expect("victim payload");
        rotating
            .upsert_credential_state(CredentialState::new("sibling", "provider", false, 2))
            .expect("sibling credential");
        rotating
            .upsert_credential_health(CredentialHealthState::new(
                "victim",
                CredentialHealthStatus::Healthy,
                2,
            ))
            .expect("health");
        rotating
            .upsert_cooldown(CooldownState::new("provider", "provider", 100, 2))
            .expect("cooldown");
        rotating
            .upsert_session_affinity(SessionAffinity::new(
                "protected-session",
                "provider",
                "victim",
                "model",
                2,
                100,
            ))
            .expect("affinity");
        rotating
            .append_decision(DecisionRecord::new(
                "protected-decision",
                "route",
                "model",
                2,
            ))
            .expect("decision");
        rotating
            .append_request_event(RequestEvent::new(
                "protected-request",
                0,
                RequestEventKind::Admission,
                "listener",
                "route",
                2,
            ))
            .expect("request event");
        rotating
            .append_usage_record(UsageRecord::new(2, "protected-request", "route", "success"))
            .expect("usage record");

        let stale = SqliteStore::open_encrypted_with_retention(&path, retention, old_key)
            .expect("stale store");
        let no_key = SqliteStore::open_with_retention(&path, retention).expect("no-key store");
        rotating.rotate_master_key(new_key.clone()).expect("rotate");

        assert_mutations_are_fenced(&stale, StoreError::WrongMasterKey);
        assert_mutations_are_fenced(&no_key, StoreError::EncryptionRequired);
        assert!(matches!(
            SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"all-mutation-wrong-key").expect("wrong key"),
            ),
            Err(StoreError::WrongMasterKey)
        ));

        let current = SqliteStore::open_encrypted(&path, new_key).expect("current store");
        assert_eq!(
            current.len().expect("lengths"),
            StoreLengths {
                credentials: 2,
                affinities: 1,
                decisions: 1,
                request_events: 1,
                usage_records: 1,
            }
        );
        assert_eq!(
            current
                .credential_payload("victim")
                .expect("payload lookup")
                .expect("payload")
                .as_bytes(),
            b"protected-token"
        );
        assert!(current
            .credential_health("victim")
            .expect("health lookup")
            .is_some());
        assert!(current
            .cooldown("provider", "provider", 3)
            .expect("cooldown lookup")
            .is_some());
        assert!(current
            .session_affinity("protected-session", 3)
            .expect("affinity lookup")
            .is_some());
        assert_eq!(
            current.decisions().expect("decisions")[0].request_id,
            "protected-decision"
        );
        assert_eq!(
            current.request_events().expect("request events")[0].request_id,
            "protected-request"
        );
        assert_eq!(
            current.usage_records().expect("usage records")[0].request_id,
            "protected-request"
        );
    }

    #[test]
    fn stale_multi_instance_cas_is_rejected_without_overwriting_new_tokens() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let key = MasterKey::from_bytes(b"multi-instance cas key").expect("key");
        {
            let store = SqliteStore::open_encrypted(&path, key.clone()).expect("open");
            store
                .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
                .expect("metadata");
            store
                .upsert_credential_payload(
                    "credential",
                    &CredentialPayload::new(b"original-token").expect("payload"),
                    1,
                )
                .expect("payload");
        }

        let first = SqliteStore::open_encrypted(&path, key.clone()).expect("first instance");
        let second = SqliteStore::open_encrypted(&path, key).expect("second instance");
        let first_revision = first
            .credential_state("credential")
            .expect("first state")
            .expect("state")
            .revision;
        let second_revision = second
            .credential_state("credential")
            .expect("second state")
            .expect("state")
            .revision;
        assert_eq!(first_revision, second_revision);
        first
            .compare_and_swap_credential_payload(
                "credential",
                first_revision,
                &CredentialPayload::new(b"first-token").expect("payload"),
                2,
            )
            .expect("first CAS");
        assert_eq!(
            second.compare_and_swap_credential_payload(
                "credential",
                second_revision,
                &CredentialPayload::new(b"stale-token").expect("payload"),
                3,
            ),
            Err(StoreError::CredentialRevisionConflict)
        );
        assert_eq!(
            second
                .credential_payload("credential")
                .expect("payload lookup")
                .expect("payload")
                .as_bytes(),
            b"first-token"
        );
    }

    #[test]
    fn cas_payload_failure_rolls_back_metadata_revision() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let key = MasterKey::from_bytes(b"cas rollback key").expect("key");
        {
            let store = SqliteStore::open_encrypted(&path, key.clone()).expect("open");
            store
                .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
                .expect("metadata");
            store
                .upsert_credential_payload(
                    "credential",
                    &CredentialPayload::new(b"original-token").expect("payload"),
                    1,
                )
                .expect("payload");
        }
        let raw = Connection::open(&path).expect("raw database");
        raw.execute_batch(
            "CREATE TRIGGER reject_payload_update
             BEFORE UPDATE ON credential_payloads
             BEGIN SELECT RAISE(ABORT, 'payload write rejected'); END;",
        )
        .expect("trigger");
        drop(raw);

        let store = SqliteStore::open_encrypted(&path, key).expect("reopen");
        assert!(matches!(
            store.compare_and_swap_credential_payload(
                "credential",
                1,
                &CredentialPayload::new(b"replacement-token").expect("payload"),
                2,
            ),
            Err(StoreError::Sqlite(_))
        ));
        assert_eq!(
            store
                .credential_state("credential")
                .expect("state lookup")
                .expect("state")
                .revision,
            1
        );
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("payload lookup")
                .expect("payload")
                .as_bytes(),
            b"original-token"
        );
    }

    #[test]
    fn wrong_master_key_open_does_not_mutate_existing_token_or_revision() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let correct_key = MasterKey::from_bytes(b"correct cas key").expect("key");
        {
            let store = SqliteStore::open_encrypted(&path, correct_key.clone()).expect("open");
            store
                .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
                .expect("metadata");
            store
                .upsert_credential_payload(
                    "credential",
                    &CredentialPayload::new(b"original-token").expect("payload"),
                    1,
                )
                .expect("payload");
        }
        assert!(matches!(
            SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"wrong cas key").expect("wrong key"),
            ),
            Err(StoreError::WrongMasterKey)
        ));

        let store = SqliteStore::open_encrypted(&path, correct_key).expect("correct reopen");
        assert_eq!(
            store
                .credential_state("credential")
                .expect("state lookup")
                .expect("state")
                .revision,
            1
        );
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("payload lookup")
                .expect("payload")
                .as_bytes(),
            b"original-token"
        );
    }

    #[test]
    fn encrypted_payload_tampering_fails_closed() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let key = MasterKey::from_bytes(b"tamper test key").expect("key");
        let store = SqliteStore::open_encrypted(&path, key.clone()).expect("open store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_credential_payload(
                "credential",
                &CredentialPayload::new(b"secret-value").expect("payload"),
                2,
            )
            .expect("payload");
        drop(store);

        let raw = Connection::open(&path).expect("raw database");
        let mut envelope: Vec<u8> = raw
            .query_row(
                "SELECT envelope FROM credential_payloads WHERE credential_id = 'credential'",
                [],
                |row| row.get(0),
            )
            .expect("envelope");
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        raw.execute(
            "UPDATE credential_payloads SET envelope = ?1 WHERE credential_id = 'credential'",
            params![envelope],
        )
        .expect("tamper");
        drop(raw);

        let store = SqliteStore::open_encrypted(&path, key).expect("reopen");
        assert_eq!(
            store.credential_payload("credential"),
            Err(StoreError::CredentialEnvelopeAuthenticationFailed)
        );
    }

    #[test]
    fn unencrypted_store_rejects_credential_payloads() {
        let store = SqliteStore::open_in_memory().expect("store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        let payload = CredentialPayload::new(b"secret-value").expect("payload");
        assert_eq!(
            store.upsert_credential_payload("credential", &payload, 2),
            Err(StoreError::EncryptionRequired)
        );
        assert_eq!(
            store.credential_payload("credential"),
            Err(StoreError::EncryptionRequired)
        );
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_rejects_non_private_wal_sidecar() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let sidecar = PathBuf::from(format!("{}-wal", path.display()));
        std::fs::write(&sidecar, []).expect("sidecar");
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644))
            .expect("sidecar permissions");
        assert!(matches!(
            SqliteStore::open(&path),
            Err(StoreError::UnsafePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_rejects_non_private_existing_database() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        std::fs::write(&path, []).expect("database placeholder");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        assert!(matches!(
            SqliteStore::open(&path),
            Err(StoreError::UnsafePath(_))
        ));
    }

    #[test]
    fn migration_failure_rolls_back_every_statement() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let connection = Connection::open(&path).expect("create database");
        connection
            .execute_batch(MIGRATIONS[0].1)
            .expect("apply first migration");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("set version");
        connection
            .execute_batch("CREATE VIEW cooldowns AS SELECT 1 AS scope")
            .expect("create conflicting view");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set database permissions");
        }

        assert!(matches!(
            SqliteStore::open(&path),
            Err(StoreError::Migration { version: 2, .. })
        ));
        let connection = Connection::open(&path).expect("reopen raw database");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read version");
        assert_eq!(version, 1);
        let health_exists: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'credential_health'",
                [],
                |row| row.get(0),
            )
            .optional()
            .expect("inspect schema");
        assert!(health_exists.is_none());
    }

    #[test]
    fn wrong_key_first_v6_upgrade_does_not_claim_encryption_fence() {
        let directory = private_tempdir();
        let path = directory.path().join("v6-encrypted.sqlite");
        let correct_key = MasterKey::from_bytes(b"v6-upgrade-correct-key").expect("key");
        let cipher = CredentialCipher::new(correct_key.clone());
        let connection = Connection::open(&path).expect("create database");
        for &(version, sql) in MIGRATIONS.iter().take(6) {
            connection
                .execute_batch(sql)
                .expect("apply legacy migration");
            connection
                .pragma_update(None, "user_version", version)
                .expect("set legacy version");
        }
        connection
            .execute(
                "INSERT INTO credentials
                 (credential_id, provider_id, enabled, updated_at, revision)
                 VALUES ('credential', 'provider', 1, 1, 1)",
                [],
            )
            .expect("credential");
        let credential_envelope = cipher
            .seal_for(
                &CredentialPayload::new(b"credential-token").expect("payload"),
                b"credential",
            )
            .expect("credential envelope");
        connection
            .execute(
                "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                 VALUES ('credential', ?1, 1)",
                params![credential_envelope],
            )
            .expect("credential payload");
        let mut event = RequestEvent::new(
            "legacy-request",
            0,
            RequestEventKind::Completion,
            "listener",
            "route",
            1,
        );
        event.id = 1;
        let event_envelope = encrypt_request_event(&cipher, &event).expect("event envelope");
        connection
            .execute(
                "INSERT INTO request_events (recorded_at, envelope)
                 VALUES (1, ?1)",
                params![event_envelope],
            )
            .expect("request event");
        let mut usage = UsageRecord::new(1, "legacy-request", "route", "success");
        usage.id = 1;
        let usage_envelope = encrypt_usage_record(&cipher, &usage).expect("usage envelope");
        connection
            .execute(
                "INSERT INTO usage_records (recorded_at, envelope)
                 VALUES (1, ?1)",
                params![usage_envelope],
            )
            .expect("usage record");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("database permissions");
        }

        assert!(matches!(
            SqliteStore::open_encrypted(
                &path,
                MasterKey::from_bytes(b"v6-upgrade-wrong-key").expect("wrong key")
            ),
            Err(StoreError::WrongMasterKey)
        ));
        let store = SqliteStore::open_encrypted(&path, correct_key).expect("correct key");
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("payload")
                .expect("credential")
                .as_bytes(),
            b"credential-token"
        );
        assert_eq!(
            store
                .request_events_for("legacy-request")
                .expect("legacy timeline")
                .len(),
            1
        );
        assert_eq!(store.usage_records().expect("legacy usage").len(), 1);
        let connection = store.connection.lock().expect("connection");
        let indexed: (bool, bool) = connection
            .query_row(
                "SELECT request_index IS NOT NULL, event_index IS NOT NULL
                 FROM request_events WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("backfilled indexes");
        assert_eq!(indexed, (true, true));
    }

    #[test]
    fn v5_upgrade_backfills_legacy_request_indexes() {
        let directory = private_tempdir();
        let path = directory.path().join("v5-request-history.sqlite");
        let key = MasterKey::from_bytes(b"v5-upgrade-key").expect("key");
        let cipher = CredentialCipher::new(key.clone());
        let connection = Connection::open(&path).expect("create database");
        for &(version, sql) in MIGRATIONS.iter().take(5) {
            connection
                .execute_batch(sql)
                .expect("apply legacy migration");
            connection
                .pragma_update(None, "user_version", version)
                .expect("set legacy version");
        }
        let mut event = RequestEvent::new(
            "v5-request",
            0,
            RequestEventKind::Completion,
            "listener",
            "route",
            1,
        );
        event.id = 1;
        let envelope = encrypt_request_event(&cipher, &event).expect("event envelope");
        connection
            .execute(
                "INSERT INTO request_events (recorded_at, envelope) VALUES (1, ?1)",
                params![envelope],
            )
            .expect("event");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("database permissions");
        }

        let store = SqliteStore::open_encrypted(&path, key).expect("upgrade");
        assert_eq!(
            store
                .request_events_for("v5-request")
                .expect("timeline")
                .len(),
            1
        );
        let connection = store.connection.lock().expect("connection");
        let indexed: (bool, bool) = connection
            .query_row(
                "SELECT request_index IS NOT NULL, event_index IS NOT NULL
                 FROM request_events WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("backfilled indexes");
        assert_eq!(indexed, (true, true));
    }

    #[test]
    fn request_history_is_encrypted_bounded_and_authenticated() {
        let directory = private_tempdir();
        let path = directory.path().join("requests.sqlite");
        let key_bytes = b"request-history-test-master-key";
        let retention = policy(4, 4, 4)
            .with_request_history(8, 1_000)
            .expect("request retention");
        let store = SqliteStore::open_encrypted_with_retention(
            &path,
            retention,
            MasterKey::from_bytes(key_bytes).expect("master key"),
        )
        .expect("encrypted store");
        let mut event = RequestEvent::new(
            "request-secret-sentinel",
            0,
            crate::RequestEventKind::Selection,
            "listener-secret-sentinel",
            "route-secret-sentinel",
            100,
        );
        event.provider = Some("provider-secret-sentinel".to_owned());
        let persisted = store.append_request_event(event).expect("encrypted event");
        assert_eq!(persisted.id, 1);
        drop(store);

        let mut raw = fs::read(&path).expect("database bytes");
        let wal = path.with_extension("sqlite-wal");
        if wal.exists() {
            raw.extend(fs::read(wal).expect("WAL bytes"));
        }
        for sentinel in [
            b"request-secret-sentinel".as_slice(),
            b"listener-secret-sentinel".as_slice(),
            b"provider-secret-sentinel".as_slice(),
        ] {
            assert!(!raw.windows(sentinel.len()).any(|window| window == sentinel));
        }

        let reopened = SqliteStore::open_encrypted_with_retention(
            &path,
            retention,
            MasterKey::from_bytes(key_bytes).expect("reopen key"),
        )
        .expect("reopen encrypted store");
        let events = reopened
            .request_events_for("request-secret-sentinel")
            .expect("decrypted timeline");
        assert_eq!(events, vec![persisted]);

        let unencrypted = SqliteStore::open_in_memory().expect("plain store");
        assert_eq!(
            unencrypted.append_request_event(RequestEvent::new(
                "request",
                0,
                crate::RequestEventKind::Admission,
                "listener",
                "route",
                1,
            )),
            Err(StoreError::EncryptionRequired)
        );
    }

    #[test]
    fn request_timeline_merges_legacy_and_indexed_rows_after_migration() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"mixed-request-history-key").expect("master key"),
        )
        .expect("store");
        let legacy = store
            .append_request_event(RequestEvent::new(
                "mixed-request",
                0,
                RequestEventKind::Admission,
                "listener",
                "route",
                1,
            ))
            .expect("legacy event");
        let indexed = store
            .append_request_event(RequestEvent::new(
                "mixed-request",
                1,
                RequestEventKind::Completion,
                "listener",
                "route",
                2,
            ))
            .expect("indexed event");
        {
            let connection = store.connection.lock().expect("connection");
            connection
                .execute(
                    "UPDATE request_events
                     SET request_index = NULL, event_index = NULL WHERE id = ?1",
                    [legacy.id],
                )
                .expect("mark pre-migration row");
        }

        assert_eq!(
            store
                .request_events_for("mixed-request")
                .expect("mixed timeline"),
            vec![legacy, indexed]
        );
    }

    #[test]
    fn request_history_cap_counts_legacy_and_indexed_rows_together() {
        let retention = policy(4, 4, 4)
            .with_request_history(128, 1_000_000)
            .expect("request retention");
        let store = SqliteStore::open_in_memory_encrypted_with_retention(
            retention,
            MasterKey::from_bytes(b"mixed-request-cap-key").expect("master key"),
        )
        .expect("encrypted store");
        for event_index in 0..MAX_REQUEST_EVENTS_PER_REQUEST as u32 {
            store
                .append_request_event(RequestEvent::new(
                    "mixed-cap",
                    event_index,
                    RequestEventKind::Attempt,
                    "listener",
                    "route",
                    u64::from(event_index),
                ))
                .expect("legacy candidate");
        }
        {
            let connection = store.connection.lock().expect("connection");
            connection
                .execute(
                    "UPDATE request_events SET request_index = NULL, event_index = NULL",
                    [],
                )
                .expect("mark legacy rows");
        }
        for event_index in
            MAX_REQUEST_EVENTS_PER_REQUEST as u32..(MAX_REQUEST_EVENTS_PER_REQUEST as u32 + 5)
        {
            store
                .append_request_event(RequestEvent::new(
                    "mixed-cap",
                    event_index,
                    RequestEventKind::Completion,
                    "listener",
                    "route",
                    u64::from(event_index),
                ))
                .expect("indexed candidate");
        }
        let events = store.request_events_for("mixed-cap").expect("timeline");
        assert_eq!(events.len(), MAX_REQUEST_EVENTS_PER_REQUEST);
        assert_eq!(events.first().map(|event| event.event_index), Some(5));
        assert_eq!(events.last().map(|event| event.event_index), Some(68));
    }

    #[test]
    fn request_history_retention_uses_event_order_without_cross_request_scans() {
        let retention = policy(4, 4, 4)
            .with_request_history(128, 1_000_000)
            .expect("request retention");
        let store = SqliteStore::open_in_memory_encrypted_with_retention(
            retention,
            MasterKey::from_bytes(b"request-history-index-master-key").expect("master key"),
        )
        .expect("encrypted store");

        for event_index in 0..(MAX_REQUEST_EVENTS_PER_REQUEST as u32 + 5) {
            store
                .append_request_event(RequestEvent::new(
                    "one",
                    event_index,
                    RequestEventKind::Attempt,
                    "listener",
                    "route",
                    u64::from(event_index),
                ))
                .expect("request event");
        }
        let events = store.request_events_for("one").expect("request timeline");
        assert_eq!(events.len(), MAX_REQUEST_EVENTS_PER_REQUEST);
        assert_eq!(events.first().map(|event| event.event_index), Some(5));
        assert_eq!(events.last().map(|event| event.event_index), Some(68));
        store
            .append_request_event(RequestEvent::new(
                "one",
                2,
                RequestEventKind::Retry,
                "listener",
                "route",
                69,
            ))
            .expect("out-of-order event");
        assert_eq!(
            store
                .request_events_for("one")
                .expect("bounded timeline")
                .len(),
            MAX_REQUEST_EVENTS_PER_REQUEST
        );

        store
            .append_request_event(RequestEvent::new(
                "two",
                0,
                RequestEventKind::Admission,
                "listener",
                "route",
                100,
            ))
            .expect("unrelated request event");
        {
            let connection = store.connection.lock().expect("connection");
            connection
                .execute(
                    "UPDATE request_events SET envelope = X'00'
                     WHERE id = (SELECT id FROM request_events WHERE event_index = 68)",
                    [],
                )
                .expect("tamper unrelated event");
        }
        store
            .append_request_event(RequestEvent::new(
                "two",
                1,
                RequestEventKind::Completion,
                "listener",
                "route",
                101,
            ))
            .expect("indexed retention must not decrypt unrelated events");
        assert_eq!(
            store
                .request_events_for("two")
                .expect("unrelated timeline remains readable")
                .len(),
            2
        );
    }

    #[test]
    fn concurrent_request_history_writes_remain_bounded_and_ordered() {
        let retention = policy(8, 8, 8)
            .with_request_history(8, 1_000_000)
            .expect("request retention");
        let store = Arc::new(
            SqliteStore::open_in_memory_encrypted_with_retention(
                retention,
                MasterKey::from_bytes(b"request-history-concurrency-master-key")
                    .expect("master key"),
            )
            .expect("encrypted store"),
        );
        let mut threads = Vec::new();
        for worker in 0..16 {
            let store = Arc::clone(&store);
            threads.push(thread::spawn(move || {
                store
                    .append_request_event(RequestEvent::new(
                        format!("request-{worker}"),
                        0,
                        RequestEventKind::Admission,
                        "listener",
                        "route",
                        worker,
                    ))
                    .expect("request event");
            }));
        }
        for thread in threads {
            thread.join().expect("request writer");
        }
        let events = store.request_events().expect("request history");
        assert_eq!(events.len(), retention.max_request_events);
        assert!(events.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert!(events
            .iter()
            .all(|event| event.request_id.starts_with("request-")));
    }

    #[test]
    fn usage_ledger_is_encrypted_bounded_and_restart_safe() {
        let directory = private_tempdir();
        let path = directory.path().join("usage.sqlite");
        let key_bytes = b"usage-ledger-test-master-key";
        let retention = policy(4, 4, 4)
            .with_usage_history(2, 100)
            .expect("usage retention");
        let store = SqliteStore::open_encrypted_with_retention(
            &path,
            retention,
            MasterKey::from_bytes(key_bytes).expect("master key"),
        )
        .expect("encrypted store");
        let mut record = UsageRecord::new(
            100,
            "usage-request-secret-sentinel",
            "usage-route-secret-sentinel",
            "success",
        );
        record.provider = Some("usage-provider-secret-sentinel".to_owned());
        record.input_tokens = Some(7);
        let persisted = store.append_usage_record(record).expect("encrypted usage");
        drop(store);

        let mut raw = fs::read(&path).expect("database bytes");
        let wal = path.with_extension("sqlite-wal");
        if wal.exists() {
            raw.extend(fs::read(wal).expect("WAL bytes"));
        }
        for sentinel in [
            b"usage-request-secret-sentinel".as_slice(),
            b"usage-route-secret-sentinel".as_slice(),
            b"usage-provider-secret-sentinel".as_slice(),
        ] {
            assert!(!raw.windows(sentinel.len()).any(|window| window == sentinel));
        }

        let reopened = SqliteStore::open_encrypted_with_retention(
            &path,
            retention,
            MasterKey::from_bytes(key_bytes).expect("reopen key"),
        )
        .expect("reopen encrypted store");
        assert_eq!(
            reopened.usage_records().expect("decrypted usage"),
            vec![persisted.clone()]
        );
        let newer = reopened
            .append_usage_record(UsageRecord::new(200, "newer-request", "route", "success"))
            .expect("newer usage");
        reopened
            .append_usage_record(UsageRecord::new(
                0,
                "out-of-order-stale",
                "route",
                "success",
            ))
            .expect("stale usage accepted then pruned");
        assert_eq!(
            reopened.usage_records().expect("retained usage"),
            vec![persisted, newer]
        );

        let unencrypted = SqliteStore::open_in_memory().expect("plain store");
        assert_eq!(
            unencrypted.append_usage_record(UsageRecord::new(1, "request", "route", "success",)),
            Err(StoreError::EncryptionRequired)
        );
    }

    #[test]
    fn usage_ledger_tampering_fails_closed() {
        let directory = private_tempdir();
        let store = SqliteStore::open_encrypted(
            directory.path().join("usage-tamper.sqlite"),
            MasterKey::from_bytes(b"usage tamper master key").expect("master key"),
        )
        .expect("encrypted store");
        let persisted = store
            .append_usage_record(UsageRecord::new(100, "request", "route", "success"))
            .expect("usage record");
        {
            let connection = store.connection.lock().expect("connection");
            let mut payload: Vec<u8> = connection
                .query_row(
                    "SELECT envelope FROM usage_records WHERE id = ?1",
                    [persisted.id],
                    |row| row.get(0),
                )
                .expect("encrypted payload");
            let last = payload.last_mut().expect("non-empty envelope");
            *last ^= 1;
            connection
                .execute(
                    "UPDATE usage_records SET envelope = ?1 WHERE id = ?2",
                    params![payload, persisted.id],
                )
                .expect("tampered payload persisted");
        }
        assert_eq!(
            store.usage_records(),
            Err(StoreError::CredentialEnvelopeAuthenticationFailed)
        );
    }

    #[test]
    fn concurrent_sqlite_writes_are_transactional_and_bounded() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let store = Arc::new(
            SqliteStore::open_with_retention(&path, policy(32, 32, 32)).expect("open store"),
        );
        let mut threads = Vec::new();
        for worker in 0..8 {
            let store = Arc::clone(&store);
            threads.push(thread::spawn(move || {
                let id = format!("credential-{worker}");
                store
                    .upsert_credential_state(CredentialState::new(
                        id.clone(),
                        "provider",
                        true,
                        worker,
                    ))
                    .expect("credential");
                store
                    .upsert_session_affinity(SessionAffinity::new(
                        &id, "provider", &id, "model", worker, 100,
                    ))
                    .expect("affinity");
                store
                    .append_decision(DecisionRecord::new(
                        format!("request-{worker}"),
                        "route",
                        "model",
                        worker,
                    ))
                    .expect("decision");
            }));
        }
        for thread in threads {
            thread.join().expect("worker");
        }
        assert_eq!(
            store.len().expect("length"),
            StoreLengths {
                credentials: 8,
                affinities: 8,
                decisions: 8,
                request_events: 0,
                usage_records: 0,
            }
        );
    }
}
