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
    DecisionRecord, MasterKey, PruneReport, RetentionPolicy, SessionAffinity, Store, StoreError,
    StoreLengths, StoreResult, Timestamp,
};

const MAX_COOLDOWNS: usize = 4_096;
const LATEST_SCHEMA_VERSION: i64 = 3;
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("migrations/001_initial.sql")),
    (2, include_str!("migrations/002_health_and_cooldowns.sql")),
    (3, include_str!("migrations/003_credential_payloads.sql")),
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
        Ok(StoreLengths {
            credentials,
            affinities,
            decisions,
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
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let envelope = cipher.seal_for(payload, credential_id.as_bytes())?;
        self.with_transaction(|transaction| {
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
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
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

    /// Remove one encrypted credential payload.
    pub fn remove_credential_payload(&self, credential_id: &str) -> StoreResult<bool> {
        non_empty("credential_id", credential_id)?;
        let encryption = self.encryption_read()?;
        if encryption.is_none() {
            return Err(StoreError::EncryptionRequired);
        }
        self.with_transaction(|transaction| {
            let removed = transaction
                .execute(
                    "DELETE FROM credential_payloads WHERE credential_id = ?1",
                    [credential_id],
                )
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    /// Re-encrypt every payload in one transaction with a new master key.
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
        let rows = {
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
        for (credential_id, envelope) in rows {
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
        transaction.commit().map_err(sqlite_error)?;
        *encryption = Some(Arc::clone(&next));
        self.ensure_private_sidecars()?;
        Ok(rotated)
    }

    /// Alias for [`Self::rotate_master_key`].
    pub fn rotate_credential_payloads(&self, master_key: MasterKey) -> StoreResult<usize> {
        self.rotate_master_key(master_key)
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
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let value = operation(&transaction)?;
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_private_sidecars()?;
        Ok(value)
    }

    fn with_immediate_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
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
    Ok(SqliteStore {
        retention,
        connection: Arc::new(Mutex::new(connection)),
        path,
        encryption: Arc::new(RwLock::new(
            master_key.map(|key| Arc::new(CredentialCipher::new(key))),
        )),
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

fn evict_credentials(transaction: &Transaction<'_>, limit: usize) -> StoreResult<usize> {
    let limit =
        i64::try_from(limit).map_err(|_| StoreError::Sqlite("retention overflow".to_owned()))?;
    let removed = transaction
        .execute(
            "DELETE FROM credentials WHERE credential_id IN (
                 SELECT credential_id FROM credentials
                 ORDER BY updated_at ASC, credential_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM credentials) - ?1, 0)
             )",
            [limit],
        )
        .map_err(sqlite_error)?;
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
            let old: Option<CredentialState> = transaction
                .query_row(
                    "SELECT credential_id, provider_id, enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?;
            let old =
                old.ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
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
            if !enabled {
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
            } else {
                transaction
                    .execute(
                        "UPDATE credential_health SET status = 'healthy', cooldown_until = NULL,
                         updated_at = ?1 WHERE credential_id = ?2 AND status = 'disabled'",
                        params![updated_at, credential_id],
                    )
                    .map_err(sqlite_error)?;
            }
            Ok(CredentialState {
                enabled,
                updated_at,
                revision,
                ..old
            })
        })
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
            transaction
                .execute(
                    "DELETE FROM credential_health WHERE credential_id = ?1",
                    [credential_id],
                )
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    fn upsert_credential_health(
        &self,
        state: CredentialHealthState,
    ) -> StoreResult<CredentialHealthState> {
        non_empty("credential_id", &state.credential_id)?;
        let connection = self.connection()?;
        connection
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
        let connection = self.connection()?;
        let removed = connection
            .execute(
                "DELETE FROM cooldowns WHERE scope = ?1 AND scope_key = ?2",
                params![scope, key],
            )
            .map_err(sqlite_error)?;
        Ok(removed != 0)
    }

    fn upsert_session_affinity(&self, affinity: SessionAffinity) -> StoreResult<SessionAffinity> {
        non_empty("key", &affinity.key)?;
        non_empty("provider_id", &affinity.provider_id)?;
        non_empty("credential_id", &affinity.credential_id)?;
        non_empty("upstream_model", &affinity.upstream_model)?;
        self.with_transaction(|transaction| {
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
        let connection = self.connection()?;
        let removed = connection
            .execute("DELETE FROM affinities WHERE key = ?1", [key])
            .map_err(sqlite_error)?;
        Ok(removed != 0)
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
            Ok(PruneReport {
                expired_affinities,
                evicted_credentials,
                evicted_affinities,
                evicted_decisions,
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
    use crate::{CredentialHealthStatus, DecisionCandidate};

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
    fn sqlite_expiry_is_applied_after_restart() {
        let directory = private_tempdir();
        let path = directory.path().join("pooler.sqlite");
        let store = SqliteStore::open(&path).expect("open store");
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

        let old_store = SqliteStore::open_encrypted(&path, old_key).expect("old open");
        assert_eq!(
            old_store.credential_payload("credential"),
            Err(StoreError::WrongMasterKey)
        );
        drop(old_store);
        let new_store = SqliteStore::open_encrypted(&path, new_key).expect("new open");
        assert!(new_store
            .credential_payload("credential")
            .expect("new load")
            .is_some());
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
    fn wrong_master_key_cas_does_not_mutate_existing_token_or_revision() {
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
        let wrong_store = SqliteStore::open_encrypted(
            &path,
            MasterKey::from_bytes(b"wrong cas key").expect("wrong key"),
        )
        .expect("wrong-key open");
        assert_eq!(
            wrong_store.compare_and_swap_credential_payload(
                "credential",
                1,
                &CredentialPayload::new(b"replacement-token").expect("payload"),
                2,
            ),
            Err(StoreError::WrongMasterKey)
        );
        drop(wrong_store);

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
                    .upsert_session_affinity(affinity(&id, worker, 100))
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
            }
        );
    }
}
