//! SQLite-backed implementation of the mutable Pooler state store.
//!
//! The connection is deliberately kept behind one mutex.  Pooler state
//! updates are small, and serializing them here makes each operation's
//! transaction boundary explicit while still allowing callers to share the
//! store safely across worker threads.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::{
    non_empty, CooldownState, CredentialHealthState, CredentialHealthStatus, CredentialState,
    DecisionRecord, PruneReport, RetentionPolicy, SessionAffinity, Store, StoreError, StoreLengths,
    StoreResult, Timestamp,
};

const MAX_COOLDOWNS: usize = 4_096;
const LATEST_SCHEMA_VERSION: i64 = 2;
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("migrations/001_initial.sql")),
    (2, include_str!("migrations/002_health_and_cooldowns.sql")),
];

/// A transactional, WAL-backed SQLite [`Store`].
#[derive(Clone)]
pub struct SqliteStore {
    retention: RetentionPolicy,
    connection: Arc<Mutex<Connection>>,
    path: Option<PathBuf>,
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
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        initialize_connection(connection, false, retention, Some(path))
    }

    /// Open an in-memory database.  This is intended for tests and ephemeral
    /// deployments; file privacy checks do not apply to it.
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::open_in_memory_with_retention(RetentionPolicy::default())
    }

    /// Open an in-memory database with explicit retention.
    pub fn open_in_memory_with_retention(retention: RetentionPolicy) -> StoreResult<Self> {
        let connection = Connection::open_in_memory().map_err(sqlite_error)?;
        initialize_connection(connection, true, retention, None)
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

    fn connection(&self) -> StoreResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StoreError::LockPoisoned)
    }

    fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let value = operation(&transaction)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(value)
    }
}

fn initialize_connection(
    mut connection: Connection,
    in_memory: bool,
    retention: RetentionPolicy,
    path: Option<PathBuf>,
) -> StoreResult<SqliteStore> {
    connection
        .busy_timeout(Duration::from_secs(5))
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
    Ok(SqliteStore {
        retention,
        connection: Arc::new(Mutex::new(connection)),
        path,
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
