//! SQLite-backed implementation of the mutable Pooler state store.
//!
//! The connection is deliberately kept behind one mutex.  Pooler state
//! updates are small, and serializing them here makes each operation's
//! transaction boundary explicit while still allowing callers to share the
//! store safely across worker threads.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use rusqlite::{
    backup::Backup, params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior,
};

use crate::{
    encrypted::{CredentialCipher, CredentialPayload, CREDENTIAL_IDENTITY_AAD_VERSION},
    hex_digest, non_empty, validate_fingerprint, ActivatedCredentialState, AffinityBindingIdentity,
    AuditRecord, ConditionalCredentialMutation, CooldownState, CredentialConfigurationActivation,
    CredentialConfigurationIdentity, CredentialFingerprintRetirement, CredentialHealthState,
    CredentialHealthStatus, CredentialState, DecisionRecord, DraftRecord, ManagedSecretRecord,
    ManagementSessionRecord, MasterKey, MemoryStore, OAuthFlowRecord, OAuthFlowStatus, PruneReport,
    ReloadRecord, RequestEvent, RetentionPolicy, SecretPayload, SessionAffinity, Store, StoreError,
    StoreLengths, StoreResult, Timestamp, UsageRecord, MAX_REQUEST_EVENTS_PER_REQUEST,
};

const MAX_COOLDOWNS: usize = 4_096;
const LATEST_SCHEMA_VERSION: i64 = 14;
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("migrations/001_initial.sql")),
    (2, include_str!("migrations/002_health_and_cooldowns.sql")),
    (3, include_str!("migrations/003_credential_payloads.sql")),
    (4, include_str!("migrations/004_request_events.sql")),
    (5, include_str!("migrations/005_usage_ledger.sql")),
    (6, include_str!("migrations/006_request_event_indexes.sql")),
    (7, include_str!("migrations/007_encryption_fence.sql")),
    (8, include_str!("migrations/008_control_plane_identity.sql")),
    (
        9,
        include_str!("migrations/009_reload_completion_generation.sql"),
    ),
    (10, include_str!("migrations/010_reload_kind.sql")),
    (
        11,
        include_str!("migrations/011_credential_revision_clock.sql"),
    ),
    (
        12,
        include_str!("migrations/012_credential_payload_generation.sql"),
    ),
    (
        13,
        include_str!("migrations/013_credential_payload_reencryption.sql"),
    ),
    (
        14,
        include_str!("migrations/014_credential_revision_write_guard.sql"),
    ),
];

/// Credential metadata paired with the generation and decrypted payload, when present.
pub type CredentialPayloadState = (CredentialState, Option<(u64, CredentialPayload)>);

/// Stable identity of one open file-backed SQLite generation domain.
///
/// The database's persisted metadata cannot establish this identity because a
/// raw filesystem copy preserves every row. Unix device/inode and Windows
/// volume/file-index metadata identify the actual file opened by this process.
/// Other platforms fail closed and require one cloned store handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileGenerationDomain {
    device: u64,
    inode: u64,
}

/// A transactional, WAL-backed SQLite [`Store`].
#[derive(Clone)]
pub struct SqliteStore {
    retention: RetentionPolicy,
    connection: Arc<Mutex<Connection>>,
    path: Option<PathBuf>,
    file_generation_domain: Option<FileGenerationDomain>,
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
    /// Checkpoint a quiesced source database and copy its main database with
    /// SQLite's online-backup API.
    ///
    /// The caller must have stopped every writer before entering this
    /// boundary. The exclusive transaction is an additional fail-closed
    /// guard against a writer that was not stopped; it is released only after
    /// the backup has completed. WAL and SHM files are intentionally not
    /// copied: a completed TRUNCATE checkpoint makes the staged main database
    /// self-contained.
    pub fn checkpoint_and_backup_quiesced(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> StoreResult<()> {
        checkpoint_and_backup_quiesced(source.as_ref(), destination.as_ref())
    }

    /// Compatibility spelling for migration callers.
    pub fn backup_quiesced(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> StoreResult<()> {
        Self::checkpoint_and_backup_quiesced(source, destination)
    }

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
        let affinities = count_rows(&connection, "affinities")?
            .saturating_add(count_rows(&connection, "scoped_affinities")?);
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

    /// Return whether one credential owns an encrypted payload without
    /// opening its envelope. This metadata-only check lets callers reject
    /// legacy identity adoption before any token material is touched.
    pub fn credential_payload_exists(&self, credential_id: &str) -> StoreResult<bool> {
        non_empty("credential_id", credential_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT 1 FROM credential_payloads WHERE credential_id = ?1",
                [credential_id],
                |_row| Ok(true),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(sqlite_error)
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
        self.upsert_credential_payload_with_fingerprint(credential_id, None, payload, updated_at)
    }

    /// Persist a payload only when the caller's immutable identity fingerprint
    /// still matches the credential metadata.
    pub fn upsert_credential_payload_for_fingerprint(
        &self,
        credential_id: &str,
        configuration_fingerprint: &str,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<()> {
        self.upsert_credential_payload_with_fingerprint(
            credential_id,
            Some(configuration_fingerprint),
            payload,
            updated_at,
        )
    }

    fn upsert_credential_payload_with_fingerprint(
        &self,
        credential_id: &str,
        expected_fingerprint: Option<&str>,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<()> {
        non_empty("credential_id", credential_id)?;
        if let Some(fingerprint) = expected_fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let current: CredentialState = transaction
                .query_row(
                    "SELECT credential_id, provider_id, configuration_fingerprint,
                            enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
            if let Some(expected) = expected_fingerprint {
                if current.configuration_fingerprint != expected {
                    return Err(StoreError::CredentialFingerprintConflict);
                }
            }
            let existing = transaction
                .query_row(
                    "SELECT envelope, generation FROM credential_payloads
                     WHERE credential_id = ?1",
                    [credential_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            u64::try_from(row.get::<_, i64>(1)?).unwrap_or(u64::MAX),
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?;
            if let Some((existing_envelope, _)) = &existing {
                let aad = credential_payload_aad(credential_id, &current.configuration_fingerprint);
                cipher.open_for(existing_envelope, &aad)?;
            }
            let aad = credential_payload_aad(credential_id, &current.configuration_fingerprint);
            let envelope = cipher.seal_for(payload, &aad)?;
            let allocation_revision = existing
                .as_ref()
                .map_or(current.revision, |(_, generation)| {
                    current.revision.max(*generation)
                });
            let generation =
                next_credential_revision(transaction, credential_id, allocation_revision)?;
            let changed = transaction
                .execute(
                    "UPDATE credentials SET updated_at = ?1, revision = ?2
                     WHERE credential_id = ?3 AND revision = ?4",
                    params![
                        updated_at,
                        i64::try_from(generation)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                        credential_id,
                        i64::try_from(current.revision)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            transaction
                .execute(
                    "INSERT INTO credential_payloads
                       (credential_id, envelope, updated_at, generation)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       envelope = excluded.envelope,
                       updated_at = excluded.updated_at,
                       generation = excluded.generation",
                    params![
                        credential_id,
                        envelope,
                        updated_at,
                        i64::try_from(generation)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                    ],
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
        self.compare_and_swap_credential_payload_with_fingerprint(
            credential_id,
            expected_revision,
            None,
            payload,
            updated_at,
        )
    }

    /// Compare-and-swap a payload while fencing the immutable credential
    /// configuration identity before any existing ciphertext is opened.
    pub fn compare_and_swap_credential_payload_for_fingerprint(
        &self,
        credential_id: &str,
        expected_revision: u64,
        configuration_fingerprint: &str,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        self.compare_and_swap_credential_payload_with_fingerprint(
            credential_id,
            expected_revision,
            Some(configuration_fingerprint),
            payload,
            updated_at,
        )
    }

    fn compare_and_swap_credential_payload_with_fingerprint(
        &self,
        credential_id: &str,
        expected_revision: u64,
        expected_fingerprint: Option<&str>,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        non_empty("credential_id", credential_id)?;
        if let Some(fingerprint) = expected_fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let current: CredentialState = transaction
                .query_row(
                    "SELECT credential_id, provider_id, configuration_fingerprint,
                            enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
            if let Some(expected) = expected_fingerprint {
                if current.configuration_fingerprint != expected {
                    return Err(StoreError::CredentialFingerprintConflict);
                }
            }
            let existing = transaction
                .query_row(
                    "SELECT envelope, generation FROM credential_payloads
                     WHERE credential_id = ?1",
                    [credential_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            u64::try_from(row.get::<_, i64>(1)?).unwrap_or(u64::MAX),
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?;
            let current_generation = existing
                .as_ref()
                .map_or(current.revision, |(_, generation)| *generation);
            if current_generation != expected_revision {
                return Err(StoreError::CredentialRevisionConflict);
            }
            if let Some((existing_envelope, _)) = existing {
                // Authenticate the old value before changing either the
                // metadata revision or the encrypted payload. A wrong key
                // must fail closed rather than overwrite an unreadable token.
                let aad = credential_payload_aad(credential_id, &current.configuration_fingerprint);
                cipher.open_for(&existing_envelope, &aad)?;
            }
            let aad = credential_payload_aad(credential_id, &current.configuration_fingerprint);
            let envelope = cipher.seal_for(payload, &aad)?;
            let revision = next_credential_revision(
                transaction,
                credential_id,
                current.revision.max(current_generation),
            )?;
            let changed = transaction
                .execute(
                    "UPDATE credentials SET updated_at = ?1, revision = ?2
                     WHERE credential_id = ?3 AND revision = ?4",
                    params![
                        updated_at,
                        i64::try_from(revision).unwrap_or(i64::MAX),
                        credential_id,
                        i64::try_from(current.revision).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            transaction
                .execute(
                    "INSERT INTO credential_payloads
                       (credential_id, envelope, updated_at, generation)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       envelope = excluded.envelope,
                       updated_at = excluded.updated_at,
                       generation = excluded.generation",
                    params![
                        credential_id,
                        envelope,
                        updated_at,
                        i64::try_from(revision)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(CredentialState {
                updated_at,
                revision,
                ..current
            })
        })
    }

    /// Atomically install a validated login profile, adopting an allowed
    /// prior fingerprint and enabling the account in the same transaction.
    ///
    /// `expected_fingerprint` and `expected_generation` are both absent only
    /// when the caller observed no credential row. Any concurrent state or
    /// payload change aborts without retiring the previous usable payload.
    #[allow(clippy::too_many_arguments)] // Inputs define one atomic login-replacement fence.
    pub(crate) fn replace_credential_payload_for_login(
        &self,
        credential_id: &str,
        provider_id: &str,
        expected_fingerprint: Option<&str>,
        expected_generation: Option<u64>,
        configuration_fingerprint: &str,
        payload: &CredentialPayload,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        non_empty("credential_id", credential_id)?;
        non_empty("provider_id", provider_id)?;
        validate_fingerprint(configuration_fingerprint)?;
        if configuration_fingerprint.is_empty()
            || expected_fingerprint.is_some() != expected_generation.is_some()
        {
            return Err(StoreError::InvalidCredentialFingerprint);
        }
        if let Some(fingerprint) = expected_fingerprint {
            validate_fingerprint(fingerprint)?;
        }
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let current: Option<CredentialState> = transaction
                .query_row(
                    "SELECT credential_id, provider_id, configuration_fingerprint,
                            enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?;
            let existing = transaction
                .query_row(
                    "SELECT envelope, generation FROM credential_payloads
                     WHERE credential_id = ?1",
                    [credential_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            u64::try_from(row.get::<_, i64>(1)?).unwrap_or(u64::MAX),
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?;

            let current_revision = match (&current, expected_fingerprint, expected_generation) {
                (None, None, None) => 0,
                (None, Some(_), Some(_)) => {
                    return Err(StoreError::CredentialNotFound(credential_id.to_owned()));
                }
                (Some(_), None, None) => {
                    return Err(StoreError::CredentialRevisionConflict);
                }
                (Some(current), Some(expected_fingerprint), Some(expected_generation)) => {
                    if current.provider_id != provider_id
                        || current.configuration_fingerprint != expected_fingerprint
                    {
                        return Err(StoreError::CredentialFingerprintConflict);
                    }
                    let current_generation = existing
                        .as_ref()
                        .map_or(current.revision, |(_, generation)| *generation);
                    if current_generation != expected_generation {
                        return Err(StoreError::CredentialRevisionConflict);
                    }
                    current.revision
                }
                _ => return Err(StoreError::InvalidCredentialFingerprint),
            };

            if let (Some(current), Some((envelope, _))) = (&current, &existing) {
                let aad = credential_payload_aad(credential_id, &current.configuration_fingerprint);
                cipher.open_for(envelope, &aad)?;
            }
            let envelope = cipher.seal_for(
                payload,
                &credential_payload_aad(credential_id, configuration_fingerprint),
            )?;
            let allocation_revision = existing
                .as_ref()
                .map_or(current_revision, |(_, generation)| {
                    current_revision.max(*generation)
                });
            let revision =
                next_credential_revision(transaction, credential_id, allocation_revision)?;
            let revision_i64 =
                i64::try_from(revision).map_err(|_| StoreError::CredentialRevisionConflict)?;
            let identity_changed = current
                .as_ref()
                .is_some_and(|state| state.configuration_fingerprint != configuration_fingerprint);
            if identity_changed {
                delete_credential_dependents(transaction, credential_id)?;
            }
            let changed = if current.is_some() {
                transaction
                    .execute(
                        "UPDATE credentials
                         SET configuration_fingerprint = ?1, enabled = 1,
                             updated_at = ?2, revision = ?3
                         WHERE credential_id = ?4 AND revision = ?5",
                        params![
                            configuration_fingerprint,
                            updated_at,
                            revision_i64,
                            credential_id,
                            i64::try_from(current_revision)
                                .map_err(|_| StoreError::CredentialRevisionConflict)?,
                        ],
                    )
                    .map_err(sqlite_error)?
            } else {
                transaction
                    .execute(
                        "INSERT INTO credentials
                         (credential_id, provider_id, configuration_fingerprint,
                          enabled, updated_at, revision)
                         VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                        params![
                            credential_id,
                            provider_id,
                            configuration_fingerprint,
                            updated_at,
                            revision_i64,
                        ],
                    )
                    .map_err(sqlite_error)?
            };
            if changed != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            if !identity_changed {
                transaction
                    .execute(
                        "UPDATE credential_health
                         SET status = 'healthy', cooldown_until = NULL, updated_at = ?1
                         WHERE credential_id = ?2 AND status = 'disabled'",
                        params![updated_at, credential_id],
                    )
                    .map_err(sqlite_error)?;
            }
            transaction
                .execute(
                    "INSERT INTO credential_payloads
                       (credential_id, envelope, updated_at, generation)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       envelope = excluded.envelope,
                       updated_at = excluded.updated_at,
                       generation = excluded.generation",
                    params![credential_id, envelope, updated_at, revision_i64],
                )
                .map_err(sqlite_error)?;
            evict_credentials(transaction, self.retention.max_credentials)?;
            Ok(CredentialState {
                credential_id: credential_id.to_owned(),
                provider_id: provider_id.to_owned(),
                configuration_fingerprint: configuration_fingerprint.to_owned(),
                enabled: true,
                updated_at,
                revision,
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
        let fingerprint: String = connection
            .query_row(
                "SELECT configuration_fingerprint FROM credentials WHERE credential_id = ?1",
                [credential_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
        let envelope = connection
            .query_row(
                "SELECT envelope FROM credential_payloads WHERE credential_id = ?1",
                [credential_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let aad = credential_payload_aad(credential_id, &fingerprint);
        envelope
            .map(|value| cipher.open_for(&value, &aad))
            .transpose()
    }

    /// Load a payload only when an expected immutable identity fingerprint
    /// matches the persisted credential metadata.
    pub fn credential_payload_for_fingerprint(
        &self,
        credential_id: &str,
        configuration_fingerprint: &str,
    ) -> StoreResult<Option<CredentialPayload>> {
        non_empty("credential_id", credential_id)?;
        validate_fingerprint(configuration_fingerprint)?;
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, cipher)?;
        let row = connection
            .query_row(
                "SELECT c.configuration_fingerprint, p.envelope
                 FROM credentials AS c
                 LEFT JOIN credential_payloads AS p ON p.credential_id = c.credential_id
                 WHERE c.credential_id = ?1",
                [credential_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
        if row.0 != configuration_fingerprint {
            return Err(StoreError::CredentialFingerprintConflict);
        }
        let aad = credential_payload_aad(credential_id, &row.0);
        row.1.map(|value| cipher.open_for(&value, &aad)).transpose()
    }

    /// Return the generation a payload compare-and-swap must own for one
    /// immutable credential identity. Before the first payload is written,
    /// the metadata revision fences concurrent identity and state changes.
    pub fn credential_payload_compare_generation_for_fingerprint(
        &self,
        credential_id: &str,
        configuration_fingerprint: &str,
    ) -> StoreResult<u64> {
        non_empty("credential_id", credential_id)?;
        validate_fingerprint(configuration_fingerprint)?;
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, cipher)?;
        let row = connection
            .query_row(
                "SELECT c.configuration_fingerprint, c.revision, p.generation
                 FROM credentials AS c
                 LEFT JOIN credential_payloads AS p
                   ON p.credential_id = c.credential_id
                 WHERE c.credential_id = ?1",
                [credential_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
        if row.0 != configuration_fingerprint {
            return Err(StoreError::CredentialFingerprintConflict);
        }
        let generation = row.2.unwrap_or(row.1);
        u64::try_from(generation).map_err(|_| StoreError::CredentialRevisionConflict)
    }

    /// Load credential metadata and its encrypted payload under one SQLite
    /// connection lock. This prevents an OAuth reader from pairing a newer
    /// revision with an older payload while a refresh transaction commits.
    pub fn credential_payload_with_state(
        &self,
        credential_id: &str,
    ) -> StoreResult<Option<CredentialPayloadState>> {
        non_empty("credential_id", credential_id)?;
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, cipher)?;
        let row = connection
            .query_row(
                "SELECT c.credential_id, c.provider_id, c.configuration_fingerprint,
                        c.enabled, c.updated_at, c.revision,
                        p.generation, p.envelope
                 FROM credentials AS c
                 LEFT JOIN credential_payloads AS p
                   ON p.credential_id = c.credential_id
                 WHERE c.credential_id = ?1",
                [credential_id],
                |row| {
                    let state = CredentialState {
                        credential_id: row.get(0)?,
                        provider_id: row.get(1)?,
                        configuration_fingerprint: row.get(2)?,
                        enabled: row.get::<_, i64>(3)? != 0,
                        updated_at: row.get(4)?,
                        revision: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(u64::MAX),
                    };
                    let generation = row
                        .get::<_, Option<i64>>(6)?
                        .map(|value| u64::try_from(value).unwrap_or(u64::MAX));
                    let envelope = row.get::<_, Option<Vec<u8>>>(7)?;
                    Ok((state, generation.zip(envelope)))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(state, payload)| {
            let aad = credential_payload_aad(credential_id, &state.configuration_fingerprint);
            payload
                .map(|(generation, value)| {
                    cipher
                        .open_for(&value, &aad)
                        .map(|payload| (generation, payload))
                })
                .transpose()
                .map(|payload| (state, payload))
        })
        .transpose()
    }

    /// Load credential metadata and its encrypted payload only after the
    /// caller's immutable configuration fingerprint matches. The comparison
    /// is deliberately performed while the ciphertext is still opaque so a
    /// reused account ID cannot become a decryption oracle or overwrite path.
    pub fn credential_payload_with_state_for_fingerprint(
        &self,
        credential_id: &str,
        configuration_fingerprint: &str,
    ) -> StoreResult<Option<CredentialPayloadState>> {
        non_empty("credential_id", credential_id)?;
        validate_fingerprint(configuration_fingerprint)?;
        let encryption = self.encryption_read()?;
        let cipher = encryption.as_ref().ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, cipher)?;
        let row = connection
            .query_row(
                "SELECT c.credential_id, c.provider_id, c.configuration_fingerprint,
                        c.enabled, c.updated_at, c.revision,
                        p.generation, p.envelope
                 FROM credentials AS c
                 LEFT JOIN credential_payloads AS p
                   ON p.credential_id = c.credential_id
                 WHERE c.credential_id = ?1",
                [credential_id],
                |row| {
                    let state = CredentialState {
                        credential_id: row.get(0)?,
                        provider_id: row.get(1)?,
                        configuration_fingerprint: row.get(2)?,
                        enabled: row.get::<_, i64>(3)? != 0,
                        updated_at: row.get(4)?,
                        revision: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(u64::MAX),
                    };
                    let generation = row
                        .get::<_, Option<i64>>(6)?
                        .map(|value| u64::try_from(value).unwrap_or(u64::MAX));
                    let envelope = row.get::<_, Option<Vec<u8>>>(7)?;
                    Ok((state, generation.zip(envelope)))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((state, payload)) = row else {
            return Ok(None);
        };
        if state.configuration_fingerprint != configuration_fingerprint {
            return Err(StoreError::CredentialFingerprintConflict);
        }
        let aad = credential_payload_aad(credential_id, &state.configuration_fingerprint);
        payload
            .map(|(generation, value)| {
                cipher
                    .open_for(&value, &aad)
                    .map(|payload| (generation, payload))
            })
            .transpose()
            .map(|payload| Some((state, payload)))
    }

    /// Explicitly adopt a new immutable credential identity. Legacy rows use
    /// an empty fingerprint and version-1 AAD; adoption authenticates that
    /// payload and re-encrypts it under the version-2 fingerprint AAD in one
    /// transaction. No implicit account-ID reuse is permitted.
    pub fn adopt_credential_fingerprint(
        &self,
        credential_id: &str,
        expected_old_fingerprint: &str,
        new_fingerprint: &str,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        non_empty("credential_id", credential_id)?;
        validate_fingerprint(expected_old_fingerprint)?;
        validate_fingerprint(new_fingerprint)?;
        if new_fingerprint.is_empty() {
            return Err(StoreError::InvalidCredentialFingerprint);
        }
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let current: CredentialState = transaction
                .query_row(
                    "SELECT credential_id, provider_id, configuration_fingerprint,
                            enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
            if current.configuration_fingerprint != expected_old_fingerprint {
                return Err(StoreError::CredentialFingerprintConflict);
            }
            let old_aad = credential_payload_aad(credential_id, expected_old_fingerprint);
            let new_aad = credential_payload_aad(credential_id, new_fingerprint);
            let replacement = transaction
                .query_row(
                    "SELECT envelope, generation FROM credential_payloads
                     WHERE credential_id = ?1",
                    [credential_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            u64::try_from(row.get::<_, i64>(1)?).unwrap_or(u64::MAX),
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?
                .map(|(envelope, generation)| {
                    cipher
                        .open_for(&envelope, &old_aad)
                        .and_then(|payload| cipher.seal_for(&payload, &new_aad))
                        .map(|replacement| (replacement, generation))
                })
                .transpose()?;
            let allocation_revision = replacement
                .as_ref()
                .map_or(current.revision, |(_, generation)| {
                    current.revision.max(*generation)
                });
            let revision =
                next_credential_revision(transaction, credential_id, allocation_revision)?;
            let changed = transaction
                .execute(
                    "UPDATE credentials
                     SET configuration_fingerprint = ?1, updated_at = ?2, revision = ?3
                     WHERE credential_id = ?4 AND revision = ?5",
                    params![
                        new_fingerprint,
                        updated_at,
                        i64::try_from(revision).unwrap_or(i64::MAX),
                        credential_id,
                        i64::try_from(current.revision).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            if let Some((envelope, _)) = replacement {
                transaction
                    .execute(
                        "UPDATE credential_payloads
                         SET envelope = ?1, updated_at = ?2, generation = ?3
                         WHERE credential_id = ?4",
                        params![
                            envelope,
                            updated_at,
                            i64::try_from(revision)
                                .map_err(|_| StoreError::CredentialRevisionConflict)?,
                            credential_id,
                        ],
                    )
                    .map_err(sqlite_error)?;
            }
            Ok(CredentialState {
                configuration_fingerprint: new_fingerprint.to_owned(),
                updated_at,
                revision,
                ..current
            })
        })
    }

    /// Replace a legacy credential identity while deliberately discarding its
    /// encrypted payload. The credential is disabled and the metadata change,
    /// payload removal, and revision advance commit atomically.
    ///
    /// This is the fail-closed migration path when a newer fingerprint covers
    /// identity fields that the legacy fingerprint omitted. Preserving or
    /// re-encrypting the old payload would incorrectly bless it for the newer
    /// identity.
    pub fn retire_credential_fingerprint(
        &self,
        credential_id: &str,
        expected_old_fingerprint: &str,
        new_fingerprint: &str,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        let current = self
            .credential_state(credential_id)?
            .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
        let retirement = CredentialFingerprintRetirement::new(
            credential_id,
            current.provider_id,
            expected_old_fingerprint,
            new_fingerprint,
        )?;
        self.retire_credential_fingerprints_atomically(&[retirement], updated_at)?
            .into_iter()
            .next()
            .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))
    }

    /// Retire a batch of legacy credential fingerprints in one transaction.
    ///
    /// Every provider and fingerprint is validated before any payload is
    /// removed. A stale, missing, duplicate, unreadable, or otherwise invalid
    /// member aborts the entire batch, preserving every prior credential.
    pub fn retire_credential_fingerprints_atomically(
        &self,
        retirements: &[CredentialFingerprintRetirement],
        updated_at: Timestamp,
    ) -> StoreResult<Vec<CredentialState>> {
        let mut credential_ids = BTreeSet::new();
        for retirement in retirements {
            if !credential_ids.insert(retirement.credential_id()) {
                return Err(StoreError::CredentialFingerprintConflict);
            }
        }
        if retirements.is_empty() {
            return Ok(Vec::new());
        }
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let mut current_states = Vec::with_capacity(retirements.len());
            for retirement in retirements {
                let current: CredentialState = transaction
                    .query_row(
                        "SELECT credential_id, provider_id, configuration_fingerprint,
                                enabled, updated_at, revision
                         FROM credentials WHERE credential_id = ?1",
                        [retirement.credential_id()],
                        credential_from_row,
                    )
                    .optional()
                    .map_err(sqlite_error)?
                    .ok_or_else(|| {
                        StoreError::CredentialNotFound(retirement.credential_id().to_owned())
                    })?;
                if current.provider_id != retirement.provider_id() {
                    return Err(StoreError::CredentialFingerprintConflict);
                }
                if current.configuration_fingerprint == retirement.replacement_fingerprint() {
                    current_states.push(current);
                    continue;
                }
                if current.configuration_fingerprint != retirement.expected_fingerprint() {
                    return Err(StoreError::CredentialFingerprintConflict);
                }
                if let Some(envelope) = transaction
                    .query_row(
                        "SELECT envelope FROM credential_payloads WHERE credential_id = ?1",
                        [retirement.credential_id()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?
                {
                    let aad = credential_payload_aad(
                        retirement.credential_id(),
                        retirement.expected_fingerprint(),
                    );
                    cipher.open_for(&envelope, &aad)?;
                }
                current_states.push(current);
            }

            let mut retired = Vec::with_capacity(retirements.len());
            for (retirement, current) in retirements.iter().zip(current_states) {
                if current.configuration_fingerprint == retirement.replacement_fingerprint() {
                    retired.push(current);
                    continue;
                }
                let revision = next_credential_revision(
                    transaction,
                    retirement.credential_id(),
                    current.revision,
                )?;
                delete_credential_dependents(transaction, retirement.credential_id())?;
                transaction
                    .execute(
                        "DELETE FROM credential_payloads WHERE credential_id = ?1",
                        [retirement.credential_id()],
                    )
                    .map_err(sqlite_error)?;
                let changed = transaction
                    .execute(
                        "UPDATE credentials
                         SET configuration_fingerprint = ?1, enabled = 0,
                             updated_at = ?2, revision = ?3
                         WHERE credential_id = ?4 AND revision = ?5",
                        params![
                            retirement.replacement_fingerprint(),
                            updated_at,
                            i64::try_from(revision)
                                .map_err(|_| StoreError::CredentialRevisionConflict)?,
                            retirement.credential_id(),
                            i64::try_from(current.revision)
                                .map_err(|_| StoreError::CredentialRevisionConflict)?,
                        ],
                    )
                    .map_err(sqlite_error)?;
                if changed != 1 {
                    return Err(StoreError::CredentialRevisionConflict);
                }
                transaction
                    .execute(
                        "INSERT INTO credential_health
                         (credential_id, status, failure_count, cooldown_until, updated_at)
                         VALUES (?1, 'disabled', 0, NULL, ?2)
                         ON CONFLICT(credential_id) DO UPDATE SET
                           status = 'disabled', failure_count = 0,
                           cooldown_until = NULL, updated_at = excluded.updated_at",
                        params![retirement.credential_id(), updated_at],
                    )
                    .map_err(sqlite_error)?;
                retired.push(CredentialState {
                    configuration_fingerprint: retirement.replacement_fingerprint().to_owned(),
                    enabled: false,
                    updated_at,
                    revision,
                    ..current
                });
            }
            Ok(retired)
        })
    }

    /// Compatibility spelling for callers that use the full configuration
    /// terminology.
    pub fn adopt_credential_configuration_fingerprint(
        &self,
        credential_id: &str,
        expected_old_fingerprint: &str,
        new_fingerprint: &str,
        updated_at: Timestamp,
    ) -> StoreResult<CredentialState> {
        self.adopt_credential_fingerprint(
            credential_id,
            expected_old_fingerprint,
            new_fingerprint,
            updated_at,
        )
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
        self.with_immediate_transaction(|transaction| {
            let current: Option<(u64, Option<u64>)> = transaction
                .query_row(
                    "SELECT c.revision, p.generation
                     FROM credentials AS c
                     LEFT JOIN credential_payloads AS p
                       ON p.credential_id = c.credential_id
                     WHERE c.credential_id = ?1",
                    [credential_id],
                    |row| {
                        Ok((
                            u64::try_from(row.get::<_, i64>(0)?).unwrap_or(u64::MAX),
                            row.get::<_, Option<i64>>(1)?
                                .map(|generation| u64::try_from(generation).unwrap_or(u64::MAX)),
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?;
            let Some((current_revision, payload_generation)) = current else {
                return Ok(false);
            };
            let allocation_revision = payload_generation.map_or(current_revision, |generation| {
                current_revision.max(generation)
            });
            let next_revision =
                next_credential_revision(transaction, credential_id, allocation_revision)?;
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
                    params![
                        i64::try_from(next_revision)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                        credential_id,
                        i64::try_from(current_revision)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                    ],
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
                    "SELECT p.credential_id, c.configuration_fingerprint, p.envelope,
                            p.generation
                     FROM credential_payloads AS p
                     JOIN credentials AS c ON c.credential_id = p.credential_id
                     ORDER BY p.credential_id ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        u64::try_from(row.get::<_, i64>(3)?).unwrap_or(u64::MAX),
                    ))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        let payload_reencryption_armed = !credential_rows.is_empty();
        if payload_reencryption_armed {
            let armed = transaction
                .execute(
                    "UPDATE credential_payload_reencryption_guard SET active = 1
                     WHERE singleton = 1 AND active = 0",
                    [],
                )
                .map_err(sqlite_error)?;
            if armed != 1 {
                return Err(StoreError::Sqlite(
                    "credential payload re-encryption guard is unavailable".to_owned(),
                ));
            }
        }
        let mut rotated = 0_usize;
        for (credential_id, fingerprint, envelope, payload_generation) in credential_rows {
            let aad = credential_payload_aad(&credential_id, &fingerprint);
            let payload = current.open_for(&envelope, &aad)?;
            let replacement = next.seal_for(&payload, &aad)?;
            let changed = transaction
                .execute(
                    "UPDATE credential_payloads SET envelope = ?1
                     WHERE credential_id = ?2 AND generation = ?3",
                    params![
                        replacement,
                        credential_id,
                        i64::try_from(payload_generation)
                            .map_err(|_| StoreError::CredentialRevisionConflict)?,
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::CredentialRevisionConflict);
            }
            rotated += 1;
        }
        if payload_reencryption_armed {
            let disarmed = transaction
                .execute(
                    "UPDATE credential_payload_reencryption_guard SET active = 0
                     WHERE singleton = 1 AND active = 1",
                    [],
                )
                .map_err(sqlite_error)?;
            if disarmed != 1 {
                return Err(StoreError::Sqlite(
                    "credential payload re-encryption guard could not be cleared".to_owned(),
                ));
            }
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

        let managed_secret_rows = {
            let mut statement = transaction
                .prepare("SELECT secret_id, envelope FROM managed_secrets ORDER BY secret_id ASC")
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        for (secret_id, envelope) in managed_secret_rows {
            let payload = current.open_for(&envelope, &managed_secret_aad(&secret_id))?;
            let replacement = next.seal_for(&payload, &managed_secret_aad(&secret_id))?;
            transaction
                .execute(
                    "UPDATE managed_secrets SET envelope = ?1 WHERE secret_id = ?2",
                    params![replacement, secret_id],
                )
                .map_err(sqlite_error)?;
            rotated += 1;
        }

        let draft_rows = {
            let mut statement = transaction
                .prepare("SELECT draft_id, envelope FROM management_drafts ORDER BY draft_id ASC")
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        for (draft_id, envelope) in draft_rows {
            let payload = current.open_for(&envelope, &draft_aad(draft_id))?;
            let replacement = next.seal_for(&payload, &draft_aad(draft_id))?;
            transaction
                .execute(
                    "UPDATE management_drafts SET envelope = ?1 WHERE draft_id = ?2",
                    params![replacement, draft_id],
                )
                .map_err(sqlite_error)?;
            rotated += 1;
        }

        let oauth_rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT flow_id, pkce_envelope FROM oauth_flows
                     WHERE pkce_envelope IS NOT NULL ORDER BY flow_id ASC",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        for (flow_id, envelope) in oauth_rows {
            let payload = current.open_for(&envelope, &oauth_pkce_aad(&flow_id))?;
            let replacement = next.seal_for(&payload, &oauth_pkce_aad(&flow_id))?;
            transaction
                .execute(
                    "UPDATE oauth_flows SET pkce_envelope = ?1 WHERE flow_id = ?2",
                    params![replacement, flow_id],
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

    /// Persist an affinity in the version-2 composite binding namespace.
    pub fn upsert_scoped_session_affinity(
        &self,
        affinity: SessionAffinity,
    ) -> StoreResult<SessionAffinity> {
        non_empty("key", &affinity.key)?;
        non_empty("provider_id", &affinity.provider_id)?;
        non_empty("credential_id", &affinity.credential_id)?;
        non_empty("upstream_model", &affinity.upstream_model)?;
        let scope = affinity.binding_identity();
        scope.validate()?;
        self.with_transaction(|transaction| {
            require_credential(transaction, &affinity.credential_id)?;
            transaction
                .execute(
                    "DELETE FROM scoped_affinities WHERE expires_at <= ?1",
                    [affinity.created_at],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    "INSERT INTO scoped_affinities
                     (key, route_id, policy_id, logical_model, account_pool_id,
                      target_binding_id, provider_id, credential_id, upstream_model,
                      created_at, last_used_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11)
                     ON CONFLICT(key, route_id, policy_id, logical_model,
                                 account_pool_id, target_binding_id) DO UPDATE SET
                       provider_id = excluded.provider_id,
                       credential_id = excluded.credential_id,
                       upstream_model = excluded.upstream_model,
                       created_at = excluded.created_at,
                       last_used_at = excluded.last_used_at,
                       expires_at = excluded.expires_at",
                    params![
                        &affinity.key,
                        &affinity.route_id,
                        &affinity.policy_id,
                        &affinity.logical_model,
                        &affinity.account_pool_id,
                        &affinity.target_binding_id,
                        &affinity.provider_id,
                        &affinity.credential_id,
                        &affinity.upstream_model,
                        affinity.created_at,
                        affinity.expires_at,
                    ],
                )
                .map_err(sqlite_error)?;
            evict_scoped_affinities(transaction, self.retention.max_affinities)
        })?;
        Ok(affinity)
    }

    /// Restore an affinity only for the exact route/policy/model/pool/binding
    /// identity that created it.
    pub fn scoped_session_affinity(
        &self,
        key: &str,
        scope: &AffinityBindingIdentity,
        now: Timestamp,
    ) -> StoreResult<Option<SessionAffinity>> {
        non_empty("key", key)?;
        scope.validate()?;
        self.with_transaction(|transaction| {
            transaction
                .execute(
                    "DELETE FROM scoped_affinities WHERE expires_at <= ?1",
                    [now],
                )
                .map_err(sqlite_error)?;
            let value = transaction
                .query_row(
                    "SELECT key, route_id, policy_id, logical_model, account_pool_id,
                            target_binding_id, provider_id, credential_id, upstream_model,
                            created_at, last_used_at, expires_at
                     FROM scoped_affinities
                     WHERE key = ?1 AND route_id = ?2 AND policy_id = ?3
                       AND logical_model = ?4 AND account_pool_id = ?5
                       AND target_binding_id = ?6",
                    params![
                        key,
                        &scope.route_id,
                        &scope.policy_id,
                        &scope.logical_model,
                        &scope.account_pool_id,
                        &scope.target_binding_id,
                    ],
                    affinity_from_row,
                )
                .optional()
                .map_err(sqlite_error)?;
            if value.is_some() {
                transaction
                    .execute(
                        "UPDATE scoped_affinities
                         SET last_used_at = MAX(last_used_at, ?1)
                         WHERE key = ?2 AND route_id = ?3 AND policy_id = ?4
                           AND logical_model = ?5 AND account_pool_id = ?6
                           AND target_binding_id = ?7",
                        params![
                            now,
                            key,
                            &scope.route_id,
                            &scope.policy_id,
                            &scope.logical_model,
                            &scope.account_pool_id,
                            &scope.target_binding_id,
                        ],
                    )
                    .map_err(sqlite_error)?;
            }
            Ok(value.map(|mut affinity| {
                affinity.last_used_at = affinity.last_used_at.max(now);
                affinity
            }))
        })
    }

    /// List all non-expired scoped affinities in stable composite-key order.
    pub fn scoped_session_affinities(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>> {
        self.with_transaction(|transaction| {
            transaction
                .execute(
                    "DELETE FROM scoped_affinities WHERE expires_at <= ?1",
                    [now],
                )
                .map_err(sqlite_error)?;
            let mut statement = transaction
                .prepare(
                    "SELECT key, route_id, policy_id, logical_model, account_pool_id,
                            target_binding_id, provider_id, credential_id, upstream_model,
                            created_at, last_used_at, expires_at
                     FROM scoped_affinities
                     ORDER BY key, route_id, policy_id, logical_model,
                              account_pool_id, target_binding_id",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], affinity_from_row)
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
        })
    }

    /// Remove one exact scoped affinity binding.
    pub fn remove_scoped_session_affinity(
        &self,
        key: &str,
        scope: &AffinityBindingIdentity,
    ) -> StoreResult<bool> {
        non_empty("key", key)?;
        scope.validate()?;
        self.with_transaction(|transaction| {
            let removed = transaction
                .execute(
                    "DELETE FROM scoped_affinities
                     WHERE key = ?1 AND route_id = ?2 AND policy_id = ?3
                       AND logical_model = ?4 AND account_pool_id = ?5
                       AND target_binding_id = ?6",
                    params![
                        key,
                        &scope.route_id,
                        &scope.policy_id,
                        &scope.logical_model,
                        &scope.account_pool_id,
                        &scope.target_binding_id,
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    /// Insert or replace one encrypted managed secret with optional revision
    /// fencing. The returned record never contains the secret bytes.
    pub fn put_managed_secret(
        &self,
        mut record: ManagedSecretRecord,
        payload: &SecretPayload,
        expected_revision: Option<u64>,
    ) -> StoreResult<ManagedSecretRecord> {
        validate_control_text("secret_id", &record.secret_id, 256)?;
        validate_control_text("owner_id", &record.owner_id, 256)?;
        validate_control_text("kind", &record.kind, 128)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::ManagedSecretEncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            let existing = transaction
                .query_row(
                    "SELECT owner_id, kind, revision, created_at, updated_at, expires_at, envelope
                     FROM managed_secrets WHERE secret_id = ?1",
                    [&record.secret_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, u64>(4)?,
                            row.get::<_, Option<u64>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(sqlite_error)?;
            let (revision, created_at) = if let Some((owner, kind, old_revision, created, _, _, envelope)) = existing {
                if owner != record.owner_id || kind != record.kind {
                    return Err(StoreError::OwnerMismatch);
                }
                let old_revision = u64::try_from(old_revision)
                    .map_err(|_| StoreError::ManagedSecretRevisionConflict)?;
                if expected_revision != Some(old_revision) {
                    return Err(StoreError::ManagedSecretRevisionConflict);
                }
                let aad = managed_secret_aad(&record.secret_id);
                cipher.open_for(&envelope, &aad)?;
                (old_revision.saturating_add(1), created)
            } else {
                if expected_revision.is_some() {
                    return Err(StoreError::ManagedSecretRevisionConflict);
                }
                (1, record.created_at)
            };
            record.revision = revision;
            record.created_at = created_at;
            record.updated_at = record.updated_at.max(record.created_at);
            let envelope = cipher.seal_for(payload, &managed_secret_aad(&record.secret_id))?;
            transaction
                .execute(
                    "INSERT INTO managed_secrets
                     (secret_id, owner_id, kind, revision, created_at, updated_at, expires_at, envelope)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(secret_id) DO UPDATE SET
                       revision = excluded.revision, updated_at = excluded.updated_at,
                       expires_at = excluded.expires_at, envelope = excluded.envelope",
                    params![
                        &record.secret_id,
                        &record.owner_id,
                        &record.kind,
                        i64::try_from(record.revision).unwrap_or(i64::MAX),
                        record.created_at,
                        record.updated_at,
                        record.expires_at,
                        envelope,
                    ],
                )
                .map_err(sqlite_error)?;
            prune_managed_secrets(
                transaction,
                self.retention.max_managed_secrets,
                self.retention.control_history_ttl_ms,
                record.updated_at,
            )?;
            Ok(record.clone())
        })
    }

    /// Compare-and-swap spelling for callers that make revision fencing
    /// explicit.
    pub fn compare_and_swap_managed_secret(
        &self,
        record: ManagedSecretRecord,
        expected_revision: u64,
        payload: &SecretPayload,
    ) -> StoreResult<ManagedSecretRecord> {
        self.put_managed_secret(record, payload, Some(expected_revision))
    }

    pub fn managed_secret(&self, secret_id: &str) -> StoreResult<Option<ManagedSecretRecord>> {
        validate_control_text("secret_id", secret_id, 256)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT secret_id, owner_id, kind, revision, created_at, updated_at, expires_at
                 FROM managed_secrets WHERE secret_id = ?1",
                [secret_id],
                managed_secret_from_row,
            )
            .optional()
            .map_err(sqlite_error)
    }

    pub fn managed_secret_payload(&self, secret_id: &str) -> StoreResult<SecretPayload> {
        validate_control_text("secret_id", secret_id, 256)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::ManagedSecretEncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, &cipher)?;
        let envelope = connection
            .query_row(
                "SELECT envelope FROM managed_secrets WHERE secret_id = ?1",
                [secret_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(StoreError::ManagedSecretNotFound)?;
        cipher.open_for(&envelope, &managed_secret_aad(secret_id))
    }

    pub fn remove_managed_secret(&self, secret_id: &str) -> StoreResult<bool> {
        validate_control_text("secret_id", secret_id, 256)?;
        self.with_transaction(|transaction| {
            let removed = transaction
                .execute(
                    "DELETE FROM managed_secrets WHERE secret_id = ?1",
                    [secret_id],
                )
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    /// Create a cookie-authenticated management session. Only a keyed digest
    /// of `cookie_secret` is persisted.
    pub fn create_management_session(
        &self,
        mut record: ManagementSessionRecord,
        cookie_secret: &[u8],
    ) -> StoreResult<ManagementSessionRecord> {
        validate_control_text("session_id", &record.session_id, 256)?;
        validate_control_text("actor_id", &record.actor_id, 256)?;
        validate_secret_input(cookie_secret)?;
        if record.expires_at <= record.created_at {
            return Err(StoreError::RecordExpired);
        }
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let cookie_hash = cipher.secret_index(cookie_secret);
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            transaction
                .execute(
                    "DELETE FROM management_sessions WHERE expires_at <= ?1 OR revoked_at IS NOT NULL",
                    [record.created_at],
                )
                .map_err(sqlite_error)?;
            let exists: Option<i64> = transaction
                .query_row(
                    "SELECT 1 FROM management_sessions
                     WHERE session_id = ?1 OR cookie_hash = ?2",
                    params![&record.session_id, cookie_hash.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            if exists.is_some() {
                return Err(StoreError::ManagementSessionAlreadyExists);
            }
            record.revision = 1;
            transaction
                .execute(
                    "INSERT INTO management_sessions
                     (session_id, actor_id, cookie_hash, revision, created_at, expires_at, revoked_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                    params![
                        &record.session_id,
                        &record.actor_id,
                        cookie_hash.as_slice(),
                        record.revision,
                        record.created_at,
                        record.expires_at,
                    ],
                )
                .map_err(sqlite_error)?;
            prune_management_sessions(
                transaction,
                self.retention.max_management_sessions,
                record.created_at,
            )?;
            Ok(record.clone())
        })
    }

    pub fn management_session(
        &self,
        session_id: &str,
        now: Timestamp,
    ) -> StoreResult<Option<ManagementSessionRecord>> {
        validate_control_text("session_id", session_id, 256)?;
        let connection = self.connection()?;
        let record = connection
            .query_row(
                "SELECT session_id, actor_id, revision, created_at, expires_at, revoked_at
                 FROM management_sessions WHERE session_id = ?1",
                [session_id],
                management_session_from_row,
            )
            .optional()
            .map_err(sqlite_error)?;
        Ok(record.filter(|value| value.active_at(now)))
    }

    pub fn management_session_by_cookie(
        &self,
        cookie_secret: &[u8],
        now: Timestamp,
    ) -> StoreResult<Option<ManagementSessionRecord>> {
        validate_secret_input(cookie_secret)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let cookie_hash = cipher.secret_index(cookie_secret);
        let connection = self.connection()?;
        let record = connection
            .query_row(
                "SELECT session_id, actor_id, revision, created_at, expires_at, revoked_at
                 FROM management_sessions WHERE cookie_hash = ?1",
                [cookie_hash.as_slice()],
                management_session_from_row,
            )
            .optional()
            .map_err(sqlite_error)?;
        Ok(record.filter(|value| value.active_at(now)))
    }

    pub fn revoke_management_session(
        &self,
        session_id: &str,
        expected_revision: u64,
        revoked_at: Timestamp,
    ) -> StoreResult<ManagementSessionRecord> {
        validate_control_text("session_id", session_id, 256)?;
        self.with_immediate_transaction(|transaction| {
            let current = transaction
                .query_row(
                    "SELECT session_id, actor_id, revision, created_at, expires_at, revoked_at
                     FROM management_sessions WHERE session_id = ?1",
                    [session_id],
                    management_session_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or(StoreError::OwnerMismatch)?;
            if current.revision != expected_revision {
                return Err(StoreError::ManagementRevisionConflict);
            }
            let revision = current.revision.saturating_add(1);
            let changed = transaction
                .execute(
                    "UPDATE management_sessions SET revision = ?1, revoked_at = ?2
                     WHERE session_id = ?3 AND revision = ?4",
                    params![
                        i64::try_from(revision).unwrap_or(i64::MAX),
                        revoked_at,
                        session_id,
                        i64::try_from(expected_revision).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::ManagementRevisionConflict);
            }
            Ok(ManagementSessionRecord {
                revision,
                revoked_at: Some(revoked_at),
                ..current
            })
        })
    }

    /// Create an owner-scoped encrypted draft. The payload is deliberately
    /// rejected when it resembles a secret-bearing record.
    pub fn create_draft(&self, mut draft: DraftRecord) -> StoreResult<DraftRecord> {
        validate_draft(&draft)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            transaction
                .execute(
                    "INSERT INTO management_drafts
                     (owner_id, kind, etag, base_generation, revision, created_at,
                      updated_at, expires_at, envelope)
                     VALUES (?1, ?2, '', ?3, 1, ?4, ?4, ?5, X'00')",
                    params![
                        &draft.owner_id,
                        &draft.kind,
                        i64::try_from(draft.base_generation).unwrap_or(i64::MAX),
                        draft.created_at,
                        draft.expires_at,
                    ],
                )
                .map_err(sqlite_error)?;
            let id = transaction.last_insert_rowid();
            if id <= 0 {
                return Err(StoreError::ManagementCapacity);
            }
            draft.draft_id = u64::try_from(id).map_err(|_| StoreError::ManagementCapacity)?;
            draft.revision = 1;
            draft.updated_at = draft.created_at;
            draft.etag = draft_etag(&draft);
            let envelope = cipher.seal_for(&SecretPayload::new(&draft.payload)?, &draft_aad(id))?;
            transaction
                .execute(
                    "UPDATE management_drafts SET etag = ?1, envelope = ?2 WHERE draft_id = ?3",
                    params![&draft.etag, envelope, id],
                )
                .map_err(sqlite_error)?;
            prune_drafts(
                transaction,
                self.retention.max_drafts,
                self.retention.control_history_ttl_ms,
                draft.created_at,
            )?;
            Ok(draft.clone())
        })
    }

    /// Update an owned draft under both owner and revision/ETag fencing.
    pub fn update_draft(
        &self,
        draft_id: u64,
        owner_id: &str,
        expected_revision: u64,
        expected_etag: &str,
        payload: Vec<u8>,
        updated_at: Timestamp,
    ) -> StoreResult<DraftRecord> {
        validate_control_text("owner_id", owner_id, 256)?;
        validate_control_text("etag", expected_etag, 256)?;
        validate_payload(&payload)?;
        self.with_immediate_transaction(|transaction| {
            let cipher = self
                .encryption_read()?
                .clone()
                .ok_or(StoreError::EncryptionRequired)?;
            assert_cipher_current_transaction(transaction, &cipher)?;
            let current = load_draft_transaction(transaction, &cipher, draft_id)?
                .ok_or(StoreError::RecordExpired)?;
            if !current.active_at(updated_at) {
                return Err(StoreError::RecordExpired);
            }
            if current.owner_id != owner_id {
                return Err(StoreError::OwnerMismatch);
            }
            if current.revision != expected_revision || current.etag != expected_etag {
                return Err(StoreError::ManagementRevisionConflict);
            }
            let mut next = DraftRecord {
                draft_id,
                owner_id: current.owner_id,
                kind: current.kind,
                etag: String::new(),
                base_generation: current.base_generation,
                revision: current.revision.saturating_add(1),
                payload,
                created_at: current.created_at,
                updated_at,
                expires_at: current.expires_at,
            };
            next.etag = draft_etag(&next);
            let envelope = cipher.seal_for(
                &SecretPayload::new(&next.payload)?,
                &draft_aad(i64::try_from(draft_id).unwrap_or(i64::MAX)),
            )?;
            let changed = transaction
                .execute(
                    "UPDATE management_drafts
                     SET etag = ?1, revision = ?2, updated_at = ?3, envelope = ?4
                     WHERE draft_id = ?5 AND owner_id = ?6 AND revision = ?7 AND etag = ?8",
                    params![
                        &next.etag,
                        i64::try_from(next.revision).unwrap_or(i64::MAX),
                        next.updated_at,
                        envelope,
                        i64::try_from(draft_id).unwrap_or(i64::MAX),
                        owner_id,
                        i64::try_from(expected_revision).unwrap_or(i64::MAX),
                        expected_etag,
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::ManagementRevisionConflict);
            }
            Ok(next)
        })
    }

    pub fn draft(
        &self,
        draft_id: u64,
        owner_id: &str,
        now: Timestamp,
    ) -> StoreResult<Option<DraftRecord>> {
        validate_control_text("owner_id", owner_id, 256)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        let draft = load_draft_connection(&connection, &cipher, draft_id)?;
        match draft {
            Some(value) if value.owner_id != owner_id => Err(StoreError::OwnerMismatch),
            Some(value) if !value.active_at(now) => Err(StoreError::RecordExpired),
            value => Ok(value),
        }
    }

    pub fn drafts_for_owner(
        &self,
        owner_id: &str,
        now: Timestamp,
    ) -> StoreResult<Vec<DraftRecord>> {
        validate_control_text("owner_id", owner_id, 256)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT draft_id FROM management_drafts
                 WHERE owner_id = ?1 AND expires_at > ?2
                 ORDER BY updated_at DESC, draft_id DESC",
            )
            .map_err(sqlite_error)?;
        let ids = statement
            .query_map(params![owner_id, now], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                load_draft_connection(
                    &connection,
                    &cipher,
                    u64::try_from(id).map_err(|_| StoreError::ManagementCapacity)?,
                )?
                .ok_or(StoreError::RecordExpired)
            })
            .collect()
    }

    pub fn remove_draft(&self, draft_id: u64, owner_id: &str) -> StoreResult<bool> {
        validate_control_text("owner_id", owner_id, 256)?;
        self.with_transaction(|transaction| {
            let current_owner: Option<String> = transaction
                .query_row(
                    "SELECT owner_id FROM management_drafts WHERE draft_id = ?1",
                    [i64::try_from(draft_id).unwrap_or(i64::MAX)],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            if let Some(current_owner) = current_owner {
                if current_owner != owner_id {
                    return Err(StoreError::OwnerMismatch);
                }
            }
            let removed = transaction
                .execute(
                    "DELETE FROM management_drafts WHERE draft_id = ?1 AND owner_id = ?2",
                    params![i64::try_from(draft_id).unwrap_or(i64::MAX), owner_id],
                )
                .map_err(sqlite_error)?;
            Ok(removed != 0)
        })
    }

    pub fn append_audit_record(&self, mut record: AuditRecord) -> StoreResult<AuditRecord> {
        validate_audit_record(&record)?;
        self.with_transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO management_audit_records
                     (owner_id, action, resource, outcome, generation, error_code, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        &record.owner_id,
                        &record.action,
                        &record.resource,
                        &record.outcome,
                        i64::try_from(record.generation).unwrap_or(i64::MAX),
                        &record.error_code,
                        record.recorded_at,
                    ],
                )
                .map_err(sqlite_error)?;
            let id = transaction.last_insert_rowid();
            record.id = u64::try_from(id).map_err(|_| StoreError::ManagementCapacity)?;
            prune_audit_records(
                transaction,
                self.retention.max_audit_records,
                self.retention.control_history_ttl_ms,
                record.recorded_at,
            )?;
            Ok(record.clone())
        })
    }

    pub fn audit_records(&self) -> StoreResult<Vec<AuditRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, owner_id, action, resource, outcome, generation,
                        error_code, recorded_at
                 FROM management_audit_records ORDER BY id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], audit_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    pub fn append_reload_record(&self, mut record: ReloadRecord) -> StoreResult<ReloadRecord> {
        validate_reload_record(&record)?;
        self.with_transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO management_reload_records
                     (owner_id, kind, generation, completed_generation, status, etag, error_code,
                      started_at, completed_at, revision)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
                    params![
                        &record.owner_id,
                        &record.kind,
                        i64::try_from(record.generation).unwrap_or(i64::MAX),
                        record
                            .completed_generation
                            .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                        &record.status,
                        &record.etag,
                        &record.error_code,
                        record.started_at,
                        record.completed_at,
                    ],
                )
                .map_err(sqlite_error)?;
            let id = transaction.last_insert_rowid();
            record.id = u64::try_from(id).map_err(|_| StoreError::ManagementCapacity)?;
            record.revision = 1;
            prune_reload_records(
                transaction,
                self.retention.max_reload_records,
                self.retention.control_history_ttl_ms,
                record.started_at,
            )?;
            Ok(record.clone())
        })
    }

    pub fn update_reload_record(
        &self,
        record_id: u64,
        expected_revision: u64,
        status: &str,
        error_code: Option<&str>,
        completed_at: Option<Timestamp>,
        completed_generation: Option<u64>,
    ) -> StoreResult<ReloadRecord> {
        validate_control_text("status", status, 128)?;
        if let Some(error_code) = error_code {
            validate_control_text("error_code", error_code, 128)?;
        }
        self.with_immediate_transaction(|transaction| {
            let current = transaction
                .query_row(
                    "SELECT id, owner_id, kind, generation, completed_generation, status, etag, error_code,
                            started_at, completed_at, revision
                     FROM management_reload_records WHERE id = ?1",
                    [i64::try_from(record_id).unwrap_or(i64::MAX)],
                    reload_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or(StoreError::ManagementRevisionConflict)?;
            if current.revision != expected_revision {
                return Err(StoreError::ManagementRevisionConflict);
            }
            let revision = current.revision.saturating_add(1);
            let changed = transaction
                .execute(
                    "UPDATE management_reload_records
                     SET status = ?1, error_code = ?2, completed_at = ?3,
                         completed_generation = ?4, revision = ?5
                     WHERE id = ?6 AND revision = ?7",
                    params![
                        status,
                        error_code,
                        completed_at,
                        completed_generation.map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                        i64::try_from(revision).unwrap_or(i64::MAX),
                        i64::try_from(record_id).unwrap_or(i64::MAX),
                        i64::try_from(expected_revision).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::ManagementRevisionConflict);
            }
            Ok(ReloadRecord {
                status: status.to_owned(),
                error_code: error_code.map(ToOwned::to_owned),
                completed_at,
                completed_generation,
                revision,
                ..current
            })
        })
    }

    pub fn reload_records(&self) -> StoreResult<Vec<ReloadRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, owner_id, kind, generation, completed_generation, status, etag, error_code,
                        started_at, completed_at, revision
                 FROM management_reload_records ORDER BY id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], reload_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    /// Persist one owner-scoped OAuth flow. State is keyed and the PKCE
    /// verifier is encrypted; neither raw value is represented in the row.
    pub fn begin_oauth_flow(
        &self,
        mut record: OAuthFlowRecord,
        state: &[u8],
        pkce_verifier: Option<&SecretPayload>,
    ) -> StoreResult<OAuthFlowRecord> {
        validate_oauth_flow(&record)?;
        validate_secret_input(state)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let state_hash = cipher.secret_index(state);
        let pkce_envelope = pkce_verifier
            .map(|value| cipher.seal_for(value, &oauth_pkce_aad(&record.flow_id)))
            .transpose()?;
        self.with_immediate_transaction(|transaction| {
            assert_cipher_current_transaction(transaction, &cipher)?;
            transaction
                .execute(
                    "DELETE FROM oauth_flows WHERE expires_at <= ?1",
                    [record.created_at],
                )
                .map_err(sqlite_error)?;
            let duplicate: Option<i64> = transaction
                .query_row(
                    "SELECT 1 FROM oauth_flows
                     WHERE (provider_id = ?1 AND account_id = ?2 AND status = 'pending')
                        OR state_hash = ?3",
                    params![
                        &record.provider_id,
                        &record.account_id,
                        state_hash.as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            if duplicate.is_some() {
                return Err(StoreError::OAuthFlowAlreadyExists);
            }
            record.status = OAuthFlowStatus::Pending;
            record.revision = 1;
            transaction
                .execute(
                    "INSERT INTO oauth_flows
                     (flow_id, owner_id, provider_id, account_id, flow_kind, status,
                      state_hash, pkce_envelope, revision, created_at, expires_at,
                      state_consumed_at, completed_at, error_code)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, NULL, NULL, NULL)",
                    params![
                        &record.flow_id,
                        &record.owner_id,
                        &record.provider_id,
                        &record.account_id,
                        &record.flow_kind,
                        record.status.as_str(),
                        state_hash.as_slice(),
                        pkce_envelope,
                        record.created_at,
                        record.expires_at,
                    ],
                )
                .map_err(map_oauth_sqlite_error)?;
            prune_oauth_flows(
                transaction,
                self.retention.max_oauth_flows,
                self.retention.control_history_ttl_ms,
                record.created_at,
            )?;
            Ok(record.clone())
        })
    }

    pub fn oauth_flow(&self, flow_id: &str) -> StoreResult<Option<OAuthFlowRecord>> {
        validate_control_text("flow_id", flow_id, 256)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT flow_id, owner_id, provider_id, account_id, flow_kind, status,
                        revision, created_at, expires_at, state_consumed_at,
                        completed_at, error_code
                 FROM oauth_flows WHERE flow_id = ?1",
                [flow_id],
                oauth_flow_from_row,
            )
            .optional()
            .map_err(sqlite_error)
    }

    /// Read a pending, unconsumed flow by the caller-held raw state without
    /// consuming it. Callback handlers should use [`Self::consume_oauth_state`]
    /// for the one-time transition.
    pub fn oauth_flow_by_state(
        &self,
        state: &[u8],
        now: Timestamp,
    ) -> StoreResult<Option<OAuthFlowRecord>> {
        validate_secret_input(state)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let state_hash = cipher.secret_index(state);
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, &cipher)?;
        connection
            .query_row(
                "SELECT flow_id, owner_id, provider_id, account_id, flow_kind, status,
                        revision, created_at, expires_at, state_consumed_at,
                        completed_at, error_code
                 FROM oauth_flows
                 WHERE state_hash = ?1 AND state_consumed_at IS NULL
                   AND expires_at > ?2 AND status = 'pending'",
                params![state_hash.as_slice(), now],
                oauth_flow_from_row,
            )
            .optional()
            .map_err(sqlite_error)
    }

    /// Correlate a callback without requiring the dashboard session cookie.
    /// The lookup returns metadata only and consumes the one-time state.
    pub fn consume_oauth_state(
        &self,
        state: &[u8],
        now: Timestamp,
    ) -> StoreResult<Option<OAuthFlowRecord>> {
        validate_secret_input(state)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let state_hash = cipher.secret_index(state);
        self.with_immediate_transaction(|transaction| {
            let current = transaction
                .query_row(
                    "SELECT flow_id, owner_id, provider_id, account_id, flow_kind, status,
                            revision, created_at, expires_at, state_consumed_at,
                            completed_at, error_code
                     FROM oauth_flows
                     WHERE state_hash = ?1 AND state_consumed_at IS NULL
                       AND expires_at > ?2 AND status = 'pending'",
                    params![state_hash.as_slice(), now],
                    oauth_flow_from_row,
                )
                .optional()
                .map_err(sqlite_error)?;
            let Some(current) = current else {
                return Ok(None);
            };
            let changed = transaction
                .execute(
                    "UPDATE oauth_flows SET state_consumed_at = ?, revision = revision + 1
                     WHERE flow_id = ? AND revision = ? AND state_consumed_at IS NULL",
                    params![
                        now,
                        &current.flow_id,
                        i64::try_from(current.revision).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::OAuthStateConflict);
            }
            Ok(Some(OAuthFlowRecord {
                state_consumed_at: Some(now),
                revision: current.revision.saturating_add(1),
                ..current
            }))
        })
    }

    pub fn oauth_flow_pkce_verifier(&self, flow_id: &str) -> StoreResult<Option<SecretPayload>> {
        validate_control_text("flow_id", flow_id, 256)?;
        let cipher = self
            .encryption_read()?
            .clone()
            .ok_or(StoreError::EncryptionRequired)?;
        let connection = self.connection()?;
        assert_cipher_current_connection(&connection, &cipher)?;
        let envelope = connection
            .query_row(
                "SELECT pkce_envelope FROM oauth_flows WHERE flow_id = ?1",
                [flow_id],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(StoreError::OAuthFlowNotFound)?;
        envelope
            .map(|value| cipher.open_for(&value, &oauth_pkce_aad(flow_id)))
            .transpose()
    }

    pub fn update_oauth_flow(
        &self,
        flow_id: &str,
        owner_id: &str,
        expected_revision: u64,
        status: OAuthFlowStatus,
        error_code: Option<&str>,
        completed_at: Option<Timestamp>,
    ) -> StoreResult<OAuthFlowRecord> {
        validate_control_text("flow_id", flow_id, 256)?;
        validate_control_text("owner_id", owner_id, 256)?;
        if let Some(error_code) = error_code {
            validate_control_text("error_code", error_code, 128)?;
        }
        self.with_immediate_transaction(|transaction| {
            let current = transaction
                .query_row(
                    "SELECT flow_id, owner_id, provider_id, account_id, flow_kind, status,
                            revision, created_at, expires_at, state_consumed_at,
                            completed_at, error_code
                     FROM oauth_flows WHERE flow_id = ?1",
                    [flow_id],
                    oauth_flow_from_row,
                )
                .optional()
                .map_err(sqlite_error)?
                .ok_or(StoreError::OAuthFlowNotFound)?;
            if current.owner_id != owner_id {
                return Err(StoreError::OwnerMismatch);
            }
            if current.revision != expected_revision {
                return Err(StoreError::ManagementRevisionConflict);
            }
            let revision = current.revision.saturating_add(1);
            let changed = transaction
                .execute(
                    "UPDATE oauth_flows
                     SET status = ?1, error_code = ?2, completed_at = ?3, revision = ?4
                     WHERE flow_id = ?5 AND revision = ?6 AND owner_id = ?7",
                    params![
                        status.as_str(),
                        error_code,
                        completed_at,
                        i64::try_from(revision).unwrap_or(i64::MAX),
                        flow_id,
                        i64::try_from(expected_revision).unwrap_or(i64::MAX),
                        owner_id,
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(StoreError::ManagementRevisionConflict);
            }
            Ok(OAuthFlowRecord {
                status,
                error_code: error_code.map(ToOwned::to_owned),
                completed_at,
                revision,
                ..current
            })
        })
    }

    pub fn oauth_flows_for_owner(&self, owner_id: &str) -> StoreResult<Vec<OAuthFlowRecord>> {
        validate_control_text("owner_id", owner_id, 256)?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT flow_id, owner_id, provider_id, account_id, flow_kind, status,
                        revision, created_at, expires_at, state_consumed_at,
                        completed_at, error_code
                 FROM oauth_flows WHERE owner_id = ?1
                 ORDER BY created_at ASC, flow_id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([owner_id], oauth_flow_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
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
    let file_generation_domain = path
        .as_deref()
        .map(database_file_generation_domain)
        .transpose()?
        .flatten();
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
        file_generation_domain,
        encryption: Arc::new(RwLock::new(encryption)),
    })
}

fn checkpoint_and_backup_quiesced(source: &Path, destination: &Path) -> StoreResult<()> {
    if source.as_os_str().is_empty() || destination.as_os_str().is_empty() {
        return Err(StoreError::InvalidPath(
            "SQLite backup paths must not be empty".to_owned(),
        ));
    }
    let source_metadata = fs::symlink_metadata(source).map_err(io_error)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(StoreError::InvalidPath(
            "SQLite backup source must be a regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if source_metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::UnsafePath(
                "SQLite backup source must be owner-private".to_owned(),
            ));
        }
    }
    if fs::symlink_metadata(destination).is_ok() {
        return Err(StoreError::InvalidPath(
            "SQLite backup destination already exists".to_owned(),
        ));
    }
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        if !parent.is_dir() {
            return Err(StoreError::InvalidPath(
                "SQLite backup destination parent is not a directory".to_owned(),
            ));
        }
    }

    let source_connection = Connection::open(source).map_err(sqlite_error)?;
    source_connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(sqlite_error)?;
    let result = (|| {
        // The caller has already quiesced the owning service. Checkpoint first
        // so the backup does not depend on WAL/SHM sidecars. SQLite's online
        // backup API must not be started from a connection holding a write
        // transaction, so the quiescence contract is enforced by the caller.
        checkpoint_connection(&source_connection)?;
        let mut destination_connection = Connection::open(destination).map_err(sqlite_error)?;
        let backup_result = (|| {
            let backup = Backup::new(&source_connection, &mut destination_connection)
                .map_err(sqlite_error)?;
            backup
                .run_to_completion(256, Duration::from_millis(1), None)
                .map_err(sqlite_error)
        })();
        drop(destination_connection);
        backup_result?;
        checkpoint_connection(&source_connection)?;
        let destination_connection = Connection::open(destination).map_err(sqlite_error)?;
        let integrity: String = destination_connection
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .map_err(sqlite_error)?;
        if !integrity.eq_ignore_ascii_case("ok") {
            return Err(StoreError::Sqlite(format!(
                "SQLite backup integrity check reported `{integrity}`"
            )));
        }
        destination_connection
            .execute(
                "UPDATE store_identity SET identity = randomblob(16) WHERE singleton = 1",
                [],
            )
            .map_err(sqlite_error)?;
        drop(destination_connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600))
                .map_err(io_error)?;
        }
        fs::File::open(destination)
            .and_then(|file| file.sync_all())
            .map_err(io_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = destination.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }
    result
}

fn checkpoint_connection(connection: &Connection) -> StoreResult<()> {
    let result = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(sqlite_error)?;
    if result.0 != 0 {
        return Err(StoreError::Sqlite(
            "SQLite WAL checkpoint remained busy".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn database_file_generation_domain(path: &Path) -> StoreResult<Option<FileGenerationDomain>> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::metadata(path).map_err(io_error)?;
    Ok(Some(FileGenerationDomain {
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

#[cfg(windows)]
fn database_file_generation_domain(path: &Path) -> StoreResult<Option<FileGenerationDomain>> {
    use std::os::windows::fs::MetadataExt as _;

    let metadata = fs::metadata(path).map_err(io_error)?;
    Ok(metadata
        .volume_serial_number()
        .zip(metadata.file_index())
        .map(|(volume, index)| FileGenerationDomain {
            device: u64::from(volume),
            inode: index,
        }))
}

#[cfg(not(any(unix, windows)))]
fn database_file_generation_domain(_path: &Path) -> StoreResult<Option<FileGenerationDomain>> {
    Ok(None)
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
                "SELECT p.credential_id, c.configuration_fingerprint, p.envelope
                 FROM credential_payloads AS p
                 JOIN credentials AS c ON c.credential_id = p.credential_id
                 ORDER BY p.credential_id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (credential_id, fingerprint, envelope) in credential_rows {
        let aad = credential_payload_aad(&credential_id, &fingerprint);
        cipher.open_for(&envelope, &aad)?;
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

    let managed_secret_rows = {
        let mut statement = transaction
            .prepare("SELECT secret_id, envelope FROM managed_secrets ORDER BY secret_id ASC")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (secret_id, envelope) in managed_secret_rows {
        cipher.open_for(&envelope, &managed_secret_aad(&secret_id))?;
    }

    let draft_rows = {
        let mut statement = transaction
            .prepare("SELECT draft_id, envelope FROM management_drafts ORDER BY draft_id ASC")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (draft_id, envelope) in draft_rows {
        cipher.open_for(&envelope, &draft_aad(draft_id))?;
    }

    let oauth_rows = {
        let mut statement = transaction
            .prepare(
                "SELECT flow_id, pkce_envelope FROM oauth_flows
                 WHERE pkce_envelope IS NOT NULL ORDER BY flow_id ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for (flow_id, envelope) in oauth_rows {
        cipher.open_for(&envelope, &oauth_pkce_aad(&flow_id))?;
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
    let revision: i64 = row.get(5)?;
    Ok(CredentialState {
        credential_id: row.get(0)?,
        provider_id: row.get(1)?,
        configuration_fingerprint: row.get(2)?,
        enabled: row.get::<_, i64>(3)? != 0,
        updated_at: row.get(4)?,
        revision: u64::try_from(revision).unwrap_or(u64::MAX),
    })
}

fn affinity_from_row(row: &Row<'_>) -> rusqlite::Result<SessionAffinity> {
    Ok(SessionAffinity {
        key: row.get(0)?,
        provider_id: row.get(6)?,
        credential_id: row.get(7)?,
        upstream_model: row.get(8)?,
        route_id: row.get(1)?,
        policy_id: row.get(2)?,
        logical_model: row.get(3)?,
        account_pool_id: row.get(4)?,
        target_binding_id: row.get(5)?,
        created_at: row.get(9)?,
        last_used_at: row.get(10)?,
        expires_at: row.get(11)?,
    })
}

fn legacy_affinity_from_row(row: &Row<'_>) -> rusqlite::Result<SessionAffinity> {
    Ok(SessionAffinity {
        key: row.get(0)?,
        provider_id: row.get(1)?,
        credential_id: row.get(2)?,
        upstream_model: row.get(3)?,
        route_id: String::new(),
        policy_id: String::new(),
        logical_model: String::new(),
        account_pool_id: String::new(),
        target_binding_id: String::new(),
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
        target_binding_id: row.get(8).map_err(sqlite_error)?,
        priority_tier: row
            .get::<_, Option<i64>>(9)
            .map_err(sqlite_error)?
            .map(|value| {
                u32::try_from(value).map_err(|_| StoreError::Sqlite("priority overflow".to_owned()))
            })
            .transpose()?,
        attempt: row
            .get::<_, i64>(10)
            .map_err(sqlite_error)
            .and_then(|value| {
                u32::try_from(value).map_err(|_| StoreError::Sqlite("attempt overflow".to_owned()))
            })?,
        configuration_generation: row.get::<_, i64>(11).map_err(sqlite_error).and_then(
            |value| {
                u64::try_from(value)
                    .map_err(|_| StoreError::Sqlite("generation overflow".to_owned()))
            },
        )?,
        reason: row.get(12).map_err(sqlite_error)?,
        recorded_at: row.get(13).map_err(sqlite_error)?,
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
    transaction
        .execute(
            "DELETE FROM scoped_affinities WHERE credential_id = ?1",
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

fn evict_scoped_affinities(transaction: &Transaction<'_>, limit: usize) -> StoreResult<usize> {
    let limit =
        i64::try_from(limit).map_err(|_| StoreError::Sqlite("retention overflow".to_owned()))?;
    let removed = transaction
        .execute(
            "DELETE FROM scoped_affinities WHERE rowid IN (
                 SELECT rowid FROM scoped_affinities
                 ORDER BY last_used_at ASC, created_at ASC, key ASC,
                          route_id ASC, policy_id ASC, logical_model ASC,
                          account_pool_id ASC, target_binding_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM scoped_affinities) - ?1, 0)
             )",
            [limit],
        )
        .map_err(sqlite_error)?;
    Ok(removed)
}

const MAX_CONTROL_TEXT_BYTES: usize = 512;
const MAX_CONTROL_PAYLOAD_BYTES: usize = 256 * 1024;

fn validate_control_text(field: &'static str, value: &str, max: usize) -> StoreResult<()> {
    non_empty(field, value)?;
    if value.len() > max {
        return Err(StoreError::Serialization(format!(
            "{field} exceeds metadata bounds"
        )));
    }
    Ok(())
}

fn validate_secret_input(value: &[u8]) -> StoreResult<()> {
    if value.is_empty() {
        return Err(StoreError::EmptyCredentialPayload);
    }
    if value.len() > MAX_CONTROL_TEXT_BYTES {
        return Err(StoreError::Serialization(
            "control secret exceeds metadata bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> StoreResult<()> {
    if payload.is_empty() || payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(StoreError::Serialization(
            "control payload exceeds bounds".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| {
        StoreError::Serialization("control draft payload must be valid JSON".to_owned())
    })?;
    validate_draft_value(&value, None)
}

fn validate_draft_value(value: &serde_json::Value, key: Option<&str>) -> StoreResult<()> {
    let rejected = || {
        StoreError::Serialization("control draft must not contain secret-bearing fields".to_owned())
    };
    if let Some(key) = key {
        let key = key.to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "access_token" | "refresh_token" | "password" | "cookie_secret" | "pkce_verifier"
        ) {
            return Err(rejected());
        }
        if matches!(key.as_str(), "secret" | "client_secret") {
            let reference = value.as_str().is_some_and(|value| {
                value.len() <= 2_048
                    && !value.chars().any(char::is_control)
                    && ["managed:", "file:", "env:", "keyring:"]
                        .into_iter()
                        .any(|prefix| value.strip_prefix(prefix).is_some_and(|id| !id.is_empty()))
            });
            if !reference {
                return Err(rejected());
            }
        }
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                validate_draft_value(value, Some(key))?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_draft_value(value, None)?;
            }
        }
        serde_json::Value::String(value) if value.to_ascii_lowercase().contains("bearer ") => {
            return Err(rejected());
        }
        _ => {}
    }
    Ok(())
}

fn validate_draft(draft: &DraftRecord) -> StoreResult<()> {
    validate_control_text("owner_id", &draft.owner_id, 256)?;
    validate_control_text("kind", &draft.kind, 128)?;
    if draft.expires_at <= draft.created_at {
        return Err(StoreError::RecordExpired);
    }
    validate_payload(&draft.payload)
}

fn validate_audit_record(record: &AuditRecord) -> StoreResult<()> {
    if let Some(owner_id) = &record.owner_id {
        validate_control_text("owner_id", owner_id, 256)?;
    }
    validate_control_text("action", &record.action, 128)?;
    validate_control_text("resource", &record.resource, 256)?;
    validate_control_text("outcome", &record.outcome, 128)?;
    if let Some(error_code) = &record.error_code {
        validate_control_text("error_code", error_code, 128)?;
    }
    Ok(())
}

fn validate_reload_record(record: &ReloadRecord) -> StoreResult<()> {
    if let Some(owner_id) = &record.owner_id {
        validate_control_text("owner_id", owner_id, 256)?;
    }
    validate_control_text("kind", &record.kind, 64)?;
    validate_control_text("status", &record.status, 128)?;
    if let Some(etag) = &record.etag {
        validate_control_text("etag", etag, 256)?;
    }
    if let Some(error_code) = &record.error_code {
        validate_control_text("error_code", error_code, 128)?;
    }
    Ok(())
}

fn validate_oauth_flow(record: &OAuthFlowRecord) -> StoreResult<()> {
    for (field, value) in [
        ("flow_id", record.flow_id.as_str()),
        ("owner_id", record.owner_id.as_str()),
        ("provider_id", record.provider_id.as_str()),
        ("account_id", record.account_id.as_str()),
        ("flow_kind", record.flow_kind.as_str()),
    ] {
        validate_control_text(field, value, 256)?;
    }
    if record.expires_at <= record.created_at {
        return Err(StoreError::RecordExpired);
    }
    if let Some(error_code) = &record.error_code {
        validate_control_text("error_code", error_code, 128)?;
    }
    Ok(())
}

fn managed_secret_aad(secret_id: &str) -> Vec<u8> {
    format!("pooler-managed-secret:v1:{secret_id}").into_bytes()
}

fn draft_aad(draft_id: i64) -> Vec<u8> {
    format!("pooler-management-draft:v1:{draft_id}").into_bytes()
}

fn oauth_pkce_aad(flow_id: &str) -> Vec<u8> {
    format!("pooler-oauth-pkce:v1:{flow_id}").into_bytes()
}

fn draft_etag(draft: &DraftRecord) -> String {
    let mut value = Vec::with_capacity(draft.payload.len() + 128);
    value.extend_from_slice(b"pooler-draft-etag:v1|");
    value.extend_from_slice(draft.owner_id.as_bytes());
    value.push(b'|');
    value.extend_from_slice(draft.kind.as_bytes());
    value.push(b'|');
    value.extend_from_slice(draft.base_generation.to_string().as_bytes());
    value.push(b'|');
    value.extend_from_slice(draft.revision.to_string().as_bytes());
    value.push(b'|');
    value.extend_from_slice(&draft.payload);
    hex_digest(&value)
}

fn managed_secret_from_row(row: &Row<'_>) -> rusqlite::Result<ManagedSecretRecord> {
    Ok(ManagedSecretRecord {
        secret_id: row.get(0)?,
        owner_id: row.get(1)?,
        kind: row.get(2)?,
        revision: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(u64::MAX),
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        expires_at: row.get(6)?,
    })
}

fn management_session_from_row(row: &Row<'_>) -> rusqlite::Result<ManagementSessionRecord> {
    Ok(ManagementSessionRecord {
        session_id: row.get(0)?,
        actor_id: row.get(1)?,
        revision: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(u64::MAX),
        created_at: row.get(3)?,
        expires_at: row.get(4)?,
        revoked_at: row.get(5)?,
    })
}

fn audit_from_row(row: &Row<'_>) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(u64::MAX),
        owner_id: row.get(1)?,
        action: row.get(2)?,
        resource: row.get(3)?,
        outcome: row.get(4)?,
        generation: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(u64::MAX),
        error_code: row.get(6)?,
        recorded_at: row.get(7)?,
    })
}

fn reload_from_row(row: &Row<'_>) -> rusqlite::Result<ReloadRecord> {
    Ok(ReloadRecord {
        id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(u64::MAX),
        owner_id: row.get(1)?,
        kind: row.get(2)?,
        generation: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(u64::MAX),
        completed_generation: row
            .get::<_, Option<i64>>(4)?
            .map(|value| u64::try_from(value).unwrap_or(u64::MAX)),
        status: row.get(5)?,
        etag: row.get(6)?,
        error_code: row.get(7)?,
        started_at: row.get(8)?,
        completed_at: row.get(9)?,
        revision: u64::try_from(row.get::<_, i64>(10)?).unwrap_or(u64::MAX),
    })
}

fn oauth_flow_from_row(row: &Row<'_>) -> rusqlite::Result<OAuthFlowRecord> {
    let status: String = row.get(5)?;
    let status = OAuthFlowStatus::parse(&status).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid OAuth flow status",
            )),
        )
    })?;
    Ok(OAuthFlowRecord {
        flow_id: row.get(0)?,
        owner_id: row.get(1)?,
        provider_id: row.get(2)?,
        account_id: row.get(3)?,
        flow_kind: row.get(4)?,
        status,
        revision: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(u64::MAX),
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        state_consumed_at: row.get(9)?,
        completed_at: row.get(10)?,
        error_code: row.get(11)?,
    })
}

fn load_draft_connection(
    connection: &Connection,
    cipher: &CredentialCipher,
    draft_id: u64,
) -> StoreResult<Option<DraftRecord>> {
    let row = connection
        .query_row(
            "SELECT draft_id, owner_id, kind, etag, base_generation, revision,
                    created_at, updated_at, expires_at, envelope
             FROM management_drafts WHERE draft_id = ?1",
            [i64::try_from(draft_id).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, u64>(7)?,
                    row.get::<_, u64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        id,
        owner_id,
        kind,
        etag,
        base_generation,
        revision,
        created_at,
        updated_at,
        expires_at,
        envelope,
    )) = row
    else {
        return Ok(None);
    };
    let payload = cipher.open_for(&envelope, &draft_aad(id))?;
    let payload = payload.into_bytes();
    let draft = DraftRecord {
        draft_id: u64::try_from(id).map_err(|_| StoreError::ManagementCapacity)?,
        owner_id,
        kind,
        etag,
        base_generation: u64::try_from(base_generation).unwrap_or(u64::MAX),
        revision: u64::try_from(revision).unwrap_or(u64::MAX),
        payload,
        created_at,
        updated_at,
        expires_at,
    };
    if draft.etag != draft_etag(&draft) {
        return Err(StoreError::CredentialEnvelopeAuthenticationFailed);
    }
    Ok(Some(draft))
}

fn load_draft_transaction(
    transaction: &Transaction<'_>,
    cipher: &CredentialCipher,
    draft_id: u64,
) -> StoreResult<Option<DraftRecord>> {
    let row = transaction
        .query_row(
            "SELECT draft_id, owner_id, kind, etag, base_generation, revision,
                    created_at, updated_at, expires_at, envelope
             FROM management_drafts WHERE draft_id = ?1",
            [i64::try_from(draft_id).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, u64>(7)?,
                    row.get::<_, u64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        id,
        owner_id,
        kind,
        etag,
        base_generation,
        revision,
        created_at,
        updated_at,
        expires_at,
        envelope,
    )) = row
    else {
        return Ok(None);
    };
    let payload = cipher.open_for(&envelope, &draft_aad(id))?.into_bytes();
    let draft = DraftRecord {
        draft_id: u64::try_from(id).map_err(|_| StoreError::ManagementCapacity)?,
        owner_id,
        kind,
        etag,
        base_generation: u64::try_from(base_generation).unwrap_or(u64::MAX),
        revision: u64::try_from(revision).unwrap_or(u64::MAX),
        payload,
        created_at,
        updated_at,
        expires_at,
    };
    if draft.etag != draft_etag(&draft) {
        return Err(StoreError::CredentialEnvelopeAuthenticationFailed);
    }
    Ok(Some(draft))
}

fn prune_managed_secrets(
    transaction: &Transaction<'_>,
    limit: usize,
    ttl: u64,
    now: Timestamp,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM managed_secrets WHERE expires_at IS NOT NULL AND expires_at <= ?1
             OR updated_at < ?2",
            params![now, now.saturating_sub(ttl)],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM managed_secrets WHERE secret_id IN (
                 SELECT secret_id FROM managed_secrets ORDER BY updated_at ASC, secret_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM managed_secrets) - ?1, 0)
             )",
            [i64::try_from(limit).map_err(|_| StoreError::ManagementCapacity)?],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn prune_management_sessions(
    transaction: &Transaction<'_>,
    limit: usize,
    now: Timestamp,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM management_sessions WHERE expires_at <= ?1 OR revoked_at IS NOT NULL",
            [now],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM management_sessions WHERE session_id IN (
                 SELECT session_id FROM management_sessions
                 ORDER BY created_at ASC, session_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM management_sessions) - ?1, 0)
             )",
            [i64::try_from(limit).map_err(|_| StoreError::ManagementCapacity)?],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn prune_drafts(
    transaction: &Transaction<'_>,
    limit: usize,
    ttl: u64,
    now: Timestamp,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM management_drafts WHERE expires_at <= ?1 OR updated_at < ?2",
            params![now, now.saturating_sub(ttl)],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM management_drafts WHERE draft_id IN (
                 SELECT draft_id FROM management_drafts ORDER BY updated_at ASC, draft_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM management_drafts) - ?1, 0)
             )",
            [i64::try_from(limit).map_err(|_| StoreError::ManagementCapacity)?],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn prune_audit_records(
    transaction: &Transaction<'_>,
    limit: usize,
    ttl: u64,
    now: Timestamp,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM management_audit_records WHERE recorded_at < ?1",
            [now.saturating_sub(ttl)],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM management_audit_records WHERE id IN (
                 SELECT id FROM management_audit_records ORDER BY id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM management_audit_records) - ?1, 0)
             )",
            [i64::try_from(limit).map_err(|_| StoreError::ManagementCapacity)?],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn prune_reload_records(
    transaction: &Transaction<'_>,
    limit: usize,
    ttl: u64,
    now: Timestamp,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM management_reload_records WHERE started_at < ?1",
            [now.saturating_sub(ttl)],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM management_reload_records WHERE id IN (
                 SELECT id FROM management_reload_records ORDER BY id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM management_reload_records) - ?1, 0)
             )",
            [i64::try_from(limit).map_err(|_| StoreError::ManagementCapacity)?],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn prune_oauth_flows(
    transaction: &Transaction<'_>,
    limit: usize,
    ttl: u64,
    now: Timestamp,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM oauth_flows WHERE expires_at <= ?1 OR created_at < ?2",
            params![now, now.saturating_sub(ttl)],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM oauth_flows WHERE flow_id IN (
                 SELECT flow_id FROM oauth_flows ORDER BY created_at ASC, flow_id ASC
                 LIMIT MAX((SELECT COUNT(*) FROM oauth_flows) - ?1, 0)
             )",
            [i64::try_from(limit).map_err(|_| StoreError::ManagementCapacity)?],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn map_oauth_sqlite_error(error: rusqlite::Error) -> StoreError {
    if error.to_string().contains("UNIQUE constraint failed") {
        StoreError::OAuthFlowAlreadyExists
    } else {
        sqlite_error(error)
    }
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

fn next_credential_revision(
    transaction: &Transaction<'_>,
    _credential_id: &str,
    current_revision: u64,
) -> StoreResult<u64> {
    let minimum = current_revision
        .checked_add(1)
        .ok_or(StoreError::CredentialRevisionConflict)?;
    let minimum = i64::try_from(minimum).map_err(|_| StoreError::CredentialRevisionConflict)?;
    let advanced = transaction
        .execute(
            "UPDATE credential_revision_clock
             SET revision = CASE
                 WHEN revision < ?1 THEN ?1
                 ELSE revision + 1
             END
             WHERE singleton = 1 AND revision < ?2",
            params![minimum, i64::MAX],
        )
        .map_err(sqlite_error)?;
    if advanced != 1 {
        return Err(StoreError::CredentialRevisionConflict);
    }
    let revision = transaction
        .query_row(
            "SELECT revision FROM credential_revision_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let revision = u64::try_from(revision).map_err(|_| StoreError::CredentialRevisionConflict)?;
    let armed = transaction
        .execute(
            "UPDATE credential_revision_write_guard SET revision = ?1
             WHERE singleton = 1 AND revision IS NULL",
            [i64::try_from(revision).map_err(|_| StoreError::CredentialRevisionConflict)?],
        )
        .map_err(sqlite_error)?;
    if armed != 1 {
        return Err(StoreError::CredentialRevisionConflict);
    }
    Ok(revision)
}

fn set_credential_enabled_tx(
    transaction: &Transaction<'_>,
    credential_id: &str,
    enabled: bool,
    updated_at: Timestamp,
) -> StoreResult<CredentialState> {
    let old = transaction
        .query_row(
            "SELECT credential_id, provider_id, configuration_fingerprint,
                    enabled, updated_at, revision
             FROM credentials WHERE credential_id = ?1",
            [credential_id],
            credential_from_row,
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| StoreError::CredentialNotFound(credential_id.to_owned()))?;
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
    if old.enabled == enabled {
        return Ok(old);
    }
    let revision = next_credential_revision(transaction, credential_id, old.revision)?;
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
    Ok(CredentialState {
        enabled,
        updated_at,
        revision,
        ..old
    })
}

fn set_credential_enabled_if_current_tx(
    transaction: &Transaction<'_>,
    credential_id: &str,
    expected_revision: u64,
    expected_provider_id: &str,
    expected_configuration_fingerprint: &str,
    enabled: bool,
    updated_at: Timestamp,
) -> StoreResult<ConditionalCredentialMutation> {
    let current = transaction
        .query_row(
            "SELECT c.credential_id, c.provider_id, c.configuration_fingerprint,
                    c.enabled, c.updated_at, c.revision, p.generation
             FROM credentials c
             LEFT JOIN credential_payloads p
               ON p.credential_id = c.credential_id
             WHERE c.credential_id = ?1",
            [credential_id],
            |row| {
                Ok((
                    credential_from_row(row)?,
                    row.get::<_, Option<i64>>(6)?
                        .map(|value| u64::try_from(value).unwrap_or(u64::MAX)),
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((current, credential_payload_generation)) = current else {
        return Ok(ConditionalCredentialMutation::Missing);
    };
    let compare_generation = credential_payload_generation.unwrap_or(current.revision);
    if compare_generation != expected_revision
        || current.provider_id != expected_provider_id
        || current.configuration_fingerprint != expected_configuration_fingerprint
    {
        return Ok(ConditionalCredentialMutation::Stale {
            current,
            credential_payload_present: Some(credential_payload_generation.is_some()),
            credential_payload_generation,
        });
    }
    set_credential_enabled_tx(transaction, credential_id, enabled, updated_at)
        .map(ConditionalCredentialMutation::Applied)
}

fn set_credential_enabled_if_newer_payload_tx(
    transaction: &Transaction<'_>,
    identity: &CredentialConfigurationIdentity,
    expected_metadata_revision: u64,
    previous_generation: u64,
    enabled: bool,
    updated_at: Timestamp,
) -> StoreResult<ConditionalCredentialMutation> {
    let current = transaction
        .query_row(
            "SELECT c.credential_id, c.provider_id, c.configuration_fingerprint,
                    c.enabled, c.updated_at, c.revision, p.generation
             FROM credentials c
             LEFT JOIN credential_payloads p
               ON p.credential_id = c.credential_id
             WHERE c.credential_id = ?1",
            [identity.credential_id()],
            |row| {
                Ok((
                    credential_from_row(row)?,
                    row.get::<_, Option<i64>>(6)?
                        .map(|value| u64::try_from(value).unwrap_or(u64::MAX)),
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((current, credential_payload_generation)) = current else {
        return Ok(ConditionalCredentialMutation::Missing);
    };
    let payload_is_newer =
        credential_payload_generation.is_some_and(|generation| generation > previous_generation);
    let metadata_is_fenced = current.revision == expected_metadata_revision
        || credential_payload_generation == Some(current.revision);
    if !identity.matches(&current) || !payload_is_newer || !metadata_is_fenced {
        return Ok(ConditionalCredentialMutation::Stale {
            current,
            credential_payload_present: Some(credential_payload_generation.is_some()),
            credential_payload_generation,
        });
    }
    set_credential_enabled_tx(transaction, identity.credential_id(), enabled, updated_at)
        .map(ConditionalCredentialMutation::Applied)
}

fn credential_payload_aad(credential_id: &str, fingerprint: &str) -> Vec<u8> {
    if fingerprint.is_empty() {
        // Version-1 rows are intentionally kept adoptable. The migration
        // leaves their metadata fingerprint empty and this exact legacy AAD
        // is used only until an explicit adoption transaction re-encrypts it.
        return credential_id.as_bytes().to_vec();
    }
    format!(
        "pooler-credential-payload:v{}:{}:{}:{}",
        CREDENTIAL_IDENTITY_AAD_VERSION,
        credential_id.len(),
        credential_id,
        fingerprint
    )
    .into_bytes()
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

    fn shares_credential_generation_domain(&self, store: &SqliteStore) -> bool {
        Arc::ptr_eq(&self.connection, &store.connection)
            || self
                .file_generation_domain
                .zip(store.file_generation_domain)
                .is_some_and(|(left, right)| left == right)
    }

    fn upsert_credential_state(&self, state: CredentialState) -> StoreResult<CredentialState> {
        non_empty("credential_id", &state.credential_id)?;
        non_empty("provider_id", &state.provider_id)?;
        validate_fingerprint(&state.configuration_fingerprint)?;
        let (revision, configuration_fingerprint) = self.with_immediate_transaction(|transaction| {
            let existing: Option<(String, i64, String, bool)> = transaction
                .query_row(
                    "SELECT provider_id, revision, configuration_fingerprint,
                            EXISTS(SELECT 1 FROM credential_payloads
                                   WHERE credential_id = credentials.credential_id)
                     FROM credentials WHERE credential_id = ?1",
                    [&state.credential_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(sqlite_error)?;
            if let Some((existing_provider, _, existing_fingerprint, payload_exists)) = &existing {
                let provider_changed = existing_provider != &state.provider_id;
                let fingerprint_changed = !state.configuration_fingerprint.is_empty()
                    && existing_fingerprint != &state.configuration_fingerprint;
                if *payload_exists && (provider_changed || fingerprint_changed) {
                    return Err(StoreError::CredentialFingerprintConflict);
                }
            }
            let configuration_fingerprint = if state.configuration_fingerprint.is_empty() {
                existing
                    .as_ref()
                    .filter(|(provider, _, _, _)| provider == &state.provider_id)
                    .map_or_else(String::new, |(_, _, fingerprint, _)| fingerprint.clone())
            } else {
                state.configuration_fingerprint.clone()
            };
            let current_revision = existing
                .as_ref()
                .map(|(_, value, _, _)| {
                    u64::try_from(*value).map_err(|_| StoreError::CredentialRevisionConflict)
                })
                .transpose()?
                .unwrap_or(0);
            let revision = next_credential_revision(
                transaction,
                &state.credential_id,
                current_revision,
            )?;
            let revision_i64 = i64::try_from(revision)
                .map_err(|_| StoreError::CredentialRevisionConflict)?;
            let identity_changed = existing.as_ref().is_some_and(
                |(provider, _, fingerprint, _)| {
                    provider != &state.provider_id || fingerprint != &configuration_fingerprint
                },
            );
            if identity_changed {
                delete_credential_dependents(transaction, &state.credential_id)?;
            }
            transaction
                .execute(
                    "INSERT INTO credentials
                     (credential_id, provider_id, configuration_fingerprint, enabled, updated_at, revision)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(credential_id) DO UPDATE SET
                       provider_id = excluded.provider_id,
                       configuration_fingerprint = excluded.configuration_fingerprint,
                       enabled = excluded.enabled,
                       updated_at = excluded.updated_at,
                       revision = excluded.revision",
                    params![
                        &state.credential_id,
                        &state.provider_id,
                        &configuration_fingerprint,
                        i64::from(state.enabled),
                        state.updated_at,
                        revision_i64,
                    ],
                )
                .map_err(sqlite_error)?;
            evict_credentials(transaction, self.retention.max_credentials)?;
            Ok((revision, configuration_fingerprint))
        })?;
        Ok(CredentialState {
            configuration_fingerprint,
            revision,
            ..state
        })
    }

    fn activate_credential_configurations(
        &self,
        activations: &[CredentialConfigurationActivation],
    ) -> StoreResult<Vec<ActivatedCredentialState>> {
        let mut credential_ids = BTreeSet::new();
        for activation in activations {
            let desired = activation.desired();
            non_empty("credential_id", &desired.credential_id)?;
            non_empty("provider_id", &desired.provider_id)?;
            validate_fingerprint(&desired.configuration_fingerprint)?;
            if desired.configuration_fingerprint.is_empty()
                || !credential_ids.insert(desired.credential_id.as_str())
            {
                return Err(StoreError::CredentialFingerprintConflict);
            }
        }
        let cipher = if activations
            .iter()
            .any(|activation| activation.retirement().is_some())
        {
            Some(
                self.encryption_read()?
                    .clone()
                    .ok_or(StoreError::EncryptionRequired)?,
            )
        } else {
            None
        };

        self.with_immediate_transaction(|transaction| {
            if let Some(cipher) = &cipher {
                assert_cipher_current_transaction(transaction, cipher)?;
            }
            let mut observed = Vec::with_capacity(activations.len());
            for activation in activations {
                let desired = activation.desired();
                let current = transaction
                    .query_row(
                        "SELECT credential_id, provider_id, configuration_fingerprint,
                                enabled, updated_at, revision
                         FROM credentials WHERE credential_id = ?1",
                        [&desired.credential_id],
                        credential_from_row,
                    )
                    .optional()
                    .map_err(sqlite_error)?;
                if current.as_ref() != activation.expected() {
                    return Err(StoreError::CredentialRevisionConflict);
                }
                let envelope = transaction
                    .query_row(
                        "SELECT envelope FROM credential_payloads WHERE credential_id = ?1",
                        [&desired.credential_id],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?;

                if let Some(retirement) = activation.retirement() {
                    let current = current.as_ref().ok_or_else(|| {
                        StoreError::CredentialNotFound(desired.credential_id.clone())
                    })?;
                    if current.provider_id != retirement.provider_id()
                        || (current.configuration_fingerprint != retirement.expected_fingerprint()
                            && current.configuration_fingerprint
                                != retirement.replacement_fingerprint())
                    {
                        return Err(StoreError::CredentialFingerprintConflict);
                    }
                    if current.configuration_fingerprint == retirement.expected_fingerprint() {
                        if let Some(envelope) = &envelope {
                            let aad = credential_payload_aad(
                                retirement.credential_id(),
                                retirement.expected_fingerprint(),
                            );
                            cipher
                                .as_ref()
                                .ok_or(StoreError::EncryptionRequired)?
                                .open_for(envelope, &aad)?;
                        }
                    }
                } else if current.as_ref().is_some_and(|state| {
                    state.provider_id != desired.provider_id
                        || state.configuration_fingerprint != desired.configuration_fingerprint
                }) && envelope.is_some()
                {
                    return Err(StoreError::CredentialFingerprintConflict);
                }
                observed.push((current, envelope.is_some()));
            }

            let mut activated = Vec::with_capacity(activations.len());
            for (activation, (current, _payload_present)) in
                activations.iter().zip(observed.into_iter())
            {
                let desired = activation.desired();
                let exact_identity = current.as_ref().is_some_and(|state| {
                    state.provider_id == desired.provider_id
                        && state.configuration_fingerprint == desired.configuration_fingerprint
                });
                let retiring = activation.retirement().is_some_and(|retirement| {
                    current.as_ref().is_some_and(|state| {
                        state.configuration_fingerprint == retirement.expected_fingerprint()
                    })
                });
                let state = if exact_identity {
                    current.expect("exact identity requires a current credential")
                } else {
                    let safe_legacy_identity = current.as_ref().is_some_and(|state| {
                        state.provider_id == desired.provider_id
                            && state.configuration_fingerprint.is_empty()
                    });
                    let current_revision = current.as_ref().map_or(0, |state| state.revision);
                    let revision = next_credential_revision(
                        transaction,
                        &desired.credential_id,
                        current_revision,
                    )?;
                    if current.is_some() {
                        delete_credential_dependents(transaction, &desired.credential_id)?;
                    }
                    if retiring {
                        transaction
                            .execute(
                                "DELETE FROM credential_payloads WHERE credential_id = ?1",
                                [&desired.credential_id],
                            )
                            .map_err(sqlite_error)?;
                    }
                    let enabled = if retiring {
                        false
                    } else if safe_legacy_identity {
                        current.as_ref().is_some_and(|state| state.enabled)
                    } else {
                        desired.enabled
                    };
                    let revision_i64 = i64::try_from(revision)
                        .map_err(|_| StoreError::CredentialRevisionConflict)?;
                    if let Some(current) = &current {
                        let changed = transaction
                            .execute(
                                "UPDATE credentials
                                 SET provider_id = ?1, configuration_fingerprint = ?2,
                                     enabled = ?3, updated_at = ?4, revision = ?5
                                 WHERE credential_id = ?6 AND revision = ?7",
                                params![
                                    &desired.provider_id,
                                    &desired.configuration_fingerprint,
                                    i64::from(enabled),
                                    desired.updated_at,
                                    revision_i64,
                                    &desired.credential_id,
                                    i64::try_from(current.revision)
                                        .map_err(|_| StoreError::CredentialRevisionConflict)?,
                                ],
                            )
                            .map_err(sqlite_error)?;
                        if changed != 1 {
                            return Err(StoreError::CredentialRevisionConflict);
                        }
                    } else {
                        transaction
                            .execute(
                                "INSERT INTO credentials
                                 (credential_id, provider_id, configuration_fingerprint,
                                  enabled, updated_at, revision)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                params![
                                    &desired.credential_id,
                                    &desired.provider_id,
                                    &desired.configuration_fingerprint,
                                    i64::from(enabled),
                                    desired.updated_at,
                                    revision_i64,
                                ],
                            )
                            .map_err(sqlite_error)?;
                    }
                    if retiring {
                        transaction
                            .execute(
                                "INSERT INTO credential_health
                                 (credential_id, status, failure_count, cooldown_until, updated_at)
                                 VALUES (?1, 'disabled', 0, NULL, ?2)
                                 ON CONFLICT(credential_id) DO UPDATE SET
                                   status = 'disabled', failure_count = 0,
                                   cooldown_until = NULL, updated_at = excluded.updated_at",
                                params![&desired.credential_id, desired.updated_at],
                            )
                            .map_err(sqlite_error)?;
                    }
                    CredentialState {
                        enabled,
                        revision,
                        ..desired.clone()
                    }
                };
                let health_disabled = transaction
                    .query_row(
                        "SELECT status = 'disabled' FROM credential_health
                         WHERE credential_id = ?1",
                        [&state.credential_id],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?
                    .unwrap_or(false);
                activated.push(ActivatedCredentialState::new(state, health_disabled));
            }
            evict_credentials(transaction, self.retention.max_credentials)?;
            Ok(activated)
        })
    }

    fn credential_state(&self, credential_id: &str) -> StoreResult<Option<CredentialState>> {
        non_empty("credential_id", credential_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT credential_id, provider_id, configuration_fingerprint,
                        enabled, updated_at, revision
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
                "SELECT credential_id, provider_id, configuration_fingerprint,
                        enabled, updated_at, revision
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
        self.with_immediate_transaction(|transaction| {
            set_credential_enabled_tx(transaction, credential_id, enabled, updated_at)
        })
    }

    fn set_credential_enabled_if_identity(
        &self,
        identity: &CredentialConfigurationIdentity,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation> {
        self.with_immediate_transaction(|transaction| {
            let current = transaction
                .query_row(
                    "SELECT credential_id, provider_id, configuration_fingerprint,
                            enabled, updated_at, revision
                     FROM credentials WHERE credential_id = ?1",
                    [identity.credential_id()],
                    credential_from_row,
                )
                .optional()
                .map_err(sqlite_error)?;
            let Some(current) = current else {
                return Ok(ConditionalCredentialMutation::Missing);
            };
            if !identity.matches(&current) {
                return Ok(ConditionalCredentialMutation::Stale {
                    current,
                    credential_payload_present: None,
                    credential_payload_generation: None,
                });
            }
            set_credential_enabled_tx(transaction, identity.credential_id(), enabled, updated_at)
                .map(ConditionalCredentialMutation::Applied)
        })
    }

    fn set_credential_enabled_if_current(
        &self,
        credential_id: &str,
        expected_revision: u64,
        expected_provider_id: &str,
        expected_configuration_fingerprint: &str,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation> {
        non_empty("credential_id", credential_id)?;
        non_empty("expected_provider_id", expected_provider_id)?;
        validate_fingerprint(expected_configuration_fingerprint)?;
        self.with_immediate_transaction(|transaction| {
            set_credential_enabled_if_current_tx(
                transaction,
                credential_id,
                expected_revision,
                expected_provider_id,
                expected_configuration_fingerprint,
                enabled,
                updated_at,
            )
        })
    }

    fn set_credential_enabled_if_newer_payload(
        &self,
        identity: &CredentialConfigurationIdentity,
        expected_metadata_revision: u64,
        previous_generation: u64,
        enabled: bool,
        updated_at: Timestamp,
    ) -> StoreResult<ConditionalCredentialMutation> {
        self.with_immediate_transaction(|transaction| {
            set_credential_enabled_if_newer_payload_tx(
                transaction,
                identity,
                expected_metadata_revision,
                previous_generation,
                enabled,
                updated_at,
            )
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

    fn switch_credential_if_identities(
        &self,
        selected: &CredentialConfigurationIdentity,
        siblings: &[CredentialConfigurationIdentity],
        updated_at: Timestamp,
    ) -> StoreResult<Option<Vec<CredentialState>>> {
        self.with_immediate_transaction(|transaction| {
            for identity in std::iter::once(selected).chain(siblings) {
                let current = transaction
                    .query_row(
                        "SELECT credential_id, provider_id, configuration_fingerprint,
                                enabled, updated_at, revision
                         FROM credentials WHERE credential_id = ?1",
                        [identity.credential_id()],
                        credential_from_row,
                    )
                    .optional()
                    .map_err(sqlite_error)?;
                let Some(current) = current else {
                    return Ok(None);
                };
                if !identity.matches(&current) {
                    return Ok(None);
                }
            }

            let mut states = Vec::with_capacity(siblings.len().saturating_add(1));
            states.push(set_credential_enabled_tx(
                transaction,
                selected.credential_id(),
                true,
                updated_at,
            )?);
            for sibling in siblings
                .iter()
                .filter(|sibling| sibling.credential_id() != selected.credential_id())
            {
                states.push(set_credential_enabled_tx(
                    transaction,
                    sibling.credential_id(),
                    false,
                    updated_at,
                )?);
            }
            Ok(Some(states))
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

    fn cooldowns_snapshot(&self, now: Timestamp) -> StoreResult<Vec<CooldownState>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT scope, scope_key, until_at, reason, updated_at
                 FROM cooldowns WHERE until_at > ?1
                 ORDER BY scope ASC, scope_key ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([now], cooldown_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
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
                    legacy_affinity_from_row,
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
                .query_map([], legacy_affinity_from_row)
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
        })
    }

    fn session_affinities_snapshot(&self, now: Timestamp) -> StoreResult<Vec<SessionAffinity>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT key, provider_id, credential_id, upstream_model, created_at, last_used_at, expires_at
                 FROM affinities WHERE expires_at > ?1
                 ORDER BY key ASC",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([now], legacy_affinity_from_row)
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
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
                      selected_credential, upstream_model, target_binding_id, priority_tier,
                      attempt, configuration_generation, reason, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        &record.request_id,
                        &record.route_id,
                        &record.model,
                        candidates,
                        &record.selected_provider,
                        &record.selected_credential,
                        &record.upstream_model,
                        &record.target_binding_id,
                        record.priority_tier.map(i64::from),
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
                 selected_credential, upstream_model, target_binding_id, priority_tier,
                 attempt, configuration_generation, reason, recorded_at
                 FROM decisions ORDER BY id ASC",
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
                 selected_credential, upstream_model, target_binding_id, priority_tier,
                 attempt, configuration_generation, reason, recorded_at
                 FROM decisions ORDER BY id DESC LIMIT ?1",
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
            let expired_scoped_affinities = transaction
                .execute(
                    "DELETE FROM scoped_affinities WHERE expires_at <= ?1",
                    [now],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute("DELETE FROM cooldowns WHERE until_at <= ?1", [now])
                .map_err(sqlite_error)?;
            let evicted_credentials =
                evict_credentials(transaction, self.retention.max_credentials)?;
            let evicted_affinities =
                evict_affinities(transaction, self.retention.max_affinities)?.saturating_add(
                    evict_scoped_affinities(transaction, self.retention.max_affinities)?,
                );
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
                expired_affinities: expired_affinities.saturating_add(expired_scoped_affinities),
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
    use crate::{
        CredentialFingerprintInput, CredentialHealthStatus, DecisionCandidate, RequestEventKind,
    };

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
    fn conditional_enablement_rejects_stale_sqlite_generation_and_identity() {
        let store = SqliteStore::open_in_memory().expect("store");
        let fingerprint = "a".repeat(64);
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                1,
            ))
            .expect("credential insert");
        let replacement_fingerprint = "b".repeat(64);
        for (revision, provider, candidate_fingerprint) in [
            (0, "provider", fingerprint.as_str()),
            (1, "replacement-provider", fingerprint.as_str()),
            (1, "provider", replacement_fingerprint.as_str()),
        ] {
            assert!(matches!(
                store
                    .set_credential_enabled_if_current(
                        "credential",
                        revision,
                        provider,
                        candidate_fingerprint,
                        false,
                        2,
                    )
                    .expect("conditional mutation"),
                ConditionalCredentialMutation::Stale { .. }
            ));
        }
        assert!(
            store
                .credential_state("credential")
                .expect("credential state")
                .expect("credential exists")
                .enabled
        );

        let disabled = store
            .set_credential_enabled_if_current("credential", 1, "provider", &fingerprint, false, 3)
            .expect("current generation disables")
            .into_applied()
            .expect("fence matches");
        assert!(!disabled.enabled);
        assert_eq!(disabled.revision, 2);
        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "credential",
                    1,
                    "provider",
                    &fingerprint,
                    false,
                    4,
                )
                .expect("stale repeated mutation"),
            ConditionalCredentialMutation::Stale { .. }
        ));
        assert_eq!(
            store
                .credential_state("credential")
                .expect("credential state")
                .expect("credential exists")
                .revision,
            2
        );
        assert!(store
            .remove_credential_state("credential")
            .expect("remove credential"));
        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "credential",
                    2,
                    "provider",
                    &fingerprint,
                    false,
                    5,
                )
                .expect("missing conditional mutation is stale"),
            ConditionalCredentialMutation::Missing
        ));
    }

    #[test]
    fn newer_payload_enablement_rechecks_payload_presence_atomically() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"newer-payload-enablement-key").expect("key"),
        )
        .expect("store");
        let fingerprint = "a".repeat(64);
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                false,
                1,
            ))
            .expect("credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "credential",
                &fingerprint,
                &CredentialPayload::new(b"failed-token").expect("payload"),
                2,
            )
            .expect("failed generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint)
            .expect("failed generation");
        let login = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                failed_generation,
                &fingerprint,
                &CredentialPayload::new(b"new-login-token").expect("payload"),
                3,
            )
            .expect("new login generation");
        let identity = CredentialConfigurationIdentity::new("credential", "provider", &fingerprint)
            .expect("identity");
        assert!(matches!(
            store
                .set_credential_enabled_if_newer_payload(
                    &identity,
                    login.revision,
                    failed_generation,
                    true,
                    4,
                )
                .expect("enable newer login"),
            ConditionalCredentialMutation::Applied(_)
        ));

        store
            .set_credential_enabled("credential", false, 5)
            .expect("disable before next login");
        let replacement = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                login.revision,
                &fingerprint,
                &CredentialPayload::new(b"replacement-login-token").expect("payload"),
                6,
            )
            .expect("replacement login generation");
        assert!(replacement.revision > login.revision);
        assert!(store
            .remove_credential_payload("credential")
            .expect("concurrent revoke"));

        assert!(matches!(
            store
                .set_credential_enabled_if_newer_payload(
                    &identity,
                    replacement.revision,
                    login.revision,
                    true,
                    7,
                )
                .expect("recheck removed payload"),
            ConditionalCredentialMutation::Stale {
                credential_payload_present: Some(false),
                ..
            }
        ));
        assert!(
            !store
                .credential_state("credential")
                .expect("credential state")
                .expect("credential exists")
                .enabled
        );
    }

    #[test]
    fn newer_payload_enablement_does_not_override_a_concurrent_disable() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"newer-payload-disable-fence-key").expect("key"),
        )
        .expect("store");
        let fingerprint = "b".repeat(64);
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                1,
            ))
            .expect("credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "credential",
                &fingerprint,
                &CredentialPayload::new(b"failed-token").expect("payload"),
                2,
            )
            .expect("failed generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint)
            .expect("failed generation");
        let login = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                failed_generation,
                &fingerprint,
                &CredentialPayload::new(b"new-login-token").expect("payload"),
                3,
            )
            .expect("new login generation");
        let observed = match store
            .set_credential_enabled_if_current(
                "credential",
                failed_generation,
                "provider",
                &fingerprint,
                true,
                4,
            )
            .expect("stale failed-generation mutation")
        {
            ConditionalCredentialMutation::Stale {
                current,
                credential_payload_present: Some(true),
                credential_payload_generation: Some(generation),
            } => {
                assert_eq!(generation, login.revision);
                assert!(current.enabled);
                current
            }
            outcome => panic!("unexpected mutation outcome: {outcome:?}"),
        };
        let disabled = store
            .set_credential_enabled("credential", false, 5)
            .expect("concurrent operator disable");
        assert!(disabled.revision > observed.revision);

        let identity = CredentialConfigurationIdentity::new("credential", "provider", &fingerprint)
            .expect("identity");
        assert!(matches!(
            store
                .set_credential_enabled_if_newer_payload(
                    &identity,
                    observed.revision,
                    failed_generation,
                    true,
                    6,
                )
                .expect("metadata-fenced newer login"),
            ConditionalCredentialMutation::Stale { current, .. } if !current.enabled
        ));
        assert!(
            !store
                .credential_state("credential")
                .expect("credential state")
                .expect("credential exists")
                .enabled
        );
    }

    #[test]
    fn newer_payload_enablement_accepts_a_benign_concurrent_refresh() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"newer-payload-refresh-fence-key").expect("key"),
        )
        .expect("store");
        let fingerprint = "c".repeat(64);
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                false,
                1,
            ))
            .expect("credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "credential",
                &fingerprint,
                &CredentialPayload::new(b"failed-token").expect("payload"),
                2,
            )
            .expect("failed generation");
        let failed_generation = store
            .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint)
            .expect("failed generation");
        let login = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                failed_generation,
                &fingerprint,
                &CredentialPayload::new(b"new-login-token").expect("payload"),
                3,
            )
            .expect("new login generation");
        let observed = match store
            .set_credential_enabled_if_current(
                "credential",
                failed_generation,
                "provider",
                &fingerprint,
                true,
                4,
            )
            .expect("stale failed-generation mutation")
        {
            ConditionalCredentialMutation::Stale { current, .. } => current,
            outcome => panic!("unexpected mutation outcome: {outcome:?}"),
        };
        assert!(!observed.enabled);
        let refreshed = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                login.revision,
                &fingerprint,
                &CredentialPayload::new(b"refreshed-token").expect("payload"),
                5,
            )
            .expect("concurrent refresh");
        assert!(refreshed.revision > observed.revision);

        let identity = CredentialConfigurationIdentity::new("credential", "provider", &fingerprint)
            .expect("identity");
        assert!(matches!(
            store
                .set_credential_enabled_if_newer_payload(
                    &identity,
                    observed.revision,
                    failed_generation,
                    true,
                    6,
                )
                .expect("refresh-compatible newer login"),
            ConditionalCredentialMutation::Applied(current) if current.enabled
        ));
    }

    #[test]
    fn credential_generation_domain_requires_the_same_sqlite_database() {
        let first = SqliteStore::open_in_memory().expect("first store");
        let shared = first.clone();
        let second = SqliteStore::open_in_memory().expect("second store");
        assert!(first.shares_credential_generation_domain(&shared));
        assert!(!first.shares_credential_generation_domain(&second));

        let directory = private_tempdir();
        let path = directory.path().join("shared-generation.sqlite");
        let first = SqliteStore::open(&path).expect("first file-backed store");
        let second = SqliteStore::open(&path).expect("second file-backed store");
        assert!(first.shares_credential_generation_domain(&second));

        let alias_directory = directory.path().join("alias");
        fs::create_dir(&alias_directory).expect("alias directory");
        let aliased = SqliteStore::open(alias_directory.join("../shared-generation.sqlite"))
            .expect("lexically aliased store");
        assert!(first.shares_credential_generation_domain(&aliased));
    }

    #[cfg(unix)]
    #[test]
    fn credential_generation_domain_rejects_a_raw_database_copy() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = private_tempdir();
        let original_path = directory.path().join("original.sqlite");
        let copied_path = directory.path().join("copied.sqlite");
        {
            let original = SqliteStore::open(&original_path).expect("seed original store");
            original
                .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
                .expect("seed credential");
        }
        fs::copy(&original_path, &copied_path).expect("raw database copy");
        fs::set_permissions(&copied_path, fs::Permissions::from_mode(0o600))
            .expect("private copied database");

        let original = SqliteStore::open(&original_path).expect("open original store");
        let copied = SqliteStore::open(&copied_path).expect("open copied store");
        assert!(!original.shares_credential_generation_domain(&copied));
    }

    #[cfg(unix)]
    #[test]
    fn credential_generation_domain_rejects_a_database_replaced_at_the_same_path() {
        let directory = private_tempdir();
        let path = directory.path().join("replaceable.sqlite");
        let original = SqliteStore::open(&path).expect("original store");
        let displaced = directory.path().join("displaced.sqlite");
        fs::rename(&path, &displaced).expect("displace original database");
        for suffix in ["-wal", "-shm"] {
            let mut source = path.as_os_str().to_owned();
            source.push(suffix);
            let source = PathBuf::from(source);
            if source.exists() {
                let mut destination = displaced.as_os_str().to_owned();
                destination.push(suffix);
                fs::rename(source, PathBuf::from(destination)).expect("displace sidecar");
            }
        }
        let replacement = SqliteStore::open(&path).expect("replacement store");
        assert!(!original.shares_credential_generation_domain(&replacement));
    }

    #[test]
    fn credential_revision_clock_remains_constant_space_after_unique_deletions() {
        let store = SqliteStore::open_in_memory().expect("store");
        for index in 0..256 {
            let credential_id = format!("credential-{index}");
            store
                .upsert_credential_state(CredentialState::new(
                    &credential_id,
                    "provider",
                    true,
                    index,
                ))
                .expect("credential insert");
            assert!(store
                .remove_credential_state(&credential_id)
                .expect("credential removal"));
        }
        let connection = store.connection.lock().expect("connection");
        let (rows, revision): (usize, u64) = connection
            .query_row(
                "SELECT COUNT(*), MAX(revision) FROM credential_revision_clock",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("revision clock");
        assert_eq!(rows, 1);
        assert_eq!(revision, 256);
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
    fn account_switch_reenables_selected_health_without_advancing_credential_revision() {
        let directory = private_tempdir();
        let path = directory.path().join("switch-health.sqlite");
        let original_revision;
        {
            let store = SqliteStore::open(&path).expect("open store");
            let selected = store
                .upsert_credential_state(CredentialState::new("primary", "provider", true, 1))
                .expect("primary");
            original_revision = selected.revision;
            store
                .upsert_credential_state(CredentialState::new("backup", "provider", true, 1))
                .expect("backup");
            store
                .upsert_credential_health(CredentialHealthState::new(
                    "primary",
                    CredentialHealthStatus::Disabled,
                    2,
                ))
                .expect("disable health");

            let states = store
                .switch_credential("primary", &["backup".to_owned()], 3)
                .expect("switch");
            let primary = states
                .iter()
                .find(|state| state.credential_id == "primary")
                .expect("primary state");
            assert_eq!(primary.revision, original_revision);
            assert!(primary.enabled);
        }

        let reopened = SqliteStore::open(&path).expect("reopen store");
        let state = reopened
            .credential_state("primary")
            .expect("primary state")
            .expect("primary exists");
        assert!(state.enabled);
        assert_eq!(state.revision, original_revision);
        assert_eq!(
            reopened
                .credential_health("primary")
                .expect("primary health")
                .expect("primary health exists")
                .status,
            CredentialHealthStatus::Healthy
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
    fn identity_fenced_sqlite_switch_validates_every_account_atomically() {
        let store = SqliteStore::open_in_memory().expect("store");
        let current_fingerprint = "a".repeat(64);
        let stale_fingerprint = "b".repeat(64);
        for (credential_id, enabled) in [("primary", false), ("backup", true)] {
            store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    credential_id,
                    "provider",
                    &current_fingerprint,
                    enabled,
                    1,
                ))
                .expect("credential");
        }
        let primary =
            CredentialConfigurationIdentity::new("primary", "provider", &current_fingerprint)
                .expect("primary identity");
        let backup =
            CredentialConfigurationIdentity::new("backup", "provider", &current_fingerprint)
                .expect("backup identity");
        let stale_backup =
            CredentialConfigurationIdentity::new("backup", "provider", &stale_fingerprint)
                .expect("stale backup identity");

        assert!(store
            .switch_credential_if_identities(&primary, std::slice::from_ref(&stale_backup), 2,)
            .expect("stale switch")
            .is_none());
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

        assert!(store
            .switch_credential_if_identities(&primary, std::slice::from_ref(&backup), 3)
            .expect("current switch")
            .is_some());
        assert!(
            store
                .credential_state("primary")
                .expect("primary state")
                .expect("primary exists")
                .enabled
        );
        assert!(
            !store
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
    fn sqlite_snapshots_filter_without_mutating_durable_state() {
        let store = SqliteStore::open_in_memory().expect("store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        store
            .upsert_cooldown(CooldownState::new("provider", "provider", 10, 1))
            .expect("cooldown");
        store
            .upsert_session_affinity(affinity("session", 1, 10))
            .expect("affinity");

        assert!(store
            .cooldowns_snapshot(10)
            .expect("cooldown snapshot")
            .is_empty());
        assert!(store
            .session_affinities_snapshot(10)
            .expect("affinity snapshot")
            .is_empty());

        assert!(store
            .cooldown("provider", "provider", 9)
            .expect("cooldown lookup")
            .is_some());
        let affinity = store
            .session_affinity("session", 2)
            .expect("affinity lookup")
            .expect("affinity");
        assert_eq!(affinity.last_used_at, 2);
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
        let state_before = store
            .credential_state("credential")
            .expect("state before rotation")
            .expect("credential before rotation");
        let generation_before = store
            .credential_payload_compare_generation_for_fingerprint("credential", "")
            .expect("generation before rotation");

        assert_eq!(store.rotate_master_key(new_key.clone()).expect("rotate"), 1);
        assert_eq!(
            store
                .credential_state("credential")
                .expect("state after rotation")
                .expect("credential after rotation"),
            state_before
        );
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", "")
                .expect("generation after rotation"),
            generation_before
        );
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("load after rotate")
                .expect("payload")
                .as_bytes(),
            b"refresh-token-value"
        );
        {
            let connection = store.connection.lock().expect("connection");
            let guard_active: i64 = connection
                .query_row(
                    "SELECT active FROM credential_payload_reencryption_guard WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("re-encryption guard");
            assert_eq!(guard_active, 0);
            let rejected = connection.execute(
                "UPDATE credential_payloads SET envelope = envelope
                 WHERE credential_id = 'credential'",
                [],
            );
            assert!(rejected
                .expect_err("generation-unaware envelope update must be rejected")
                .to_string()
                .contains("credential payload generation must advance"));
        }
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
    fn recreated_credential_cannot_reuse_an_old_payload_generation() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"credential incarnation generation key").expect("key"),
        )
        .expect("store");
        let fingerprint = "a".repeat(64);
        let first = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                1,
            ))
            .expect("first credential incarnation");
        let old_generation = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                first.revision,
                &fingerprint,
                &CredentialPayload::new(b"old-token").expect("old payload"),
                2,
            )
            .expect("persist old token")
            .revision;

        assert!(store
            .remove_credential_payload("credential")
            .expect("remove old payload"));
        assert!(store
            .remove_credential_state("credential")
            .expect("remove old metadata"));

        let recreated = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "credential",
                "provider",
                &fingerprint,
                true,
                3,
            ))
            .expect("recreate credential");
        let fresh = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                recreated.revision,
                &fingerprint,
                &CredentialPayload::new(b"fresh-token").expect("fresh payload"),
                4,
            )
            .expect("persist fresh token");
        assert!(fresh.revision > old_generation);

        assert!(matches!(
            store
                .set_credential_enabled_if_current(
                    "credential",
                    old_generation,
                    "provider",
                    &fingerprint,
                    false,
                    5,
                )
                .expect("stale mutation"),
            ConditionalCredentialMutation::Stale { .. }
        ));
        assert!(
            store
                .credential_state("credential")
                .expect("credential state")
                .expect("recreated credential exists")
                .enabled
        );
        assert_eq!(
            store
                .credential_payload("credential")
                .expect("payload lookup")
                .expect("fresh payload")
                .as_bytes(),
            b"fresh-token"
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
                2,
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
            2
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
            2
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
            "UPDATE credential_payloads
             SET envelope = ?1, generation = generation + 1
             WHERE credential_id = 'credential'",
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
    fn v10_upgrade_backfills_payload_generation_and_allows_metadata_races() {
        let directory = private_tempdir();
        let path = directory.path().join("v10-payload-generation.sqlite");
        let key = MasterKey::from_bytes(b"v10-payload-generation-key").expect("key");
        let cipher = CredentialCipher::new(key.clone());
        let fingerprint = "a".repeat(64);
        let connection = Connection::open(&path).expect("create database");
        for &(version, sql) in MIGRATIONS.iter().take(10) {
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
                 (credential_id, provider_id, enabled, updated_at, revision,
                  configuration_fingerprint)
                 VALUES ('credential', 'provider', 1, 1, 7, ?1)",
                [&fingerprint],
            )
            .expect("credential");
        let envelope = cipher
            .seal_for(
                &CredentialPayload::new(b"legacy-token").expect("payload"),
                &credential_payload_aad("credential", &fingerprint),
            )
            .expect("envelope");
        connection
            .execute(
                "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                 VALUES ('credential', ?1, 1)",
                params![envelope],
            )
            .expect("payload");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("database permissions");
        }

        let store = SqliteStore::open_encrypted(&path, key).expect("upgrade");
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint,)
                .expect("backfilled generation"),
            7
        );
        let disabled = store
            .set_credential_enabled("credential", false, 2)
            .expect("metadata-only disable");
        assert!(disabled.revision > 7);
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint,)
                .expect("unchanged payload generation"),
            7
        );
        let rotated = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                7,
                &fingerprint,
                &CredentialPayload::new(b"fresh-token").expect("fresh payload"),
                3,
            )
            .expect("payload CAS after metadata mutation");
        assert!(rotated.revision > disabled.revision);
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint,)
                .expect("rotated generation"),
            rotated.revision
        );
    }

    #[test]
    fn v11_upgrade_backfills_payload_generation_from_metadata_revision() {
        let directory = private_tempdir();
        let path = directory.path().join("v11-payload-generation.sqlite");
        let connection = Connection::open(&path).expect("create database");
        for &(version, sql) in MIGRATIONS.iter().take(10) {
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
                 (credential_id, provider_id, enabled, updated_at, revision,
                  configuration_fingerprint)
                 VALUES ('credential', 'provider', 1, 1, 41, '')",
                [],
            )
            .expect("credential");
        connection
            .execute(
                "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                 VALUES ('credential', X'01', 1)",
                [],
            )
            .expect("payload");
        connection
            .execute_batch(MIGRATIONS[10].1)
            .expect("apply version 11 migration");
        connection
            .pragma_update(None, "user_version", 11)
            .expect("set version 11");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("database permissions");
        }

        let store = SqliteStore::open(&path).expect("upgrade");
        let connection = store.connection.lock().expect("connection");
        let (
            schema_version,
            payload_generation,
            clock_rows,
            clock_revision,
            reencryption_guard_active,
        ): (i64, u64, usize, u64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT user_version FROM pragma_user_version),
                   (SELECT generation FROM credential_payloads
                    WHERE credential_id = 'credential'),
                   (SELECT COUNT(*) FROM credential_revision_clock),
                   (SELECT revision FROM credential_revision_clock WHERE singleton = 1),
                   (SELECT active FROM credential_payload_reencryption_guard WHERE singleton = 1)",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("migrated generations");
        assert_eq!(schema_version, 14);
        assert_eq!(payload_generation, 41);
        assert_eq!(clock_rows, 1);
        assert_eq!(clock_revision, 41);
        assert_eq!(reencryption_guard_active, 0);
    }

    #[test]
    fn v10_upgrade_rejects_already_open_legacy_metadata_recreation() {
        let directory = private_tempdir();
        let path = directory.path().join("v10-legacy-metadata-writer.sqlite");
        let key = MasterKey::from_bytes(b"v10-legacy-metadata-writer-key").expect("key");
        let cipher = CredentialCipher::new(key.clone());
        let fingerprint = "a".repeat(64);
        let mut legacy = Connection::open(&path).expect("open legacy connection");
        for &(version, sql) in MIGRATIONS.iter().take(10) {
            legacy.execute_batch(sql).expect("apply legacy migration");
            legacy
                .pragma_update(None, "user_version", version)
                .expect("set legacy version");
        }
        legacy
            .execute(
                "INSERT INTO credentials
                 (credential_id, provider_id, enabled, updated_at, revision,
                  configuration_fingerprint)
                 VALUES ('credential', 'provider', 1, 1, 7, ?1)",
                [&fingerprint],
            )
            .expect("credential");
        let original = cipher
            .seal_for(
                &CredentialPayload::new(b"original-token").expect("payload"),
                &credential_payload_aad("credential", &fingerprint),
            )
            .expect("original envelope");
        legacy
            .execute(
                "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                 VALUES ('credential', ?1, 1)",
                [&original],
            )
            .expect("legacy payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("database permissions");
        }

        let store = SqliteStore::open_encrypted(&path, key).expect("upgrade");
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint,)
                .expect("backfilled generation"),
            7
        );

        let transaction = legacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("legacy transaction");
        transaction
            .execute(
                "DELETE FROM credentials WHERE credential_id = 'credential'",
                [],
            )
            .expect("legacy delete");
        let recreated = transaction.execute(
            "INSERT INTO credentials
             (credential_id, provider_id, enabled, updated_at, revision,
              configuration_fingerprint)
             VALUES ('credential', 'provider', 1, 2, 1, ?1)",
            [&fingerprint],
        );
        if recreated.is_ok() {
            transaction.commit().expect("commit legacy recreation");
        } else {
            transaction
                .rollback()
                .expect("roll back rejected recreation");
        }
        assert!(recreated.is_err());

        let state = store
            .credential_state("credential")
            .expect("credential state")
            .expect("credential remains");
        assert_eq!(state.revision, 7);
        assert_eq!(
            store
                .credential_payload_for_fingerprint("credential", &fingerprint)
                .expect("payload after rejected recreation")
                .expect("payload remains")
                .as_bytes(),
            b"original-token"
        );
    }

    #[test]
    fn v11_upgrade_rejects_already_open_legacy_payload_writer() {
        let directory = private_tempdir();
        let path = directory.path().join("v11-legacy-writer.sqlite");
        let key = MasterKey::from_bytes(b"v11-legacy-writer-key").expect("key");
        let cipher = CredentialCipher::new(key.clone());
        let fingerprint = "a".repeat(64);
        let mut legacy = Connection::open(&path).expect("open legacy connection");
        for &(version, sql) in MIGRATIONS.iter().take(11) {
            legacy.execute_batch(sql).expect("apply legacy migration");
            legacy
                .pragma_update(None, "user_version", version)
                .expect("set legacy version");
        }
        legacy
            .execute(
                "INSERT INTO credentials
                 (credential_id, provider_id, enabled, updated_at, revision,
                  configuration_fingerprint)
                 VALUES ('credential', 'provider', 1, 1, 7, ?1)",
                [&fingerprint],
            )
            .expect("credential");
        let original = cipher
            .seal_for(
                &CredentialPayload::new(b"original-token").expect("payload"),
                &credential_payload_aad("credential", &fingerprint),
            )
            .expect("original envelope");
        legacy
            .execute(
                "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
                 VALUES ('credential', ?1, 1)",
                [&original],
            )
            .expect("legacy payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("database permissions");
        }

        let store = SqliteStore::open_encrypted(&path, key).expect("upgrade");
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint,)
                .expect("backfilled generation"),
            7
        );
        let replacement = cipher
            .seal_for(
                &CredentialPayload::new(b"legacy-writer-token").expect("payload"),
                &credential_payload_aad("credential", &fingerprint),
            )
            .expect("replacement envelope");
        let transaction = legacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("legacy transaction");
        let legacy_metadata_write = transaction.execute(
            "UPDATE credentials SET updated_at = 2, revision = 8
             WHERE credential_id = 'credential' AND revision = 7",
            [],
        );
        assert!(legacy_metadata_write
            .expect_err("generation-unaware metadata update must be rejected")
            .to_string()
            .contains("credential revision was not allocated"));
        let legacy_write = transaction.execute(
            "INSERT INTO credential_payloads (credential_id, envelope, updated_at)
             VALUES ('credential', ?1, 2)
             ON CONFLICT(credential_id) DO UPDATE SET
               envelope = excluded.envelope,
               updated_at = excluded.updated_at",
            [&replacement],
        );
        assert!(legacy_write.is_err());
        transaction.rollback().expect("roll back rejected writer");

        let state = store
            .credential_state("credential")
            .expect("credential state")
            .expect("credential exists");
        assert_eq!(state.revision, 7);
        assert_eq!(
            store
                .credential_payload_compare_generation_for_fingerprint("credential", &fingerprint,)
                .expect("generation after rejected writer"),
            7
        );
        assert_eq!(
            store
                .credential_payload_for_fingerprint("credential", &fingerprint)
                .expect("payload after rejected writer")
                .expect("payload remains")
                .as_bytes(),
            b"original-token"
        );

        let rotated = store
            .compare_and_swap_credential_payload_for_fingerprint(
                "credential",
                7,
                &fingerprint,
                &CredentialPayload::new(b"current-writer-token").expect("payload"),
                3,
            )
            .expect("current generation-aware writer");
        assert!(rotated.revision > 7);
        assert_eq!(
            store
                .credential_payload_for_fingerprint("credential", &fingerprint)
                .expect("current payload")
                .expect("current payload")
                .as_bytes(),
            b"current-writer-token"
        );
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

    #[test]
    fn identity_fingerprint_fences_payload_cas_and_supports_explicit_adoption() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"fingerprint-test-key").expect("key"),
        )
        .expect("store");
        let first = CredentialFingerprintInput {
            account_id: "account-a".to_owned(),
            provider_instance_id: "provider-a".to_owned(),
            provider_origin: "https://example.test".to_owned(),
            auth_kind: "oauth".to_owned(),
            provider_profile: "example".to_owned(),
            oauth_client_id: Some("client-a".to_owned()),
            oauth_grant_type: Some("authorization_code".to_owned()),
            oauth_scopes: vec!["openid".to_owned()],
            authorization_endpoint: Some("https://example.test/authorize".to_owned()),
            token_endpoint: Some("https://example.test/token".to_owned()),
            revocation_endpoint: None,
            identity_endpoint: None,
            callback_endpoint: Some("http://127.0.0.1:8787/callback".to_owned()),
            oauth_client_secret_reference: None,
            oauth_additional_identity: Vec::new(),
            auth_placement: "bearer".to_owned(),
        }
        .fingerprint()
        .expect("fingerprint");
        let second = CredentialFingerprintInput {
            account_id: "account-a".to_owned(),
            provider_instance_id: "provider-a".to_owned(),
            provider_origin: "https://example.test".to_owned(),
            auth_kind: "oauth".to_owned(),
            provider_profile: "example".to_owned(),
            oauth_client_id: Some("client-b".to_owned()),
            oauth_grant_type: Some("authorization_code".to_owned()),
            oauth_scopes: vec!["openid".to_owned()],
            authorization_endpoint: Some("https://example.test/authorize".to_owned()),
            token_endpoint: Some("https://example.test/token".to_owned()),
            revocation_endpoint: None,
            identity_endpoint: None,
            callback_endpoint: Some("http://127.0.0.1:8787/callback".to_owned()),
            oauth_client_secret_reference: None,
            oauth_additional_identity: Vec::new(),
            auth_placement: "bearer".to_owned(),
        }
        .fingerprint()
        .expect("fingerprint");
        assert_ne!(first, second);
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account-a",
                "provider-a",
                &first,
                true,
                1,
            ))
            .expect("state");
        store
            .upsert_credential_payload_for_fingerprint(
                "account-a",
                &first,
                &CredentialPayload::new(b"stable-secret").expect("payload"),
                1,
            )
            .expect("payload");
        assert_eq!(
            store.upsert_credential_state(CredentialState::new_with_fingerprint(
                "account-a",
                "provider-a",
                &second,
                true,
                2,
            )),
            Err(StoreError::CredentialFingerprintConflict)
        );
        assert_eq!(
            store.credential_payload_for_fingerprint("account-a", &second),
            Err(StoreError::CredentialFingerprintConflict)
        );
        assert_eq!(
            store
                .credential_payload_for_fingerprint("account-a", &first)
                .expect("payload")
                .expect("payload")
                .as_bytes(),
            b"stable-secret"
        );

        let legacy = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"legacy-adoption-key").expect("key"),
        )
        .expect("legacy store");
        legacy
            .upsert_credential_state(CredentialState::new(
                "legacy-account",
                "provider-a",
                true,
                1,
            ))
            .expect("legacy state");
        legacy
            .upsert_credential_payload(
                "legacy-account",
                &CredentialPayload::new(b"legacy-secret").expect("payload"),
                1,
            )
            .expect("legacy payload");
        let adopted = legacy
            .adopt_credential_fingerprint("legacy-account", "", &first, 2)
            .expect("adopt");
        assert_eq!(adopted.configuration_fingerprint, first);
        assert_eq!(
            legacy
                .credential_payload("legacy-account")
                .expect("payload")
                .expect("payload")
                .as_bytes(),
            b"legacy-secret"
        );
    }

    #[test]
    fn credential_configuration_activation_rolls_back_the_batch_on_a_stale_expectation() {
        let store = SqliteStore::open_in_memory().expect("store");
        let old = "a".repeat(64);
        let replacement = "b".repeat(64);
        for credential_id in ["account-a", "account-b"] {
            store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    credential_id,
                    "provider",
                    &old,
                    true,
                    1,
                ))
                .expect("credential");
        }
        let first_before = store
            .credential_state("account-a")
            .expect("first state")
            .expect("first state");
        let second_before = store
            .credential_state("account-b")
            .expect("second state")
            .expect("second state");
        store
            .set_credential_enabled("account-b", false, 2)
            .expect("concurrent metadata mutation");
        let activations = [
            CredentialConfigurationActivation::new(
                Some(first_before.clone()),
                CredentialState::new_with_fingerprint(
                    "account-a",
                    "provider",
                    &replacement,
                    true,
                    3,
                ),
                None,
            )
            .expect("first activation"),
            CredentialConfigurationActivation::new(
                Some(second_before),
                CredentialState::new_with_fingerprint(
                    "account-b",
                    "provider",
                    &replacement,
                    true,
                    3,
                ),
                None,
            )
            .expect("second activation"),
        ];

        assert_eq!(
            store.activate_credential_configurations(&activations),
            Err(StoreError::CredentialRevisionConflict)
        );
        assert_eq!(
            store
                .credential_state("account-a")
                .expect("first state after rollback")
                .expect("first state after rollback"),
            first_before
        );
        let second_after = store
            .credential_state("account-b")
            .expect("second state after rollback")
            .expect("second state after rollback");
        assert!(!second_after.enabled);
        assert_eq!(second_after.configuration_fingerprint, old);
    }

    #[test]
    fn exact_credential_configuration_activation_preserves_operator_state() {
        let store = SqliteStore::open_in_memory().expect("store");
        let fingerprint = "c".repeat(64);
        let current = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account",
                "provider",
                &fingerprint,
                false,
                1,
            ))
            .expect("credential");
        store
            .upsert_credential_health(CredentialHealthState::new(
                "account",
                CredentialHealthStatus::Disabled,
                2,
            ))
            .expect("disabled health");
        let activation = CredentialConfigurationActivation::new(
            Some(current.clone()),
            CredentialState::new_with_fingerprint("account", "provider", &fingerprint, true, 99),
            None,
        )
        .expect("activation");

        let activated = store
            .activate_credential_configurations(&[activation])
            .expect("activate");
        assert_eq!(activated.len(), 1);
        assert_eq!(activated[0].state(), &current);
        assert!(activated[0].health_disabled());
        assert!(!activated[0].effectively_enabled());
    }

    #[test]
    fn legacy_credential_configuration_adoption_preserves_enablement() {
        let store = SqliteStore::open_in_memory().expect("store");
        let fingerprint = "d".repeat(64);
        let legacy = store
            .upsert_credential_state(CredentialState::new("account", "provider", false, 1))
            .expect("legacy credential");
        let activation = CredentialConfigurationActivation::new(
            Some(legacy.clone()),
            CredentialState::new_with_fingerprint("account", "provider", &fingerprint, true, 2),
            None,
        )
        .expect("activation");

        let activated = store
            .activate_credential_configurations(&[activation])
            .expect("activate");
        let state = activated[0].state();
        assert!(!state.enabled);
        assert_eq!(state.configuration_fingerprint, fingerprint);
        assert!(state.revision > legacy.revision);
    }

    #[test]
    fn replaced_credential_configuration_purges_identity_dependents() {
        let store = SqliteStore::open_in_memory().expect("store");
        let old = "e".repeat(64);
        let replacement = "f".repeat(64);
        let current = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account", "provider", &old, true, 1,
            ))
            .expect("credential");
        store
            .upsert_credential_health(CredentialHealthState::new(
                "account",
                CredentialHealthStatus::CoolingDown,
                2,
            ))
            .expect("health");
        store
            .upsert_cooldown(CooldownState::new("credential", "account", 100, 2))
            .expect("cooldown");
        store
            .upsert_session_affinity(SessionAffinity::new(
                "session", "provider", "account", "model", 2, 100,
            ))
            .expect("affinity");
        let activation = CredentialConfigurationActivation::new(
            Some(current),
            CredentialState::new_with_fingerprint("account", "provider", &replacement, true, 3),
            None,
        )
        .expect("activation");

        let activated = store
            .activate_credential_configurations(&[activation])
            .expect("activate");
        assert_eq!(activated[0].state().configuration_fingerprint, replacement);
        assert!(store
            .credential_health("account")
            .expect("health after replacement")
            .is_none());
        assert!(store
            .cooldown("credential", "account", 3)
            .expect("cooldown after replacement")
            .is_none());
        assert!(store
            .session_affinity("session", 3)
            .expect("affinity after replacement")
            .is_none());
    }

    #[test]
    fn credential_configuration_activation_retires_historical_oauth_atomically() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"activation-retirement-key").expect("key"),
        )
        .expect("store");
        let old = "1".repeat(64);
        let replacement = "2".repeat(64);
        let current = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account", "provider", &old, true, 1,
            ))
            .expect("credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "account",
                &old,
                &CredentialPayload::new(b"historical-token").expect("payload"),
                2,
            )
            .expect("payload");
        let expected = store
            .credential_state("account")
            .expect("current state")
            .expect("current state");
        assert!(expected.revision >= current.revision);
        let retirement =
            CredentialFingerprintRetirement::new("account", "provider", &old, &replacement)
                .expect("retirement");
        let activation = CredentialConfigurationActivation::new(
            Some(expected),
            CredentialState::new_with_fingerprint("account", "provider", &replacement, true, 3),
            Some(retirement),
        )
        .expect("activation");

        let activated = store
            .activate_credential_configurations(&[activation])
            .expect("activate");
        assert!(!activated[0].state().enabled);
        assert!(activated[0].health_disabled());
        assert_eq!(activated[0].state().configuration_fingerprint, replacement);
        assert!(!store
            .credential_payload_exists("account")
            .expect("payload existence"));
    }

    #[test]
    fn already_applied_retirement_preserves_a_newer_login() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"activation-newer-login-key").expect("key"),
        )
        .expect("store");
        let old = "3".repeat(64);
        let replacement = "4".repeat(64);
        store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account",
                "provider",
                &replacement,
                true,
                1,
            ))
            .expect("credential");
        store
            .upsert_credential_payload_for_fingerprint(
                "account",
                &replacement,
                &CredentialPayload::new(b"new-login-token").expect("payload"),
                2,
            )
            .expect("new login");
        let current = store
            .credential_state("account")
            .expect("current state")
            .expect("current state");
        let retirement =
            CredentialFingerprintRetirement::new("account", "provider", &old, &replacement)
                .expect("retirement");
        let activation = CredentialConfigurationActivation::new(
            Some(current.clone()),
            CredentialState::new_with_fingerprint("account", "provider", &replacement, false, 3),
            Some(retirement),
        )
        .expect("activation");

        let activated = store
            .activate_credential_configurations(&[activation])
            .expect("activate");
        assert_eq!(activated[0].state(), &current);
        assert!(activated[0].effectively_enabled());
        assert_eq!(
            store
                .credential_payload_for_fingerprint("account", &replacement)
                .expect("payload")
                .expect("payload")
                .as_bytes(),
            b"new-login-token"
        );
    }

    #[test]
    fn fingerprint_retirement_discards_payload_and_disables_credential() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"fingerprint-retirement-key").expect("key"),
        )
        .expect("store");
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        let state = store
            .upsert_credential_state(CredentialState::new_with_fingerprint(
                "account", "provider", &old, true, 1,
            ))
            .expect("state");
        store
            .upsert_credential_payload_for_fingerprint(
                "account",
                &old,
                &CredentialPayload::new(b"legacy-secret").expect("payload"),
                2,
            )
            .expect("payload");

        let retired = store
            .retire_credential_fingerprint("account", &old, &new, 3)
            .expect("retire legacy identity");

        assert_eq!(retired.configuration_fingerprint, new);
        assert!(!retired.enabled);
        assert!(retired.revision > state.revision);
        assert!(!store
            .credential_payload_exists("account")
            .expect("payload existence"));
        assert_eq!(
            store.credential_payload_for_fingerprint("account", &old),
            Err(StoreError::CredentialFingerprintConflict)
        );
        assert!(store
            .credential_payload_for_fingerprint("account", &new)
            .expect("current fingerprint")
            .is_none());
    }

    #[test]
    fn fingerprint_retirement_batch_rolls_back_when_a_later_identity_is_stale() {
        let store = SqliteStore::open_in_memory_encrypted(
            MasterKey::from_bytes(b"fingerprint-retirement-batch-key").expect("key"),
        )
        .expect("store");
        let first_old = "a".repeat(64);
        let first_new = "b".repeat(64);
        let second_old = "c".repeat(64);
        let second_new = "d".repeat(64);
        let stale_second = "e".repeat(64);

        for (credential_id, fingerprint, payload) in [
            (
                "account-a",
                first_old.as_str(),
                b"first-legacy-secret".as_slice(),
            ),
            (
                "account-b",
                second_old.as_str(),
                b"second-legacy-secret".as_slice(),
            ),
        ] {
            store
                .upsert_credential_state(CredentialState::new_with_fingerprint(
                    credential_id,
                    "provider",
                    fingerprint,
                    true,
                    1,
                ))
                .expect("state");
            store
                .upsert_credential_payload_for_fingerprint(
                    credential_id,
                    fingerprint,
                    &CredentialPayload::new(payload).expect("payload"),
                    2,
                )
                .expect("persist payload");
        }
        let first_before = store
            .credential_state("account-a")
            .expect("first state")
            .expect("first state");
        let second_before = store
            .credential_state("account-b")
            .expect("second state")
            .expect("second state");

        let retirements = [
            CredentialFingerprintRetirement::new("account-a", "provider", &first_old, &first_new)
                .expect("first retirement"),
            CredentialFingerprintRetirement::new(
                "account-b",
                "provider",
                &stale_second,
                &second_new,
            )
            .expect("stale second retirement"),
        ];
        assert_eq!(
            store.retire_credential_fingerprints_atomically(&retirements, 3),
            Err(StoreError::CredentialFingerprintConflict)
        );

        assert_eq!(
            store
                .credential_state("account-a")
                .expect("first state after rollback")
                .expect("first state after rollback"),
            first_before
        );
        assert_eq!(
            store
                .credential_state("account-b")
                .expect("second state after rollback")
                .expect("second state after rollback"),
            second_before
        );
        assert_eq!(
            store
                .credential_payload_for_fingerprint("account-a", &first_old)
                .expect("first payload after rollback")
                .expect("first payload after rollback")
                .as_bytes(),
            b"first-legacy-secret"
        );
        assert_eq!(
            store
                .credential_payload_for_fingerprint("account-b", &second_old)
                .expect("second payload after rollback")
                .expect("second payload after rollback")
                .as_bytes(),
            b"second-legacy-secret"
        );
    }

    #[test]
    fn scoped_affinity_uses_composite_binding_identity() {
        let store = SqliteStore::open_in_memory().expect("store");
        store
            .upsert_credential_state(CredentialState::new("credential", "provider", true, 1))
            .expect("credential");
        let first_scope =
            AffinityBindingIdentity::new("route-a", "policy-a", "model-a", "pool-a", "target-a");
        let second_scope =
            AffinityBindingIdentity::new("route-b", "policy-a", "model-a", "pool-a", "target-a");
        store
            .upsert_scoped_session_affinity(SessionAffinity::new_scoped(
                "conversation",
                "provider",
                "credential",
                "upstream-a",
                first_scope.clone(),
                1,
                100,
            ))
            .expect("first affinity");
        store
            .upsert_scoped_session_affinity(SessionAffinity::new_scoped(
                "conversation",
                "provider",
                "credential",
                "upstream-b",
                second_scope.clone(),
                1,
                100,
            ))
            .expect("second affinity");
        assert_eq!(
            store
                .scoped_session_affinity("conversation", &first_scope, 2)
                .expect("lookup")
                .expect("affinity")
                .upstream_model,
            "upstream-a"
        );
        assert_eq!(
            store
                .scoped_session_affinity("conversation", &second_scope, 2)
                .expect("lookup")
                .expect("affinity")
                .upstream_model,
            "upstream-b"
        );
        assert_eq!(store.scoped_session_affinities(2).expect("list").len(), 2);
    }

    #[test]
    fn durable_control_records_are_owner_scoped_encrypted_and_one_time() {
        let directory = private_tempdir();
        let path = directory.path().join("control.sqlite");
        let key = MasterKey::from_bytes(b"control-records-key").expect("key");
        let store = SqliteStore::open_encrypted(&path, key.clone()).expect("store");
        let secret = ManagedSecretRecord::new("managed-1", "session-a", "api_key", 1, None);
        store
            .put_managed_secret(
                secret,
                &SecretPayload::new(b"managed-secret-sentinel").expect("secret"),
                None,
            )
            .expect("managed secret");
        let session = store
            .create_management_session(
                ManagementSessionRecord::new("session-a", "actor-a", 1, 10_000),
                b"cookie-sentinel",
            )
            .expect("session");
        let draft = store
            .create_draft(DraftRecord::new(
                "session-a",
                "config",
                7,
                br#"{"provider":"provider-a","enabled":true}"#.to_vec(),
                1,
                10_000,
            ))
            .expect("draft");
        store
            .append_audit_record(AuditRecord::new(
                Some("session-a".to_owned()),
                "draft.commit",
                "config",
                "accepted",
                7,
                2,
            ))
            .expect("audit");
        let reload = store
            .append_reload_record(
                ReloadRecord::new(Some("session-a".to_owned()), 8, "queued", 3)
                    .with_kind("catalog"),
            )
            .expect("reload");
        let flow = store
            .begin_oauth_flow(
                OAuthFlowRecord::new(
                    "flow-a",
                    "session-a",
                    "provider-a",
                    "account-a",
                    "browser",
                    4,
                    10_000,
                ),
                b"oauth-state-sentinel",
                Some(&SecretPayload::new(b"pkce-verifier-sentinel").expect("verifier")),
            )
            .expect("OAuth flow");
        drop(store);

        let raw = std::fs::read(&path).expect("database bytes");
        assert!(!raw
            .windows(b"managed-secret-sentinel".len())
            .any(|window| window == b"managed-secret-sentinel"));
        assert!(!raw
            .windows(b"pkce-verifier-sentinel".len())
            .any(|window| window == b"pkce-verifier-sentinel"));

        let reopened = SqliteStore::open_encrypted(&path, key).expect("reopen");
        assert_eq!(
            reopened
                .managed_secret_payload("managed-1")
                .expect("secret")
                .as_bytes(),
            b"managed-secret-sentinel"
        );
        assert_eq!(
            reopened
                .management_session_by_cookie(b"cookie-sentinel", 5)
                .expect("session")
                .expect("session")
                .session_id,
            session.session_id
        );
        assert_eq!(
            reopened
                .draft(draft.draft_id, "session-a", 5)
                .expect("draft")
                .expect("draft")
                .payload,
            br#"{"provider":"provider-a","enabled":true}"#.to_vec()
        );
        assert_eq!(reopened.audit_records().expect("audit").len(), 1);
        assert_eq!(reopened.reload_records().expect("reload")[0], reload);
        assert_eq!(
            reopened
                .oauth_flow_pkce_verifier(&flow.flow_id)
                .expect("verifier")
                .expect("verifier")
                .as_bytes(),
            b"pkce-verifier-sentinel"
        );
        assert!(reopened
            .consume_oauth_state(b"oauth-state-sentinel", 5)
            .expect("consume")
            .is_some());
        assert!(reopened
            .consume_oauth_state(b"oauth-state-sentinel", 6)
            .expect("replay")
            .is_none());
        assert!(matches!(
            reopened.draft(draft.draft_id, "other-session", 5),
            Err(StoreError::OwnerMismatch)
        ));
    }

    #[test]
    fn control_drafts_allow_only_managed_secret_references() {
        validate_payload(
            br#"{"management":{"auth":{"secret":"file:/etc/pooler/management.key"}},"upstreams":{"foundry":{"oauth":{"client_secret":"managed:oauth-client"}}},"accounts":{"primary":{"secret":"managed:api-key"}}}"#,
        )
        .expect("managed references are non-secret draft metadata");

        for payload in [
            br#"{"oauth":{"client_secret":"literal-secret"}}"#.as_slice(),
            br#"{"oauth":{"access_token":"literal-token"}}"#.as_slice(),
            br#"{"header":"Bearer literal-token"}"#.as_slice(),
        ] {
            assert!(validate_payload(payload).is_err());
        }
    }
}
