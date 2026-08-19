use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The resource classes whose lifetime is checked by [`LeakCounters`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LeakKind {
    /// A spawned request, stream, or helper task.
    Task,
    /// A concurrency permit.
    Permit,
    /// An OAuth refresh lease.
    RefreshLease,
    /// A temporary capture/spool file.
    TemporaryFile,
    /// A tracked secret buffer.
    SecretMaterial,
}

impl LeakKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Task => "tasks",
            Self::Permit => "permits",
            Self::RefreshLease => "refresh leases",
            Self::TemporaryFile => "temporary files",
            Self::SecretMaterial => "secret material",
        }
    }
}

#[derive(Debug, Default)]
struct LeakState {
    tasks: AtomicU64,
    permits: AtomicU64,
    refresh_leases: AtomicU64,
    temporary_files: AtomicU64,
    secret_material: AtomicU64,
}

/// A point-in-time view of resources owned by a test.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LeakSnapshot {
    pub tasks: u64,
    pub permits: u64,
    pub refresh_leases: u64,
    pub temporary_files: u64,
    pub secret_material: u64,
}

impl LeakSnapshot {
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.tasks == 0
            && self.permits == 0
            && self.refresh_leases == 0
            && self.temporary_files == 0
            && self.secret_material == 0
    }

    #[must_use]
    pub const fn total(self) -> u64 {
        self.tasks
            + self.permits
            + self.refresh_leases
            + self.temporary_files
            + self.secret_material
    }

    #[must_use]
    pub const fn secrets(self) -> u64 {
        self.secret_material
    }
}

/// Error returned when a test finishes with resources still tracked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeakError {
    pub snapshot: LeakSnapshot,
}

impl fmt::Display for LeakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tracked resources leaked: {:?}", self.snapshot)
    }
}

impl std::error::Error for LeakError {}

/// A cloneable collection of atomic resource counters.
#[derive(Clone, Debug, Default)]
pub struct LeakCounters {
    state: Arc<LeakState>,
}

impl LeakCounters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire a resource guard.  Dropping the guard decrements the matching
    /// counter, including when a future is cancelled or panics during unwind.
    #[must_use]
    pub fn acquire(&self, kind: LeakKind) -> LeakGuard {
        self.increment(kind);
        LeakGuard {
            counters: self.clone(),
            kind,
            released: false,
        }
    }

    #[must_use]
    pub fn task(&self) -> LeakGuard {
        self.acquire(LeakKind::Task)
    }

    #[must_use]
    pub fn permit(&self) -> LeakGuard {
        self.acquire(LeakKind::Permit)
    }

    #[must_use]
    pub fn refresh_lease(&self) -> LeakGuard {
        self.acquire(LeakKind::RefreshLease)
    }

    #[must_use]
    pub fn temporary_file(&self) -> LeakGuard {
        self.acquire(LeakKind::TemporaryFile)
    }

    #[must_use]
    pub fn secret_material(&self) -> LeakGuard {
        self.acquire(LeakKind::SecretMaterial)
    }

    /// Read all counters atomically.
    #[must_use]
    pub fn snapshot(&self) -> LeakSnapshot {
        LeakSnapshot {
            tasks: self.state.tasks.load(Ordering::Acquire),
            permits: self.state.permits.load(Ordering::Acquire),
            refresh_leases: self.state.refresh_leases.load(Ordering::Acquire),
            temporary_files: self.state.temporary_files.load(Ordering::Acquire),
            secret_material: self.state.secret_material.load(Ordering::Acquire),
        }
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.snapshot().is_zero()
    }

    /// Return an error containing every non-zero counter, if any remain.
    ///
    /// # Errors
    ///
    /// Returns [`LeakError`] when one or more tracked resource counts are
    /// non-zero.
    pub fn assert_zero(&self) -> Result<(), LeakError> {
        let snapshot = self.snapshot();
        if snapshot.is_zero() {
            Ok(())
        } else {
            Err(LeakError { snapshot })
        }
    }

    fn increment(&self, kind: LeakKind) {
        self.counter(kind).fetch_add(1, Ordering::AcqRel);
    }

    fn decrement(&self, kind: LeakKind) {
        // A guard is the sole owner of a decrement.  Saturating the operation
        // makes a double release harmless while still leaving the test with a
        // useful non-zero count when ownership was lost elsewhere.
        let counter = self.counter(kind);
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            Some(value.saturating_sub(1))
        });
    }

    fn counter(&self, kind: LeakKind) -> &AtomicU64 {
        match kind {
            LeakKind::Task => &self.state.tasks,
            LeakKind::Permit => &self.state.permits,
            LeakKind::RefreshLease => &self.state.refresh_leases,
            LeakKind::TemporaryFile => &self.state.temporary_files,
            LeakKind::SecretMaterial => &self.state.secret_material,
        }
    }
}

/// RAII ownership of one tracked resource.
#[derive(Debug)]
pub struct LeakGuard {
    counters: LeakCounters,
    kind: LeakKind,
    released: bool,
}

impl LeakGuard {
    #[must_use]
    pub const fn kind(&self) -> LeakKind {
        self.kind
    }

    /// Release the resource early.  Dropping an already released guard is a
    /// no-op.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.counters.decrement(self.kind);
            self.released = true;
        }
    }
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// Alias emphasizing that a guard owns one resource lease.
pub type ResourceGuard = LeakGuard;

/// Alias for code that treats all counters as a resource registry.
pub type ResourceCounters = LeakCounters;

#[derive(Debug, Default)]
struct CancellationState {
    requested: AtomicU64,
    observed: AtomicU64,
}

/// A cancellation counter shared by a scripted upstream and the code under
/// test.
#[derive(Clone, Debug, Default)]
pub struct CancellationTracker {
    state: Arc<CancellationState>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CancellationSnapshot {
    pub requested: u64,
    pub observed: u64,
}

impl CancellationTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_requested(&self) {
        self.state.requested.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_observed(&self) {
        self.state.observed.fetch_add(1, Ordering::AcqRel);
    }

    /// Record both sides of a cancellation in one operation.
    pub fn record_cancellation(&self) {
        self.record_requested();
        self.record_observed();
    }

    #[must_use]
    pub fn snapshot(&self) -> CancellationSnapshot {
        CancellationSnapshot {
            requested: self.state.requested.load(Ordering::Acquire),
            observed: self.state.observed.load(Ordering::Acquire),
        }
    }

    #[must_use]
    pub fn requested(&self) -> u64 {
        self.snapshot().requested
    }

    #[must_use]
    pub fn observed(&self) -> u64 {
        self.snapshot().observed
    }

    #[must_use]
    pub fn all_requested_observed(&self) -> bool {
        let snapshot = self.snapshot();
        snapshot.requested == snapshot.observed
    }
}
