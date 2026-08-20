use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Live and peak counts for resources owned by one HTTP runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeResourceSnapshot {
    /// Spawned runtime tasks that have not completed.
    pub tasks: u64,
    /// Request drain permits that have not been released.
    pub permits: u64,
    /// OAuth refresh operations that have not completed.
    pub refresh_leases: u64,
    /// Runtime-owned temporary files that have not been removed.
    pub temporary_files: u64,
    /// Materialized authorization values that remain in use.
    pub secret_material: u64,
    /// Highest number of simultaneously active runtime tasks.
    pub peak_tasks: u64,
    /// Highest number of simultaneously active request drain permits.
    pub peak_permits: u64,
    /// Highest number of simultaneously active OAuth refresh operations.
    pub peak_refresh_leases: u64,
    /// Highest number of simultaneously active runtime-owned temporary files.
    pub peak_temporary_files: u64,
    /// Highest number of simultaneously materialized authorization values.
    pub peak_secret_material: u64,
}

impl RuntimeResourceSnapshot {
    /// Whether every tracked resource has been released.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.tasks == 0
            && self.permits == 0
            && self.refresh_leases == 0
            && self.temporary_files == 0
            && self.secret_material == 0
    }

    /// Combine counters owned by cooperating parts of one runtime.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        Self {
            tasks: self.tasks.saturating_add(other.tasks),
            permits: self.permits.saturating_add(other.permits),
            refresh_leases: self.refresh_leases.saturating_add(other.refresh_leases),
            temporary_files: self.temporary_files.saturating_add(other.temporary_files),
            secret_material: self.secret_material.saturating_add(other.secret_material),
            peak_tasks: self.peak_tasks.saturating_add(other.peak_tasks),
            peak_permits: self.peak_permits.saturating_add(other.peak_permits),
            peak_refresh_leases: self
                .peak_refresh_leases
                .saturating_add(other.peak_refresh_leases),
            peak_temporary_files: self
                .peak_temporary_files
                .saturating_add(other.peak_temporary_files),
            peak_secret_material: self
                .peak_secret_material
                .saturating_add(other.peak_secret_material),
        }
    }
}

#[derive(Debug, Default)]
struct ResourceCount {
    current: AtomicU64,
    peak: AtomicU64,
}

impl ResourceCount {
    fn acquire(self: &Arc<Self>) -> RuntimeResourceGuard {
        let current = self
            .current
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.peak.fetch_max(current, Ordering::AcqRel);
        RuntimeResourceGuard {
            count: Arc::clone(self),
        }
    }

    fn current(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    fn peak(&self) -> u64 {
        self.peak.load(Ordering::Acquire)
    }
}

/// Process-local counters updated by production HTTP runtime ownership guards.
#[derive(Clone, Debug, Default)]
pub struct RuntimeResources {
    tasks: Arc<ResourceCount>,
    permits: Arc<ResourceCount>,
    refresh_leases: Arc<ResourceCount>,
    temporary_files: Arc<ResourceCount>,
    secret_material: Arc<ResourceCount>,
}

impl RuntimeResources {
    /// Create an empty resource registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Track one spawned runtime task until the returned guard is dropped.
    #[must_use]
    pub fn task(&self) -> RuntimeResourceGuard {
        self.tasks.acquire()
    }

    /// Track one admitted request until its drain permit is released.
    #[must_use]
    pub fn permit(&self) -> RuntimeResourceGuard {
        self.permits.acquire()
    }

    /// Track one OAuth refresh operation until it completes or is cancelled.
    #[must_use]
    pub fn refresh_lease(&self) -> RuntimeResourceGuard {
        self.refresh_leases.acquire()
    }

    /// Track one runtime-owned temporary file until it is removed.
    #[must_use]
    pub fn temporary_file(&self) -> RuntimeResourceGuard {
        self.temporary_files.acquire()
    }

    /// Track one materialized authorization value for its usable lifetime.
    #[must_use]
    pub fn secret_material(&self) -> RuntimeResourceGuard {
        self.secret_material.acquire()
    }

    /// Return a point-in-time snapshot, including lifetime peaks.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeResourceSnapshot {
        RuntimeResourceSnapshot {
            tasks: self.tasks.current(),
            permits: self.permits.current(),
            refresh_leases: self.refresh_leases.current(),
            temporary_files: self.temporary_files.current(),
            secret_material: self.secret_material.current(),
            peak_tasks: self.tasks.peak(),
            peak_permits: self.permits.peak(),
            peak_refresh_leases: self.refresh_leases.peak(),
            peak_temporary_files: self.temporary_files.peak(),
            peak_secret_material: self.secret_material.peak(),
        }
    }
}

/// RAII ownership of one resource counted by [`RuntimeResources`].
#[derive(Debug)]
pub struct RuntimeResourceGuard {
    count: Arc<ResourceCount>,
}

impl Drop for RuntimeResourceGuard {
    fn drop(&mut self) {
        self.count.current.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_report_live_resources_and_preserve_peaks_after_release() {
        let resources = RuntimeResources::new();
        let task = resources.task();
        let permit = resources.permit();
        let secret = resources.secret_material();

        let active = resources.snapshot();
        assert_eq!(active.tasks, 1);
        assert_eq!(active.permits, 1);
        assert_eq!(active.secret_material, 1);
        assert!(!active.is_zero());

        drop((task, permit, secret));
        let drained = resources.snapshot();
        assert!(drained.is_zero());
        assert_eq!(drained.peak_tasks, 1);
        assert_eq!(drained.peak_permits, 1);
        assert_eq!(drained.peak_secret_material, 1);
    }
}
