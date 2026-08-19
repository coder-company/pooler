//! Atomic, generation-tagged configuration snapshots.

use std::{
    fmt,
    ops::Deref,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use pooler_core::ConfigGeneration;
use thiserror::Error;

/// An immutable compiled configuration and the generation that owns it.
pub struct ConfigSnapshot<T> {
    generation: ConfigGeneration,
    config: Arc<T>,
}

impl<T> ConfigSnapshot<T> {
    /// Create a snapshot at `generation`.
    #[must_use]
    pub fn new(generation: ConfigGeneration, config: T) -> Self {
        Self::from_arc(generation, Arc::new(config))
    }

    /// Create a snapshot from an already shared configuration value.
    #[must_use]
    pub fn from_arc(generation: ConfigGeneration, config: Arc<T>) -> Self {
        Self { generation, config }
    }

    /// Return the generation marker.
    #[must_use]
    pub const fn generation(&self) -> ConfigGeneration {
        self.generation
    }

    /// Borrow the immutable configuration.
    #[must_use]
    pub fn config(&self) -> &T {
        &self.config
    }

    /// Clone the shared immutable configuration value.
    #[must_use]
    pub fn config_arc(&self) -> Arc<T> {
        Arc::clone(&self.config)
    }
}

impl<T> Clone for ConfigSnapshot<T> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            config: Arc::clone(&self.config),
        }
    }
}

impl<T> Deref for ConfigSnapshot<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.config()
    }
}

impl<T: fmt::Debug> fmt::Debug for ConfigSnapshot<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigSnapshot")
            .field("generation", &self.generation)
            .field("config", &self.config)
            .finish()
    }
}

/// A stale conditional install was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ConfigStoreError {
    /// Another successful reload advanced the generation first.
    #[error("configuration generation changed (expected {expected:?}, current {current:?})")]
    GenerationChanged {
        /// Generation observed before preparation.
        expected: ConfigGeneration,
        /// Generation present at install time.
        current: ConfigGeneration,
    },
}

/// Lock-free reads and atomic publication for compiled configuration.
pub struct ConfigStore<T> {
    current: ArcSwap<ConfigSnapshot<T>>,
    reload_lock: Mutex<()>,
}

impl<T> ConfigStore<T> {
    /// Create a store at [`ConfigGeneration::INITIAL`].
    #[must_use]
    pub fn new(config: T) -> Self {
        Self::with_generation(ConfigGeneration::INITIAL, config)
    }

    /// Create a store at a persisted generation.
    #[must_use]
    pub fn with_generation(generation: ConfigGeneration, config: T) -> Self {
        Self {
            current: ArcSwap::from_pointee(ConfigSnapshot::new(generation, config)),
            reload_lock: Mutex::new(()),
        }
    }

    /// Load a request snapshot.  The returned `Arc` keeps this generation alive.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ConfigSnapshot<T>> {
        self.current.load_full()
    }

    /// Return the active generation.
    #[must_use]
    pub fn generation(&self) -> ConfigGeneration {
        self.current.load().generation()
    }

    /// Publish `config` as the next generation.
    pub fn replace(&self, config: T) -> Arc<ConfigSnapshot<T>> {
        let _guard = self
            .reload_lock
            .lock()
            .expect("config reload lock poisoned");
        self.replace_locked(config)
    }

    /// Publish a parser/compiler result.  An error leaves the old pointer and
    /// generation untouched.
    pub fn replace_result<E>(&self, result: Result<T, E>) -> Result<Arc<ConfigSnapshot<T>>, E> {
        result.map(|config| self.replace(config))
    }

    /// Build the next config while holding the reload lock.  A failed build is
    /// never published.
    pub fn reload_with<E, F>(&self, build: F) -> Result<Arc<ConfigSnapshot<T>>, E>
    where
        F: FnOnce(&T) -> Result<T, E>,
    {
        let _guard = self
            .reload_lock
            .lock()
            .expect("config reload lock poisoned");
        let current = self.current.load_full();
        let config = build(current.config())?;
        let next = Arc::new(ConfigSnapshot::new(current.generation().next(), config));
        self.current.store(Arc::clone(&next));
        Ok(next)
    }

    /// Publish only when `expected` is still current.
    pub fn install_if(
        &self,
        expected: ConfigGeneration,
        config: T,
    ) -> Result<Arc<ConfigSnapshot<T>>, ConfigStoreError> {
        self.install_arc_if(expected, Arc::new(config))
    }

    /// Publish a shared candidate only when `expected` is still current.
    pub fn install_arc_if(
        &self,
        expected: ConfigGeneration,
        config: Arc<T>,
    ) -> Result<Arc<ConfigSnapshot<T>>, ConfigStoreError> {
        let _guard = self
            .reload_lock
            .lock()
            .expect("config reload lock poisoned");
        let current = self.current.load_full();
        if current.generation() != expected {
            return Err(ConfigStoreError::GenerationChanged {
                expected,
                current: current.generation(),
            });
        }
        Ok(self.replace_locked_arc(config))
    }

    fn replace_locked(&self, config: T) -> Arc<ConfigSnapshot<T>> {
        self.replace_locked_arc(Arc::new(config))
    }

    fn replace_locked_arc(&self, config: Arc<T>) -> Arc<ConfigSnapshot<T>> {
        let generation = self.current.load().generation().next();
        let next = Arc::new(ConfigSnapshot::from_arc(generation, config));
        self.current.store(Arc::clone(&next));
        next
    }
}

impl<T: fmt::Debug> fmt::Debug for ConfigStore<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot: Arc<ConfigSnapshot<T>> = self.snapshot();
        formatter
            .debug_struct("ConfigStore")
            .field("snapshot", &snapshot)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_snapshot_survives_successful_reload() {
        let store = ConfigStore::new(String::from("first"));
        let old = store.snapshot();
        let new = store.replace(String::from("second"));

        assert_eq!(old.config(), "first");
        assert_eq!(new.config(), "second");
        assert_eq!(old.generation(), ConfigGeneration::INITIAL);
        assert_eq!(new.generation(), ConfigGeneration::INITIAL.next());
    }

    #[test]
    fn failed_reload_preserves_old_snapshot() {
        let store = ConfigStore::new(String::from("valid"));
        let old = store.snapshot();
        let error = store
            .reload_with(|_| -> Result<String, &'static str> { Err("invalid") })
            .expect_err("invalid config must be rejected");

        assert_eq!(error, "invalid");
        let current = store.snapshot();
        assert_eq!(current.config(), "valid");
        assert_eq!(current.generation(), old.generation());
        assert!(Arc::ptr_eq(&old, &current));
    }
}
