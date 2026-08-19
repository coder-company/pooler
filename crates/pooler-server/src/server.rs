//! Startup, listener publication, and atomic reload coordination.

use std::sync::{Arc, Mutex as StdMutex};

use arc_swap::ArcSwapOption;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    ConfigSnapshot, ConfigStore, ConfigStoreError, Lifecycle, LifecycleError, LifecycleState,
    ListenerPreparer, PreparedListeners,
};

/// Startup failure.
#[derive(Debug, Error)]
pub enum ServerError<E> {
    /// Lifecycle did not permit the requested operation.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    /// Listener preparation failed.
    #[error("listener preparation failed: {0:?}")]
    Listener(E),
    /// Cancellation happened before prepared listeners could be published.
    #[error("server startup cancelled")]
    Cancelled,
}

/// Reload failure.  No variant after `Config` publishes a new configuration.
#[derive(Debug, Error)]
pub enum ReloadError<C, L> {
    /// Parsing/compilation rejected the candidate.
    #[error("configuration rejected: {0:?}")]
    Config(C),
    /// Listener preparation rejected the candidate.
    #[error("listener preparation failed: {0:?}")]
    Listener(L),
    /// Shutdown began while preparing listeners.
    #[error("reload cancelled")]
    Cancelled,
    /// Another writer advanced the store before this candidate was published.
    #[error(transparent)]
    GenerationChanged(#[from] ConfigStoreError),
}

/// Result of a reload attempt that first compares the candidate with the
/// active immutable configuration.
#[derive(Debug)]
pub enum ReloadOutcome<T> {
    /// The candidate was byte-for-byte/equality-equivalent and no generation
    /// or listener publication occurred.
    Unchanged(Arc<ConfigSnapshot<T>>),
    /// The candidate was prepared and atomically published as a new
    /// generation.
    Reloaded(Arc<ConfigSnapshot<T>>),
}

impl<T> ReloadOutcome<T> {
    /// Return the snapshot visible after the reload attempt.
    #[must_use]
    pub fn snapshot(&self) -> &Arc<ConfigSnapshot<T>> {
        match self {
            Self::Unchanged(snapshot) | Self::Reloaded(snapshot) => snapshot,
        }
    }

    /// Whether a new configuration generation was published.
    #[must_use]
    pub const fn changed(&self) -> bool {
        matches!(self, Self::Reloaded(_))
    }
}

/// A running server with an immutable config store and prepared listeners.
pub struct Server<C, P>
where
    P: ListenerPreparer<C>,
{
    config: ConfigStore<C>,
    lifecycle: Lifecycle,
    preparer: P,
    listeners: ArcSwapOption<PreparedListeners<P::Prepared>>,
    reload_lock: Mutex<()>,
    // Keep shutdown from crossing the final startup publication boundary.
    startup_lock: StdMutex<()>,
}

impl<C, P> Server<C, P>
where
    C: Send + Sync + 'static,
    P: ListenerPreparer<C>,
{
    /// Create a server with an initial, already compiled configuration.
    #[must_use]
    pub fn new(config: C, preparer: P) -> Self {
        Self {
            config: ConfigStore::new(config),
            lifecycle: Lifecycle::new(),
            preparer,
            listeners: ArcSwapOption::empty(),
            reload_lock: Mutex::new(()),
            startup_lock: StdMutex::new(()),
        }
    }

    /// Return the process lifecycle handle.
    #[must_use]
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle.clone()
    }

    /// Return the current request snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ConfigSnapshot<C>> {
        self.config.snapshot()
    }

    /// Return the currently published listener set.
    #[must_use]
    pub fn listeners(&self) -> Option<Arc<PreparedListeners<P::Prepared>>> {
        self.listeners.load_full()
    }

    /// Prepare and publish initial listeners, then enter `Running`.
    pub async fn start(&self) -> Result<(), ServerError<P::Error>> {
        self.lifecycle.begin_startup()?;
        let snapshot = self.config.snapshot();
        let token = self.lifecycle.cancellation_token();
        let prepared = match self.prepare(snapshot, token.clone()).await {
            Ok(prepared) => prepared,
            Err(error) => {
                self.lifecycle.mark_failed();
                return Err(error);
            }
        };
        let _startup_guard = self.startup_lock.lock().expect("startup lock poisoned");
        if token.is_cancelled() {
            if self.lifecycle.state() == LifecycleState::Starting {
                self.lifecycle.mark_failed();
            }
            return Err(ServerError::Cancelled);
        }
        self.listeners.store(Some(Arc::new(prepared)));
        if let Err(error) = self.lifecycle.mark_running() {
            self.listeners.store(None);
            return Err(ServerError::Lifecycle(error));
        }
        Ok(())
    }

    /// Prepare and publish listeners for a compiled candidate.
    ///
    /// The old config and listener set remain published until preparation
    /// succeeds.  A failed candidate therefore cannot partially reload a
    /// running server.
    pub async fn reload(
        &self,
        config: C,
    ) -> Result<Arc<ConfigSnapshot<C>>, ReloadError<(), P::Error>> {
        self.reload_result(Ok(config)).await
    }

    /// Reload a candidate only when it differs from the active configuration.
    ///
    /// Equality is checked while holding the same writer lock used for
    /// publication. This keeps repeated file-system notifications and SIGHUP
    /// requests from consuming generations or rebuilding listeners when the
    /// expanded source is unchanged.
    pub async fn reload_if_changed(
        &self,
        config: C,
    ) -> Result<ReloadOutcome<C>, ReloadError<(), P::Error>>
    where
        C: PartialEq,
    {
        self.reload_result_if_changed(Ok(config)).await
    }

    /// Fallible form of [`Self::reload_if_changed`] for parser/compiler
    /// results produced off the request/accepting path.
    pub async fn reload_result_if_changed<E>(
        &self,
        result: Result<C, E>,
    ) -> Result<ReloadOutcome<C>, ReloadError<E, P::Error>>
    where
        C: PartialEq,
    {
        let config = result.map_err(ReloadError::Config)?;
        if self.lifecycle.state() != LifecycleState::Running {
            return Err(ReloadError::Cancelled);
        }
        let _guard = self.reload_lock.lock().await;
        let old: Arc<ConfigSnapshot<C>> = self.config.snapshot();
        if old.config() == &config {
            return Ok(ReloadOutcome::Unchanged(old));
        }
        let candidate = Arc::new(ConfigSnapshot::new(old.generation().next(), config));
        let token = self.lifecycle.cancellation_token();
        let prepared = self
            .prepare(Arc::clone(&candidate), token.clone())
            .await
            .map_err(|error| match error {
                ServerError::Lifecycle(_) | ServerError::Cancelled => ReloadError::Cancelled,
                ServerError::Listener(error) => ReloadError::Listener(error),
            })?;
        if token.is_cancelled() {
            return Err(ReloadError::Cancelled);
        }
        let published = self
            .config
            .install_arc_if(old.generation(), candidate.config_arc())
            .map_err(ReloadError::GenerationChanged)?;
        self.listeners.store(Some(Arc::new(prepared)));
        Ok(ReloadOutcome::Reloaded(published))
    }

    /// Reload from a parser/compiler result, preserving the old generation on
    /// either config or listener failure.
    pub async fn reload_result<E>(
        &self,
        result: Result<C, E>,
    ) -> Result<Arc<ConfigSnapshot<C>>, ReloadError<E, P::Error>> {
        let config = result.map_err(ReloadError::Config)?;
        if self.lifecycle.state() != LifecycleState::Running {
            return Err(ReloadError::Cancelled);
        }
        let _guard = self.reload_lock.lock().await;
        let old: Arc<ConfigSnapshot<C>> = self.config.snapshot();
        let candidate = Arc::new(ConfigSnapshot::new(old.generation().next(), config));
        let token = self.lifecycle.cancellation_token();
        let prepared = self
            .prepare(Arc::clone(&candidate), token.clone())
            .await
            .map_err(|error| match error {
                ServerError::Lifecycle(_) | ServerError::Cancelled => ReloadError::Cancelled,
                ServerError::Listener(error) => ReloadError::Listener(error),
            })?;
        if token.is_cancelled() {
            return Err(ReloadError::Cancelled);
        }
        let published = self
            .config
            .install_arc_if(old.generation(), candidate.config_arc())
            .map_err(ReloadError::GenerationChanged)?;
        self.listeners.store(Some(Arc::new(prepared)));
        Ok(published)
    }

    /// Signal cancellation and enter `Draining`.
    pub fn begin_shutdown(&self) -> Result<(), LifecycleError> {
        let _startup_guard = self.startup_lock.lock().expect("startup lock poisoned");
        self.lifecycle.begin_shutdown()
    }

    /// Mark shutdown complete after owned tasks/listeners have stopped.
    pub fn finish_shutdown(&self) -> Result<(), LifecycleError> {
        self.lifecycle.finish_shutdown()
    }

    async fn prepare(
        &self,
        snapshot: Arc<ConfigSnapshot<C>>,
        token: CancellationToken,
    ) -> Result<PreparedListeners<P::Prepared>, ServerError<P::Error>> {
        if token.is_cancelled() {
            return Err(ServerError::Cancelled);
        }
        let generation = snapshot.generation();
        self.preparer
            .prepare(snapshot, token)
            .await
            .map(|listeners| PreparedListeners::new(generation, listeners))
            .map_err(ServerError::Listener)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::ListenerPreparationFuture;
    use pooler_core::ConfigGeneration;
    use tokio::sync::Notify;

    struct FakePreparer {
        fail: Arc<AtomicBool>,
    }

    impl ListenerPreparer<String> for FakePreparer {
        type Prepared = String;
        type Error = &'static str;

        fn prepare(
            &self,
            snapshot: Arc<ConfigSnapshot<String>>,
            _cancellation: CancellationToken,
        ) -> ListenerPreparationFuture<'_, Self::Prepared, Self::Error> {
            let fail = Arc::clone(&self.fail);
            Box::pin(async move {
                if fail.load(Ordering::Acquire) {
                    Err("listener rejected")
                } else {
                    Ok(snapshot.config().clone())
                }
            })
        }
    }

    struct BlockingPreparer {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl ListenerPreparer<String> for BlockingPreparer {
        type Prepared = String;
        type Error = &'static str;

        fn prepare(
            &self,
            snapshot: Arc<ConfigSnapshot<String>>,
            _cancellation: CancellationToken,
        ) -> ListenerPreparationFuture<'_, Self::Prepared, Self::Error> {
            let started = Arc::clone(&self.started);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                started.notify_one();
                release.notified().await;
                Ok(snapshot.config().clone())
            })
        }
    }

    #[tokio::test]
    async fn shutdown_during_startup_does_not_publish_listeners() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let server = Arc::new(Server::new(
            String::from("initial"),
            BlockingPreparer {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            },
        ));
        let startup = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { server.start().await })
        };

        started.notified().await;
        server
            .begin_shutdown()
            .expect("shutdown can begin while startup prepares listeners");
        release.notify_one();

        assert!(matches!(
            startup.await.expect("startup task did not panic"),
            Err(ServerError::Cancelled)
        ));
        assert!(server.listeners().is_none());
        assert_eq!(server.lifecycle().state(), LifecycleState::Draining);
    }

    #[tokio::test]
    async fn failed_listener_reload_preserves_old_snapshot_and_listener() {
        let fail = Arc::new(AtomicBool::new(false));
        let server = Server::new(
            String::from("old"),
            FakePreparer {
                fail: Arc::clone(&fail),
            },
        );
        server.start().await.expect("startup succeeds");
        let old = server.snapshot();
        fail.store(true, Ordering::Release);

        let error = server
            .reload(String::from("new"))
            .await
            .expect_err("listener failure must reject reload");
        assert!(matches!(error, ReloadError::Listener("listener rejected")));
        assert_eq!(server.snapshot().config(), "old");
        assert_eq!(server.snapshot().generation(), ConfigGeneration::INITIAL);
        assert_eq!(
            server.listeners().expect("listeners published").listeners(),
            "old"
        );
        assert_eq!(old.config(), "old");
    }

    #[tokio::test]
    async fn equivalent_reload_keeps_generation_and_listener_identity() {
        let server = Server::new(
            String::from("same"),
            FakePreparer {
                fail: Arc::new(AtomicBool::new(false)),
            },
        );
        server.start().await.expect("startup succeeds");
        let before = server.snapshot();
        let listeners_before = server.listeners().expect("listeners published");

        let outcome = server
            .reload_if_changed(String::from("same"))
            .await
            .expect("equivalent candidate is accepted as a no-op");
        assert!(!outcome.changed());
        assert_eq!(outcome.snapshot().generation(), before.generation());
        assert!(Arc::ptr_eq(outcome.snapshot(), &before));
        assert!(Arc::ptr_eq(
            &listeners_before,
            &server.listeners().expect("listeners remain published")
        ));
    }
}
