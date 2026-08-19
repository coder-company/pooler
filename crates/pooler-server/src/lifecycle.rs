//! The process state and cancellation signal shared by server tasks.

use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// State of a server process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleState {
    /// No startup work has begun.
    #[default]
    New = 0,
    /// Components are being prepared.
    Starting = 1,
    /// The server accepts requests.
    Running = 2,
    /// New requests are rejected and existing tasks should drain.
    Draining = 3,
    /// Shutdown is complete.
    Stopped = 4,
    /// Startup failed or the runtime entered a terminal failure state.
    Failed = 5,
}

impl LifecycleState {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::New,
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Draining,
            4 => Self::Stopped,
            _ => Self::Failed,
        }
    }
}

/// An invalid lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LifecycleError {
    /// The requested state transition is not valid from the current state.
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// State before the attempted transition.
        from: LifecycleState,
        /// Requested destination state.
        to: LifecycleState,
    },
}

struct Inner {
    state: AtomicU8,
    cancellation: CancellationToken,
}

/// Cloneable lifecycle handle.
#[derive(Clone)]
pub struct Lifecycle {
    inner: Arc<Inner>,
}

impl Lifecycle {
    /// Create a new lifecycle in [`LifecycleState::New`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: AtomicU8::new(LifecycleState::New as u8),
                cancellation: CancellationToken::new(),
            }),
        }
    }

    /// Return the current state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        LifecycleState::from_u8(self.inner.state.load(Ordering::Acquire))
    }

    /// Clone the cancellation signal used by server-owned tasks.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    /// Start a server whose components are already prepared.
    pub fn start(&self) -> Result<(), LifecycleError> {
        self.transition(LifecycleState::New, LifecycleState::Running)
    }

    /// Mark the beginning of asynchronous component preparation.
    pub fn begin_startup(&self) -> Result<(), LifecycleError> {
        self.transition(LifecycleState::New, LifecycleState::Starting)
    }

    /// Publish prepared components and begin accepting requests.
    pub fn mark_running(&self) -> Result<(), LifecycleError> {
        self.transition(LifecycleState::Starting, LifecycleState::Running)
    }

    /// Mark startup/runtime failure and wake all cancellation waiters.
    pub fn mark_failed(&self) {
        self.inner
            .state
            .store(LifecycleState::Failed as u8, Ordering::Release);
        self.inner.cancellation.cancel();
    }

    /// Enter draining and cancel server-owned tasks.
    pub fn begin_shutdown(&self) -> Result<(), LifecycleError> {
        let state = self.state();
        if matches!(state, LifecycleState::Draining | LifecycleState::Stopped) {
            return Ok(());
        }
        self.transition(state, LifecycleState::Draining)?;
        self.inner.cancellation.cancel();
        Ok(())
    }

    /// Finish shutdown after listeners and request tasks have drained.
    pub fn finish_shutdown(&self) -> Result<(), LifecycleError> {
        let state = self.state();
        if state == LifecycleState::Stopped {
            return Ok(());
        }
        self.transition(LifecycleState::Draining, LifecycleState::Stopped)
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancellation.is_cancelled()
    }

    /// Wait for shutdown cancellation.
    pub async fn cancelled(&self) {
        self.inner.cancellation.cancelled().await;
    }

    fn transition(&self, from: LifecycleState, to: LifecycleState) -> Result<(), LifecycleError> {
        self.inner
            .state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|value| LifecycleError::InvalidTransition {
                from: LifecycleState::from_u8(value),
                to,
            })
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_cancels_waiters_and_is_idempotent() {
        let lifecycle = Lifecycle::new();
        lifecycle.start().expect("new lifecycle starts");
        let waiter = lifecycle.clone();
        let task = tokio::spawn(async move {
            waiter.cancelled().await;
            true
        });

        lifecycle.begin_shutdown().expect("shutdown starts");
        lifecycle
            .begin_shutdown()
            .expect("second shutdown is harmless");
        assert_eq!(lifecycle.state(), LifecycleState::Draining);
        assert!(lifecycle.is_cancelled());
        lifecycle.finish_shutdown().expect("shutdown finishes");
        assert_eq!(lifecycle.state(), LifecycleState::Stopped);
        assert!(task.await.expect("waiter panicked"));
    }

    #[test]
    fn startup_failure_cancels_without_accepting_requests() {
        let lifecycle = Lifecycle::new();
        lifecycle.begin_startup().expect("startup starts");
        lifecycle.mark_failed();
        assert_eq!(lifecycle.state(), LifecycleState::Failed);
        assert!(lifecycle.is_cancelled());
    }
}
