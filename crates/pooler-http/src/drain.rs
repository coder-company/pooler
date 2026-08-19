use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use thiserror::Error;
use tokio::{sync::Notify, time};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default)]
struct DrainState {
    active: usize,
    draining: bool,
}

struct Inner {
    state: Mutex<DrainState>,
    notify: Notify,
    cancellation: CancellationToken,
}

/// Coordinates graceful shutdown and prevents new requests once draining
/// starts.
#[derive(Clone)]
pub struct DrainController {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for DrainController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DrainController")
            .field("active", &self.active())
            .field("is_draining", &self.is_draining())
            .finish()
    }
}

/// Errors from a graceful drain operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum DrainError {
    #[error("drain timed out with {active} active request(s)")]
    Timeout { active: usize },
}

/// A permit representing one request in flight.  Dropping it decrements the
/// controller's active count and wakes drain waiters.
pub struct DrainGuard {
    inner: Arc<Inner>,
    released: bool,
}

impl std::fmt::Debug for DrainGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DrainGuard")
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl DrainController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(DrainState::default()),
                notify: Notify::new(),
                cancellation: CancellationToken::new(),
            }),
        }
    }

    /// Acquire a permit for a new request.  Acquisition is synchronous and
    /// linearized with [`DrainController::begin_drain`].
    pub fn try_acquire(&self) -> Option<DrainGuard> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.draining {
            return None;
        }
        state.active = state.active.saturating_add(1);
        drop(state);
        Some(DrainGuard {
            inner: Arc::clone(&self.inner),
            released: false,
        })
    }

    /// Begin graceful drain, canceling the shared shutdown token and refusing
    /// all subsequent acquisitions.
    pub fn begin_drain(&self) {
        let should_cancel = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.draining {
                false
            } else {
                state.draining = true;
                true
            }
        };
        if should_cancel {
            self.inner.cancellation.cancel();
            self.inner.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .draining
    }

    #[must_use]
    pub fn active(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    /// A token canceled when draining starts.  Request tasks should select on
    /// this token together with their downstream disconnect token.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    /// Wait until all acquired permits are released, beginning drain first.
    pub async fn drain(&self, timeout: Duration) -> Result<(), DrainError> {
        self.begin_drain();
        let wait = async {
            loop {
                let notified = self.inner.notify.notified();
                tokio::pin!(notified);
                // Register before checking the count to close the
                // check/register race.
                notified.as_mut().enable();
                if self.active() == 0 {
                    return;
                }
                notified.await;
            }
        };

        if time::timeout(timeout, wait).await.is_ok() {
            Ok(())
        } else {
            Err(DrainError::Timeout {
                active: self.active(),
            })
        }
    }
}

impl Default for DrainController {
    fn default() -> Self {
        Self::new()
    }
}

impl DrainGuard {
    #[must_use]
    pub fn is_released(&self) -> bool {
        self.released
    }

    /// A token canceled when the owning controller enters drain.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    /// Release explicitly, making it possible to end a request before the
    /// guard leaves scope.  This is idempotent.
    pub fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        drop(state);
        self.inner.notify.notify_waiters();
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn drain_waits_for_guards_and_rejects_new_work() {
        let controller = DrainController::new();
        let guard = controller.try_acquire().unwrap();
        assert_eq!(controller.active(), 1);

        let waiter = {
            let controller = controller.clone();
            tokio::spawn(async move { controller.drain(Duration::from_secs(1)).await })
        };
        tokio::task::yield_now().await;
        assert!(controller.is_draining());
        assert!(controller.try_acquire().is_none());
        assert!(controller.cancellation_token().is_cancelled());

        drop(guard);
        assert!(waiter.await.unwrap().is_ok());
        assert_eq!(controller.active(), 0);
    }

    #[tokio::test]
    async fn drain_timeout_reports_active_count() {
        let controller = DrainController::new();
        let _guard = controller.try_acquire().unwrap();
        assert_eq!(
            controller.drain(Duration::from_millis(1)).await,
            Err(DrainError::Timeout { active: 1 })
        );
    }
}
