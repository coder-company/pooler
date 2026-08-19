use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use http_body::{Body, Frame, SizeHint};
use thiserror::Error;
use tokio::{sync::Notify, time};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

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

/// A body that keeps a drain permit until its response has finished.
///
/// A response body can outlive the service future that produced its headers.
/// Holding the guard here makes graceful drain account for the complete
/// downstream stream.  When drain begins, polling stops and the upstream body
/// is dropped so no additional work is read.
pub struct DrainedBody<B> {
    inner: Pin<Box<B>>,
    cancellation: CancellationToken,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    cancellation_error_emitted: bool,
    guard: Option<DrainGuard>,
}

impl<B> DrainedBody<B> {
    /// Wrap a body and retain `guard` until the body reaches a terminal state.
    #[must_use]
    pub fn new(inner: B, guard: DrainGuard) -> Self {
        let cancellation = guard.cancellation_token();
        let cancelled = Box::pin(cancellation.clone().cancelled_owned());
        Self {
            inner: Box::pin(inner),
            cancellation,
            cancelled,
            cancellation_error_emitted: false,
            guard: Some(guard),
        }
    }
}

impl<B> fmt::Debug for DrainedBody<B>
where
    B: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DrainedBody")
            .field("inner", &self.inner)
            .field("cancelled", &self.cancellation.is_cancelled())
            .field("has_guard", &self.guard.is_some())
            .finish()
    }
}

impl<B> Body for DrainedBody<B>
where
    B: Body,
    B::Data: bytes::Buf,
    B::Error: From<io::Error>,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.cancelled.as_mut().poll(context).is_ready() {
            self.guard.take();
            if self.cancellation_error_emitted {
                return Poll::Ready(None);
            }
            self.cancellation_error_emitted = true;
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "response canceled during forced shutdown",
            )
            .into())));
        }

        match self.inner.as_mut().poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.guard.take();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => {
                self.guard.take();
                Poll::Ready(Some(Err(error)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        (self.cancellation.is_cancelled() && self.cancellation_error_emitted)
            || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
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

    /// Begin graceful drain and refuse all subsequent acquisitions.
    /// Existing requests are not canceled until [`Self::cancel_active`] is
    /// called, so they can finish within the caller's grace period.
    pub fn begin_drain(&self) {
        let started = {
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
        if started {
            self.inner.notify.notify_waiters();
        }
    }

    /// Cancel requests that remain after the graceful drain deadline.
    pub fn cancel_active(&self) {
        self.inner.cancellation.cancel();
        self.inner.notify.notify_waiters();
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

    /// A token canceled when active requests are force-canceled after drain.
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
    use bytes::Bytes;
    use http_body_util::BodyExt;

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
        assert!(!controller.cancellation_token().is_cancelled());

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

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn drain_wakes_and_stops_a_pending_response_body() {
        let controller = DrainController::new();
        let guard = controller.try_acquire().expect("request admitted");
        let body = DrainedBody::new(PendingBody, guard);
        let task = tokio::spawn(async move {
            let mut body = std::pin::pin!(body);
            body.frame().await
        });
        tokio::task::yield_now().await;

        controller.begin_drain();
        controller.cancel_active();
        let error = task
            .await
            .expect("body task completes")
            .expect("cancellation frame")
            .expect_err("forced cancellation must truncate with an error");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(controller.active(), 0);
    }
}
