use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// A clock abstraction used by retry, timeout, and cooldown code.
///
/// Implementations must be monotonic.  [`FakeClock`] is the implementation used
/// by deterministic tests; [`SystemClock`] is useful when a component needs the
/// same interface in a small integration test.
pub trait Clock: Clone + Send + Sync + 'static {
    /// Return elapsed time from the clock's origin.
    fn now(&self) -> Duration;

    /// Return a future that completes after `duration` has elapsed according to
    /// this clock.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Return a future that completes at an absolute clock deadline.
    fn sleep_until(
        &self,
        deadline: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let duration = deadline.saturating_sub(self.now());
        self.sleep(duration)
    }
}

#[derive(Debug)]
struct FakeClockState {
    now: Mutex<Duration>,
    wake: Notify,
}

/// A manually advanced, monotonic clock.
///
/// Sleeping futures do not consume wall-clock time.  Call [`FakeClock::advance`]
/// or [`FakeClock::set`] to wake them.  The implementation uses a notification
/// plus a clock re-check, so advancing between a check and registering a waiter
/// cannot strand a sleeper.
#[derive(Clone, Debug)]
pub struct FakeClock {
    state: Arc<FakeClockState>,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeClock {
    /// Create a clock starting at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::at(Duration::ZERO)
    }

    /// Create a clock starting at `now`.
    #[must_use]
    pub fn at(now: Duration) -> Self {
        Self {
            state: Arc::new(FakeClockState {
                now: Mutex::new(now),
                wake: Notify::new(),
            }),
        }
    }

    /// Return the current logical time.
    #[must_use]
    pub fn now(&self) -> Duration {
        *self
            .state
            .now
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Advance the clock by `amount`, saturating at `Duration::MAX`.
    ///
    /// The returned value is the new logical time.  A zero advance still wakes
    /// waiters, which is useful when a test wants to re-poll futures after a
    /// state change unrelated to time.
    pub fn advance(&self, amount: Duration) -> Duration {
        let next = {
            let mut now = self
                .state
                .now
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *now = now.saturating_add(amount);
            *now
        };
        self.state.wake.notify_waiters();
        next
    }

    /// Set the logical time forward to `now`.
    ///
    /// A fake clock is monotonic: requests to move backwards are ignored and
    /// the current value is returned.
    pub fn set(&self, now: Duration) -> Duration {
        let next = {
            let mut current = self
                .state
                .now
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if now > *current {
                *current = now;
            }
            *current
        };
        self.state.wake.notify_waiters();
        next
    }

    /// Sleep until an absolute logical deadline.
    pub async fn wait_until(&self, deadline: Duration) {
        loop {
            let notified = self.state.wake.notified();
            tokio::pin!(notified);
            // Register before checking the condition.  This is the standard
            // Notify pattern that closes the check/register race.
            notified.as_mut().enable();
            if self.now() >= deadline {
                return;
            }
            notified.await;
        }
    }

    /// Return a future that completes after `duration` of logical time.
    #[must_use]
    pub fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let clock = self.clone();
        Box::pin(async move {
            let deadline = clock.now().saturating_add(duration);
            clock.wait_until(deadline).await;
        })
    }

    /// Yield a few times so tasks released by an [`advance`](Self::advance)
    /// call can make progress.  This is intentionally bounded and never waits
    /// for wall-clock time.
    pub async fn run_until_idle(&self) {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        Self::now(self)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Self::sleep(self, duration)
    }

    fn sleep_until(
        &self,
        deadline: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let clock = self.clone();
        Box::pin(async move {
            clock.wait_until(deadline).await;
        })
    }
}

/// A wall-clock implementation of [`Clock`].
#[derive(Clone, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn sleep_until(
        &self,
        deadline: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let remaining = deadline.saturating_sub(self.now());
        self.sleep(remaining)
    }
}
