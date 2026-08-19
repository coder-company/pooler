use std::time::Duration;

use thiserror::Error;
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Transport milestones for one upstream attempt.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StreamState {
    Created,
    Connecting,
    AwaitingHeaders,
    ValidatingHeaders,
    BootstrapBuffering,
    /// Downstream response headers or body output has become visible.
    Committed,
    Completed,
    Disconnected,
    /// An attempt failed before commitment and may be replayed if policy says
    /// that the request and failure are retry-safe.
    RetryableFailure,
    /// A terminal pre-commit failure for which replay is not allowed.
    Failed,
}

/// Explicit events accepted by [`StreamCommitment::transition`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StreamEvent {
    Connect,
    HeadersReceived,
    HeadersValidated,
    Bootstrap,
    /// Downstream response headers became visible.
    HeadersSent,
    Commit,
    Complete,
    Disconnect,
    RetryableFailure,
    Failure,
}

/// Invalid state transition details.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
#[error("cannot apply {event:?} while stream is in {state:?}")]
pub struct CommitmentError {
    pub state: StreamState,
    pub event: StreamEvent,
}

/// Returned when code attempts to replay an attempt after commitment or after
/// a terminal outcome.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum RetryError {
    #[error("stream output is already committed and cannot be retried")]
    Committed,
    #[error("stream is not in a retryable failure state")]
    NotRetryable,
    #[error("stream has reached a terminal state")]
    Terminal,
}

/// Why a retry wait did not complete.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum RetryWaitError {
    #[error("retry wait canceled")]
    Canceled,
}

/// Wait for a bounded retry delay while honoring request cancellation.
///
/// Cancellation is checked before the timer so a caller never starts a new
/// attempt after the request has already been canceled.
pub async fn wait_for_retry(
    delay: Duration,
    cancellation: &CancellationToken,
) -> Result<(), RetryWaitError> {
    if cancellation.is_cancelled() {
        return Err(RetryWaitError::Canceled);
    }
    if delay.is_zero() {
        return Ok(());
    }
    tokio::select! {
        () = time::sleep(delay) => Ok(()),
        () = cancellation.cancelled() => Err(RetryWaitError::Canceled),
    }
}

/// Tracks whether a downstream response has been committed and gates retries
/// accordingly.
#[derive(Debug, Clone)]
pub struct StreamCommitment {
    state: StreamState,
    attempt: u32,
    committed: bool,
}

impl Default for StreamCommitment {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCommitment {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: StreamState::Created,
            attempt: 0,
            committed: false,
        }
    }

    #[must_use]
    pub fn state(&self) -> StreamState {
        self.state
    }

    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    #[must_use]
    pub fn can_retry(&self) -> bool {
        !self.committed && self.state == StreamState::RetryableFailure
    }

    /// Apply one validated stream milestone.
    pub fn transition(&mut self, event: StreamEvent) -> Result<(), CommitmentError> {
        let next = match (self.state, event) {
            (StreamState::Created, StreamEvent::Connect) => StreamState::Connecting,
            (StreamState::Connecting, StreamEvent::HeadersReceived) => StreamState::AwaitingHeaders,
            (StreamState::AwaitingHeaders, StreamEvent::HeadersValidated) => {
                StreamState::ValidatingHeaders
            }
            (StreamState::ValidatingHeaders, StreamEvent::Bootstrap) => {
                StreamState::BootstrapBuffering
            }
            (
                StreamState::Created
                | StreamState::Connecting
                | StreamState::AwaitingHeaders
                | StreamState::ValidatingHeaders
                | StreamState::BootstrapBuffering,
                StreamEvent::HeadersSent,
            ) => StreamState::Committed,
            (StreamState::BootstrapBuffering, StreamEvent::Commit) => StreamState::Committed,
            (StreamState::Committed, StreamEvent::Complete) => StreamState::Completed,
            (StreamState::Committed, StreamEvent::Disconnect) => StreamState::Disconnected,
            (StreamState::Committed, StreamEvent::Failure) => StreamState::Failed,
            (
                StreamState::Created
                | StreamState::Connecting
                | StreamState::AwaitingHeaders
                | StreamState::ValidatingHeaders
                | StreamState::BootstrapBuffering,
                StreamEvent::RetryableFailure,
            ) => StreamState::RetryableFailure,
            (
                StreamState::Created
                | StreamState::Connecting
                | StreamState::AwaitingHeaders
                | StreamState::ValidatingHeaders
                | StreamState::BootstrapBuffering,
                StreamEvent::Failure,
            ) => StreamState::Failed,
            (
                StreamState::Created
                | StreamState::Connecting
                | StreamState::AwaitingHeaders
                | StreamState::ValidatingHeaders
                | StreamState::BootstrapBuffering,
                StreamEvent::Disconnect,
            ) => StreamState::Disconnected,
            (StreamState::RetryableFailure, StreamEvent::RetryableFailure) => {
                StreamState::RetryableFailure
            }
            _ => {
                return Err(CommitmentError {
                    state: self.state,
                    event,
                })
            }
        };

        if next == StreamState::Committed {
            self.committed = true;
        }
        self.state = next;
        Ok(())
    }

    pub fn connect(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::Connect)
    }

    pub fn headers_received(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::HeadersReceived)
    }

    pub fn validate_headers(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::HeadersValidated)
    }

    pub fn begin_bootstrap(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::Bootstrap)
    }

    /// Mark downstream response headers as visible.  Headers are a commitment
    /// boundary even when the body has not emitted its first byte.
    pub fn mark_headers_sent(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::HeadersSent)
    }

    /// Mark the first downstream-visible byte/event.  This is the point after
    /// which retries are forbidden, regardless of the eventual failure.
    pub fn commit(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::Commit)
    }

    pub fn complete(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::Complete)
    }

    pub fn disconnect(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::Disconnect)
    }

    pub fn fail_retryable(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::RetryableFailure)
    }

    pub fn fail(&mut self) -> Result<(), CommitmentError> {
        self.transition(StreamEvent::Failure)
    }

    /// Start another upstream attempt after a pre-commit retryable failure.
    ///
    /// The new attempt starts at `Connecting`; callers cannot obtain this
    /// transition once [`Self::commit`] has succeeded.
    pub fn retry(&mut self) -> Result<u32, RetryError> {
        if self.committed {
            return Err(RetryError::Committed);
        }
        if self.state != StreamState::RetryableFailure {
            return match self.state {
                StreamState::Completed | StreamState::Disconnected | StreamState::Failed => {
                    Err(RetryError::Terminal)
                }
                _ => Err(RetryError::NotRetryable),
            };
        }
        self.attempt = self.attempt.saturating_add(1);
        self.state = StreamState::Connecting;
        Ok(self.attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_bootstrap(stream: &mut StreamCommitment) {
        stream.connect().unwrap();
        stream.headers_received().unwrap();
        stream.validate_headers().unwrap();
        stream.begin_bootstrap().unwrap();
    }

    #[test]
    fn retry_is_available_before_commit() {
        let mut stream = StreamCommitment::new();
        to_bootstrap(&mut stream);
        stream.fail_retryable().unwrap();
        assert!(stream.can_retry());
        assert_eq!(stream.retry().unwrap(), 1);
        assert_eq!(stream.state(), StreamState::Connecting);
    }

    #[test]
    fn retry_is_impossible_after_commitment() {
        let mut stream = StreamCommitment::new();
        to_bootstrap(&mut stream);
        stream.commit().unwrap();
        stream.fail().unwrap();
        assert!(!stream.can_retry());
        assert_eq!(stream.retry(), Err(RetryError::Committed));
    }

    #[test]
    fn headers_are_a_commitment_boundary() {
        let mut stream = StreamCommitment::new();
        stream.connect().unwrap();
        stream.headers_received().unwrap();
        stream.validate_headers().unwrap();
        stream.mark_headers_sent().unwrap();
        assert!(stream.is_committed());
        assert!(!stream.can_retry());
        assert_eq!(
            stream.fail_retryable(),
            Err(CommitmentError {
                state: StreamState::Committed,
                event: StreamEvent::RetryableFailure,
            })
        );
        assert_eq!(stream.retry(), Err(RetryError::Committed));
    }

    #[tokio::test]
    async fn retry_wait_honors_cancellation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            wait_for_retry(Duration::from_secs(60), &cancellation).await,
            Err(RetryWaitError::Canceled)
        );
    }

    #[tokio::test]
    async fn zero_retry_wait_returns_without_sleeping() {
        let cancellation = CancellationToken::new();
        assert_eq!(wait_for_retry(Duration::ZERO, &cancellation).await, Ok(()));
    }

    #[test]
    fn terminal_states_reject_invalid_events() {
        let mut stream = StreamCommitment::new();
        to_bootstrap(&mut stream);
        stream.fail().unwrap();
        assert_eq!(stream.retry(), Err(RetryError::Terminal));
        assert_eq!(
            stream.transition(StreamEvent::Connect),
            Err(CommitmentError {
                state: StreamState::Failed,
                event: StreamEvent::Connect
            })
        );
    }
}
