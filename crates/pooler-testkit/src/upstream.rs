use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{CancellationTracker, FakeClock, LeakCounters, LeakGuard};

/// A header represented in insertion order so opaque tests can assert exact
/// forwarding.  Use [`crate::normalize_headers`] when order and casing are not
/// semantically significant.
pub type Header = (String, String);

/// An individual item emitted by a scripted upstream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ScriptedChunk {
    /// Raw bytes from an HTTP body or opaque transport.
    Bytes(Vec<u8>),
    /// A text chunk, useful for adapters that expose decoded body fragments.
    Text(String),
    /// One server-sent event.  `event` is absent for the default SSE event.
    Sse { event: Option<String>, data: String },
    /// A WebSocket frame.  `opcode` follows RFC 6455 values.
    Frame {
        opcode: u8,
        fin: bool,
        payload: Vec<u8>,
    },
    /// A Connect/gRPC envelope.  `flags` contains the five-bit compression and
    /// end-stream flags used by the protocol codec.
    Connect { flags: u8, payload: Vec<u8> },
    /// Advance the test clock before emitting the next chunk.  Delays are not
    /// themselves returned by [`ScriptedUpstream::execute`].
    #[serde(with = "duration_millis")]
    Delay(Duration),
    /// Fail the stream at this exact point.
    Error(ScriptedError),
    /// A protocol-level terminal marker.
    End,
}

impl ScriptedChunk {
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    #[must_use]
    pub fn sse(data: impl Into<String>) -> Self {
        Self::Sse {
            event: None,
            data: data.into(),
        }
    }

    #[must_use]
    pub fn sse_event(event: impl Into<String>, data: impl Into<String>) -> Self {
        Self::Sse {
            event: Some(event.into()),
            data: data.into(),
        }
    }

    #[must_use]
    pub fn frame(opcode: u8, fin: bool, payload: impl Into<Vec<u8>>) -> Self {
        Self::Frame {
            opcode,
            fin,
            payload: payload.into(),
        }
    }

    #[must_use]
    pub fn websocket(opcode: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self::frame(opcode, true, payload)
    }

    #[must_use]
    pub fn connect(flags: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self::Connect {
            flags,
            payload: payload.into(),
        }
    }

    #[must_use]
    pub const fn delay(duration: Duration) -> Self {
        Self::Delay(duration)
    }

    #[must_use]
    pub const fn end() -> Self {
        Self::End
    }

    #[must_use]
    pub fn error(error: ScriptedError) -> Self {
        Self::Error(error)
    }

    #[must_use]
    pub fn is_delay(&self) -> bool {
        matches!(self, Self::Delay(_))
    }
}

/// Synonyms used by transport-specific tests.
pub type UpstreamChunk = ScriptedChunk;
pub type WebSocketChunk = ScriptedChunk;
pub type ConnectChunk = ScriptedChunk;

/// Failures an upstream can inject without opening a network socket.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
pub enum ScriptedError {
    #[error("connection refused")]
    ConnectionRefused,
    #[error("TLS handshake failed")]
    TlsHandshake,
    #[error("upstream timed out")]
    Timeout,
    #[error("upstream returned HTTP status {status}")]
    Status { status: u16, body: Vec<u8> },
    #[error("upstream rate limited")]
    RateLimited {
        #[serde(with = "option_duration_millis")]
        retry_after: Option<Duration>,
    },
    #[error("invalid upstream response: {0}")]
    InvalidResponse(String),
    #[error("scripted upstream has no remaining result")]
    ScriptExhausted,
    #[error("scripted stream cancelled")]
    Cancelled,
    #[error("scripted upstream error: {0}")]
    Custom(String),
}

impl ScriptedError {
    #[must_use]
    pub const fn status(status: u16) -> Self {
        Self::Status {
            status,
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn status_with_body(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Status {
            status,
            body: body.into(),
        }
    }

    #[must_use]
    pub const fn rate_limited(retry_after: Option<Duration>) -> Self {
        Self::RateLimited { retry_after }
    }

    #[must_use]
    pub fn custom(message: impl Into<String>) -> Self {
        Self::Custom(message.into())
    }
}

/// A request captured by [`ScriptedUpstream`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptedRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl ScriptedRequest {
    #[must_use]
    pub fn new(method: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        if let Some(existing) = self
            .headers
            .iter_mut()
            .find(|(header, _)| header.eq_ignore_ascii_case(&name))
        {
            existing.1 = value.into();
        } else {
            self.headers.push((name, value.into()));
        }
    }

    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    #[must_use]
    pub fn body_as_string(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }
}

/// A response and its scripted stream.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptedResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub chunks: Vec<ScriptedChunk>,
}

impl ScriptedResponse {
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            chunks: Vec::new(),
        }
    }

    #[must_use]
    pub const fn ok() -> Self {
        Self::new(200)
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_chunk(mut self, chunk: ScriptedChunk) -> Self {
        self.chunks.push(chunk);
        self
    }

    #[must_use]
    pub fn with_chunks<I>(mut self, chunks: I) -> Self
    where
        I: IntoIterator<Item = ScriptedChunk>,
    {
        self.chunks.extend(chunks);
        self
    }

    #[must_use]
    pub fn stream(&self, clock: FakeClock) -> ScriptedStream {
        ScriptedStream::new(self.clone(), clock)
    }
}

/// One result consumed by a scripted upstream call.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
pub enum ScriptedResult {
    #[error("scripted response")]
    Response(ScriptedResponse),
    #[error(transparent)]
    Error(#[from] ScriptedError),
    #[error("scripted stream cancelled")]
    Cancelled,
}

/// Alias useful when a caller models a script as a sequence of outcomes.
pub type ScriptedOutcome = ScriptedResult;

impl ScriptedResult {
    #[must_use]
    pub const fn ok() -> Self {
        Self::Response(ScriptedResponse::ok())
    }

    #[must_use]
    pub const fn response(response: ScriptedResponse) -> Self {
        Self::Response(response)
    }

    #[must_use]
    pub const fn error(error: ScriptedError) -> Self {
        Self::Error(error)
    }
}

/// What happened during one invocation of a scripted upstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallOutcome {
    Pending,
    Response { status: u16 },
    Error(ScriptedError),
    Cancelled,
}

/// A recorded request and terminal outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedCall {
    pub request: ScriptedRequest,
    pub started_at: Duration,
    pub finished_at: Option<Duration>,
    pub outcome: CallOutcome,
}

#[derive(Debug)]
struct UpstreamState {
    script: Mutex<VecDeque<ScriptedResult>>,
    calls: Mutex<Vec<RecordedCall>>,
    cancellations: AtomicU64,
    active: AtomicU64,
}

/// A deterministic, in-process upstream.
///
/// Each call consumes one [`ScriptedResult`] in FIFO order and records the
/// request, logical start/finish time, and terminal outcome.  A result can
/// include [`ScriptedChunk::Delay`] items, which wait on the supplied
/// [`FakeClock`] and make cancellation tests deterministic.
#[derive(Clone, Debug)]
pub struct ScriptedUpstream {
    state: Arc<UpstreamState>,
    clock: FakeClock,
    counters: Option<LeakCounters>,
}

impl Default for ScriptedUpstream {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedUpstream {
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(FakeClock::new())
    }

    #[must_use]
    pub fn with_clock(clock: FakeClock) -> Self {
        Self {
            state: Arc::new(UpstreamState {
                script: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
                cancellations: AtomicU64::new(0),
                active: AtomicU64::new(0),
            }),
            clock,
            counters: None,
        }
    }

    #[must_use]
    pub fn with_script<I>(script: I) -> Self
    where
        I: IntoIterator<Item = ScriptedResult>,
    {
        let upstream = Self::new();
        upstream.extend(script);
        upstream
    }

    #[must_use]
    pub fn with_counters(mut self, counters: LeakCounters) -> Self {
        self.counters = Some(counters);
        self
    }

    #[must_use]
    pub fn clock(&self) -> FakeClock {
        self.clock.clone()
    }

    pub fn push(&self, result: ScriptedResult) {
        self.state
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(result);
    }

    pub fn extend<I>(&self, results: I)
    where
        I: IntoIterator<Item = ScriptedResult>,
    {
        self.state
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(results);
    }

    pub fn clear_script(&self) {
        self.state
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.state
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Execute the next script item without an external cancellation token.
    ///
    /// # Errors
    ///
    /// Returns the scripted error, including [`ScriptedError::ScriptExhausted`]
    /// when no result remains, or [`ScriptedError::Cancelled`] when the script
    /// itself injects cancellation.
    pub async fn execute(
        &self,
        request: ScriptedRequest,
    ) -> Result<ScriptedResponse, ScriptedError> {
        self.execute_inner(request, None, None).await
    }

    /// Execute the next item while observing a Tokio cancellation token.
    ///
    /// # Errors
    ///
    /// Returns the scripted error or [`ScriptedError::Cancelled`] when the
    /// token is cancelled while a delay is pending.
    pub async fn execute_with_cancellation(
        &self,
        request: ScriptedRequest,
        cancellation: &CancellationToken,
    ) -> Result<ScriptedResponse, ScriptedError> {
        self.execute_inner(request, Some(cancellation), None).await
    }

    /// Execute the next item and record cancellation in `tracker`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::execute_with_cancellation`].
    pub async fn execute_with_tracker(
        &self,
        request: ScriptedRequest,
        cancellation: &CancellationToken,
        tracker: &CancellationTracker,
    ) -> Result<ScriptedResponse, ScriptedError> {
        self.execute_inner(request, Some(cancellation), Some(tracker))
            .await
    }

    async fn execute_inner(
        &self,
        request: ScriptedRequest,
        cancellation: Option<&CancellationToken>,
        tracker: Option<&CancellationTracker>,
    ) -> Result<ScriptedResponse, ScriptedError> {
        let script = self
            .state
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or(ScriptedResult::Error(ScriptedError::ScriptExhausted));
        let call_index = {
            let mut calls = self
                .state
                .calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let index = calls.len();
            calls.push(RecordedCall {
                request,
                started_at: self.clock.now(),
                finished_at: None,
                outcome: CallOutcome::Pending,
            });
            index
        };
        self.state.active.fetch_add(1, Ordering::AcqRel);
        let mut guard = CallGuard {
            state: Arc::clone(&self.state),
            index: call_index,
            clock: self.clock.clone(),
            tracker: tracker.cloned(),
            counter: self.counters.as_ref().map(LeakCounters::task),
            finished: false,
        };

        let result = if cancellation.is_some_and(CancellationToken::is_cancelled) {
            Err(ScriptedError::Cancelled)
        } else {
            self.play(script, cancellation).await
        };
        guard.finish(&result);
        result
    }

    async fn play(
        &self,
        script: ScriptedResult,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ScriptedResponse, ScriptedError> {
        let mut response = match script {
            ScriptedResult::Response(response) => response,
            ScriptedResult::Error(error) => return Err(error),
            ScriptedResult::Cancelled => return Err(ScriptedError::Cancelled),
        };
        for chunk in &response.chunks {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(ScriptedError::Cancelled);
            }
            match chunk {
                ScriptedChunk::Delay(duration) => {
                    if let Some(token) = cancellation {
                        tokio::select! {
                            () = self.clock.wait_until(self.clock.now().saturating_add(*duration)) => {}
                            () = token.cancelled() => return Err(ScriptedError::Cancelled),
                        }
                    } else {
                        self.clock
                            .wait_until(self.clock.now().saturating_add(*duration))
                            .await;
                    }
                }
                ScriptedChunk::Error(error) => return Err(error.clone()),
                ScriptedChunk::End
                | ScriptedChunk::Bytes(_)
                | ScriptedChunk::Text(_)
                | ScriptedChunk::Sse { .. }
                | ScriptedChunk::Frame { .. }
                | ScriptedChunk::Connect { .. } => {}
            }
        }
        // Keep the delay markers in the returned response: callers comparing a
        // script can still inspect the exact injection, while stream consumers
        // receive only the actual data through `ScriptedStream::next_chunk`.
        response.chunks.shrink_to_fit();
        Ok(response)
    }

    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.state
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn requests(&self) -> Vec<ScriptedRequest> {
        self.calls().into_iter().map(|call| call.request).collect()
    }

    #[must_use]
    pub fn active_calls(&self) -> u64 {
        self.state.active.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn cancellation_count(&self) -> u64 {
        self.state.cancellations.load(Ordering::Acquire)
    }

    fn mark_cancelled(state: &UpstreamState, index: usize, clock: &FakeClock) {
        state.cancellations.fetch_add(1, Ordering::AcqRel);
        let mut calls = state.calls.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(call) = calls.get_mut(index) {
            call.finished_at = Some(clock.now());
            call.outcome = CallOutcome::Cancelled;
        }
    }
}

struct CallGuard {
    state: Arc<UpstreamState>,
    index: usize,
    clock: FakeClock,
    tracker: Option<CancellationTracker>,
    counter: Option<LeakGuard>,
    finished: bool,
}

impl CallGuard {
    fn finish(&mut self, result: &Result<ScriptedResponse, ScriptedError>) {
        if self.finished {
            return;
        }
        if matches!(result, Err(ScriptedError::Cancelled)) {
            ScriptedUpstream::mark_cancelled(&self.state, self.index, &self.clock);
            if let Some(tracker) = &self.tracker {
                tracker.record_cancellation();
            }
        } else {
            let outcome = match result {
                Ok(response) => CallOutcome::Response {
                    status: response.status,
                },
                Err(error) => CallOutcome::Error(error.clone()),
            };
            let mut calls = self
                .state
                .calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(call) = calls.get_mut(self.index) {
                call.finished_at = Some(self.clock.now());
                call.outcome = outcome;
            }
        }
        self.state.active.fetch_sub(1, Ordering::AcqRel);
        self.finished = true;
        let _ = self.counter.take();
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.finished {
            ScriptedUpstream::mark_cancelled(&self.state, self.index, &self.clock);
            if let Some(tracker) = &self.tracker {
                tracker.record_cancellation();
            }
            self.state.active.fetch_sub(1, Ordering::AcqRel);
            self.finished = true;
        }
    }
}

/// A stream view over a scripted response.  Delays are consumed internally;
/// callers receive data, protocol markers, and injected errors in order.
#[derive(Clone, Debug)]
pub struct ScriptedStream {
    chunks: VecDeque<ScriptedChunk>,
    clock: FakeClock,
    cancellation: Option<CancellationToken>,
    tracker: Option<CancellationTracker>,
    cancelled: bool,
}

impl ScriptedStream {
    #[must_use]
    pub fn new(response: ScriptedResponse, clock: FakeClock) -> Self {
        Self {
            chunks: response.chunks.into(),
            clock,
            cancellation: None,
            tracker: None,
            cancelled: false,
        }
    }

    #[must_use]
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = Some(token);
        self
    }

    #[must_use]
    pub fn with_tracker(mut self, tracker: CancellationTracker) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// Return the next data item, waiting on any preceding delay marker.
    pub async fn next_chunk(&mut self) -> Option<Result<ScriptedChunk, ScriptedError>> {
        loop {
            let chunk = self.chunks.pop_front()?;
            if self.cancelled {
                return Some(Err(ScriptedError::Cancelled));
            }
            if self
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                self.cancelled = true;
                if let Some(tracker) = &self.tracker {
                    tracker.record_cancellation();
                }
                return Some(Err(ScriptedError::Cancelled));
            }
            match chunk {
                ScriptedChunk::Delay(duration) => {
                    if let Some(token) = &self.cancellation {
                        tokio::select! {
                            () = self.clock.wait_until(self.clock.now().saturating_add(duration)) => {}
                            () = token.cancelled() => {
                                self.cancelled = true;
                                if let Some(tracker) = &self.tracker {
                                    tracker.record_cancellation();
                                }
                                return Some(Err(ScriptedError::Cancelled));
                            }
                        }
                    } else {
                        self.clock
                            .wait_until(self.clock.now().saturating_add(duration))
                            .await;
                    }
                }
                ScriptedChunk::Error(error) => return Some(Err(error)),
                ScriptedChunk::End => return Some(Ok(ScriptedChunk::End)),
                data => return Some(Ok(data)),
            }
        }
    }

    /// Alias for [`Self::next_chunk`].
    pub async fn next_item(&mut self) -> Option<Result<ScriptedChunk, ScriptedError>> {
        self.next_chunk().await
    }
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis().try_into().unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

mod option_duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            None => serializer.serialize_none(),
            Some(duration) => {
                serializer.serialize_some(&duration.as_millis().try_into().unwrap_or(u64::MAX))
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<u64>::deserialize(deserializer).map(|value| value.map(Duration::from_millis))
    }
}
