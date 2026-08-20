//! Bounded OpenAI Responses WebSocket transport for semantic HTTP routes.

use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{header, HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use pooler_core::RouteLimits;
use pooler_protocol::{
    LossPolicy, OpenAiResponsesEventDecoder, OpenAiResponsesEventEncoder, StreamEvent,
};
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::{net::TcpStream, sync::mpsc, sync::Mutex, time};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        protocol::{Message, WebSocketConfig},
        Error as TungsteniteError,
    },
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

use crate::{BoxError, RuntimeResources, SseEncoder, SseEvent, SseLimits};

pub(crate) const RESPONSES_WEBSOCKET_BETA: &str = "responses_websockets=2026-02-06";
const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(55 * 60);
const CLOSE_TIMEOUT: Duration = Duration::from_millis(100);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Authentication generation included in a reusable connection's identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CredentialGeneration {
    /// Generation from the persisted OAuth token store.
    Native(u64),
    /// Digest of materialized static authentication plus configuration generation.
    Materialized([u8; 32]),
}

/// Exact isolation boundary for one reusable Responses WebSocket.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConnectionIdentity {
    profile: Arc<str>,
    account: Arc<str>,
    endpoint: Arc<str>,
    generation: CredentialGeneration,
    session: Option<Arc<str>>,
}

impl ConnectionIdentity {
    pub(crate) fn new(
        profile: impl Into<Arc<str>>,
        account: impl Into<Arc<str>>,
        endpoint: impl Into<Arc<str>>,
        generation: CredentialGeneration,
        session: Option<Arc<str>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            account: account.into(),
            endpoint: endpoint.into(),
            generation,
            session,
        }
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn same_credential_scope(&self, other: &Self) -> bool {
        self.profile == other.profile
            && self.account == other.account
            && self.endpoint == other.endpoint
    }

    fn cacheable(&self) -> bool {
        self.session.is_some()
    }
}

#[derive(Clone, Debug)]
struct Continuation {
    request: Value,
    response_id: String,
    response_items: Vec<Value>,
}

#[derive(Debug)]
struct CachedConnection {
    socket: Socket,
    created_at: Instant,
    last_used_at: Instant,
    continuation: Option<Continuation>,
}

#[derive(Debug, Default)]
struct PoolState {
    connections: BTreeMap<ConnectionIdentity, CachedConnection>,
}

/// Process-local pool of serial, reusable Responses connections.
#[derive(Clone, Debug)]
pub(crate) struct OpenAiResponsesWebSocketPool {
    state: Arc<Mutex<PoolState>>,
    idle_ttl: Duration,
    max_age: Duration,
}

impl Default for OpenAiResponsesWebSocketPool {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(PoolState::default())),
            idle_ttl: DEFAULT_IDLE_TTL,
            max_age: DEFAULT_MAX_AGE,
        }
    }
}

/// Inputs for one semantic Responses WebSocket attempt.
pub(crate) struct OpenAiResponsesWebSocketAttempt {
    pub identity: ConnectionIdentity,
    pub headers: HeaderMap,
    pub request_body: Bytes,
    pub limits: RouteLimits,
    pub loss_policy: LossPolicy,
    pub connect_deadline: Instant,
    pub first_event_deadline: Instant,
    pub request_deadline: Instant,
    pub idle_timeout: Duration,
    pub cancellation: CancellationToken,
    pub resources: RuntimeResources,
}

/// Marker carried in an internal response extension after semantic conversion.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SemanticWebSocketResponse;

/// Body fed by a supervised WebSocket reader.
pub(crate) struct OpenAiResponsesWebSocketBody {
    receiver: mpsc::Receiver<Result<Bytes, OpenAiResponsesWebSocketError>>,
    cancellation: CancellationToken,
    ended: bool,
}

impl std::fmt::Debug for OpenAiResponsesWebSocketBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenAiResponsesWebSocketBody")
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl Body for OpenAiResponsesWebSocketBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => {
                self.ended = true;
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for OpenAiResponsesWebSocketBody {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Sanitized failures from the Responses WebSocket boundary.
#[derive(Debug, Error)]
pub(crate) enum OpenAiResponsesWebSocketError {
    #[error("invalid OpenAI Responses WebSocket request")]
    InvalidRequest,
    #[error("OpenAI Responses WebSocket handshake failed with status {0}")]
    HandshakeStatus(u16),
    #[error("OpenAI Responses WebSocket connection failed")]
    Connect,
    #[error("OpenAI Responses WebSocket operation timed out")]
    Timeout,
    #[error("OpenAI Responses WebSocket operation was cancelled")]
    Cancelled,
    #[error("OpenAI Responses WebSocket message exceeded configured bounds")]
    MessageTooLarge,
    #[error("OpenAI Responses WebSocket closed before a terminal response")]
    Incomplete,
    #[error("invalid OpenAI Responses WebSocket event")]
    Protocol,
}

impl OpenAiResponsesWebSocketError {
    pub(crate) const fn handshake_status(&self) -> Option<u16> {
        match self {
            Self::HandshakeStatus(status) => Some(*status),
            _ => None,
        }
    }
}

struct ActiveConnection {
    socket: Socket,
    created_at: Instant,
    continuation: Option<Continuation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Terminal {
    None,
    Completed,
    Other,
}

struct EncodedProviderEvent {
    bytes: Bytes,
    terminal: Terminal,
    response_id: Option<String>,
}

struct TurnCodec {
    decoder: OpenAiResponsesEventDecoder,
    encoder: OpenAiResponsesEventEncoder,
    loss_policy: LossPolicy,
    sse: SseEncoder,
    response_items: Vec<Value>,
}

impl TurnCodec {
    fn new(limits: &RouteLimits, loss_policy: LossPolicy) -> Self {
        Self {
            decoder: OpenAiResponsesEventDecoder::new(),
            encoder: OpenAiResponsesEventEncoder::new(),
            loss_policy,
            sse: SseEncoder::with_limits(SseLimits::new(
                bounded_usize(limits.max_frame_bytes),
                bounded_usize(limits.max_event_bytes),
            )),
            response_items: Vec::new(),
        }
    }

    fn encode(
        &mut self,
        mut value: Value,
    ) -> Result<EncodedProviderEvent, OpenAiResponsesWebSocketError> {
        let object = value
            .as_object_mut()
            .ok_or(OpenAiResponsesWebSocketError::Protocol)?;
        let event_type = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or(OpenAiResponsesWebSocketError::Protocol)?
            .to_owned();
        if event_type == "response.done" {
            object.insert(
                "type".to_owned(),
                Value::String("response.completed".to_owned()),
            );
        }
        let normalized_type = object
            .get("type")
            .and_then(Value::as_str)
            .expect("event type remains a string");
        let terminal = match normalized_type {
            "response.completed" => Terminal::Completed,
            "response.incomplete" | "response.failed" | "error" => Terminal::Other,
            _ => Terminal::None,
        };
        let response_id = object
            .get("response")
            .and_then(Value::as_object)
            .and_then(|response| response.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let raw =
            serde_json::to_vec(&value).map_err(|_| OpenAiResponsesWebSocketError::Protocol)?;
        let semantic = self
            .decoder
            .decode_data(&raw)
            .map_err(|_| OpenAiResponsesWebSocketError::Protocol)?;
        let mut output = Vec::new();
        for event in semantic {
            self.encode_semantic_event(&event, &mut output)?;
        }
        if terminal != Terminal::None {
            self.decoder
                .finish()
                .map_err(|_| OpenAiResponsesWebSocketError::Protocol)?;
        }
        Ok(EncodedProviderEvent {
            bytes: Bytes::from(output),
            terminal,
            response_id,
        })
    }

    fn encode_semantic_event(
        &mut self,
        event: &StreamEvent,
        output: &mut Vec<u8>,
    ) -> Result<(), OpenAiResponsesWebSocketError> {
        let encoded = self
            .encoder
            .encode_event(event, self.loss_policy)
            .map_err(|_| OpenAiResponsesWebSocketError::Protocol)?;
        for encoded in encoded {
            if let Ok(value) = serde_json::from_slice::<Value>(&encoded.body) {
                if value.get("type").and_then(Value::as_str) == Some("response.output_item.done") {
                    if let Some(item) = value.get("item") {
                        self.response_items.push(item.clone());
                    }
                }
            }
            let data = String::from_utf8(encoded.body)
                .map_err(|_| OpenAiResponsesWebSocketError::Protocol)?;
            let event = SseEvent::new(data).with_event(encoded.event);
            let bytes = self
                .sse
                .encode(&event)
                .map_err(|_| OpenAiResponsesWebSocketError::MessageTooLarge)?;
            output.extend_from_slice(&bytes);
        }
        Ok(())
    }
}

impl OpenAiResponsesWebSocketPool {
    pub(crate) async fn execute(
        &self,
        attempt: OpenAiResponsesWebSocketAttempt,
    ) -> Result<OpenAiResponsesWebSocketBody, OpenAiResponsesWebSocketError> {
        let OpenAiResponsesWebSocketAttempt {
            identity,
            headers,
            request_body,
            limits,
            loss_policy,
            connect_deadline,
            first_event_deadline,
            request_deadline,
            idle_timeout,
            cancellation,
            resources,
        } = attempt;
        let mut connection = self
            .acquire(
                &identity,
                &headers,
                &limits,
                connect_deadline,
                &cancellation,
            )
            .await?;
        let full_request = prepare_full_request(&request_body)?;
        let request = request_for_connection(&full_request, connection.continuation.take());
        let request = serde_json::to_string(&request)
            .map_err(|_| OpenAiResponsesWebSocketError::InvalidRequest)?;
        send_request(
            &mut connection.socket,
            request,
            request_deadline,
            &cancellation,
        )
        .await?;

        let first = read_provider_event(
            &mut connection.socket,
            first_event_deadline.min(request_deadline),
            idle_timeout,
            &cancellation,
            &CancellationToken::new(),
        )
        .await?;
        limits
            .check_bootstrap(
                u64::try_from(serde_json::to_vec(&first).map_or(usize::MAX, |bytes| bytes.len()))
                    .unwrap_or(u64::MAX),
                1,
            )
            .map_err(|_| OpenAiResponsesWebSocketError::MessageTooLarge)?;

        let body_cancellation = CancellationToken::new();
        let (sender, receiver) = mpsc::channel(1);
        let body = OpenAiResponsesWebSocketBody {
            receiver,
            cancellation: body_cancellation.clone(),
            ended: false,
        };
        let mut codec = TurnCodec::new(&limits, loss_policy);
        let first = match codec.encode(first) {
            Ok(event) => event,
            Err(error) => {
                let _ = sender.try_send(Err(error));
                close_socket(connection.socket, "protocol_error").await;
                return Ok(body);
            }
        };

        if first.terminal != Terminal::None {
            if !first.bytes.is_empty() {
                let _ = sender.try_send(Ok(first.bytes));
            }
            drop(sender);
            let continuation = continuation_after_terminal(
                first.terminal,
                first.response_id,
                full_request,
                codec.response_items,
            );
            let keep = first.terminal != Terminal::Other;
            self.release(identity, connection, continuation, keep).await;
            return Ok(body);
        }

        let pool = self.clone();
        let task_identity = identity;
        let task = resources.task();
        tokio::spawn(async move {
            let _task = task;
            if !first.bytes.is_empty() && sender.send(Ok(first.bytes)).await.is_err() {
                close_socket(connection.socket, "downstream_closed").await;
                return;
            }
            loop {
                let value = match read_provider_event(
                    &mut connection.socket,
                    request_deadline,
                    idle_timeout,
                    &cancellation,
                    &body_cancellation,
                )
                .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        close_socket(connection.socket, "stream_error").await;
                        return;
                    }
                };
                let event = match codec.encode(value) {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        close_socket(connection.socket, "protocol_error").await;
                        return;
                    }
                };
                if !event.bytes.is_empty() && sender.send(Ok(event.bytes)).await.is_err() {
                    close_socket(connection.socket, "downstream_closed").await;
                    return;
                }
                if event.terminal != Terminal::None {
                    let continuation = continuation_after_terminal(
                        event.terminal,
                        event.response_id,
                        full_request,
                        codec.response_items,
                    );
                    let keep = event.terminal != Terminal::Other;
                    pool.release(task_identity, connection, continuation, keep)
                        .await;
                    return;
                }
            }
        });
        Ok(body)
    }

    async fn acquire(
        &self,
        identity: &ConnectionIdentity,
        headers: &HeaderMap,
        limits: &RouteLimits,
        connect_deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<ActiveConnection, OpenAiResponsesWebSocketError> {
        let now = Instant::now();
        let (cached, invalidated) = {
            let mut state = self.state.lock().await;
            let invalidated_keys = state
                .connections
                .keys()
                .filter(|candidate| {
                    candidate.same_credential_scope(identity)
                        && candidate.generation != identity.generation
                })
                .cloned()
                .collect::<Vec<_>>();
            let invalidated = invalidated_keys
                .into_iter()
                .filter_map(|key| state.connections.remove(&key))
                .collect::<Vec<_>>();
            let cached = identity
                .cacheable()
                .then(|| state.connections.remove(identity))
                .flatten();
            (cached, invalidated)
        };
        drop(invalidated);
        if let Some(cached) = cached {
            if within_reuse_bounds(
                cached.created_at,
                cached.last_used_at,
                now,
                self.idle_ttl,
                self.max_age,
            ) {
                return Ok(ActiveConnection {
                    socket: cached.socket,
                    created_at: cached.created_at,
                    continuation: cached.continuation,
                });
            }
            drop(cached);
        }
        let socket = connect(
            identity.endpoint(),
            headers,
            limits,
            connect_deadline,
            cancellation,
        )
        .await?;
        Ok(ActiveConnection {
            socket,
            created_at: now,
            continuation: None,
        })
    }

    async fn release(
        &self,
        identity: ConnectionIdentity,
        connection: ActiveConnection,
        continuation: Option<Continuation>,
        keep: bool,
    ) {
        let now = Instant::now();
        if !identity.cacheable()
            || !keep
            || now.saturating_duration_since(connection.created_at) >= self.max_age
        {
            close_socket(connection.socket, "turn_done").await;
            return;
        }
        let cached = CachedConnection {
            socket: connection.socket,
            created_at: connection.created_at,
            last_used_at: now,
            continuation,
        };
        let replaced = self.state.lock().await.connections.insert(identity, cached);
        if let Some(replaced) = replaced {
            close_socket(replaced.socket, "duplicate_idle_connection").await;
        }
    }
}

fn prepare_full_request(input: &[u8]) -> Result<Value, OpenAiResponsesWebSocketError> {
    let mut value: Value =
        serde_json::from_slice(input).map_err(|_| OpenAiResponsesWebSocketError::InvalidRequest)?;
    let object = value
        .as_object_mut()
        .ok_or(OpenAiResponsesWebSocketError::InvalidRequest)?;
    object.remove("type");
    object.insert("store".to_owned(), Value::Bool(false));
    object.insert("stream".to_owned(), Value::Bool(true));
    Ok(value)
}

fn request_for_connection(full: &Value, continuation: Option<Continuation>) -> Value {
    let mut request = full.clone();
    if let Some(continuation) = continuation {
        if let Some(delta) = continuation_delta(full, &continuation) {
            if let Some(object) = request.as_object_mut() {
                object.insert(
                    "previous_response_id".to_owned(),
                    Value::String(continuation.response_id),
                );
                object.insert("input".to_owned(), Value::Array(delta));
            }
        }
    }
    if let Some(object) = request.as_object_mut() {
        object.insert(
            "type".to_owned(),
            Value::String("response.create".to_owned()),
        );
    }
    request
}

fn continuation_delta(full: &Value, continuation: &Continuation) -> Option<Vec<Value>> {
    if request_parameters(full) != request_parameters(&continuation.request) {
        return None;
    }
    let current = full.get("input")?.as_array()?;
    let previous = continuation.request.get("input")?.as_array()?;
    let baseline_len = previous
        .len()
        .saturating_add(continuation.response_items.len());
    if current.len() < baseline_len {
        return None;
    }
    if current[..previous.len()] != previous[..] {
        return None;
    }
    if current[previous.len()..baseline_len] != continuation.response_items[..] {
        return None;
    }
    Some(current[baseline_len..].to_vec())
}

fn request_parameters(value: &Value) -> Option<Map<String, Value>> {
    let mut object = value.as_object()?.clone();
    object.remove("input");
    object.remove("previous_response_id");
    object.remove("type");
    Some(object)
}

fn continuation_after_terminal(
    terminal: Terminal,
    response_id: Option<String>,
    request: Value,
    response_items: Vec<Value>,
) -> Option<Continuation> {
    (terminal == Terminal::Completed)
        .then_some(response_id)
        .flatten()
        .map(|response_id| Continuation {
            request,
            response_id,
            response_items,
        })
}

async fn connect(
    endpoint: &str,
    headers: &HeaderMap,
    limits: &RouteLimits,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Socket, OpenAiResponsesWebSocketError> {
    let mut request = endpoint
        .into_client_request()
        .map_err(|_| OpenAiResponsesWebSocketError::InvalidRequest)?;
    for (name, value) in headers {
        if is_handshake_header(name.as_str()) {
            continue;
        }
        request.headers_mut().append(name, value.clone());
    }
    request.headers_mut().insert(
        "openai-beta",
        HeaderValue::from_static(RESPONSES_WEBSOCKET_BETA),
    );
    let config = WebSocketConfig::default()
        .max_frame_size(Some(bounded_usize(limits.max_frame_bytes)))
        .max_message_size(Some(bounded_usize(
            limits.max_event_bytes.min(limits.max_response_body_bytes),
        )));
    let result = tokio::select! {
        result = time::timeout_at(
            time::Instant::from_std(deadline),
            connect_async_with_config(request, Some(config), false),
        ) => result.map_err(|_| OpenAiResponsesWebSocketError::Timeout)?,
        () = cancellation.cancelled() => return Err(OpenAiResponsesWebSocketError::Cancelled),
    };
    result.map(|(socket, _)| socket).map_err(map_connect_error)
}

fn map_connect_error(error: TungsteniteError) -> OpenAiResponsesWebSocketError {
    match error {
        TungsteniteError::Http(response) => {
            OpenAiResponsesWebSocketError::HandshakeStatus(response.status().as_u16())
        }
        TungsteniteError::Capacity(_) => OpenAiResponsesWebSocketError::MessageTooLarge,
        _ => OpenAiResponsesWebSocketError::Connect,
    }
}

async fn send_request(
    socket: &mut Socket,
    request: String,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), OpenAiResponsesWebSocketError> {
    tokio::select! {
        result = time::timeout_at(
            time::Instant::from_std(deadline),
            socket.send(Message::Text(request.into())),
        ) => result
            .map_err(|_| OpenAiResponsesWebSocketError::Timeout)?
            .map_err(|_| OpenAiResponsesWebSocketError::Connect),
        () = cancellation.cancelled() => Err(OpenAiResponsesWebSocketError::Cancelled),
    }
}

async fn read_provider_event(
    socket: &mut Socket,
    hard_deadline: Instant,
    idle_timeout: Duration,
    cancellation: &CancellationToken,
    body_cancellation: &CancellationToken,
) -> Result<Value, OpenAiResponsesWebSocketError> {
    loop {
        let idle_deadline = Instant::now()
            .checked_add(idle_timeout)
            .unwrap_or(hard_deadline)
            .min(hard_deadline);
        let message = tokio::select! {
            result = time::timeout_at(time::Instant::from_std(idle_deadline), socket.next()) => {
                result.map_err(|_| OpenAiResponsesWebSocketError::Timeout)?
            }
            () = cancellation.cancelled() => return Err(OpenAiResponsesWebSocketError::Cancelled),
            () = body_cancellation.cancelled() => return Err(OpenAiResponsesWebSocketError::Cancelled),
        };
        let message = message
            .ok_or(OpenAiResponsesWebSocketError::Incomplete)?
            .map_err(|error| match error {
                TungsteniteError::Capacity(_) => OpenAiResponsesWebSocketError::MessageTooLarge,
                _ => OpenAiResponsesWebSocketError::Incomplete,
            })?;
        let bytes = match message {
            Message::Text(text) => text.as_bytes().to_vec(),
            Message::Binary(bytes) => bytes.to_vec(),
            Message::Ping(_) | Message::Pong(_) => {
                socket
                    .flush()
                    .await
                    .map_err(|_| OpenAiResponsesWebSocketError::Incomplete)?;
                continue;
            }
            Message::Close(_) => return Err(OpenAiResponsesWebSocketError::Incomplete),
            Message::Frame(_) => continue,
        };
        return serde_json::from_slice(&bytes).map_err(|_| OpenAiResponsesWebSocketError::Protocol);
    }
}

async fn close_socket(mut socket: Socket, reason: &'static str) {
    let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
        reason: reason.into(),
    };
    let _ = time::timeout(CLOSE_TIMEOUT, socket.close(Some(frame))).await;
}

fn is_handshake_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "upgrade"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
            | "content-length"
            | "content-type"
            | "accept"
    )
}

pub(crate) fn materialized_generation(
    configuration_generation: u64,
    headers: &HeaderMap,
) -> CredentialGeneration {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(&configuration_generation.to_be_bytes());
    for name in [
        header::AUTHORIZATION.as_str(),
        "x-api-key",
        "x-goog-api-key",
    ] {
        context.update(name.as_bytes());
        for value in headers.get_all(name) {
            context.update(value.as_bytes());
        }
    }
    let digest = context.finish();
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    CredentialGeneration::Materialized(fingerprint)
}

fn bounded_usize(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

fn within_reuse_bounds(
    created_at: Instant,
    last_used_at: Instant,
    now: Instant,
    idle_ttl: Duration,
    max_age: Duration,
) -> bool {
    now.saturating_duration_since(last_used_at) < idle_ttl
        && now.saturating_duration_since(created_at) < max_age
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use futures_util::{SinkExt, StreamExt};
    use http_body_util::BodyExt;
    use serde_json::json;
    use tokio::{net::TcpListener, task::JoinHandle};
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{handshake::server::Request, Message},
    };

    use super::*;

    #[test]
    fn cache_identity_isolates_accounts_profiles_endpoints_and_rotations() {
        let base = ConnectionIdentity::new(
            "openai_api_key",
            "account-a",
            "ws://api.example/v1/responses",
            CredentialGeneration::Native(1),
            Some(Arc::from("session-a")),
        );
        let rotated = ConnectionIdentity::new(
            "openai_api_key",
            "account-a",
            "ws://api.example/v1/responses",
            CredentialGeneration::Native(2),
            Some(Arc::from("session-a")),
        );
        let other_account = ConnectionIdentity::new(
            "openai_api_key",
            "account-b",
            "ws://api.example/v1/responses",
            CredentialGeneration::Native(1),
            Some(Arc::from("session-a")),
        );
        let other_profile = ConnectionIdentity::new(
            "codex_subscription",
            "account-a",
            "ws://api.example/v1/responses",
            CredentialGeneration::Native(1),
            Some(Arc::from("session-a")),
        );
        let other_endpoint = ConnectionIdentity::new(
            "openai_api_key",
            "account-a",
            "ws://other.example/v1/responses",
            CredentialGeneration::Native(1),
            Some(Arc::from("session-a")),
        );
        let other_session = ConnectionIdentity::new(
            "openai_api_key",
            "account-a",
            "ws://api.example/v1/responses",
            CredentialGeneration::Native(1),
            Some(Arc::from("session-b")),
        );

        assert!(base.same_credential_scope(&rotated));
        assert_ne!(base, rotated);
        assert!(!base.same_credential_scope(&other_account));
        assert!(!base.same_credential_scope(&other_profile));
        assert!(!base.same_credential_scope(&other_endpoint));
        assert!(base.same_credential_scope(&other_session));
        assert_ne!(base, other_session);
    }

    #[test]
    fn cached_connections_obey_idle_and_hard_age_bounds() {
        let now = Instant::now();
        assert!(within_reuse_bounds(
            now - Duration::from_secs(10),
            now - Duration::from_secs(2),
            now,
            Duration::from_secs(5),
            Duration::from_secs(20),
        ));
        assert!(!within_reuse_bounds(
            now - Duration::from_secs(10),
            now - Duration::from_secs(5),
            now,
            Duration::from_secs(5),
            Duration::from_secs(20),
        ));
        assert!(!within_reuse_bounds(
            now - Duration::from_secs(20),
            now - Duration::from_secs(1),
            now,
            Duration::from_secs(5),
            Duration::from_secs(20),
        ));
    }

    #[test]
    fn continuation_requires_matching_parameters_and_exact_request_response_prefix() {
        let request = json!({
            "model":"gpt-test",
            "stream":true,
            "store":false,
            "reasoning":{"effort":"high"},
            "input":[{"role":"user","content":"first"}]
        });
        let response_item = json!({
            "id":"msg_1",
            "type":"message",
            "role":"assistant",
            "status":"completed",
            "content":[{"type":"output_text","text":"answer","annotations":[]}]
        });
        let continuation = Continuation {
            request: request.clone(),
            response_id: "resp_1".to_owned(),
            response_items: vec![response_item.clone()],
        };
        let matching = json!({
            "model":"gpt-test",
            "stream":true,
            "store":false,
            "reasoning":{"effort":"high"},
            "input":[
                {"role":"user","content":"first"},
                response_item,
                {"role":"user","content":"second"}
            ]
        });
        assert_eq!(
            continuation_delta(&matching, &continuation),
            Some(vec![json!({"role":"user","content":"second"})])
        );

        let mut changed = matching.clone();
        changed["reasoning"]["effort"] = Value::String("low".to_owned());
        assert_eq!(continuation_delta(&changed, &continuation), None);
        let mut wrong_prefix = matching;
        wrong_prefix["input"][0]["content"] = Value::String("different".to_owned());
        assert_eq!(continuation_delta(&wrong_prefix, &continuation), None);
    }

    #[test]
    fn semantic_codec_preserves_tools_reasoning_and_usage() {
        let mut codec = TurnCodec::new(&RouteLimits::default(), LossPolicy::Reject);
        let events = [
            json!({"type":"response.created","response":{"id":"resp_1","model":"gpt-test","status":"in_progress","output":[]}}),
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"rs_1","type":"reasoning","status":"in_progress","summary":[]}}),
            json!({"type":"response.reasoning_summary_part.added","item_id":"rs_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":""}}),
            json!({"type":"response.reasoning_summary_text.delta","item_id":"rs_1","output_index":0,"summary_index":0,"delta":"plan"}),
            json!({"type":"response.output_item.done","output_index":0,"item":{"id":"rs_1","type":"reasoning","status":"completed","summary":[{"type":"summary_text","text":"plan"}],"encrypted_content":"encrypted"}}),
            json!({"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read","arguments":"","status":"in_progress"}}),
            json!({"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"{\"path\":\"a\"}"}),
            json!({"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":1,"arguments":"{\"path\":\"a\"}"}),
            json!({"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read","arguments":"{\"path\":\"a\"}","status":"completed"}}),
            json!({"type":"response.completed","response":{"id":"resp_1","model":"gpt-test","status":"completed","usage":{"input_tokens":12,"input_tokens_details":{"cached_tokens":3},"output_tokens":7,"output_tokens_details":{"reasoning_tokens":4},"total_tokens":19}}}),
        ];
        let mut wire = Vec::new();
        for event in events {
            wire.extend_from_slice(&codec.encode(event).expect("event converts").bytes);
        }
        let wire = String::from_utf8(wire).expect("encoded SSE is UTF-8");
        assert!(wire.contains("response.reasoning_summary_text.delta"));
        assert!(wire.contains("encrypted"));
        assert!(wire.contains("response.function_call_arguments.delta"));
        assert!(wire.contains("call_1"));
        assert!(wire.contains("\"input_tokens\":12"));
        assert!(wire.contains("\"reasoning_tokens\":4"));
    }

    #[tokio::test]
    async fn provider_event_is_the_retry_commitment_boundary() {
        let (pre_url, pre_headers, pre_task) = spawn_test_server(false).await;
        let pre = attempt(&pre_url, pre_headers);
        let error = OpenAiResponsesWebSocketPool::default()
            .execute(pre)
            .await
            .expect_err("close before an event is a pre-commit error");
        assert!(matches!(error, OpenAiResponsesWebSocketError::Incomplete));
        pre_task.await.expect("pre-commit server joins");

        let (post_url, post_headers, post_task) = spawn_test_server(true).await;
        let post = attempt(&post_url, post_headers.clone());
        let body = OpenAiResponsesWebSocketPool::default()
            .execute(post)
            .await
            .expect("first provider event commits the response");
        assert!(
            body.collect().await.is_err(),
            "post-commit close is a body error"
        );
        post_task.await.expect("post-commit server joins");
        assert!(post_headers.load(Ordering::Acquire));
    }

    fn attempt(
        endpoint: &str,
        observed_headers: Arc<AtomicBool>,
    ) -> OpenAiResponsesWebSocketAttempt {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-key"),
        );
        let now = Instant::now();
        let _ = observed_headers;
        OpenAiResponsesWebSocketAttempt {
            identity: ConnectionIdentity::new(
                "openai_api_key",
                "account-a",
                endpoint,
                CredentialGeneration::Native(1),
                Some(Arc::from("session-a")),
            ),
            headers,
            request_body: Bytes::from_static(
                br#"{"model":"gpt-test","input":[{"role":"user","content":"hello"}],"store":true,"stream":true}"#,
            ),
            limits: RouteLimits::default(),
            loss_policy: LossPolicy::Reject,
            connect_deadline: now + Duration::from_secs(2),
            first_event_deadline: now + Duration::from_secs(2),
            request_deadline: now + Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            cancellation: CancellationToken::new(),
            resources: RuntimeResources::new(),
        }
    }

    async fn spawn_test_server(
        send_first_event: bool,
    ) -> (String, Arc<AtomicBool>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test server binds");
        let address = listener.local_addr().expect("test address");
        let observed = Arc::new(AtomicBool::new(false));
        let task_observed = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("test server accepts");
            let mut socket = accept_hdr_async(stream, move |request: &Request, response| {
                let authorized = request.headers().get(header::AUTHORIZATION)
                    == Some(&HeaderValue::from_static("Bearer test-key"));
                let beta = request.headers().get("openai-beta")
                    == Some(&HeaderValue::from_static(RESPONSES_WEBSOCKET_BETA));
                task_observed.store(authorized && beta, Ordering::Release);
                Ok(response)
            })
            .await
            .expect("test handshake");
            let request = socket
                .next()
                .await
                .expect("response.create arrives")
                .expect("response.create is valid");
            let request = request.into_text().expect("request is text");
            let request: Value = serde_json::from_str(&request).expect("request is JSON");
            assert_eq!(request["type"], "response.create");
            assert_eq!(request["store"], false);
            if send_first_event {
                socket
                    .send(Message::Text(
                        json!({"type":"response.created","response":{"id":"resp_1","model":"gpt-test","status":"in_progress","output":[]}})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .expect("first provider event");
            }
            let _ = socket.close(None).await;
        });
        (format!("ws://{address}/v1/responses"), observed, task)
    }
}
