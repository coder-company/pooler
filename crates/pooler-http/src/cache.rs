//! Bounded cache primitives for fully buffered HTTP responses.
//!
//! The cache deliberately has no streaming fan-out path.  A caller either
//! receives a completed response, waits for another caller to complete one,
//! or becomes the one caller allowed to fetch the response.  Keys contain
//! only a digest of request data, so request bodies and credentials never
//! appear in cache diagnostics.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, StatusCode, Version};
use ring::digest::{digest, SHA256};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Version of the canonical cache-key format.
pub const CACHE_KEY_VERSION: u8 = 1;
/// Default cache lifetime for an explicitly enabled route.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(1);
/// Default number of completed entries retained by one route cache.
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 64;
/// Default total response bytes retained by one route cache.
pub const DEFAULT_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of configured request headers used in a key.
pub const MAX_CACHE_KEY_HEADERS: usize = 16;

/// A route's bounded cache policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePolicy {
    /// Whether this policy is active.
    pub enabled: bool,
    /// How long a completed response remains usable.
    pub ttl: Duration,
    /// Maximum completed entries for the route.
    pub max_entries: usize,
    /// Maximum total response bytes for the route.
    pub max_bytes: usize,
    /// Whether equivalent requests may share one in-flight fetch.
    pub coalesce: bool,
    /// Non-sensitive request headers included in the key.
    pub key_headers: Vec<HeaderName>,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: DEFAULT_CACHE_TTL,
            max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            max_bytes: DEFAULT_CACHE_MAX_BYTES,
            coalesce: true,
            key_headers: Vec::new(),
        }
    }
}

impl CachePolicy {
    /// Return whether the policy can retain responses.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.enabled && !self.ttl.is_zero() && self.max_entries > 0 && self.max_bytes > 0
    }

    /// Headers included in the canonical request key.
    #[must_use]
    pub fn key_headers(&self) -> &[HeaderName] {
        &self.key_headers
    }
}

/// Digest-backed request key.  The original request data is not retained.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    /// Build a deterministic key from route inputs and the effective body.
    ///
    /// Values are length-delimited before hashing.  This avoids ambiguous
    /// concatenations while keeping bodies, authorization values, and other
    /// request data out of the retained key.
    #[must_use]
    pub fn from_request(input: CacheKeyInput<'_>) -> Self {
        let mut canonical = Vec::new();
        canonical.push(CACHE_KEY_VERSION);
        push_field(&mut canonical, &input.generation.to_be_bytes());
        push_field(&mut canonical, input.route.as_bytes());
        push_field(&mut canonical, input.target.as_bytes());
        push_field(&mut canonical, input.method.as_bytes());
        push_field(&mut canonical, input.uri.as_bytes());
        for name in input.key_headers {
            push_field(&mut canonical, name.as_str().as_bytes());
            for value in input.headers.get_all(name) {
                push_field(&mut canonical, value.as_bytes());
            }
            push_field(&mut canonical, &[]);
        }
        push_field(&mut canonical, input.body);
        let digest = digest(&SHA256, &canonical);
        let mut key = [0_u8; 32];
        key.copy_from_slice(digest.as_ref());
        Self(key)
    }
}

/// Request fields used to derive a [`CacheKey`].
pub struct CacheKeyInput<'a> {
    /// Configuration generation.
    pub generation: u64,
    /// Stable route ID.
    pub route: &'a str,
    /// Effective upstream target input.
    pub target: &'a str,
    /// Request method.
    pub method: &'a str,
    /// Request path and query.
    pub uri: &'a str,
    /// Request headers.
    pub headers: &'a HeaderMap,
    /// Header allowlist selected by configuration.
    pub key_headers: &'a [HeaderName],
    /// Effective, fully buffered request body.
    pub body: &'a [u8],
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

/// A response safe to clone into multiple completed callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
}

impl CachedResponse {
    /// Construct a response after its body has been fully collected.
    #[must_use]
    pub fn new(status: StatusCode, version: Version, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            version,
            headers,
            body,
        }
    }

    /// Response status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Response HTTP version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Response headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Fully buffered response body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Number of body bytes retained by this response.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

struct Entry {
    response: Arc<CachedResponse>,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlightResult {
    Complete,
    Retry,
}

struct FlightState {
    result: Option<FlightResult>,
    subscribers: usize,
}

struct Flight {
    state: Mutex<FlightState>,
    notify: Notify,
    cancellation: CancellationToken,
    reserved_bytes: Mutex<usize>,
}

impl Flight {
    fn new(reserved_bytes: usize) -> Self {
        Self {
            state: Mutex::new(FlightState {
                result: None,
                subscribers: 1,
            }),
            notify: Notify::new(),
            cancellation: CancellationToken::new(),
            reserved_bytes: Mutex::new(reserved_bytes),
        }
    }

    fn add_subscriber(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.result.is_none() {
            state.subscribers = state.subscribers.saturating_add(1);
        }
    }

    fn result(&self) -> Option<FlightResult> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .result
    }

    fn complete(&self, result: FlightResult) {
        let changed = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.result.is_some() {
                false
            } else {
                state.result = Some(result);
                true
            }
        };
        if changed {
            self.cancellation.cancel();
            self.notify.notify_waiters();
        }
    }

    fn release_follower(&self) -> bool {
        let cancel = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.subscribers = state.subscribers.saturating_sub(1);
            state.subscribers == 0 && state.result.is_none()
        };
        if cancel {
            self.cancellation.cancel();
            self.complete(FlightResult::Retry);
        }
        cancel
    }

    fn add_reserved_bytes(&self, bytes: usize) {
        let mut reserved = self
            .reserved_bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *reserved = reserved.saturating_add(bytes);
    }

    fn reserved_bytes(&self) -> usize {
        *self
            .reserved_bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<CacheKey, Entry>,
    order: VecDeque<CacheKey>,
    bytes: usize,
    flights: HashMap<CacheKey, Arc<Flight>>,
    flight_bytes: usize,
}

struct CacheInner {
    policy: CachePolicy,
    state: Mutex<CacheState>,
}

/// One bounded response cache, normally owned by one route plan.
#[derive(Clone)]
pub struct ResponseCache {
    inner: Arc<CacheInner>,
}

impl std::fmt::Debug for ResponseCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        formatter
            .debug_struct("ResponseCache")
            .field("enabled", &self.inner.policy.enabled)
            .field("entries", &state.entries.len())
            .field("bytes", &state.bytes)
            .field("in_flight", &state.flights.len())
            .finish()
    }
}

impl ResponseCache {
    /// Construct a route cache with the supplied bounded policy.
    #[must_use]
    pub fn new(policy: CachePolicy) -> Self {
        Self {
            inner: Arc::new(CacheInner {
                policy,
                state: Mutex::new(CacheState::default()),
            }),
        }
    }

    /// Return the immutable policy used by this cache.
    #[must_use]
    pub fn policy(&self) -> &CachePolicy {
        &self.inner.policy
    }

    /// Look up an unexpired completed response.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<Arc<CachedResponse>> {
        if !self.inner.policy.usable() {
            return None;
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired = state
            .entries
            .get(key)
            .is_some_and(|entry| entry.expires_at <= now);
        if expired {
            remove_entry(&mut state, key);
            return None;
        }
        let response = state
            .entries
            .get(key)
            .map(|entry| Arc::clone(&entry.response))?;
        state.order.retain(|entry| entry != key);
        state.order.push_back(*key);
        Some(response)
    }

    /// Start or join a request whose response is not yet cached.
    pub fn begin(&self, key: CacheKey) -> CacheLookup {
        self.begin_with_size(key, 0)
    }

    /// Start or join a request while reserving its already-buffered request
    /// bytes against the route's bounded in-flight budget.
    pub fn begin_with_size(&self, key: CacheKey, request_bytes: usize) -> CacheLookup {
        if !self.inner.policy.usable() {
            return CacheLookup::Disabled;
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(flight) = state.flights.get(&key) {
            if self.inner.policy.coalesce {
                flight.add_subscriber();
                return CacheLookup::Follower(CacheFollower {
                    cache: self.clone(),
                    key,
                    flight: Arc::clone(flight),
                    released: false,
                });
            }
            return CacheLookup::Disabled;
        }
        if state.flights.len() >= self.inner.policy.max_entries
            || request_bytes > self.inner.policy.max_bytes
            || state.flight_bytes.saturating_add(request_bytes) > self.inner.policy.max_bytes
        {
            return CacheLookup::Disabled;
        }
        let flight = Arc::new(Flight::new(request_bytes));
        state.flight_bytes = state.flight_bytes.saturating_add(request_bytes);
        state.flights.insert(key, Arc::clone(&flight));
        CacheLookup::Leader(CacheLeader {
            cache: self.clone(),
            key,
            flight,
            completed: false,
        })
    }

    /// Return bounded cache occupancy for diagnostics and tests.
    #[must_use]
    pub fn occupancy(&self) -> (usize, usize, usize) {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.entries.len(), state.bytes, state.flights.len())
    }

    fn publish(&self, key: CacheKey, response: Arc<CachedResponse>) {
        let response_bytes = response.body_len();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if response_bytes <= self.inner.policy.max_bytes {
            if let Some(previous) = state.entries.remove(&key) {
                state.bytes = state.bytes.saturating_sub(previous.response.body_len());
            }
            state.bytes = state.bytes.saturating_add(response_bytes);
            state.entries.insert(
                key,
                Entry {
                    response,
                    expires_at: Instant::now() + self.inner.policy.ttl,
                },
            );
            state.order.retain(|entry| entry != &key);
            state.order.push_back(key);
            while state.entries.len() > self.inner.policy.max_entries
                || state.bytes > self.inner.policy.max_bytes
            {
                let Some(oldest) = state.order.pop_front() else {
                    break;
                };
                remove_entry(&mut state, &oldest);
            }
        }
        if let Some(flight) = state.flights.remove(&key) {
            state.flight_bytes = state.flight_bytes.saturating_sub(flight.reserved_bytes());
            flight.complete(FlightResult::Complete);
        }
    }

    fn reserve_response(&self, key: &CacheKey, response_bytes: usize) -> bool {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .bytes
            .saturating_add(state.flight_bytes)
            .saturating_add(response_bytes)
            > self.inner.policy.max_bytes
        {
            return false;
        }
        let Some(flight) = state.flights.get_mut(key) else {
            return false;
        };
        flight.add_reserved_bytes(response_bytes);
        state.flight_bytes = state.flight_bytes.saturating_add(response_bytes);
        true
    }

    fn fail(&self, key: &CacheKey) {
        let flight = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let flight = state.flights.remove(key);
            if let Some(flight) = flight.as_ref() {
                state.flight_bytes = state.flight_bytes.saturating_sub(flight.reserved_bytes());
            }
            flight
        };
        if let Some(flight) = flight {
            flight.complete(FlightResult::Retry);
        }
    }
}

fn remove_entry(state: &mut CacheState, key: &CacheKey) {
    if let Some(entry) = state.entries.remove(key) {
        state.bytes = state.bytes.saturating_sub(entry.response.body_len());
    }
    state.order.retain(|entry| entry != key);
}

/// Result of starting a cache operation.
pub enum CacheLookup {
    /// Caching is disabled or coalescing is disabled for an occupied key.
    Disabled,
    /// This caller owns the upstream fetch.
    Leader(CacheLeader),
    /// Another caller owns the upstream fetch.
    Follower(CacheFollower),
}

/// The one caller allowed to publish a response for a key.
pub struct CacheLeader {
    cache: ResponseCache,
    key: CacheKey,
    flight: Arc<Flight>,
    completed: bool,
}

impl CacheLeader {
    /// Cancellation token shared with the in-flight operation.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.flight.cancellation.clone()
    }

    /// Publish a fully buffered response and wake all followers.
    pub fn publish(mut self, response: CachedResponse) {
        self.cache.publish(self.key, Arc::new(response));
        self.completed = true;
    }

    /// Reserve a known response length before buffering it. Returns `false`
    /// when the route's aggregate in-flight byte bound would be exceeded.
    pub fn reserve_response_bytes(&mut self, response_bytes: usize) -> bool {
        self.cache.reserve_response(&self.key, response_bytes)
    }

    /// Mark the operation as non-cacheable and wake followers to retry.
    pub fn fail(mut self) {
        self.cache.fail(&self.key);
        self.completed = true;
    }
}

impl Drop for CacheLeader {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.fail(&self.key);
        }
    }
}

/// A follower waiting for a completed response.
pub struct CacheFollower {
    cache: ResponseCache,
    key: CacheKey,
    flight: Arc<Flight>,
    released: bool,
}

impl CacheFollower {
    /// Wait for the owner, returning `None` on follower cancellation or a
    /// failed/non-cacheable owner operation.
    pub async fn wait(mut self, cancellation: &CancellationToken) -> Option<Arc<CachedResponse>> {
        loop {
            if self.flight.result().is_some() {
                let _ = self.flight.release_follower();
                self.released = true;
                return self.cache.get(&self.key, Instant::now());
            }
            let notified = self.flight.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            tokio::select! {
                _ = notified => {}
                () = cancellation.cancelled() => {
                    let _ = self.flight.release_follower();
                    self.released = true;
                    return None;
                }
            }
        }
    }
}

impl Drop for CacheFollower {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.flight.release_follower();
            self.released = true;
        }
    }
}

/// Copy only response headers that are safe to replay from a cache.
///
/// Hop-by-hop and identity-bearing headers are intentionally excluded.  The
/// caller supplies an already validated response status and body.
#[must_use]
pub fn replayable_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut replayed = HeaderMap::new();
    for (name, value) in headers {
        if is_non_replayable_header(name) {
            continue;
        }
        replayed.append(name.clone(), value.clone());
    }
    replayed
}

/// Return whether response cache semantics are safe to replay.
///
/// A response with `Vary` cannot be safely replayed by this small cache
/// because the route policy does not dynamically expand its request-key
/// allowlist. Private/no-store responses and identity-setting responses are
/// likewise left on the normal streaming path.
#[must_use]
pub fn safe_response_for_cache(headers: &HeaderMap) -> bool {
    if headers.contains_key("vary")
        || headers.contains_key("set-cookie")
        || headers.contains_key("www-authenticate")
    {
        return false;
    }
    all_header_values_allow_replay(headers, "cache-control", cache_control_forbids_replay)
        && all_header_values_allow_replay(headers, "pragma", pragma_forbids_replay)
}

fn all_header_values_allow_replay(
    headers: &HeaderMap,
    name: &'static str,
    forbids_replay: fn(&str) -> bool,
) -> bool {
    headers.get_all(name).iter().all(|value| {
        value
            .to_str()
            .map(|value| !value.split(',').any(forbids_replay))
            .unwrap_or(false)
    })
}

fn cache_control_forbids_replay(directive: &str) -> bool {
    matches!(
        directive_token(directive).as_str(),
        "no-store" | "no-cache" | "private"
    )
}

fn pragma_forbids_replay(directive: &str) -> bool {
    directive_token(directive) == "no-cache"
}

fn directive_token(directive: &str) -> String {
    directive
        .trim()
        .split_once('=')
        .map_or_else(|| directive.trim(), |(token, _)| token.trim())
        .to_ascii_lowercase()
}

fn is_non_replayable_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "set-cookie"
            | "www-authenticate"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Return whether a configured key header is safe to include by name.
#[must_use]
pub fn safe_key_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-refresh-token"
    ) && !name.as_str().ends_with("-token")
        && !name.as_str().ends_with("-secret")
        && !name.as_str().ends_with("-credential")
}

/// Return whether a request can be safely used as a cache key.
///
/// Authorization, cookies, and other identity-bearing headers are never
/// accepted. Conditional and custom headers must be explicitly included in
/// the route key allowlist; silently ignoring them would allow responses for
/// one identity or representation to reach another.
#[must_use]
pub fn safe_request_for_cache(headers: &HeaderMap, policy: &CachePolicy) -> bool {
    headers.iter().all(|(name, _)| {
        if is_ignored_transport_header(name) {
            return true;
        }
        if !safe_key_header(name) {
            return false;
        }
        if policy.key_headers.contains(name) {
            return true;
        }
        is_default_key_header(name)
    })
}

fn is_ignored_transport_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_default_key_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "accept" | "accept-encoding" | "content-type" | "idempotency-key" | "user-agent"
    )
}

/// Return whether this HTTP operation may share a cached completed response.
///
/// GET and HEAD are replay-safe by method semantics. POST is accepted only
/// when the request carries an explicit idempotency key.
#[must_use]
pub fn safe_method_for_cache(method: &str, idempotency_key_present: bool) -> bool {
    matches!(method, "GET" | "HEAD") || (method == "POST" && idempotency_key_present)
}

/// Return a body-bearing HTTP response from a cached value.
#[must_use]
pub fn response_from_cache(cached: &CachedResponse) -> http::Response<Bytes> {
    let mut response = http::Response::new(cached.body.clone());
    *response.status_mut() = cached.status;
    *response.version_mut() = cached.version;
    *response.headers_mut() = cached.headers.clone();
    response
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn policy() -> CachePolicy {
        CachePolicy {
            enabled: true,
            ttl: Duration::from_secs(1),
            max_entries: 2,
            max_bytes: 8,
            coalesce: true,
            key_headers: vec![HeaderName::from_static("accept")],
        }
    }

    fn key(body: &[u8]) -> CacheKey {
        CacheKey::from_request(CacheKeyInput {
            generation: 1,
            route: "route",
            target: "upstream",
            method: "POST",
            uri: "/v1/chat",
            headers: &HeaderMap::new(),
            key_headers: &[],
            body,
        })
    }

    #[test]
    fn key_is_deterministic_without_retaining_input() {
        assert_eq!(key(b"one"), key(b"one"));
        assert_ne!(key(b"one"), key(b"two"));
    }

    #[test]
    fn cache_enforces_entries_and_bytes() {
        let cache = ResponseCache::new(policy());
        for body in [b"one".as_slice(), b"two", b"three"] {
            let key = key(body);
            let CacheLookup::Leader(owner) = cache.begin(key) else {
                panic!("cache owner");
            };
            owner.publish(CachedResponse::new(
                StatusCode::OK,
                Version::HTTP_11,
                HeaderMap::new(),
                Bytes::copy_from_slice(body),
            ));
        }
        let (entries, bytes, flights) = cache.occupancy();
        assert_eq!(entries, 2);
        assert_eq!(bytes, 8);
        assert_eq!(flights, 0);
    }

    #[test]
    fn cache_hit_updates_lru_recency() {
        let cache = ResponseCache::new(policy());
        let first = key(b"one");
        let second = key(b"two");
        let third = key(b"three");
        for key in [first, second] {
            let CacheLookup::Leader(owner) = cache.begin(key) else {
                panic!("cache owner");
            };
            owner.publish(CachedResponse::new(
                StatusCode::OK,
                Version::HTTP_11,
                HeaderMap::new(),
                Bytes::from_static(b"one"),
            ));
        }

        assert!(cache.get(&first, Instant::now()).is_some());
        let CacheLookup::Leader(owner) = cache.begin(third) else {
            panic!("cache owner");
        };
        owner.publish(CachedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"two"),
        ));

        assert!(cache.get(&first, Instant::now()).is_some());
        assert!(cache.get(&second, Instant::now()).is_none());
        assert!(cache.get(&third, Instant::now()).is_some());
    }

    #[test]
    fn expired_entries_are_not_replayed() {
        let cache = ResponseCache::new(CachePolicy {
            ttl: Duration::from_millis(1),
            ..policy()
        });
        let request_key = key(b"expiring");
        let CacheLookup::Leader(owner) = cache.begin(request_key) else {
            panic!("leader");
        };
        owner.publish(CachedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"body"),
        ));
        assert!(cache
            .get(&request_key, Instant::now() + Duration::from_secs(1))
            .is_none());
        assert_eq!(cache.occupancy(), (0, 0, 0));
    }

    #[tokio::test]
    async fn follower_waits_for_completed_response() {
        let cache = ResponseCache::new(policy());
        let request_key = key(b"body");
        let CacheLookup::Leader(owner) = cache.begin(request_key) else {
            panic!("leader");
        };
        let CacheLookup::Follower(follower) = cache.begin(request_key) else {
            panic!("follower");
        };
        let cancellation = CancellationToken::new();
        let waiter = tokio::spawn(async move { follower.wait(&cancellation).await });
        owner.publish(CachedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"response"),
        ));
        let response = waiter.await.expect("waiter").expect("response");
        assert_eq!(response.body(), &Bytes::from_static(b"response"));
    }

    #[tokio::test]
    async fn canceled_follower_does_not_cancel_owner() {
        let cache = ResponseCache::new(policy());
        let request_key = key(b"body");
        let CacheLookup::Leader(owner) = cache.begin(request_key) else {
            panic!("leader");
        };
        let CacheLookup::Follower(follower) = cache.begin(request_key) else {
            panic!("follower");
        };
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(follower.wait(&cancellation).await.is_none());
        assert_eq!(cache.occupancy().2, 1);
        owner.fail();
        assert_eq!(cache.occupancy().2, 0);
    }

    #[tokio::test]
    async fn dropped_owner_wakes_followers_to_retry() {
        let cache = ResponseCache::new(policy());
        let request_key = key(b"owner-drop");
        let CacheLookup::Leader(owner) = cache.begin(request_key) else {
            panic!("leader");
        };
        let CacheLookup::Follower(follower) = cache.begin(request_key) else {
            panic!("follower");
        };
        drop(owner);
        let cancellation = CancellationToken::new();
        assert!(follower.wait(&cancellation).await.is_none());
        assert_eq!(cache.occupancy().2, 0);
        assert!(matches!(cache.begin(request_key), CacheLookup::Leader(_)));
    }

    #[test]
    fn owner_drop_cancels_the_shared_operation() {
        let cache = ResponseCache::new(policy());
        let request_key = key(b"cancel-owner");
        let CacheLookup::Leader(owner) = cache.begin(request_key) else {
            panic!("leader");
        };
        let cancellation = owner.cancellation_token();
        drop(owner);
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn coalescing_can_be_disabled_without_disabling_completed_cache() {
        let cache = ResponseCache::new(CachePolicy {
            coalesce: false,
            ..policy()
        });
        let request_key = key(b"no-coalesce");
        let CacheLookup::Leader(owner) = cache.begin(request_key) else {
            panic!("leader");
        };
        assert!(matches!(cache.begin(request_key), CacheLookup::Disabled));
        owner.publish(CachedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"body"),
        ));
        assert!(cache.get(&request_key, Instant::now()).is_some());
    }

    #[test]
    fn in_flight_entries_respect_entry_and_byte_bounds() {
        let cache = ResponseCache::new(CachePolicy {
            max_entries: 1,
            max_bytes: 4,
            ..policy()
        });
        let first = key(b"first");
        let second = key(b"second");
        let CacheLookup::Leader(owner) = cache.begin_with_size(first, 4) else {
            panic!("first leader");
        };
        assert!(matches!(
            cache.begin_with_size(second, 0),
            CacheLookup::Disabled
        ));
        owner.fail();
        assert!(matches!(
            cache.begin_with_size(second, 5),
            CacheLookup::Disabled
        ));
        assert!(matches!(
            cache.begin_with_size(second, 4),
            CacheLookup::Leader(_)
        ));
    }

    #[test]
    fn unsafe_key_headers_are_rejected() {
        assert!(!safe_key_header(&HeaderName::from_static("authorization")));
        assert!(!safe_key_header(&HeaderName::from_static(
            "x-session-token"
        )));
        assert!(safe_key_header(&HeaderName::from_static("x-tenant")));
    }

    #[test]
    fn replayed_headers_exclude_identity_and_transport_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("set-cookie", HeaderValue::from_static("session=secret"));
        headers.insert("connection", HeaderValue::from_static("close"));
        let replayed = replayable_response_headers(&headers);
        assert!(replayed.contains_key("content-type"));
        assert!(!replayed.contains_key("set-cookie"));
        assert!(!replayed.contains_key("connection"));
    }

    #[test]
    fn request_identity_and_unkeyed_conditionals_disable_cache() {
        let policy = CachePolicy {
            key_headers: vec![HeaderName::from_static("x-tenant")],
            ..policy()
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("session=one"));
        assert!(!safe_request_for_cache(&headers, &policy));

        headers.clear();
        headers.insert("x-tenant", HeaderValue::from_static("acme"));
        assert!(safe_request_for_cache(&headers, &policy));
        headers.insert("range", HeaderValue::from_static("bytes=0-10"));
        assert!(!safe_request_for_cache(&headers, &policy));
    }

    #[test]
    fn varying_or_private_responses_are_not_cached() {
        let mut headers = HeaderMap::new();
        headers.insert("vary", HeaderValue::from_static("accept-language"));
        assert!(!safe_response_for_cache(&headers));
        headers.clear();
        headers.insert(
            "cache-control",
            HeaderValue::from_static("max-age=60, private=\"set-cookie\""),
        );
        assert!(!safe_response_for_cache(&headers));
        headers.clear();
        headers.append("cache-control", HeaderValue::from_static("max-age=60"));
        headers.append("cache-control", HeaderValue::from_static("no-store=1"));
        assert!(!safe_response_for_cache(&headers));
        headers.clear();
        headers.append("pragma", HeaderValue::from_static("other"));
        headers.append("pragma", HeaderValue::from_static("no-cache=1"));
        assert!(!safe_response_for_cache(&headers));
        headers.clear();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        assert!(safe_response_for_cache(&headers));
    }

    #[test]
    fn post_cache_requires_idempotency_key() {
        assert!(safe_method_for_cache("GET", false));
        assert!(safe_method_for_cache("HEAD", false));
        assert!(!safe_method_for_cache("POST", false));
        assert!(safe_method_for_cache("POST", true));
        assert!(!safe_method_for_cache("PUT", true));
    }
}
