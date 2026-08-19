//! Per-request state shared by route plans and components.

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;

use crate::{ConfigGeneration, ListenerId, ModelId, RequestId, RouteId, SessionId, TraceId};

/// Downstream identity metadata. It deliberately stores an identity label, not
/// a bearer token, password, cookie, or other authorization material.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DownstreamIdentity {
    /// No downstream identity was supplied or authentication was not configured.
    #[default]
    Anonymous,
    /// A redacted principal or key identifier assigned by the auth layer.
    Principal { id: String },
}

impl DownstreamIdentity {
    /// Construct a principal from a non-empty, non-whitespace label.
    pub fn principal(id: impl Into<String>) -> Result<Self, IdentityError> {
        let id = id.into();
        if id.is_empty() {
            return Err(IdentityError::Empty);
        }
        if id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(IdentityError::InvalidCharacter);
        }
        Ok(Self::Principal { id })
    }

    /// Return the principal label, if one is present.
    #[must_use]
    pub fn principal_id(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::Principal { id } => Some(id),
        }
    }
}

/// Validation failures for downstream identity labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentityError {
    #[error("downstream identity must not be empty")]
    Empty,
    #[error("downstream identity contains whitespace or a control character")]
    InvalidCharacter,
}

/// Type-keyed metadata attached by components during one request.
///
/// `Debug` reports only the number of entries. This keeps accidental logging of
/// an extension value from becoming a credential leak.
#[derive(Clone, Default)]
pub struct Extensions(Arc<RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>);

impl Extensions {
    /// Insert or replace a typed extension.
    pub fn insert<T>(&self, value: T)
    where
        T: Any + Send + Sync,
    {
        let mut values = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        values.insert(TypeId::of::<T>(), Arc::new(value));
    }

    /// Retrieve a typed extension by cloning its shared handle.
    #[must_use]
    pub fn get<T>(&self) -> Option<Arc<T>>
    where
        T: Any + Send + Sync,
    {
        let values = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        values
            .get(&TypeId::of::<T>())
            .and_then(|value| Arc::clone(value).downcast::<T>().ok())
    }

    /// Remove and return a typed extension, if present.
    pub fn remove<T>(&self) -> Option<Arc<T>>
    where
        T: Any + Send + Sync,
    {
        let mut values = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        values
            .remove(&TypeId::of::<T>())
            .and_then(|value| value.downcast::<T>().ok())
    }

    /// Number of currently stored extension values.
    #[must_use]
    pub fn len(&self) -> usize {
        let values = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        values.len()
    }

    /// Whether no extension values are currently stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Extensions")
            .field("len", &self.len())
            .finish()
    }
}

/// Request-scoped metadata captured at admission time.
///
/// The context contains IDs, policy metadata, cancellation, and typed
/// extensions. It intentionally has no field or API for raw credentials or
/// authorization material.
#[derive(Clone)]
pub struct RequestContext {
    request_id: RequestId,
    trace_id: TraceId,
    generation: ConfigGeneration,
    listener_id: ListenerId,
    route_id: RouteId,
    started_at: Instant,
    deadline: Option<Instant>,
    identity: DownstreamIdentity,
    model_id: Option<ModelId>,
    session_id: Option<SessionId>,
    cancellation: CancellationToken,
    extensions: Extensions,
}

impl RequestContext {
    /// Create a request context with generated request and trace IDs.
    pub fn new(generation: ConfigGeneration, listener_id: ListenerId, route_id: RouteId) -> Self {
        Self::with_ids(
            RequestId::new(),
            TraceId::new(),
            generation,
            listener_id,
            route_id,
        )
    }

    /// Create a context when an ingress layer already assigned request IDs.
    #[must_use]
    pub fn with_ids(
        request_id: RequestId,
        trace_id: TraceId,
        generation: ConfigGeneration,
        listener_id: ListenerId,
        route_id: RouteId,
    ) -> Self {
        Self {
            request_id,
            trace_id,
            generation,
            listener_id,
            route_id,
            started_at: Instant::now(),
            deadline: None,
            identity: DownstreamIdentity::Anonymous,
            model_id: None,
            session_id: None,
            cancellation: CancellationToken::new(),
            extensions: Extensions::default(),
        }
    }

    /// Return the request ID.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Return the trace ID.
    #[must_use]
    pub const fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Return the immutable configuration generation captured by this request.
    #[must_use]
    pub const fn generation(&self) -> ConfigGeneration {
        self.generation
    }

    /// Return the listener selected for ingress.
    #[must_use]
    pub const fn listener_id(&self) -> &ListenerId {
        &self.listener_id
    }

    /// Return the route selected for this request.
    #[must_use]
    pub const fn route_id(&self) -> &RouteId {
        &self.route_id
    }

    /// Return the monotonic admission timestamp.
    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.started_at
    }

    /// Return the optional monotonic deadline.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Return the redacted downstream identity metadata.
    #[must_use]
    pub const fn identity(&self) -> &DownstreamIdentity {
        &self.identity
    }

    /// Return the extracted model identifier, if routing has resolved one.
    #[must_use]
    pub const fn model_id(&self) -> Option<&ModelId> {
        self.model_id.as_ref()
    }

    /// Return the extracted session identifier, if one is available.
    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    /// Set an absolute deadline.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    /// Set a deadline relative to now.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.deadline = Some(Instant::now() + timeout);
    }

    /// Set redacted downstream identity metadata.
    pub fn set_identity(&mut self, identity: DownstreamIdentity) {
        self.identity = identity;
    }

    /// Set the extracted model identifier.
    pub fn set_model_id(&mut self, model_id: Option<ModelId>) {
        self.model_id = model_id;
    }

    /// Set the extracted session identifier.
    pub fn set_session_id(&mut self, session_id: Option<SessionId>) {
        self.session_id = session_id;
    }

    /// Return a shared cancellation token for upstream work.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Cancel all work associated with this request.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Whether the request has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Whether the configured deadline has elapsed.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Access typed request extensions.
    #[must_use]
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestContext")
            .field("request_id", &self.request_id)
            .field("trace_id", &self.trace_id)
            .field("generation", &self.generation)
            .field("listener_id", &self.listener_id)
            .field("route_id", &self.route_id)
            .field("identity", &self.identity)
            .field("model_id", &self.model_id)
            .field("session_id", &self.session_id)
            .field("deadline", &self.deadline)
            .field("cancelled", &self.is_cancelled())
            .field("extensions", &self.extensions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{ConfigGeneration, ListenerId, RouteId};

    fn context() -> RequestContext {
        RequestContext::new(
            ConfigGeneration::new(7),
            ListenerId::new("local").unwrap(),
            RouteId::new("route").unwrap(),
        )
    }

    #[test]
    fn context_contains_routing_metadata_but_no_secret_field() {
        let mut context = context();
        let model = ModelId::new("gpt-5.6-sol").unwrap();
        let session = SessionId::new("conversation-1").unwrap();
        context.set_model_id(Some(model.clone()));
        context.set_session_id(Some(session.clone()));
        context.set_identity(DownstreamIdentity::principal("key-17").unwrap());
        assert_eq!(context.generation().value(), 7);
        assert_eq!(context.model_id(), Some(&model));
        assert_eq!(context.session_id(), Some(&session));
        assert_eq!(context.identity().principal_id(), Some("key-17"));
    }

    #[test]
    fn cancellation_is_shared_by_clones() {
        let context = context();
        let clone = context.clone();
        assert!(!clone.is_cancelled());
        context.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn deadline_and_extensions_are_bounded_metadata() {
        let mut context = context();
        context.set_deadline(Some(Instant::now() - Duration::from_secs(1)));
        assert!(context.is_expired());
        context.extensions().insert::<u32>(42);
        context
            .extensions()
            .insert::<String>("redacted-label".to_owned());
        assert_eq!(context.extensions().get::<u32>().as_deref(), Some(&42));
        let debug = format!("{context:?}");
        assert!(debug.contains("extensions"));
        assert!(!debug.contains("redacted-label"));
        assert_eq!(context.extensions().remove::<u32>().as_deref(), Some(&42));
        assert!(!context.extensions().is_empty());
    }

    #[test]
    fn identity_rejects_ambiguous_labels() {
        assert!(DownstreamIdentity::principal("").is_err());
        assert!(DownstreamIdentity::principal("has whitespace").is_err());
        assert!(DownstreamIdentity::principal("key-17").is_ok());
    }
}
