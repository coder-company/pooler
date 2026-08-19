//! Shared, dependency-light contracts for the Pooler protocol runtime.
//!
//! This crate owns identifiers, request metadata, explicit representation and
//! loss policies, capability matching, bounded route limits, and common error
//! classification. It contains no transport implementation and no credential
//! values.

#![forbid(unsafe_code)]

mod capabilities;
mod context;
mod error;
mod id;
mod limits;
mod mode;

pub use capabilities::{Capability, CapabilitySet};
pub use context::{DownstreamIdentity, Extensions, IdentityError, RequestContext};
pub use error::{
    ErrorClass, ErrorClassification, ErrorScope, PoolerError, PoolerResult, ReplaySafety,
    Retryability,
};
pub use id::{
    ComponentId, ConfigGeneration, CredentialId, IdentifierError, ListenerId, ModelId, ProviderId,
    RequestId, RouteId, SessionId, TargetId, TraceId, MAX_IDENTIFIER_LENGTH,
};
pub use limits::{LimitResource, LimitValidationError, RouteLimits, TimeoutResource};
pub use mode::{BodyMode, LossPolicy};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_contracts_compose_for_a_route() {
        let route = RouteId::new("private-inference").unwrap();
        let listener = ListenerId::new("local").unwrap();
        let context = RequestContext::new(ConfigGeneration::INITIAL, listener, route);
        let capabilities =
            CapabilitySet::from_iter([Capability::Text, Capability::Tools, Capability::Streaming]);

        assert_eq!(context.generation(), ConfigGeneration::INITIAL);
        assert!(capabilities.contains_all(CapabilitySet::from(Capability::Tools)));
        assert_eq!(BodyMode::default(), BodyMode::Opaque);
        assert_eq!(LossPolicy::default(), LossPolicy::Reject);
        RouteLimits::default().validate().unwrap();
    }
}
