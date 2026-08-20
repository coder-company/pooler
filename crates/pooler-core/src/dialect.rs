//! Per-model dialect facts that shape a request after a target is chosen.
//!
//! A [`CapabilitySet`](crate::CapabilitySet) answers whether a target *may*
//! serve a request; it is a boolean routing decision. A [`ModelDialect`]
//! answers *how* the request and response must be shaped once that target is
//! chosen. The two are deliberately separate: dialect facts include response
//! field names and value domains, which a capability bitset cannot represent.
//!
//! Dialect facts never silently rewrite a request. When a model rejects a
//! parameter the caller supplied, the route resolves that conflict through
//! [`LossPolicy`](crate::LossPolicy), so the omission is rejected before
//! upstream execution or reported as configured degradation. Silently dropping
//! the field would hide a caller-visible behavior change.

use serde::{Deserialize, Serialize};

/// Whether a model accepts an optional request parameter.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ParamSupport {
    /// The parameter may be forwarded upstream unchanged.
    #[default]
    Accepted,
    /// The model rejects the parameter, so forwarding it fails the request.
    Rejected,
}

impl ParamSupport {
    /// Whether the parameter may be forwarded upstream.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// How one upstream model deviates from its protocol's default request shape.
///
/// The default dialect describes a model that accepts every standard sampling
/// parameter. A provider adapter or catalog source overrides only the facts it
/// has actually observed.
///
/// Response decoding is deliberately not described here. The OpenAI Chat
/// decoder accepts every reasoning field name it has observed, which keeps
/// models absent from the catalog working; a per-model declaration would only
/// narrow that.
///
/// ```
/// use pooler_core::{ModelDialect, ParamSupport};
///
/// let dialect = ModelDialect::new().rejecting_temperature();
///
/// assert_eq!(dialect.temperature, ParamSupport::Rejected);
/// assert!(!dialect.is_default());
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelDialect {
    /// Whether the model accepts a `temperature` sampling parameter.
    pub temperature: ParamSupport,
}

impl ModelDialect {
    /// The dialect assumed when a provider reports no deviation.
    pub const DEFAULT: Self = Self {
        temperature: ParamSupport::Accepted,
    };

    /// Construct the default dialect.
    #[must_use]
    pub const fn new() -> Self {
        Self::DEFAULT
    }

    /// Record that the model rejects the `temperature` parameter.
    #[must_use]
    pub const fn rejecting_temperature(mut self) -> Self {
        self.temperature = ParamSupport::Rejected;
        self
    }

    /// Whether this dialect matches the protocol default in every respect.
    #[must_use]
    pub fn is_default(self) -> bool {
        self == Self::DEFAULT
    }
}

impl Default for ModelDialect {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dialect_forwards_temperature() {
        let dialect = ModelDialect::default();
        assert!(dialect.is_default());
        assert!(dialect.temperature.is_accepted());
    }

    #[test]
    fn builders_record_observed_deviations() {
        let dialect = ModelDialect::new().rejecting_temperature();
        assert!(!dialect.temperature.is_accepted());
        assert!(!dialect.is_default());
    }

    #[test]
    fn absent_fields_deserialize_to_the_default_dialect() {
        let dialect: ModelDialect = serde_json::from_str("{}").expect("deserialize empty dialect");
        assert_eq!(dialect, ModelDialect::DEFAULT);
    }

    #[test]
    fn dialect_serializes_with_stable_snake_case_names() {
        let dialect = ModelDialect::new().rejecting_temperature();
        assert_eq!(
            serde_json::to_string(&dialect).expect("serialize dialect"),
            r#"{"temperature":"rejected"}"#
        );
    }

    #[test]
    fn unknown_dialect_fields_are_rejected() {
        serde_json::from_str::<ModelDialect>(r#"{"top_k":"accepted"}"#)
            .expect_err("unknown dialect fields must be rejected");
    }
}
