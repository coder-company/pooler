//! Explicit body handling and conversion-loss policies.

use serde::{Deserialize, Serialize};

/// How a route handles its request and response representation.
///
/// Opaque and inspect modes intentionally avoid forcing a semantic decode. A
/// route may therefore preserve provider-specific bytes even when another route
/// in the same process uses semantic conversion.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyMode {
    /// Forward bytes or frames without semantic decoding.
    #[default]
    Opaque,
    /// Extract bounded routing fields while retaining the original body.
    Inspect,
    /// Parse a known representation and apply bounded field-level changes.
    Patch,
    /// Decode into Pooler's protocol-neutral semantic representation.
    Semantic,
}

impl BodyMode {
    /// Whether this mode requires semantic decoding.
    #[must_use]
    pub const fn is_semantic(self) -> bool {
        matches!(self, Self::Semantic)
    }

    /// Whether this mode promises to retain the original representation.
    #[must_use]
    pub const fn preserves_original(self) -> bool {
        matches!(self, Self::Opaque | Self::Inspect)
    }

    /// Whether this mode can mutate a structured representation.
    #[must_use]
    pub const fn can_patch(self) -> bool {
        matches!(self, Self::Patch)
    }
}

/// What a semantic route should do when a conversion cannot retain all fields.
///
/// The policy is explicit so an adapter cannot silently drop tools, media,
/// reasoning state, identifiers, or terminal event information.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LossPolicy {
    /// Reject before upstream execution when required semantics are unsupported.
    #[default]
    Reject,
    /// Carry provider-specific fields in an extension namespace where possible.
    Preserve,
    /// Perform configured lossy conversion and emit a structured warning.
    Degrade,
}

impl LossPolicy {
    /// Whether unsupported required semantics should fail the request.
    #[must_use]
    pub const fn rejects_unsupported(self) -> bool {
        matches!(self, Self::Reject)
    }

    /// Whether extension storage is the preferred loss strategy.
    #[must_use]
    pub const fn preserves_extensions(self) -> bool {
        matches!(self, Self::Preserve)
    }

    /// Whether configured lossy conversion is allowed.
    #[must_use]
    pub const fn allows_degradation(self) -> bool {
        matches!(self, Self::Degrade)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_modes_have_explicit_semantics() {
        assert!(BodyMode::Opaque.preserves_original());
        assert!(BodyMode::Inspect.preserves_original());
        assert!(BodyMode::Patch.can_patch());
        assert!(BodyMode::Semantic.is_semantic());
        assert!(!BodyMode::Semantic.preserves_original());
    }

    #[test]
    fn loss_policy_defaults_to_reject_and_serializes_stably() {
        assert_eq!(LossPolicy::default(), LossPolicy::Reject);
        assert!(LossPolicy::Reject.rejects_unsupported());
        assert!(LossPolicy::Preserve.preserves_extensions());
        assert!(LossPolicy::Degrade.allows_degradation());
        assert_eq!(
            serde_json::to_string(&LossPolicy::Degrade).unwrap(),
            "\"degrade\""
        );
        assert_eq!(
            serde_json::from_str::<BodyMode>("\"inspect\"").unwrap(),
            BodyMode::Inspect
        );
    }
}
