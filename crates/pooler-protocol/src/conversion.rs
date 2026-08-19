//! Loss accounting for semantic protocol conversion.

use std::fmt;

use pooler_core::LossPolicy;
use serde::{Deserialize, Serialize};

use crate::extensions::ExtensionKey;

/// Severity attached to a conversion warning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    /// Informational note about a compatibility rule.
    Info,
    /// A caller-visible semantic degradation or preservation decision.
    #[default]
    Warning,
}

/// A structured warning emitted while converting a request or stream event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionWarning {
    /// Stable machine-readable warning code.
    pub code: String,
    /// Human-readable explanation suitable for a decision record.
    pub message: String,
    /// Optional semantic field affected by this warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Whether the warning represents a loss rather than an informational
    /// compatibility rule.
    #[serde(default)]
    pub severity: WarningSeverity,
}

impl ConversionWarning {
    /// Creates a warning without associating it with one field.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            field: None,
            severity: WarningSeverity::Warning,
        }
    }

    /// Associates this warning with a semantic field.
    #[must_use]
    pub fn for_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// Changes the warning severity.
    #[must_use]
    pub const fn with_severity(mut self, severity: WarningSeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Why conversion validation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionError {
    /// Policy that was unable to accept the report.
    pub policy: LossPolicy,
    /// Required fields for which no destination representation exists.
    pub unsupported_required_fields: Vec<String>,
    /// Optional or degraded fields disallowed by the selected policy.
    pub disallowed_losses: Vec<String>,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "conversion rejected under {:?} policy",
            self.policy
        )?;
        if !self.unsupported_required_fields.is_empty() {
            write!(formatter, "; unsupported required fields: ")?;
            write_joined(formatter, &self.unsupported_required_fields)?;
        }
        if !self.disallowed_losses.is_empty() {
            write!(formatter, "; disallowed losses: ")?;
            write_joined(formatter, &self.disallowed_losses)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConversionError {}

fn write_joined(formatter: &mut fmt::Formatter<'_>, values: &[String]) -> fmt::Result {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            formatter.write_str(", ")?;
        }
        formatter.write_str(value)?;
    }
    Ok(())
}

/// A complete accounting of semantic conversion decisions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionReport {
    /// Capabilities represented without loss in the destination protocol.
    #[serde(default)]
    pub preserved_capabilities: Vec<String>,
    /// Fields represented in a deliberately reduced form.
    #[serde(default)]
    pub degraded_fields: Vec<String>,
    /// Optional fields omitted by an explicitly lossy conversion.
    #[serde(default)]
    pub dropped_optional_fields: Vec<String>,
    /// Required fields for which no supported destination representation was
    /// available.
    #[serde(default)]
    pub unsupported_required_fields: Vec<String>,
    /// Namespaced extensions retained for a destination that supports opaque
    /// state.
    #[serde(default)]
    pub preserved_extensions: Vec<ExtensionKey>,
    /// Compatibility rules selected by the encoder.
    #[serde(default)]
    pub rules_applied: Vec<String>,
    /// Structured warnings exposed to callers and decision records.
    #[serde(default)]
    pub warnings: Vec<ConversionWarning>,
}

impl ConversionReport {
    /// Records a capability that made the round trip intact.
    pub fn preserve_capability(&mut self, capability: impl Into<String>) {
        push_unique(&mut self.preserved_capabilities, capability.into());
    }

    /// Records a field represented in a reduced form and emits a warning.
    pub fn degrade_field(&mut self, field: impl Into<String>, reason: impl Into<String>) {
        let field = field.into();
        push_unique(&mut self.degraded_fields, field.clone());
        self.warnings.push(
            ConversionWarning::new("degraded_field", reason)
                .for_field(field)
                .with_severity(WarningSeverity::Warning),
        );
    }

    /// Records an optional field that was dropped and emits a warning.
    pub fn drop_optional(&mut self, field: impl Into<String>, reason: impl Into<String>) {
        let field = field.into();
        push_unique(&mut self.dropped_optional_fields, field.clone());
        self.warnings.push(
            ConversionWarning::new("dropped_optional_field", reason)
                .for_field(field)
                .with_severity(WarningSeverity::Warning),
        );
    }

    /// Records a required field that cannot be represented by the destination.
    pub fn unsupported_required(&mut self, field: impl Into<String>, reason: impl Into<String>) {
        let field = field.into();
        push_unique(&mut self.unsupported_required_fields, field.clone());
        self.warnings.push(
            ConversionWarning::new("unsupported_required_field", reason)
                .for_field(field)
                .with_severity(WarningSeverity::Warning),
        );
    }

    /// Records an extension carried through the conversion.
    pub fn preserve_extension(&mut self, extension: &ExtensionKey) {
        if !self.preserved_extensions.contains(extension) {
            self.preserved_extensions.push(extension.clone());
        }
        self.preserve_capability(extension.as_str());
    }

    /// Records a compatibility rule without classifying it as a loss.
    pub fn apply_rule(&mut self, rule: impl Into<String>) {
        push_unique(&mut self.rules_applied, rule.into());
    }

    /// Adds a caller-supplied warning.
    pub fn warn(&mut self, warning: ConversionWarning) {
        self.warnings.push(warning);
    }

    /// Merges another report while retaining deterministic insertion order.
    pub fn merge(&mut self, other: Self) {
        for capability in other.preserved_capabilities {
            self.preserve_capability(capability);
        }
        for field in other.degraded_fields {
            push_unique(&mut self.degraded_fields, field);
        }
        for field in other.dropped_optional_fields {
            push_unique(&mut self.dropped_optional_fields, field);
        }
        for field in other.unsupported_required_fields {
            push_unique(&mut self.unsupported_required_fields, field);
        }
        for extension in other.preserved_extensions {
            if !self.preserved_extensions.contains(&extension) {
                self.preserved_extensions.push(extension);
            }
        }
        for rule in other.rules_applied {
            self.apply_rule(rule);
        }
        self.warnings.extend(other.warnings);
    }

    /// Returns whether all source semantics are either preserved or explicitly
    /// represented without loss.
    #[must_use]
    pub fn is_lossless(&self) -> bool {
        self.degraded_fields.is_empty()
            && self.dropped_optional_fields.is_empty()
            && self.unsupported_required_fields.is_empty()
    }

    /// Returns whether any loss or unsupported semantic was recorded.
    #[must_use]
    pub fn has_loss(&self) -> bool {
        !self.is_lossless()
    }

    /// Validates this report against a route's explicit loss policy.
    pub fn validate(&self, policy: LossPolicy) -> Result<(), ConversionError> {
        let mut disallowed_losses = Vec::new();
        match policy {
            LossPolicy::Reject | LossPolicy::Preserve => {
                disallowed_losses.extend(self.degraded_fields.iter().cloned());
                disallowed_losses.extend(self.dropped_optional_fields.iter().cloned());
            }
            LossPolicy::Degrade => {}
        }
        let unsupported_required_fields = self.unsupported_required_fields.clone();
        if !unsupported_required_fields.is_empty() || !disallowed_losses.is_empty() {
            return Err(ConversionError {
                policy,
                unsupported_required_fields,
                disallowed_losses,
            });
        }
        Ok(())
    }

    /// Alias for [`Self::validate`] that reads naturally at an encoder call
    /// site.
    pub fn enforce(&self, policy: LossPolicy) -> Result<(), ConversionError> {
        self.validate(policy)
    }

    /// Returns whether the report is acceptable under a policy.
    #[must_use]
    pub fn is_compatible_with(&self, policy: LossPolicy) -> bool {
        self.validate(policy).is_ok()
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Convenience result used by conversion implementations.
pub type ConversionResult<T> = Result<T, ConversionError>;

#[cfg(test)]
mod tests {
    use super::{ConversionReport, LossPolicy, WarningSeverity};
    use crate::{ExtensionKey, OpaqueExtension};

    #[test]
    fn reject_and_preserve_refuse_unaccounted_loss() {
        let mut report = ConversionReport::default();
        report.degrade_field("reasoning.signature", "destination has no signature field");
        assert!(report.validate(LossPolicy::Reject).is_err());
        assert!(report.validate(LossPolicy::Preserve).is_err());
        assert!(report.validate(LossPolicy::Degrade).is_ok());
    }

    #[test]
    fn required_semantics_fail_even_when_degrading() {
        let mut report = ConversionReport::default();
        report.unsupported_required("tool_call.id", "destination requires an identifier");
        let error = report
            .validate(LossPolicy::Degrade)
            .expect_err("required loss");
        assert_eq!(error.unsupported_required_fields, vec!["tool_call.id"]);
    }

    #[test]
    fn extensions_are_counted_as_preserved_capabilities() {
        let extension = OpaqueExtension::new("provider", "opaque", vec![1]).expect("extension");
        let key = ExtensionKey::new("provider", "opaque").expect("key");
        let mut report = ConversionReport::default();
        report.preserve_extension(&key);
        report.apply_rule("provider.opaque_passthrough");
        assert!(report.is_lossless());
        assert!(report
            .preserved_capabilities
            .contains(&"provider.opaque".to_owned()));
        assert_eq!(report.preserved_extensions, vec![key]);
        assert!(report.warnings.is_empty());
        drop(extension);
    }

    #[test]
    fn warning_builder_keeps_field_and_severity() {
        let mut report = ConversionReport::default();
        report.warn(
            super::ConversionWarning::new("compatibility_rule", "used legacy field")
                .for_field("request.model")
                .with_severity(WarningSeverity::Info),
        );
        assert_eq!(report.warnings[0].field.as_deref(), Some("request.model"));
        assert_eq!(report.warnings[0].severity, WarningSeverity::Info);
    }
}
