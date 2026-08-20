//! Operator overrides applied to the merged model catalog.
//!
//! Discovery reports what a provider currently serves. It does not know which
//! of those models an operator wants exposed, nor the facts a provider list
//! endpoint never carries. An override is how that judgment is recorded, keyed
//! by the client-visible model ID so an operator names the model exactly as
//! their clients do rather than tracking upstream names and prefixes.
//!
//! Overrides are applied after the merge folds every source together, so they
//! outrank source policy, provider-reported capabilities, and the vendored
//! request-facts snapshot. That ordering is the point: the operator is the last
//! word on their own catalog.
//!
//! An override that matches no model is retained as a diagnostic rather than
//! failing the refresh. A model can disappear upstream for reasons that have
//! nothing to do with the operator's config, and dropping the whole catalog in
//! response would turn a provider's outage into a local one.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use pooler_core::{CapabilitySet, ModelDialect};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CatalogError, CatalogModel, ModelId, MAX_DISPLAY_NAME_BYTES};

/// Maximum per-model overrides accepted for one catalog.
pub const MAX_MODEL_OVERRIDES: usize = 1_024;
/// Maximum request-overlay fields accepted for one model.
pub const MAX_OVERLAY_FIELDS: usize = 32;
/// Maximum UTF-8 bytes accepted for one overlay JSON pointer.
pub const MAX_OVERLAY_POINTER_BYTES: usize = 256;
/// Maximum UTF-8 bytes accepted for one serialized overlay value.
pub const MAX_OVERLAY_VALUE_BYTES: usize = 4_096;

/// Request body fields an operator pins for one model.
///
/// A route-level transform can already set a field for every model matching a
/// prefix. This is the same operation scoped to one model, which is what lets
/// an operator say "send this reasoning effort to this model" without the
/// declaration also applying to every sibling that shares its prefix.
///
/// Fields are applied after the model name is rewritten and before the request
/// leaves, in declaration order, so a later field may overwrite an earlier one
/// at the same pointer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RequestOverlay {
    fields: Arc<[(Arc<str>, Value)]>,
}

// `serde_json::Value` is only `PartialEq` because it can hold a non-reflexive
// float. A value here is always produced by parsing JSON, and JSON has no
// literal for `NaN`, so equality is reflexive for every value this type can
// actually hold.
impl Eq for RequestOverlay {}

impl RequestOverlay {
    /// Whether this overlay pins no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Pinned fields as JSON pointer and value pairs, in declaration order.
    #[must_use]
    pub fn fields(&self) -> &[(Arc<str>, Value)] {
        &self.fields
    }

    fn compile(declared: BTreeMap<String, Value>, model: &ModelId) -> Result<Self, CatalogError> {
        if declared.len() > MAX_OVERLAY_FIELDS {
            return Err(CatalogError::OverlayLimitExceeded {
                model: model.clone(),
                actual: declared.len(),
                maximum: MAX_OVERLAY_FIELDS,
            });
        }
        let mut fields = Vec::with_capacity(declared.len());
        for (pointer, value) in declared {
            let pointer = pointer.trim();
            if !pointer.starts_with('/') || pointer.len() > MAX_OVERLAY_POINTER_BYTES {
                return Err(CatalogError::InvalidOverlayPointer {
                    model: model.clone(),
                    pointer: pointer.to_owned(),
                });
            }
            if serde_json::to_string(&value)
                .map_or(true, |text| text.len() > MAX_OVERLAY_VALUE_BYTES)
            {
                return Err(CatalogError::OverlayValueTooLarge {
                    model: model.clone(),
                    pointer: pointer.to_owned(),
                });
            }
            fields.push((Arc::from(pointer), value));
        }
        Ok(Self {
            fields: Arc::from(fields),
        })
    }
}

impl Serialize for RequestOverlay {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_map(
            self.fields
                .iter()
                .map(|(pointer, value)| (pointer.as_ref(), value)),
        )
    }
}

/// Strict override declaration for one client-visible model.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelOverrideConfig {
    /// Client-visible model ID, including any source prefix.
    pub model: String,
    /// Withhold this model from the published catalog.
    pub disabled: bool,
    /// Replacement display name.
    pub display_name: Option<String>,
    /// Replacement capability set, authoritative over what providers report.
    pub capabilities: Option<CapabilitySet>,
    /// Replacement request-shaping facts, applied to every target.
    pub dialect: Option<ModelDialect>,
    /// Request body fields pinned for this model, keyed by JSON pointer.
    ///
    /// This is where a per-model reasoning setting lives, since which field
    /// carries it differs by provider and only the operator knows which one
    /// their target accepts.
    pub request: BTreeMap<String, Value>,
}

impl ModelOverrideConfig {
    /// Validate and compile one override declaration.
    fn compile(self) -> Result<(ModelId, ModelOverride), CatalogError> {
        let model =
            ModelId::new(self.model).map_err(|error| CatalogError::InvalidOverrideModel {
                message: error.to_string(),
            })?;
        if let Some(display_name) = self.display_name.as_deref() {
            if display_name.is_empty()
                || display_name.len() > MAX_DISPLAY_NAME_BYTES
                || display_name.chars().any(char::is_control)
            {
                return Err(CatalogError::InvalidOverrideDisplayName { model });
            }
        }
        let overlay = RequestOverlay::compile(self.request, &model)?;
        let overridden = ModelOverride {
            disabled: self.disabled,
            display_name: self.display_name,
            capabilities: self.capabilities,
            dialect: self.dialect,
            overlay,
        };
        // An override that changes nothing is a declaration whose intent was
        // lost, most often a misspelled field name, so it is reported rather
        // than silently retained as a no-op.
        if !overridden.changes_anything() {
            return Err(CatalogError::EmptyOverride { model });
        }
        Ok((model, overridden))
    }
}

/// One compiled override for a client-visible model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelOverride {
    disabled: bool,
    display_name: Option<String>,
    capabilities: Option<CapabilitySet>,
    dialect: Option<ModelDialect>,
    overlay: RequestOverlay,
}

impl ModelOverride {
    /// Whether this override withholds the model from the catalog.
    #[must_use]
    pub const fn disabled(&self) -> bool {
        self.disabled
    }

    /// Replacement display name, when one was declared.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Replacement capability set, when one was declared.
    #[must_use]
    pub const fn capabilities(&self) -> Option<CapabilitySet> {
        self.capabilities
    }

    /// Replacement dialect, when one was declared.
    #[must_use]
    pub const fn dialect(&self) -> Option<ModelDialect> {
        self.dialect
    }

    /// Request body fields pinned for this model.
    #[must_use]
    pub const fn overlay(&self) -> &RequestOverlay {
        &self.overlay
    }

    fn changes_anything(&self) -> bool {
        self.disabled
            || self.display_name.is_some()
            || self.capabilities.is_some()
            || self.dialect.is_some()
            || !self.overlay.is_empty()
    }

    /// Rewrite one merged model with the facts this override declares.
    ///
    /// Capabilities and dialect are replacements rather than merges. The merge
    /// intersects capabilities across sources because two sources disagreeing
    /// about a model is a reason for caution; an operator stating a capability
    /// is not a disagreement, so intersecting their answer with the providers'
    /// would make the override unable to add anything back.
    fn apply(&self, mut model: CatalogModel) -> CatalogModel {
        if let Some(display_name) = &self.display_name {
            model.display_name = Some(display_name.clone());
        }
        if !self.overlay.is_empty() {
            model.request_overlay = self.overlay.clone();
        }
        for target in &mut model.targets {
            if let Some(capabilities) = self.capabilities {
                target.capabilities = capabilities;
            }
            if let Some(dialect) = self.dialect {
                target.dialect = dialect;
            }
        }
        model
    }
}

/// Compiled per-model overrides, keyed by client-visible model ID.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelOverrides {
    entries: BTreeMap<ModelId, ModelOverride>,
}

impl ModelOverrides {
    /// Validate and compile a set of override declarations.
    pub fn compile(declarations: Vec<ModelOverrideConfig>) -> Result<Self, CatalogError> {
        if declarations.len() > MAX_MODEL_OVERRIDES {
            return Err(CatalogError::OverrideLimitExceeded {
                actual: declarations.len(),
                maximum: MAX_MODEL_OVERRIDES,
            });
        }
        let mut entries = BTreeMap::new();
        for declaration in declarations {
            let (model, overridden) = declaration.compile()?;
            if entries.insert(model.clone(), overridden).is_some() {
                return Err(CatalogError::DuplicateOverride { model });
            }
        }
        Ok(Self { entries })
    }

    /// Whether any override was declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of declared overrides.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Override declared for one client-visible model, if any.
    #[must_use]
    pub fn get(&self, model: &ModelId) -> Option<&ModelOverride> {
        self.entries.get(model)
    }

    /// Declared overrides in model-ID order.
    pub fn iter(&self) -> impl Iterator<Item = (&ModelId, &ModelOverride)> {
        self.entries.iter()
    }

    /// Apply every override to the merged models, reporting what each did.
    ///
    /// Returns the surviving models and the state needed to explain the result:
    /// which models an operator withheld, and which overrides matched nothing.
    pub(crate) fn apply_all(
        &self,
        models: BTreeMap<ModelId, CatalogModel>,
    ) -> (BTreeMap<ModelId, CatalogModel>, OverrideState) {
        if self.entries.is_empty() {
            return (models, OverrideState::default());
        }
        let mut retained = BTreeMap::new();
        let mut disabled_models = Vec::new();
        let mut matched = BTreeSet::new();
        for (public_id, model) in models {
            let Some(overridden) = self.entries.get(&public_id) else {
                retained.insert(public_id, model);
                continue;
            };
            matched.insert(public_id.clone());
            if overridden.disabled {
                disabled_models.push(public_id);
                continue;
            }
            retained.insert(public_id.clone(), overridden.apply(model));
        }
        let unmatched_models = self
            .entries
            .keys()
            .filter(|model| !matched.contains(*model))
            .cloned()
            .collect();
        (
            retained,
            OverrideState {
                disabled_models,
                unmatched_models,
            },
        )
    }
}

/// What the declared overrides did to the published catalog.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct OverrideState {
    disabled_models: Vec<ModelId>,
    unmatched_models: Vec<ModelId>,
}

impl OverrideState {
    /// Models withheld from the catalog by an operator override.
    #[must_use]
    pub fn disabled_models(&self) -> &[ModelId] {
        &self.disabled_models
    }

    /// Overrides that matched no discovered model.
    ///
    /// A non-empty list is worth surfacing: it is either a typo in a model ID
    /// or a model the provider stopped serving.
    #[must_use]
    pub fn unmatched_models(&self) -> &[ModelId] {
        &self.unmatched_models
    }
}

#[cfg(test)]
mod tests {
    use pooler_core::{Capability, ParamSupport};

    use super::*;

    fn declaration(model: &str) -> ModelOverrideConfig {
        ModelOverrideConfig {
            model: model.to_owned(),
            ..ModelOverrideConfig::default()
        }
    }

    #[test]
    fn an_override_that_changes_nothing_is_rejected() {
        let error = ModelOverrides::compile(vec![declaration("gpt-4o")])
            .expect_err("a no-op override is reported");
        assert!(matches!(error, CatalogError::EmptyOverride { .. }));
    }

    #[test]
    fn overrides_are_keyed_by_public_model_id_and_reject_duplicates() {
        let error = ModelOverrides::compile(vec![
            ModelOverrideConfig {
                disabled: true,
                ..declaration("gpt-4o")
            },
            ModelOverrideConfig {
                disabled: true,
                ..declaration("gpt-4o")
            },
        ])
        .expect_err("a repeated model is reported");
        assert!(matches!(error, CatalogError::DuplicateOverride { .. }));
    }

    #[test]
    fn a_control_character_display_name_is_rejected() {
        let error = ModelOverrides::compile(vec![ModelOverrideConfig {
            display_name: Some("bad\nname".to_owned()),
            ..declaration("gpt-4o")
        }])
        .expect_err("a control character is reported");
        assert!(matches!(
            error,
            CatalogError::InvalidOverrideDisplayName { .. }
        ));
    }

    #[test]
    fn a_declared_capability_set_replaces_what_providers_reported() {
        let overrides = ModelOverrides::compile(vec![ModelOverrideConfig {
            capabilities: Some(CapabilitySet::from(Capability::Reasoning)),
            dialect: Some(ModelDialect::new().rejecting_temperature()),
            ..declaration("gpt-4o")
        }])
        .expect("overrides compile");
        let overridden = overrides
            .get(&ModelId::new("gpt-4o").expect("model id"))
            .expect("override is keyed by public id");

        assert_eq!(
            overridden.capabilities(),
            Some(CapabilitySet::from(Capability::Reasoning))
        );
        assert_eq!(
            overridden.dialect().map(|dialect| dialect.temperature),
            Some(ParamSupport::Rejected)
        );
        assert!(!overridden.disabled());
    }

    #[test]
    fn unknown_override_fields_are_rejected() {
        serde_json::from_str::<ModelOverrideConfig>(r#"{"model":"a","reasoning":true}"#)
            .expect_err("unknown override fields must be rejected");
    }

    #[test]
    fn a_capability_set_and_dialect_deserialize_from_operator_syntax() {
        let declaration: ModelOverrideConfig = serde_json::from_str(
            r#"{"model":"gpt-4o","capabilities":["text","reasoning"],
                "dialect":{"temperature":"rejected"}}"#,
        )
        .expect("operator syntax deserializes");

        assert_eq!(
            declaration.capabilities,
            Some(
                [Capability::Text, Capability::Reasoning]
                    .into_iter()
                    .collect()
            )
        );
        assert_eq!(
            declaration.dialect.map(|dialect| dialect.temperature),
            Some(ParamSupport::Rejected)
        );
    }
}
