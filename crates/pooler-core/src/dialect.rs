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

/// Evidence-backed support for a model feature.
///
/// `Unknown` deliberately preserves existing runtime behavior. It must not be
/// treated as positive capability evidence, but it also must not reject a
/// request that an unobserved model may accept.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FactSupport {
    /// No authoritative model fact is available.
    #[default]
    Unknown,
    /// The upstream catalog explicitly advertises support.
    Supported,
    /// The upstream catalog explicitly advertises no support.
    Unsupported,
}

impl FactSupport {
    /// Whether this fact carries no observation.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Whether this fact positively advertises support.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }

    /// Whether this fact explicitly rules support out.
    #[must_use]
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::Unsupported)
    }
}

/// Allowed reasoning-effort labels reported for one model.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReasoningEffortSupport {
    #[serde(skip_serializing_if = "is_false")]
    pub none: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub minimal: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub low: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub medium: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub high: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub xhigh: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub max: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub default: bool,
}

impl ReasoningEffortSupport {
    /// Whether no bounded effort vocabulary was reported.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.none
            && !self.minimal
            && !self.low
            && !self.medium
            && !self.high
            && !self.xhigh
            && !self.max
            && !self.default
    }

    /// Whether a canonical or provider-specific effort label is allowed.
    /// An empty set means the provider did not publish a bounded vocabulary.
    #[must_use]
    pub fn allows(&self, effort: &str) -> bool {
        self.is_empty()
            || match effort {
                "none" => self.none,
                "minimal" => self.minimal,
                "low" => self.low,
                "medium" => self.medium,
                "high" => self.high,
                "xhigh" => self.xhigh,
                "max" => self.max,
                "default" => self.default,
                _ => false,
            }
    }

    /// Record one known effort label, ignoring vocabulary Pooler cannot name.
    pub fn insert(&mut self, effort: &str) {
        match effort {
            "none" => self.none = true,
            "minimal" => self.minimal = true,
            "low" => self.low = true,
            "medium" => self.medium = true,
            "high" => self.high = true,
            "xhigh" => self.xhigh = true,
            "max" => self.max = true,
            "default" => self.default = true,
            _ => {}
        }
    }
}

/// Media modalities accepted or produced by a model.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelModalities {
    #[serde(skip_serializing_if = "is_false")]
    pub text: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub image: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub audio: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub pdf: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub video: bool,
}

impl ModelModalities {
    /// Whether the upstream supplied no modality observation.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.text && !self.image && !self.audio && !self.pdf && !self.video
    }

    /// Record one known models.dev modality, ignoring future vocabulary.
    pub fn insert(&mut self, modality: &str) {
        match modality {
            "text" => self.text = true,
            "image" => self.image = true,
            "audio" => self.audio = true,
            "pdf" => self.pdf = true,
            "video" => self.video = true,
            _ => {}
        }
    }
}

/// Provider request field used for a model's output-token ceiling.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenLimitField {
    /// Let the selected protocol adapter choose its documented default.
    #[default]
    ProtocolDefault,
    MaxTokens,
    MaxCompletionTokens,
    MaxOutputTokens,
    GenerationConfigMaxOutputTokens,
}

impl TokenLimitField {
    #[must_use]
    pub const fn is_protocol_default(&self) -> bool {
        matches!(self, Self::ProtocolDefault)
    }
}

/// Provider transformation family used to encode a semantic model request.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRequestTransform {
    /// Let the configured protocol adapter select its normal behavior.
    #[default]
    ProtocolDefault,
    #[serde(rename = "openai_chat")]
    OpenAiChat,
    AnthropicMessages,
    GeminiGenerateContent,
    #[serde(rename = "xai_chat")]
    XaiChat,
    KimiChat,
}

impl ModelRequestTransform {
    #[must_use]
    pub const fn is_protocol_default(&self) -> bool {
        matches!(self, Self::ProtocolDefault)
    }
}

/// Response field carrying interleaved reasoning, when documented.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterleavedReasoningField {
    ReasoningContent,
    ReasoningDetails,
}

/// Endpoint families known to accept this model.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelEndpointVariants {
    #[serde(skip_serializing_if = "is_false")]
    pub chat_completions: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub responses: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub messages: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub generate_content: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub realtime: bool,
}

impl ModelEndpointVariants {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.chat_completions
            && !self.responses
            && !self.messages
            && !self.generate_content
            && !self.realtime
    }
}

/// Bounded, evidence-backed facts for one upstream model.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelProfile {
    #[serde(flatten)]
    pub dialect: ModelDialect,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub reasoning: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub tools: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub parallel_tools: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub structured_output: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub attachments: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub streaming: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub reasoning_toggle: FactSupport,
    #[serde(skip_serializing_if = "FactSupport::is_unknown")]
    pub reasoning_budget_tokens: FactSupport,
    #[serde(skip_serializing_if = "ReasoningEffortSupport::is_empty")]
    pub reasoning_efforts: ReasoningEffortSupport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interleaved_reasoning: Option<InterleavedReasoningField>,
    #[serde(skip_serializing_if = "ModelModalities::is_empty")]
    pub input_modalities: ModelModalities,
    #[serde(skip_serializing_if = "ModelModalities::is_empty")]
    pub output_modalities: ModelModalities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_limit: Option<u64>,
    #[serde(skip_serializing_if = "TokenLimitField::is_protocol_default")]
    pub token_limit_field: TokenLimitField,
    #[serde(skip_serializing_if = "ModelRequestTransform::is_protocol_default")]
    pub request_transform: ModelRequestTransform,
    #[serde(skip_serializing_if = "ModelEndpointVariants::is_empty")]
    pub endpoint_variants: ModelEndpointVariants,
}

impl ModelProfile {
    pub const DEFAULT: Self = Self {
        dialect: ModelDialect::DEFAULT,
        reasoning: FactSupport::Unknown,
        tools: FactSupport::Unknown,
        parallel_tools: FactSupport::Unknown,
        structured_output: FactSupport::Unknown,
        attachments: FactSupport::Unknown,
        streaming: FactSupport::Unknown,
        reasoning_toggle: FactSupport::Unknown,
        reasoning_budget_tokens: FactSupport::Unknown,
        reasoning_efforts: ReasoningEffortSupport {
            none: false,
            minimal: false,
            low: false,
            medium: false,
            high: false,
            xhigh: false,
            max: false,
            default: false,
        },
        interleaved_reasoning: None,
        input_modalities: ModelModalities {
            text: false,
            image: false,
            audio: false,
            pdf: false,
            video: false,
        },
        output_modalities: ModelModalities {
            text: false,
            image: false,
            audio: false,
            pdf: false,
            video: false,
        },
        context_limit: None,
        input_limit: None,
        output_limit: None,
        token_limit_field: TokenLimitField::ProtocolDefault,
        request_transform: ModelRequestTransform::ProtocolDefault,
        endpoint_variants: ModelEndpointVariants {
            chat_completions: false,
            responses: false,
            messages: false,
            generate_content: false,
            realtime: false,
        },
    };

    #[must_use]
    pub fn is_default(self) -> bool {
        self == Self::DEFAULT
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
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

    #[test]
    fn model_profiles_distinguish_unknown_supported_and_unsupported_facts() {
        let mut profile = ModelProfile::DEFAULT;
        profile.reasoning = FactSupport::Supported;
        profile.tools = FactSupport::Unsupported;
        profile.reasoning_efforts.insert("low");
        profile.reasoning_efforts.insert("xhigh");
        profile.input_modalities.insert("image");
        profile.context_limit = Some(128_000);

        assert!(profile.reasoning.is_supported());
        assert!(profile.tools.is_unsupported());
        assert!(profile.parallel_tools.is_unknown());
        assert!(profile.reasoning_efforts.allows("low"));
        assert!(!profile.reasoning_efforts.allows("medium"));
        assert!(profile.input_modalities.image);
        assert!(!profile.is_default());
        let encoded = serde_json::to_string(&profile).expect("serialize profile");
        assert_eq!(
            serde_json::from_str::<ModelProfile>(&encoded).expect("deserialize profile"),
            profile
        );
    }
}
