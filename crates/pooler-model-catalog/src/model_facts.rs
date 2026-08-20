//! Pinned per-model request facts vendored as reviewable repository data.
//!
//! Provider model-list endpoints report which models an account may call. They
//! do not report how a request to those models must be shaped: OpenAI's
//! `/v1/models` response, for example, carries no indication that
//! `gpt-image-1.5` rejects `temperature`. Those facts are published by the
//! community catalog at <https://models.dev>, so Pooler pins a projection of
//! that catalog as repository data instead of hardcoding per-model branches in
//! adapters.
//!
//! Only deviations from the protocol default are recorded. A model absent from
//! the snapshot resolves to [`ModelDialect::DEFAULT`], which keeps models that
//! the upstream catalog has never seen working exactly as before.
//!
//! The projection is deliberately free of timestamps. Regenerating it from an
//! unchanged upstream document reproduces the committed bytes, so
//! `pooler catalog refresh --check` is a usable staleness gate.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use pooler_core::{ModelDialect, ParamSupport};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Snapshot format version. Loading rejects any other value.
pub const MODEL_FACTS_SCHEMA_VERSION: u32 = 1;
/// Upstream catalog this projection is derived from.
pub const MODELS_DEV_CATALOG_URL: &str = "https://models.dev/api.json";
/// Maximum bytes accepted for a projected snapshot.
pub const MAX_MODEL_FACTS_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bytes accepted for an upstream catalog document before projection.
pub const MAX_UPSTREAM_CATALOG_BYTES: usize = 32 * 1024 * 1024;
/// Maximum recorded deviations accepted in one snapshot.
pub const MAX_MODEL_FACT_ENTRIES: usize = 100_000;
/// Maximum UTF-8 bytes accepted for a provider or model key.
pub const MAX_MODEL_FACT_KEY_BYTES: usize = 512;

const BUILTIN_SNAPSHOT: &str = include_str!("../data/model-facts.json");
const DIGEST_HEX_LENGTH: usize = 64;

/// Vendored request-shaping facts, keyed by provider then upstream model ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelFacts {
    schema_version: u32,
    source_url: String,
    source_sha256: String,
    upstream_model_count: usize,
    providers: BTreeMap<String, BTreeMap<String, ModelDialect>>,
}

impl ModelFacts {
    /// The snapshot compiled into this build.
    ///
    /// ```
    /// use pooler_core::ParamSupport;
    /// use pooler_model_catalog::ModelFacts;
    ///
    /// let facts = ModelFacts::builtin();
    /// assert_eq!(
    ///     facts.dialect("openai", "gpt-image-1.5").temperature,
    ///     ParamSupport::Rejected
    /// );
    /// assert!(facts.dialect("openai", "gpt-4o").is_default());
    /// ```
    #[must_use]
    pub fn builtin() -> &'static Self {
        static BUILTIN: OnceLock<ModelFacts> = OnceLock::new();
        BUILTIN.get_or_init(|| {
            Self::from_json(BUILTIN_SNAPSHOT.as_bytes())
                .expect("vendored model-facts snapshot is valid")
        })
    }

    /// Parse and validate a projected snapshot.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ModelFactsError> {
        if bytes.len() > MAX_MODEL_FACTS_BYTES {
            return Err(ModelFactsError::TooLarge {
                actual: bytes.len(),
                maximum: MAX_MODEL_FACTS_BYTES,
            });
        }
        let facts: Self =
            serde_json::from_slice(bytes).map_err(|_| ModelFactsError::InvalidSnapshot)?;
        facts.validate()?;
        Ok(facts)
    }

    /// Project an upstream models.dev catalog document into a snapshot.
    ///
    /// Unknown upstream fields are ignored rather than rejected: the upstream
    /// document is a foreign, evolving schema, and failing the projection every
    /// time it grows a field would make the pinned data impossible to refresh.
    pub fn from_models_dev_catalog(
        document: &[u8],
        source_url: &str,
        source_sha256: &str,
    ) -> Result<Self, ModelFactsError> {
        if document.len() > MAX_UPSTREAM_CATALOG_BYTES {
            return Err(ModelFactsError::TooLarge {
                actual: document.len(),
                maximum: MAX_UPSTREAM_CATALOG_BYTES,
            });
        }
        let catalog: BTreeMap<String, UpstreamProvider> = serde_json::from_slice(document)
            .map_err(|_| ModelFactsError::InvalidUpstreamCatalog)?;

        let mut upstream_model_count = 0;
        let mut providers = BTreeMap::new();
        for (provider, upstream) in catalog {
            let mut models = BTreeMap::new();
            for (model, facts) in upstream.models {
                upstream_model_count += 1;
                let dialect = facts.dialect();
                if dialect.is_default() {
                    continue;
                }
                models.insert(model, dialect);
            }
            if !models.is_empty() {
                providers.insert(provider, models);
            }
        }

        let facts = Self {
            schema_version: MODEL_FACTS_SCHEMA_VERSION,
            source_url: source_url.to_owned(),
            source_sha256: source_sha256.to_owned(),
            upstream_model_count,
            providers,
        };
        facts.validate()?;
        Ok(facts)
    }

    /// Facts recorded for one provider's upstream model.
    ///
    /// Absent providers and models resolve to [`ModelDialect::DEFAULT`].
    #[must_use]
    pub fn dialect(&self, provider: &str, model: &str) -> ModelDialect {
        self.providers
            .get(provider)
            .and_then(|models| models.get(model))
            .copied()
            .unwrap_or(ModelDialect::DEFAULT)
    }

    /// Whether this snapshot records any deviation for a provider.
    #[must_use]
    pub fn covers_provider(&self, provider: &str) -> bool {
        self.providers.contains_key(provider)
    }

    /// Upstream catalog URL this projection was derived from.
    #[must_use]
    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    /// Lowercase hexadecimal SHA-256 of the projected upstream document.
    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// Models present in the upstream document, including non-deviating ones.
    #[must_use]
    pub const fn upstream_model_count(&self) -> usize {
        self.upstream_model_count
    }

    /// Providers with at least one recorded deviation.
    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Recorded deviations across every provider.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.providers.values().map(BTreeMap::len).sum()
    }

    /// Render the canonical on-disk form, including its trailing newline.
    pub fn to_canonical_json(&self) -> Result<String, ModelFactsError> {
        let mut rendered =
            serde_json::to_string_pretty(self).map_err(|_| ModelFactsError::InvalidSnapshot)?;
        rendered.push('\n');
        Ok(rendered)
    }

    fn validate(&self) -> Result<(), ModelFactsError> {
        if self.schema_version != MODEL_FACTS_SCHEMA_VERSION {
            return Err(ModelFactsError::UnsupportedSchemaVersion {
                found: self.schema_version,
                expected: MODEL_FACTS_SCHEMA_VERSION,
            });
        }
        if self.source_url.is_empty() || self.source_url.len() > MAX_MODEL_FACT_KEY_BYTES {
            return Err(ModelFactsError::InvalidSourceUrl);
        }
        if self.source_sha256.len() != DIGEST_HEX_LENGTH
            || !self
                .source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ModelFactsError::InvalidSourceDigest);
        }
        let entries = self.entry_count();
        if entries > MAX_MODEL_FACT_ENTRIES {
            return Err(ModelFactsError::TooManyEntries {
                actual: entries,
                maximum: MAX_MODEL_FACT_ENTRIES,
            });
        }
        if self.upstream_model_count < entries {
            return Err(ModelFactsError::InconsistentModelCount);
        }
        for (provider, models) in &self.providers {
            validate_key(provider)?;
            if models.is_empty() {
                return Err(ModelFactsError::EmptyProviderEntry);
            }
            for (model, dialect) in models {
                validate_key(model)?;
                if dialect.is_default() {
                    return Err(ModelFactsError::RedundantDefaultEntry);
                }
            }
        }
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<(), ModelFactsError> {
    if key.trim().is_empty() || key.len() > MAX_MODEL_FACT_KEY_BYTES {
        return Err(ModelFactsError::InvalidKey);
    }
    Ok(())
}

/// Failure loading or projecting vendored model facts.
///
/// No variant retains upstream document text.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ModelFactsError {
    #[error("model facts document is {actual} bytes, exceeding the {maximum} byte bound")]
    TooLarge { actual: usize, maximum: usize },
    #[error("model facts snapshot is not a valid snapshot document")]
    InvalidSnapshot,
    #[error("upstream model catalog is not a valid catalog document")]
    InvalidUpstreamCatalog,
    #[error("model facts schema version {found} is not the supported version {expected}")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("model facts source URL is empty or exceeds its length bound")]
    InvalidSourceUrl,
    #[error("model facts source digest is not lowercase hexadecimal SHA-256")]
    InvalidSourceDigest,
    #[error("model facts record {actual} deviations, exceeding the {maximum} entry bound")]
    TooManyEntries { actual: usize, maximum: usize },
    #[error("model facts record more deviations than upstream models")]
    InconsistentModelCount,
    #[error("model facts provider or model key is empty or exceeds its length bound")]
    InvalidKey,
    #[error("model facts retain a provider with no recorded deviation")]
    EmptyProviderEntry,
    #[error("model facts retain a default dialect that carries no deviation")]
    RedundantDefaultEntry,
}

#[derive(Debug, Deserialize)]
struct UpstreamProvider {
    #[serde(default)]
    models: BTreeMap<String, UpstreamModel>,
}

#[derive(Debug, Deserialize)]
struct UpstreamModel {
    /// Absent means the upstream catalog has no observation, not a rejection.
    #[serde(default)]
    temperature: Option<bool>,
}

impl UpstreamModel {
    fn dialect(&self) -> ModelDialect {
        let mut dialect = ModelDialect::DEFAULT;
        if self.temperature == Some(false) {
            dialect.temperature = ParamSupport::Rejected;
        }
        dialect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn projected(document: &str) -> ModelFacts {
        ModelFacts::from_models_dev_catalog(document.as_bytes(), MODELS_DEV_CATALOG_URL, DIGEST)
            .expect("projection succeeds")
    }

    #[test]
    fn builtin_snapshot_loads_and_records_a_known_deviation() {
        let facts = ModelFacts::builtin();
        assert_eq!(facts.source_url(), MODELS_DEV_CATALOG_URL);
        assert!(facts.entry_count() > 0);
        assert!(facts.upstream_model_count() >= facts.entry_count());
        assert_eq!(
            facts.dialect("openai", "gpt-image-1.5").temperature,
            ParamSupport::Rejected
        );
    }

    #[test]
    fn unknown_providers_and_models_resolve_to_the_default_dialect() {
        let facts = ModelFacts::builtin();
        assert!(facts
            .dialect("provider-absent-from-catalog", "any")
            .is_default());
        assert!(facts
            .dialect("openai", "model-absent-from-catalog")
            .is_default());
    }

    #[test]
    fn projection_records_only_rejections_and_counts_every_upstream_model() {
        let facts = projected(
            r#"{
              "openai": {"id":"openai","models":{
                "keeps-temperature":{"temperature":true},
                "rejects-temperature":{"temperature":false},
                "unreported-temperature":{"tool_call":true}
              }},
              "all-default": {"models":{"keeps-temperature":{"temperature":true}}}
            }"#,
        );

        assert_eq!(facts.upstream_model_count(), 4);
        assert_eq!(facts.entry_count(), 1);
        assert_eq!(facts.provider_count(), 1);
        assert!(!facts.covers_provider("all-default"));
        assert_eq!(
            facts.dialect("openai", "rejects-temperature").temperature,
            ParamSupport::Rejected
        );
        assert!(facts
            .dialect("openai", "unreported-temperature")
            .is_default());
    }

    #[test]
    fn projection_ignores_unknown_upstream_fields() {
        let facts = projected(
            r#"{"openai":{"id":"openai","npm":"x","models":{
              "rejects-temperature":{"temperature":false,"future_upstream_field":{"nested":1}}
            }}}"#,
        );

        assert_eq!(facts.entry_count(), 1);
    }

    #[test]
    fn canonical_json_round_trips_and_ends_with_one_newline() {
        let facts = projected(r#"{"openai":{"models":{"m":{"temperature":false}}}}"#);
        let rendered = facts.to_canonical_json().expect("canonical rendering");

        assert!(rendered.ends_with("}\n"));
        assert_eq!(
            ModelFacts::from_json(rendered.as_bytes()).expect("round trip"),
            facts
        );
    }

    #[test]
    fn snapshots_with_an_unsupported_schema_version_are_rejected() {
        let facts = projected(r#"{"openai":{"models":{"m":{"temperature":false}}}}"#);
        let mut document: serde_json::Value =
            serde_json::from_str(&facts.to_canonical_json().expect("render")).expect("value");
        document["schema_version"] = serde_json::json!(MODEL_FACTS_SCHEMA_VERSION + 1);

        assert_eq!(
            ModelFacts::from_json(document.to_string().as_bytes()),
            Err(ModelFactsError::UnsupportedSchemaVersion {
                found: MODEL_FACTS_SCHEMA_VERSION + 1,
                expected: MODEL_FACTS_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn snapshots_carrying_no_deviation_are_rejected_as_noncanonical() {
        let document = format!(
            r#"{{"schema_version":{MODEL_FACTS_SCHEMA_VERSION},"source_url":"{MODELS_DEV_CATALOG_URL}","source_sha256":"{DIGEST}","upstream_model_count":1,"providers":{{"openai":{{"m":{{"temperature":"accepted"}}}}}}}}"#
        );

        assert_eq!(
            ModelFacts::from_json(document.as_bytes()),
            Err(ModelFactsError::RedundantDefaultEntry)
        );
    }

    #[test]
    fn snapshots_with_an_invalid_digest_or_unknown_field_are_rejected() {
        let short_digest = format!(
            r#"{{"schema_version":{MODEL_FACTS_SCHEMA_VERSION},"source_url":"{MODELS_DEV_CATALOG_URL}","source_sha256":"abc","upstream_model_count":1,"providers":{{}}}}"#
        );
        assert_eq!(
            ModelFacts::from_json(short_digest.as_bytes()),
            Err(ModelFactsError::InvalidSourceDigest)
        );

        let unknown_field = format!(
            r#"{{"schema_version":{MODEL_FACTS_SCHEMA_VERSION},"source_url":"{MODELS_DEV_CATALOG_URL}","source_sha256":"{DIGEST}","upstream_model_count":1,"providers":{{}},"fetched_at":"now"}}"#
        );
        assert_eq!(
            ModelFacts::from_json(unknown_field.as_bytes()),
            Err(ModelFactsError::InvalidSnapshot)
        );
    }

    #[test]
    fn upstream_catalogs_that_are_not_provider_maps_are_rejected() {
        assert_eq!(
            ModelFacts::from_models_dev_catalog(b"[]", MODELS_DEV_CATALOG_URL, DIGEST),
            Err(ModelFactsError::InvalidUpstreamCatalog)
        );
        assert_eq!(
            ModelFacts::from_models_dev_catalog(
                br#"{"openai":{"models":{"m":{"temperature":"maybe"}}}}"#,
                MODELS_DEV_CATALOG_URL,
                DIGEST,
            ),
            Err(ModelFactsError::InvalidUpstreamCatalog)
        );
    }
}
