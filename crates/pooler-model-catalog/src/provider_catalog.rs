//! Base URLs and credential environment names for known providers.
//!
//! Reaching a provider requires its base URL, which every operator would
//! otherwise transcribe by hand into configuration. This table records that
//! endpoint once, as repository data, so `known_provider: groq` is enough to
//! address Groq.
//!
//! Unlike per-model request facts, which change as providers ship models and
//! are therefore projected from an upstream catalog, a provider's base URL is
//! near-static. This table is owned here and edited directly: it has no
//! upstream document, no refresh command, and no staleness gate.
//!
//! A provider whose endpoint cannot be written as one fixed URL is absent
//! rather than approximated. Azure OpenAI embeds a resource name, Bedrock a
//! region, and Vertex a project and location, so those upstreams declare `url`
//! explicitly and no entry here could substitute for it.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Table format version. Loading rejects any other value.
pub const PROVIDER_CATALOG_SCHEMA_VERSION: u32 = 1;
/// Maximum bytes accepted for a provider table document.
pub const MAX_PROVIDER_CATALOG_BYTES: usize = 1024 * 1024;
/// Maximum entries accepted in one provider table.
pub const MAX_PROVIDER_CATALOG_ENTRIES: usize = 4096;
/// Maximum UTF-8 bytes accepted for any single field.
pub const MAX_PROVIDER_CATALOG_FIELD_BYTES: usize = 512;

const BUILTIN_CATALOG: &str = include_str!("../data/providers.json");

/// Known providers, keyed by provider ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCatalog {
    schema_version: u32,
    providers: BTreeMap<String, KnownProvider>,
}

/// One provider's addressable endpoint and credential environment names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnownProvider {
    /// Display name as the provider writes it.
    pub name: String,
    /// Base URL every request to this provider is built on.
    pub base_url: String,
    /// Environment variables this provider's own tooling reads its key from,
    /// in the order that tooling prefers them. Present for suggestion only;
    /// configuration still names the secret it uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

impl ProviderCatalog {
    /// The table compiled into this build.
    ///
    /// ```
    /// use pooler_model_catalog::ProviderCatalog;
    ///
    /// let catalog = ProviderCatalog::builtin();
    /// assert_eq!(
    ///     catalog.get("groq").expect("groq is known").base_url,
    ///     "https://api.groq.com/openai/v1"
    /// );
    /// assert!(catalog.get("azure").is_none());
    /// ```
    #[must_use]
    pub fn builtin() -> &'static Self {
        static BUILTIN: OnceLock<ProviderCatalog> = OnceLock::new();
        BUILTIN.get_or_init(|| {
            Self::from_json(BUILTIN_CATALOG.as_bytes()).expect("vendored provider catalog is valid")
        })
    }

    /// Parse and validate a provider table.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProviderCatalogError> {
        if bytes.len() > MAX_PROVIDER_CATALOG_BYTES {
            return Err(ProviderCatalogError::TooLarge {
                actual: bytes.len(),
                maximum: MAX_PROVIDER_CATALOG_BYTES,
            });
        }
        let catalog: Self =
            serde_json::from_slice(bytes).map_err(|_| ProviderCatalogError::InvalidDocument)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// One known provider, or `None` when the ID is not recorded.
    #[must_use]
    pub fn get(&self, provider: &str) -> Option<&KnownProvider> {
        self.providers.get(provider)
    }

    /// Every known provider ID and entry, in ID order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &KnownProvider)> {
        self.providers
            .iter()
            .map(|(id, provider)| (id.as_str(), provider))
    }

    /// Recorded providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether the table records no provider.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    fn validate(&self) -> Result<(), ProviderCatalogError> {
        if self.schema_version != PROVIDER_CATALOG_SCHEMA_VERSION {
            return Err(ProviderCatalogError::UnsupportedSchemaVersion {
                found: self.schema_version,
                expected: PROVIDER_CATALOG_SCHEMA_VERSION,
            });
        }
        if self.providers.len() > MAX_PROVIDER_CATALOG_ENTRIES {
            return Err(ProviderCatalogError::TooManyEntries {
                actual: self.providers.len(),
                maximum: MAX_PROVIDER_CATALOG_ENTRIES,
            });
        }
        for (id, provider) in &self.providers {
            bounded_field(id)?;
            bounded_field(&provider.name)?;
            bounded_field(&provider.base_url)?;
            for name in &provider.env {
                bounded_field(name)?;
            }
            // A base URL carrying a query or fragment would be silently
            // dropped when a request path is applied to it, and a template
            // placeholder would be sent literally.
            if !base_url_is_addressable(&provider.base_url) {
                return Err(ProviderCatalogError::InvalidBaseUrl { id: id.clone() });
            }
        }
        Ok(())
    }
}

/// Whether a base URL is a plain origin and path a request can be built on.
///
/// Cleartext is accepted only for a loopback host, where the provider is a
/// model server running beside Pooler and there is no network to protect.
fn base_url_is_addressable(base_url: &str) -> bool {
    let rest = match base_url.strip_prefix("https://") {
        Some(rest) => rest,
        None => match base_url.strip_prefix("http://") {
            Some(rest) if host_is_loopback(rest) => rest,
            _ => return false,
        },
    };
    !rest.is_empty()
        && !base_url.contains(['?', '#', '$', '{'])
        && !base_url.ends_with('/')
        && !rest.starts_with('/')
}

fn host_is_loopback(rest: &str) -> bool {
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

fn bounded_field(value: &str) -> Result<(), ProviderCatalogError> {
    if value.trim().is_empty() || value.len() > MAX_PROVIDER_CATALOG_FIELD_BYTES {
        return Err(ProviderCatalogError::InvalidField);
    }
    Ok(())
}

/// Failure loading a provider table.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderCatalogError {
    #[error("provider catalog is {actual} bytes, exceeding the {maximum} byte bound")]
    TooLarge { actual: usize, maximum: usize },
    #[error("provider catalog is not a valid catalog document")]
    InvalidDocument,
    #[error("provider catalog schema version {found} is not the supported version {expected}")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("provider catalog records {actual} providers, exceeding the {maximum} entry bound")]
    TooManyEntries { actual: usize, maximum: usize },
    #[error("provider catalog field is empty or exceeds its length bound")]
    InvalidField,
    #[error("provider `{id}` has a base URL that is not a plain absolute HTTPS origin and path")]
    InvalidBaseUrl { id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_table_covers_the_providers_operators_ask_for_by_name() {
        let catalog = ProviderCatalog::builtin();
        assert!(
            catalog.len() > 150,
            "expected broad coverage, found {}",
            catalog.len()
        );
        for id in [
            "openai",
            "anthropic",
            "google",
            "groq",
            "xai",
            "mistral",
            "deepseek",
            "openrouter",
            "cerebras",
            "togetherai",
        ] {
            let provider = catalog
                .get(id)
                .unwrap_or_else(|| panic!("`{id}` must be a known provider"));
            assert!(provider.base_url.starts_with("https://"));
            assert!(!provider.env.is_empty(), "`{id}` must suggest a key source");
        }
    }

    #[test]
    fn a_provider_whose_endpoint_needs_operator_input_is_absent() {
        let catalog = ProviderCatalog::builtin();
        // Azure embeds a resource name, Bedrock a region, Vertex a project and
        // location, and these five embed an account or host in the catalog's
        // own URL template. A fixed base URL cannot address any of them.
        for id in [
            "azure",
            "azure-cognitive-services",
            "amazon-bedrock",
            "google-vertex",
            "cloudflare-workers-ai",
            "snowflake-cortex",
            "databricks",
        ] {
            assert!(
                catalog.get(id).is_none(),
                "`{id}` cannot be reduced to one base URL"
            );
        }
    }

    #[test]
    fn a_templated_or_relative_base_url_is_rejected() {
        let document = br#"{"schema_version":1,"providers":{"p":{"name":"P","base_url":"https://x/${VAR}/v1"}}}"#;
        assert_eq!(
            ProviderCatalog::from_json(document),
            Err(ProviderCatalogError::InvalidBaseUrl { id: "p".to_owned() })
        );

        let trailing =
            br#"{"schema_version":1,"providers":{"p":{"name":"P","base_url":"https://x/v1/"}}}"#;
        assert!(matches!(
            ProviderCatalog::from_json(trailing),
            Err(ProviderCatalogError::InvalidBaseUrl { .. })
        ));

        let insecure =
            br#"{"schema_version":1,"providers":{"p":{"name":"P","base_url":"http://x/v1"}}}"#;
        assert!(matches!(
            ProviderCatalog::from_json(insecure),
            Err(ProviderCatalogError::InvalidBaseUrl { .. })
        ));
    }

    #[test]
    fn cleartext_is_accepted_only_for_a_local_model_server() {
        let loopback = br#"{"schema_version":1,"providers":{"p":{"name":"P","base_url":"http://127.0.0.1:1234/v1"}}}"#;
        assert_eq!(
            ProviderCatalog::from_json(loopback)
                .expect("loopback cleartext is addressable")
                .get("p")
                .expect("provider p")
                .base_url,
            "http://127.0.0.1:1234/v1"
        );

        // A host that merely begins with a loopback label is not loopback.
        let spoofed = br#"{"schema_version":1,"providers":{"p":{"name":"P","base_url":"http://127.0.0.1.example.com/v1"}}}"#;
        assert!(matches!(
            ProviderCatalog::from_json(spoofed),
            Err(ProviderCatalogError::InvalidBaseUrl { .. })
        ));

        assert!(ProviderCatalog::builtin()
            .iter()
            .filter(|(_, provider)| provider.base_url.starts_with("http://"))
            .all(|(_, provider)| provider.base_url.contains("127.0.0.1")
                || provider.base_url.contains("localhost")));
    }

    #[test]
    fn an_unknown_field_or_version_is_rejected() {
        let versioned =
            br#"{"schema_version":2,"providers":{"p":{"name":"P","base_url":"https://x/v1"}}}"#;
        assert_eq!(
            ProviderCatalog::from_json(versioned),
            Err(ProviderCatalogError::UnsupportedSchemaVersion {
                found: 2,
                expected: 1
            })
        );

        let extra = br#"{"schema_version":1,"providers":{"p":{"name":"P","base_url":"https://x/v1","protocol":"openai"}}}"#;
        assert_eq!(
            ProviderCatalog::from_json(extra),
            Err(ProviderCatalogError::InvalidDocument)
        );
    }
}
