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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use pooler_core::Capability;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Url};

/// Table format version. Loading rejects any other value.
pub const PROVIDER_CATALOG_SCHEMA_VERSION: u32 = 1;
/// Maximum bytes accepted for a provider table document.
pub const MAX_PROVIDER_CATALOG_BYTES: usize = 1024 * 1024;
/// Maximum entries accepted in one provider table.
pub const MAX_PROVIDER_CATALOG_ENTRIES: usize = 4096;
/// Maximum UTF-8 bytes accepted for any single field.
pub const MAX_PROVIDER_CATALOG_FIELD_BYTES: usize = 512;
/// Maximum environment-variable hints retained for one provider.
pub const MAX_PROVIDER_ENV_HINTS: usize = 16;
/// Maximum aliases, exclusions, capabilities, and endpoint families retained
/// for one provider integration.
pub const MAX_PROVIDER_INTEGRATION_ITEMS: usize = 512;
/// Maximum required headers or query parameters retained for one integration.
pub const MAX_PROVIDER_REQUIRED_PARAMETERS: usize = 64;

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
    /// in the order that tooling prefers them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Complete provider integration facts. Omitted entries use the documented
    /// OpenAI-compatible defaults rather than becoming endpoint-only records.
    #[serde(default)]
    pub integration: KnownProviderIntegration,
}

/// Zero-config facts applied when a known provider is selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KnownProviderIntegration {
    /// Authentication placement (`bearer_secret`, `x_api_key`, or `header`).
    pub auth_kind: String,
    /// Header used by `auth_kind: header`.
    pub auth_header: Option<String>,
    /// Non-secret prefix used by `auth_kind: header`.
    pub auth_value_prefix: Option<String>,
    /// Bounded model-discovery parser.
    pub discovery_parser: Option<String>,
    /// Absolute model-discovery path.
    pub discovery_path: Option<String>,
    /// Exact upstream-to-public model aliases.
    pub model_aliases: BTreeMap<String, String>,
    /// Provider model names withheld from automatic publication.
    pub model_exclusions: Vec<String>,
    /// Request dialect used as the provider-level fallback.
    pub request_dialect: String,
    /// Conservative provider-level capability hints.
    pub capabilities: Vec<String>,
    /// Response classifier family used for quota and retry evidence.
    pub quota_classifier: String,
    /// Documented endpoint families exposed by this integration.
    pub endpoint_families: Vec<String>,
    /// Non-secret headers required on every provider request.
    pub required_headers: BTreeMap<String, String>,
    /// Non-secret query parameters required on every provider request.
    pub required_query: BTreeMap<String, String>,
    /// Provider-neutral native binding kind.
    pub native_kind: String,
}

impl Default for KnownProviderIntegration {
    fn default() -> Self {
        Self {
            auth_kind: "bearer_secret".to_owned(),
            auth_header: None,
            auth_value_prefix: None,
            discovery_parser: Some("openai".to_owned()),
            discovery_path: Some("/v1/models".to_owned()),
            model_aliases: BTreeMap::new(),
            model_exclusions: Vec::new(),
            request_dialect: "openai".to_owned(),
            capabilities: vec!["text".to_owned(), "streaming".to_owned()],
            quota_classifier: "openai".to_owned(),
            endpoint_families: vec!["chat_completions".to_owned(), "models".to_owned()],
            required_headers: BTreeMap::new(),
            required_query: BTreeMap::new(),
            native_kind: "openai_compatible".to_owned(),
        }
    }
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
            if provider.env.len() > MAX_PROVIDER_ENV_HINTS {
                return Err(ProviderCatalogError::TooManyIntegrationValues {
                    id: id.clone(),
                    field: "env",
                });
            }
            for name in &provider.env {
                bounded_field(name)?;
            }
            let integration = &provider.integration;
            for value in [
                integration.auth_kind.as_str(),
                integration.request_dialect.as_str(),
                integration.quota_classifier.as_str(),
                integration.native_kind.as_str(),
            ] {
                bounded_field(value)?;
            }
            validate_known_value(
                id,
                "auth_kind",
                &integration.auth_kind,
                ["bearer_secret", "header"],
            )?;
            validate_known_value(
                id,
                "request_dialect",
                &integration.request_dialect,
                ["anthropic", "gemini", "openai"],
            )?;
            validate_known_value(
                id,
                "native_kind",
                &integration.native_kind,
                ["anthropic", "gemini", "kimi", "openai_compatible", "xai"],
            )?;
            validate_known_value(
                id,
                "quota_classifier",
                &integration.quota_classifier,
                ["anthropic", "gemini", "kimi", "openai", "xai"],
            )?;
            if let Some(parser) = &integration.discovery_parser {
                validate_known_value(
                    id,
                    "discovery_parser",
                    parser,
                    ["anthropic", "gemini", "kimi", "openai"],
                )?;
            }
            if integration.auth_kind == "header" {
                let header = integration.auth_header.as_deref().ok_or_else(|| {
                    ProviderCatalogError::InvalidIntegration {
                        id: id.clone(),
                        field: "auth_header",
                    }
                })?;
                if !valid_header_name(header) {
                    return Err(ProviderCatalogError::InvalidIntegration {
                        id: id.clone(),
                        field: "auth_header",
                    });
                }
            } else if integration.auth_header.is_some()
                || integration
                    .auth_value_prefix
                    .as_deref()
                    .is_some_and(|prefix| !prefix.is_empty())
            {
                return Err(ProviderCatalogError::InvalidIntegration {
                    id: id.clone(),
                    field: "auth_header",
                });
            }
            if integration.model_aliases.len() > MAX_PROVIDER_INTEGRATION_ITEMS
                || integration.model_exclusions.len() > MAX_PROVIDER_INTEGRATION_ITEMS
                || integration.capabilities.len() > MAX_PROVIDER_INTEGRATION_ITEMS
                || integration.endpoint_families.len() > MAX_PROVIDER_INTEGRATION_ITEMS
            {
                return Err(ProviderCatalogError::TooManyIntegrationValues {
                    id: id.clone(),
                    field: "integration",
                });
            }
            if integration.required_headers.len() > MAX_PROVIDER_REQUIRED_PARAMETERS
                || integration.required_query.len() > MAX_PROVIDER_REQUIRED_PARAMETERS
            {
                return Err(ProviderCatalogError::TooManyIntegrationValues {
                    id: id.clone(),
                    field: "required_parameters",
                });
            }
            for value in integration
                .auth_header
                .iter()
                .chain(integration.auth_value_prefix.iter())
                .chain(integration.discovery_parser.iter())
                .chain(integration.discovery_path.iter())
                .chain(integration.capabilities.iter())
                .chain(integration.model_exclusions.iter())
                .chain(integration.endpoint_families.iter())
                .filter(|value| !value.is_empty())
            {
                bounded_field(value)?;
            }
            if integration.capabilities.iter().any(|name| {
                !Capability::ALL
                    .into_iter()
                    .any(|capability| capability.as_str() == name)
            }) {
                return Err(ProviderCatalogError::InvalidField);
            }
            for (key, value) in integration
                .model_aliases
                .iter()
                .chain(integration.required_headers.iter())
                .chain(integration.required_query.iter())
            {
                bounded_field(key)?;
                bounded_field(value)?;
            }
            if integration.discovery_path.as_deref().is_some_and(|path| {
                !path.starts_with('/')
                    || path.starts_with("//")
                    || path.contains(['?', '#', '\\', '\r', '\n'])
            }) {
                return Err(ProviderCatalogError::InvalidField);
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
    if base_url.len() > MAX_PROVIDER_CATALOG_FIELD_BYTES {
        return false;
    }
    let Ok(url) = Url::parse(base_url) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || base_url.ends_with('/')
    {
        return false;
    }
    let loopback = host_is_loopback(url.host());
    if url.scheme() == "http" && !loopback {
        return false;
    }
    !is_forbidden_network_target(&url) || loopback
}

fn host_is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(host)) => host.trim_end_matches('.').eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn is_forbidden_network_target(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            !host.contains('.')
                || host == "metadata"
                || host == "metadata.google.internal"
                || host == "instance-data.ec2.internal"
                || host.ends_with(".localhost")
                || host.ends_with(".local")
                || host.ends_with(".internal")
                || host.ends_with(".home.arpa")
                || host.ends_with(".test")
                || host.ends_with(".invalid")
                || host.ends_with(".nip.io")
                || host.ends_with(".xip.io")
        }
        Some(Host::Ipv4(address)) => forbidden_ipv4(address),
        Some(Host::Ipv6(address)) => forbidden_ipv6(address),
        None => true,
    }
}

fn forbidden_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_broadcast()
        || first == 0
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && matches!(second, 18 | 19))
}

fn forbidden_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] == 0x2001 && segments[1] == 0x0db8
        || address.to_ipv4_mapped().is_some_and(forbidden_ipv4)
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_CATALOG_FIELD_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn validate_known_value<const N: usize>(
    id: &str,
    field: &'static str,
    value: &str,
    allowed: [&str; N],
) -> Result<(), ProviderCatalogError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(ProviderCatalogError::UnknownIntegrationValue {
            id: id.to_owned(),
            field,
        })
    }
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
    #[error("provider `{id}` has an unknown integration value for `{field}`")]
    UnknownIntegrationValue { id: String, field: &'static str },
    #[error("provider `{id}` has an invalid integration field `{field}`")]
    InvalidIntegration { id: String, field: &'static str },
    #[error("provider `{id}` exceeds the bound for integration field `{field}`")]
    TooManyIntegrationValues { id: String, field: &'static str },
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
    fn every_known_provider_has_complete_zero_config_facts() {
        for (id, provider) in ProviderCatalog::builtin().iter() {
            let integration = &provider.integration;
            assert!(!integration.auth_kind.is_empty(), "{id}: auth placement");
            assert!(
                integration.discovery_parser.is_some(),
                "{id}: discovery parser"
            );
            assert!(integration.discovery_path.is_some(), "{id}: discovery path");
            assert!(!integration.request_dialect.is_empty(), "{id}: dialect");
            assert!(!integration.capabilities.is_empty(), "{id}: capabilities");
            assert!(!integration.quota_classifier.is_empty(), "{id}: quota");
            assert!(
                !integration.endpoint_families.is_empty(),
                "{id}: endpoint families"
            );
            assert!(!integration.native_kind.is_empty(), "{id}: native kind");
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
    fn stable_provider_ids_allow_duplicate_public_origins() {
        let document = br#"{
            "schema_version": 1,
            "providers": {
                "account-a": {"name":"A","base_url":"https://shared.example.com/v1"},
                "account-b": {"name":"B","base_url":"https://shared.example.com/v1"}
            }
        }"#;
        let catalog = ProviderCatalog::from_json(document).expect("duplicate origin is valid");
        assert_eq!(catalog.len(), 2);
        assert_eq!(
            catalog.get("account-a").expect("account a").base_url,
            catalog.get("account-b").expect("account b").base_url
        );
    }

    #[test]
    fn unknown_wire_auth_and_dialect_values_are_rejected() {
        for (field, value) in [
            ("auth_kind", "unknown_auth"),
            ("request_dialect", "unknown_wire"),
            ("native_kind", "unknown_native"),
            ("quota_classifier", "unknown_quota"),
        ] {
            let document = format!(
                r#"{{"schema_version":1,"providers":{{"p":{{"name":"P","base_url":"https://provider.example/v1","integration":{{"{field}":"{value}"}}}}}}}}"#
            );
            assert!(
                matches!(
                    ProviderCatalog::from_json(document.as_bytes()),
                    Err(ProviderCatalogError::UnknownIntegrationValue { .. })
                ),
                "unknown {field} must be rejected"
            );
        }
    }

    #[test]
    fn provider_catalog_rejects_credential_and_ssrf_url_shapes() {
        for base_url in [
            "https://user:secret@provider.example/v1",
            "https://provider.example/v1?token=secret",
            "https://provider.example/v1#fragment",
            "https://10.0.0.1/v1",
            "https://169.254.169.254/v1",
            "https://metadata.google.internal/v1",
            "http://provider.example/v1",
        ] {
            let document = format!(
                r#"{{"schema_version":1,"providers":{{"p":{{"name":"P","base_url":"{base_url}"}}}}}}"#
            );
            assert!(
                matches!(
                    ProviderCatalog::from_json(document.as_bytes()),
                    Err(ProviderCatalogError::InvalidBaseUrl { .. })
                ),
                "unsafe base URL {base_url} must be rejected"
            );
        }
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
