//! Typed, redacted policy helpers for dashboard-started OAuth flows.
//!
//! The durable store owns correlation state and encrypted PKCE material.  This
//! module owns only the small amount of non-secret metadata needed to decide
//! whether a persisted flow may be resumed by a new runtime generation.

use std::fmt;

use pooler_auth::{ProviderLoginMethod, ProviderLoginRegistry, ProviderLoginSupport};
use pooler_config::{AccountAuthKind, CompiledConfig, OAuthGrantType, OAuthPlan};
use ring::digest::{digest, SHA256};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

/// Current management OAuth metadata encoding.
pub(crate) const FLOW_METADATA_VERSION: &str = "oauth:v1";

/// One dashboard-supported OAuth mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OAuthMethod {
    DeviceCode,
    BrowserPkce,
    ClientCredentials,
}

impl OAuthMethod {
    /// Parse the stable API spelling and its deliberately small aliases.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "device" | "device_code" | "device-code" => Some(Self::DeviceCode),
            "browser" | "browser_pkce" | "authorization_code_pkce" | "authorization-code-pkce" => {
                Some(Self::BrowserPkce)
            }
            "client_credentials" | "client-credentials" => Some(Self::ClientCredentials),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceCode => "device_code",
            Self::BrowserPkce => "browser_pkce",
            Self::ClientCredentials => "client_credentials",
        }
    }

    const fn configured_grant(self) -> Option<OAuthGrantType> {
        match self {
            Self::DeviceCode => None,
            Self::BrowserPkce => Some(OAuthGrantType::AuthorizationCode),
            Self::ClientCredentials => Some(OAuthGrantType::ClientCredentials),
        }
    }
}

impl fmt::Display for OAuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Body accepted by the generic OAuth start endpoint.  Secret material and
/// provider endpoints are intentionally not accepted here; both come from
/// the canonical compiled account configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OAuthStartRequest {
    pub(crate) account: String,
    pub(crate) method: String,
}

/// Parse a bounded JSON start request without retaining the input bytes.
pub(crate) fn parse_start_request(body: &[u8]) -> Option<OAuthStartRequest> {
    if body.is_empty() || body.len() > 8 * 1024 {
        return None;
    }
    let request = serde_json::from_slice::<OAuthStartRequest>(body).ok()?;
    if request.account.is_empty()
        || request.account.len() > 128
        || request.account.chars().any(char::is_control)
    {
        return None;
    }
    OAuthMethod::parse(&request.method)?;
    Some(request)
}

/// Metadata persisted in `OAuthFlowRecord::flow_kind`.  It contains no state,
/// code, verifier, token, secret reference, or response URL query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FlowBinding {
    pub(crate) method: OAuthMethod,
    pub(crate) generation: u64,
    pub(crate) config_digest: String,
    pub(crate) fingerprint: String,
    pub(crate) callback_bind: String,
}

impl FlowBinding {
    /// Encode bounded metadata using a stable, delimiter-safe representation.
    pub(crate) fn encode(&self) -> Option<String> {
        if self.config_digest.len() != 64
            || self.fingerprint.len() != 64
            || !self
                .config_digest
                .bytes()
                .chain(self.fingerprint.bytes())
                .all(|byte| byte.is_ascii_hexdigit())
            || self.callback_bind.is_empty()
            || self.callback_bind.len() > 256
            || self.callback_bind.chars().any(char::is_control)
        {
            return None;
        }
        let callback = base64_url(self.callback_bind.as_bytes());
        let value = format!(
            "{FLOW_METADATA_VERSION}:{}:{}:{}:{}:{}",
            self.method.as_str(),
            self.generation,
            self.config_digest,
            self.fingerprint,
            callback
        );
        (value.len() <= 512).then_some(value)
    }

    /// Decode only the versioned metadata form produced above.
    pub(crate) fn decode(value: &str) -> Option<Self> {
        let mut parts = value.split(':');
        if format!("{}:{}", parts.next()?, parts.next()?) != FLOW_METADATA_VERSION {
            return None;
        }
        let method = OAuthMethod::parse(parts.next()?)?;
        let generation = parts.next()?.parse::<u64>().ok()?;
        let config_digest = parts.next()?.to_owned();
        let fingerprint = parts.next()?.to_owned();
        let callback_hex = parts.next()?;
        if parts.next().is_some()
            || config_digest.len() != 64
            || fingerprint.len() != 64
            || !config_digest
                .bytes()
                .chain(fingerprint.bytes())
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        let callback_bind = String::from_utf8(base64_unurl(callback_hex)?).ok()?;
        if callback_bind.is_empty()
            || callback_bind.len() > 256
            || callback_bind.chars().any(char::is_control)
        {
            return None;
        }
        Some(Self {
            method,
            generation,
            config_digest,
            fingerprint,
            callback_bind,
        })
    }
}

/// Return the exact callback authority/path identity used for resumption.
pub(crate) fn callback_binding(oauth: &OAuthPlan) -> Option<String> {
    let callback = oauth.callback();
    if callback.username().is_empty()
        && callback.password().is_none()
        && callback.query().is_none()
        && callback.fragment().is_none()
        && callback.path() == "/management/oauth/browser/callback"
        && callback.host_str().is_some()
        && callback.port_or_known_default().is_some()
    {
        Some(format!(
            "{}://{}{}",
            callback.scheme(),
            callback.authority(),
            callback.path()
        ))
    } else {
        None
    }
}

/// Compare a request Host header to one exact configured loopback authority.
/// Host names are case-insensitive; textual IP identity and port remain exact.
pub(crate) fn exact_loopback_host_matches(expected: &str, candidate: &str) -> bool {
    let Ok(expected_url) = Url::parse(&format!("{expected}/")) else {
        return false;
    };
    let Ok(candidate_url) = Url::parse(&format!("http://{candidate}/")) else {
        return false;
    };
    if expected_url.host_str().is_none_or(|host| {
        !(host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
    }) {
        return false;
    }
    expected_url
        .host_str()
        .zip(candidate_url.host_str())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && expected_url.port_or_known_default() == candidate_url.port_or_known_default()
}

pub(crate) fn callback_host_matches_binding(binding: &str, candidate: &str) -> bool {
    let Ok(callback) = Url::parse(binding) else {
        return false;
    };
    exact_loopback_host_matches(
        &format!("{}://{}", callback.scheme(), callback.authority()),
        candidate,
    )
}

/// Compute a non-secret digest for the parts of the compiled configuration
/// that can affect OAuth identity and callback routing.
pub(crate) fn config_digest(config: &CompiledConfig) -> String {
    let mut canonical = String::from("pooler-management-oauth-config:v1\n");
    for upstream in config.upstreams().values() {
        push_field(&mut canonical, upstream.id());
        push_field(&mut canonical, upstream.url().as_str());
        push_field(
            &mut canonical,
            upstream.native().map_or("", |native| native.kind()),
        );
        if let Some(oauth) = upstream.oauth() {
            push_field(&mut canonical, oauth.authorization_endpoint().as_str());
            push_field(&mut canonical, oauth.token_endpoint().as_str());
            push_field(&mut canonical, oauth.client_id());
            push_field(&mut canonical, oauth.grant_type().as_str());
            push_field(&mut canonical, oauth.callback().as_str());
            for scope in oauth.scopes() {
                push_field(&mut canonical, scope.as_ref());
            }
        } else {
            push_field(&mut canonical, "");
        }
    }
    for account in config.accounts().values() {
        push_field(&mut canonical, account.id());
        push_field(&mut canonical, account.provider());
        push_field(&mut canonical, account.auth_kind().as_str());
    }
    if let Some(management) = config.management() {
        push_field(&mut canonical, management.bind());
    }
    hex(digest(&SHA256, canonical.as_bytes()).as_ref())
}

/// Return whether the account's configured auth profile can safely offer a
/// requested method. Built-in profiles remain authoritative; custom profiles
/// must have complete compiled endpoints and the matching grant.
pub(crate) fn method_is_supported(
    config: &CompiledConfig,
    account_id: &str,
    method: OAuthMethod,
) -> bool {
    let Some(account) = config.accounts().get(account_id) else {
        return false;
    };
    if account.auth_kind() != AccountAuthKind::OAuth {
        return false;
    }
    let Some(upstream) = config.upstreams().get(account.provider()) else {
        return false;
    };
    let profile = upstream
        .native()
        .map(|native| native.kind())
        .or_else(|| upstream.known_provider())
        .unwrap_or(upstream.id());
    if let Ok(definition) = ProviderLoginRegistry::builtin().require(profile) {
        let support = definition.support(match method {
            OAuthMethod::DeviceCode => ProviderLoginMethod::DeviceCode,
            OAuthMethod::BrowserPkce => ProviderLoginMethod::AuthorizationCodePkce,
            OAuthMethod::ClientCredentials => ProviderLoginMethod::ClientCredentials,
        });
        if support == ProviderLoginSupport::Unsupported {
            return false;
        }
        if support == ProviderLoginSupport::Supported && method == OAuthMethod::DeviceCode {
            return profile.eq_ignore_ascii_case("openai") || profile.eq_ignore_ascii_case("codex");
        }
    } else if method == OAuthMethod::DeviceCode {
        return false;
    }
    match method.configured_grant() {
        Some(grant) => upstream.oauth().is_some_and(|oauth| {
            oauth.grant_type() == grant
                && (method != OAuthMethod::ClientCredentials || oauth.client_secret().is_some())
        }),
        None => {
            upstream
                .native()
                .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
                && upstream
                    .oauth()
                    .is_none_or(|oauth| oauth.grant_type() == OAuthGrantType::AuthorizationCode)
        }
    }
}

/// Present only capability facts and bounded rationale text to the dashboard.
pub(crate) fn capability_value(config: &CompiledConfig, account_id: &str) -> Value {
    let methods = [
        (OAuthMethod::DeviceCode, ProviderLoginMethod::DeviceCode),
        (
            OAuthMethod::BrowserPkce,
            ProviderLoginMethod::AuthorizationCodePkce,
        ),
        (
            OAuthMethod::ClientCredentials,
            ProviderLoginMethod::ClientCredentials,
        ),
    ]
    .into_iter()
    .filter_map(|(method, login_method)| {
        if !method_is_supported(config, account_id, method) {
            return None;
        }
        let account = config.accounts().get(account_id)?;
        let upstream = config.upstreams().get(account.provider())?;
        let profile = upstream
            .native()
            .map(|native| native.kind())
            .or_else(|| upstream.known_provider())
            .unwrap_or(upstream.id());
        let support = ProviderLoginRegistry::builtin()
            .require(profile)
            .ok()
            .and_then(|definition| definition.capability(login_method))
            .map_or("configured", |capability| capability.note());
        Some(json!({
            "method": method.as_str(),
            "status": "supported",
            "note": support,
        }))
    })
    .collect::<Vec<_>>();
    json!({"schema_version": 1, "account": account_id, "methods": methods})
}

pub(crate) fn flow_id_request_id(flow_id: &str) -> Option<u64> {
    flow_id
        .rsplit_once('-')
        .and_then(|(_, value)| value.parse::<u64>().ok())
}

pub(crate) fn binding_matches(
    binding: &FlowBinding,
    method: OAuthMethod,
    generation: u64,
    config_digest: &str,
    fingerprint: &str,
    callback_bind: Option<&str>,
) -> bool {
    binding.method == method
        && binding.generation == generation
        && binding.config_digest == config_digest
        && binding.fingerprint == fingerprint
        && binding.callback_bind == callback_bind.unwrap_or("")
}

fn push_field(canonical: &mut String, value: &str) {
    canonical.push_str(&value.len().to_string());
    canonical.push(':');
    canonical.push_str(value);
    canonical.push('|');
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn base64_url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn base64_unurl(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut length = 0;
    for byte in value.bytes() {
        chunk[length] = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        length += 1;
        if length == 4 {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
            output.push((chunk[2] << 6) | chunk[3]);
            length = 0;
        }
    }
    match length {
        0 => Some(output),
        2 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            Some(output)
        }
        3 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
            Some(output)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_metadata_round_trips_without_secret_fields() {
        let binding = FlowBinding {
            method: OAuthMethod::BrowserPkce,
            generation: 7,
            config_digest: "a".repeat(64),
            fingerprint: "b".repeat(64),
            callback_bind: "http://127.0.0.1:18400/management/oauth/browser/callback".to_owned(),
        };
        let encoded = binding.encode().expect("metadata");
        assert!(encoded.len() <= 256);
        let decoded = FlowBinding::decode(&encoded).expect("decoded metadata");
        assert_eq!(decoded, binding);
        assert!(!encoded.contains("state"));
        assert!(!encoded.contains("code"));
        assert!(!encoded.contains("verifier"));
    }

    #[test]
    fn exact_loopback_host_matching_keeps_ip_and_port_bound() {
        assert!(exact_loopback_host_matches(
            "http://127.0.0.1:18400",
            "127.0.0.1:18400"
        ));
        assert!(!exact_loopback_host_matches(
            "http://127.0.0.1:18400",
            "localhost:18400"
        ));
        assert!(!exact_loopback_host_matches(
            "http://127.0.0.1:18400",
            "127.0.0.1:18401"
        ));
    }

    #[test]
    fn start_request_rejects_secret_and_endpoint_fields() {
        assert!(parse_start_request(br#"{"account":"a","method":"browser_pkce"}"#).is_some());
        assert!(parse_start_request(
            br#"{"account":"a","method":"browser_pkce","client_secret":"sentinel"}"#,
        )
        .is_none());
        assert!(parse_start_request(br#"{"account":"a","method":"device_code"}"#).is_some());
    }
}
