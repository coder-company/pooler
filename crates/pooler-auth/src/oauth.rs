//! OAuth 2.0 contracts and bounded provider operations.
//!
//! The module keeps protocol mechanics separate from provider policy.  A
//! provider supplies endpoints and a transport; this module owns state and
//! redirect validation, PKCE, device polling, redaction, and token response
//! classification.  The default transport is the same Hyper + rustls stack
//! used by Pooler's HTTP proxy.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{header, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use ring::rand::SecureRandom;
use ring::{digest, rand};
use serde_json::Value;
use thiserror::Error;
use tokio::time::{self, Instant};
use tokio_util::sync::CancellationToken;
use url::{form_urlencoded, Url};

use super::{
    constant_time_eq, CredentialId, OAuthTokens, RefreshCoordinator, RefreshError, SecretValue,
};

const DEVICE_POLL_MIN_INTERVAL: Duration = Duration::from_secs(1);
const DEVICE_POLL_MAX_INTERVAL: Duration = Duration::from_secs(60);
const DEVICE_AUTHORIZATION_MAX_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// A boxed asynchronous OAuth operation.
pub type OAuthFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, OAuthError>> + Send + 'a>>;

/// A boxed asynchronous OAuth transport operation.
pub type OAuthTransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OAuthHttpResponse, OAuthTransportError>> + Send + 'a>>;

/// Errors returned by the HTTP transport without including response bodies.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OAuthTransportError {
    /// The caller cancelled the request.
    #[error("oauth transport request was cancelled")]
    Cancelled,
    /// The request could not be sent or the response could not be read.
    #[error("oauth transport request failed")]
    Failed,
    /// The response exceeded the configured bound.
    #[error("oauth transport response exceeded its limit")]
    ResponseTooLarge,
}

/// Provider error codes recognized by the OAuth token and device endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthProviderErrorCode {
    /// The authorization grant or refresh token is no longer valid.
    InvalidGrant,
    /// The user has not completed device authorization yet.
    AuthorizationPending,
    /// The provider asks the client to poll less frequently.
    SlowDown,
    /// The device code has expired.
    ExpiredToken,
    /// The user denied authorization.
    AccessDenied,
    /// The client credentials were rejected.
    InvalidClient,
    /// A provider-specific code was returned.
    Other,
}

/// OAuth operation errors.  Variants deliberately avoid carrying provider
/// response text, which is an uncontrolled input that can contain secrets.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OAuthError {
    /// The callback state did not match the state created for the login.
    #[error("oauth callback state did not match")]
    InvalidState,
    /// The callback was not received at the configured redirect target.
    #[error("oauth callback redirect did not match")]
    RedirectMismatch,
    /// The callback did not contain an authorization code.
    #[error("oauth callback did not contain an authorization code")]
    MissingCode,
    /// The user or provider denied authorization.
    #[error("oauth authorization was denied")]
    AuthorizationDenied,
    /// The provider rejected the grant and interactive login is required.
    #[error("oauth provider requires reauthorization")]
    NeedsReauth,
    /// The provider returned a non-success response without a recoverable
    /// flow-specific meaning.
    #[error("oauth provider returned an error")]
    Provider {
        /// HTTP status returned by the provider.
        status: u16,
        /// Normalized provider error category.
        code: OAuthProviderErrorCode,
    },
    /// The transport failed without exposing the request or response body.
    #[error("oauth transport failed")]
    Transport(OAuthTransportError),
    /// The provider response did not satisfy the bounded schema.
    #[error("oauth provider response was invalid")]
    InvalidResponse,
    /// The configured OAuth endpoints or client parameters are invalid.
    #[error("oauth configuration is invalid")]
    InvalidConfiguration,
    /// The operation was cancelled before completion.
    #[error("oauth operation was cancelled")]
    Cancelled,
    /// The configured operation is not available for this provider.
    #[error("oauth operation is unsupported")]
    Unsupported,
    /// A token generation changed before this operation could commit.
    #[error("oauth token generation changed during refresh")]
    GenerationConflict,
    /// No refresh token was available for the requested operation.
    #[error("oauth credential has no refresh token")]
    NoRefreshToken,
    /// The token store failed without exposing token material.
    #[error("oauth token store operation failed")]
    Store(OAuthStoreError),
}

/// An HTTP request sent to an OAuth endpoint.
///
/// Every form value is held in [`SecretValue`], including non-secret values.
/// This keeps request debug output uniformly redacted and makes the outbound
/// encoding boundary explicit.
#[derive(Clone)]
pub struct OAuthHttpRequest {
    method: Method,
    url: Url,
    form: Vec<(String, SecretValue)>,
    json_body: Option<SecretValue>,
    basic_auth: Option<(String, SecretValue)>,
    bearer_auth: Option<SecretValue>,
}

impl OAuthHttpRequest {
    /// Build a POST form request.
    #[must_use]
    pub fn post_form(url: Url, form: Vec<(String, SecretValue)>) -> Self {
        Self {
            method: Method::POST,
            url,
            form,
            json_body: None,
            basic_auth: None,
            bearer_auth: None,
        }
    }

    /// Build a POST request with a JSON body held in a redacting wrapper.
    #[must_use]
    pub fn post_json(url: Url, body: SecretValue) -> Self {
        Self {
            method: Method::POST,
            url,
            form: Vec::new(),
            json_body: Some(body),
            basic_auth: None,
            bearer_auth: None,
        }
    }

    /// Build a GET request.
    #[must_use]
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::GET,
            url,
            form: Vec::new(),
            json_body: None,
            basic_auth: None,
            bearer_auth: None,
        }
    }

    /// Attach HTTP Basic client authentication.
    #[must_use]
    pub fn with_basic_auth(mut self, username: impl Into<String>, password: SecretValue) -> Self {
        self.basic_auth = Some((username.into(), password));
        self
    }

    /// Attach a bearer token at the narrow transport boundary.
    #[must_use]
    pub fn with_bearer_auth(mut self, token: SecretValue) -> Self {
        self.bearer_auth = Some(token);
        self
    }

    /// HTTP method of the request.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Endpoint URL of the request.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return a form field for deterministic test transports.
    #[must_use]
    pub fn form_field(&self, name: &str) -> Option<&SecretValue> {
        self.form
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }

    /// Names of form fields, without their values.
    #[must_use = "iterate over the form field names"]
    pub fn form_field_names(&self) -> impl Iterator<Item = &str> {
        self.form.iter().map(|(key, _)| key.as_str())
    }

    fn form(&self) -> &[(String, SecretValue)] {
        &self.form
    }

    /// Borrow a JSON body at the outbound transport boundary.
    #[must_use]
    pub fn json_body(&self) -> Option<&SecretValue> {
        self.json_body.as_ref()
    }

    fn basic_auth(&self) -> Option<(&str, &SecretValue)> {
        self.basic_auth
            .as_ref()
            .map(|(username, password)| (username.as_str(), password))
    }

    fn bearer_auth(&self) -> Option<&SecretValue> {
        self.bearer_auth.as_ref()
    }
}

impl fmt::Debug for OAuthHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("form_fields", &self.form_field_names().collect::<Vec<_>>())
            .field(
                "basic_auth",
                &self.basic_auth.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "bearer_auth",
                &self.bearer_auth.as_ref().map(|_| "[REDACTED]"),
            )
            .field("json_body", &self.json_body.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// A bounded OAuth HTTP response.
#[derive(Clone, Eq, PartialEq)]
pub struct OAuthHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl OAuthHttpResponse {
    /// Construct a response for a deterministic mock transport.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    /// HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Borrow the response bytes at the parser boundary.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for OAuthHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthHttpResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

/// Narrow HTTP boundary used by provider implementations and deterministic
/// tests.  Implementations must not log the request or response body.
pub trait OAuthTransport: Send + Sync {
    /// Execute one bounded request, honoring cancellation before and during
    /// network I/O.
    fn send(
        &self,
        request: OAuthHttpRequest,
        cancellation: CancellationToken,
    ) -> OAuthTransportFuture<'_>;
}

type HyperOAuthClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Hyper/rustls transport shared with the rest of Pooler's HTTP stack.
#[derive(Clone)]
pub struct HyperOAuthTransport {
    client: HyperOAuthClient,
    max_response_bytes: usize,
}

impl HyperOAuthTransport {
    /// Build a transport using native roots and HTTP/1.1.
    pub fn new(max_response_bytes: usize) -> Result<Self, OAuthTransportError> {
        if max_response_bytes == 0 {
            return Err(OAuthTransportError::ResponseTooLarge);
        }
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| OAuthTransportError::Failed)?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let mut client_builder = Client::builder(TokioExecutor::new());
        client_builder.http2_adaptive_window(true);
        let client = client_builder.build(connector);
        Ok(Self {
            client,
            max_response_bytes,
        })
    }

    /// Maximum response body accepted by this transport.
    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

impl OAuthTransport for HyperOAuthTransport {
    fn send(
        &self,
        request: OAuthHttpRequest,
        cancellation: CancellationToken,
    ) -> OAuthTransportFuture<'_> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(OAuthTransportError::Cancelled);
            }

            let encoded_form = request
                .json_body()
                .map(|body| body.expose_bytes().to_vec())
                .unwrap_or_else(|| encode_form(request.form()).into_bytes());
            let mut builder = Request::builder()
                .method(request.method().clone())
                .uri(request.url().as_str())
                .header(header::ACCEPT, "application/json");
            if !encoded_form.is_empty() {
                let content_type = if request.json_body().is_some() {
                    "application/json"
                } else {
                    "application/x-www-form-urlencoded"
                };
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            if let Some((username, password)) = request.basic_auth() {
                let credentials = format!("{username}:{}", password.expose_secret());
                builder = builder.header(
                    header::AUTHORIZATION,
                    format!("Basic {}", base64_standard(credentials.as_bytes())),
                );
            }
            if let Some(token) = request.bearer_auth() {
                builder = builder.header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", token.expose_secret()),
                );
            }
            let body = Full::new(Bytes::from(encoded_form));
            let outbound = builder
                .body(body)
                .map_err(|_| OAuthTransportError::Failed)?;
            let response = tokio::select! {
                () = cancellation.cancelled() => {
                    return Err(OAuthTransportError::Cancelled);
                }
                result = self.client.request(outbound) => {
                    result.map_err(|_| OAuthTransportError::Failed)?
                }
            };
            read_response(response, self.max_response_bytes, &cancellation).await
        })
    }
}

async fn read_response(
    response: http::Response<Incoming>,
    max_response_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<OAuthHttpResponse, OAuthTransportError> {
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    loop {
        let frame = tokio::select! {
            () = cancellation.cancelled() => return Err(OAuthTransportError::Cancelled),
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|_| OAuthTransportError::Failed)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len().saturating_add(data.len()) > max_response_bytes {
            return Err(OAuthTransportError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&data);
    }
    Ok(OAuthHttpResponse::new(status, bytes))
}

fn encode_form(form: &[(String, SecretValue)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in form {
        serializer.append_pair(key, value.expose_secret());
    }
    serializer.finish()
}

fn json_form(form: &[(String, SecretValue)]) -> String {
    let mut object = serde_json::Map::new();
    for (key, value) in form {
        object.insert(key.clone(), Value::String(value.expose_secret().to_owned()));
    }
    serde_json::to_string(&object).expect("OAuth form values are always JSON strings")
}

fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

/// CSRF state created for one authorization attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct OAuthState(SecretValue);

impl OAuthState {
    /// Create cryptographically random state.
    pub fn random() -> Result<Self, OAuthError> {
        Ok(Self(SecretValue::new(random_urlsafe(32)?)))
    }

    /// Create state from a test or persisted value.
    pub fn new(value: impl Into<String>) -> Result<Self, OAuthError> {
        let value = value.into();
        if value.is_empty() || !value.is_ascii() {
            return Err(OAuthError::InvalidState);
        }
        Ok(Self(SecretValue::new(value)))
    }

    /// Constant-time comparison with a callback value.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        constant_time_eq(self.0.expose_bytes(), candidate.as_bytes())
    }

    fn value(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for OAuthState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthState([REDACTED])")
    }
}

/// PKCE verifier and S256 challenge for one authorization attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct PkcePair {
    verifier: SecretValue,
    challenge: String,
}

impl PkcePair {
    /// Generate a random RFC 7636 verifier and its S256 challenge.
    pub fn random() -> Result<Self, OAuthError> {
        Self::from_verifier(random_urlsafe(32)?)
    }

    /// Construct a pair from a deterministic verifier for tests.
    pub fn from_verifier(value: impl Into<String>) -> Result<Self, OAuthError> {
        let value = value.into();
        if !(43..=128).contains(&value.len())
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !b"-._~".contains(&byte))
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        let digest = digest::digest(&digest::SHA256, value.as_bytes());
        Ok(Self {
            verifier: SecretValue::new(value),
            challenge: base64_urlsafe(digest.as_ref()),
        })
    }

    /// S256 challenge to send to the authorization endpoint.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Borrow the verifier at the token exchange boundary.
    #[must_use]
    pub fn verifier(&self) -> &SecretValue {
        &self.verifier
    }
}

impl fmt::Debug for PkcePair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkcePair")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// Authorization code returned by a validated callback.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationCode(SecretValue);

impl AuthorizationCode {
    /// Create a code for a deterministic provider test.
    pub fn new(value: impl Into<String>) -> Result<Self, OAuthError> {
        let value = value.into();
        if value.is_empty() {
            return Err(OAuthError::MissingCode);
        }
        Ok(Self(SecretValue::new(value)))
    }

    /// Borrow the code at the token exchange boundary.
    #[must_use]
    pub fn secret(&self) -> &SecretValue {
        &self.0
    }
}

impl fmt::Debug for AuthorizationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationCode([REDACTED])")
    }
}

/// One validated login attempt.  The state and verifier must be retained by
/// the caller until [`OAuthCodeExchange::exchange_code`] completes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationAttempt {
    authorization_url: Url,
    state: OAuthState,
    pkce: PkcePair,
    redirect_uri: Url,
}

impl AuthorizationAttempt {
    /// Authorization URL to open in the user's browser.
    #[must_use]
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// State associated with this attempt.
    #[must_use]
    pub fn state(&self) -> &OAuthState {
        &self.state
    }

    /// PKCE pair associated with this attempt.
    #[must_use]
    pub fn pkce(&self) -> &PkcePair {
        &self.pkce
    }

    /// Configured redirect URI used to validate the callback.
    #[must_use]
    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Validate a browser callback and extract its authorization code.
    pub fn validate_callback(&self, callback: &Url) -> Result<AuthorizationCode, OAuthError> {
        validate_callback(&self.redirect_uri, &self.state, callback)
    }
}

impl fmt::Debug for AuthorizationAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationAttempt")
            .field("authorization_url", &redacted_url(&self.authorization_url))
            .field("state", &self.state)
            .field("pkce", &self.pkce)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Validate a callback URL against a configured redirect and state.
pub fn validate_callback(
    expected_redirect: &Url,
    expected_state: &OAuthState,
    callback: &Url,
) -> Result<AuthorizationCode, OAuthError> {
    validate_redirect_target(expected_redirect, callback)?;
    let state = unique_query_parameter(callback, "state")?.ok_or(OAuthError::InvalidState)?;
    if !expected_state.matches(&state) {
        return Err(OAuthError::InvalidState);
    }
    if unique_query_parameter(callback, "error")?.is_some() {
        return Err(OAuthError::AuthorizationDenied);
    }
    let code = unique_query_parameter(callback, "code")?.ok_or(OAuthError::MissingCode)?;
    AuthorizationCode::new(code)
}

fn validate_redirect_target(expected: &Url, actual: &Url) -> Result<(), OAuthError> {
    if expected.fragment().is_some()
        || actual.fragment().is_some()
        || expected.cannot_be_a_base()
        || actual.cannot_be_a_base()
    {
        return Err(OAuthError::RedirectMismatch);
    }
    let same_target = expected.scheme() == actual.scheme()
        && expected.username() == actual.username()
        && expected.password() == actual.password()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
        && expected.path() == actual.path();
    if !same_target {
        return Err(OAuthError::RedirectMismatch);
    }
    if let Some(expected_query) = expected.query() {
        let actual_pairs = actual.query_pairs().collect::<Vec<_>>();
        let expected_pairs = form_urlencoded::parse(expected_query.as_bytes()).collect::<Vec<_>>();
        if expected_pairs
            .iter()
            .any(|pair| !actual_pairs.iter().any(|candidate| candidate == pair))
        {
            return Err(OAuthError::RedirectMismatch);
        }
    }
    Ok(())
}

fn unique_query_parameter(url: &Url, name: &str) -> Result<Option<String>, OAuthError> {
    let mut value = None;
    for (key, candidate) in url.query_pairs() {
        if key == name {
            if value.is_some() {
                return Err(OAuthError::InvalidResponse);
            }
            value = Some(candidate.into_owned());
        }
    }
    Ok(value)
}

fn redacted_url(url: &Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    format!("{redacted}?redacted")
}

fn random_urlsafe(size: usize) -> Result<String, OAuthError> {
    let mut bytes = vec![0_u8; size];
    rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OAuthError::InvalidConfiguration)?;
    Ok(base64_urlsafe(&bytes))
}

fn base64_urlsafe(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let second = bytes.get(index + 1).copied().unwrap_or(0);
        let third = bytes.get(index + 2).copied().unwrap_or(0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if index + 1 < bytes.len() {
            output.push(TABLE[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        }
        if index + 2 < bytes.len() {
            output.push(TABLE[(third & 0x3f) as usize] as char);
        }
        index += 3;
    }
    output
}

/// How the OAuth client authenticates at the token endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OAuthClientAuth {
    /// A public client with no client secret.
    None,
    /// HTTP Basic authentication (`client_id:client_secret`).
    Basic(SecretValue),
    /// A `client_secret` form field, for providers that require it.
    RequestBody(SecretValue),
}

/// OAuth grant used to obtain and renew a provider credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OAuthGrantType {
    /// Interactive authorization-code login followed by refresh-token renewal.
    #[default]
    AuthorizationCode,
    /// Non-interactive service-account credentials reacquired when they expire.
    ClientCredentials,
}

/// Encoding accepted by a provider's token and revocation endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRequestEncoding {
    /// RFC 6749 form encoding.
    Form,
    /// Provider-specific JSON encoding.
    Json,
}

/// Device authorization dialect.
///
/// Codex does not implement RFC 8628. Its CLI issues a user code through
/// `/api/accounts/deviceauth/usercode`, polls `/api/accounts/deviceauth/token`
/// until an authorization code appears, then exchanges that code at the
/// ordinary token endpoint with `redirect_uri` set to `/deviceauth/callback`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceAuthorizationGrant {
    /// RFC 8628 device authorization grant.
    #[default]
    Rfc8628,
    /// Official Codex CLI accounts-API device login.
    CodexAccounts,
}

/// Immutable endpoint and client settings for a standard OAuth provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthClientConfig {
    /// Public OAuth client identifier.
    pub client_id: String,
    /// Exact redirect target registered with the provider.
    pub redirect_uri: Url,
    /// Authorization endpoint.
    pub authorization_endpoint: Url,
    /// Token endpoint used by code, device, and refresh flows.
    pub token_endpoint: Url,
    /// Optional device authorization endpoint.
    pub device_authorization_endpoint: Option<Url>,
    /// Optional RFC 7009 revocation endpoint.
    pub revocation_endpoint: Option<Url>,
    /// Optional identity endpoint.
    pub identity_endpoint: Option<Url>,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Client authentication policy.
    pub client_auth: OAuthClientAuth,
    /// Grant used to obtain and renew credentials.
    pub grant_type: OAuthGrantType,
    /// Token and revocation request encoding.
    pub request_encoding: OAuthRequestEncoding,
    /// Extra authorization-query parameters required by a provider.
    pub authorization_parameters: Vec<(String, String)>,
    /// Device authorization dialect. Codex uses a custom accounts API rather
    /// than RFC 8628.
    pub device_grant: DeviceAuthorizationGrant,
}

impl OAuthClientConfig {
    /// Construct a configuration after validating endpoints and redirect URI.
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: Url,
        authorization_endpoint: Url,
        token_endpoint: Url,
    ) -> Result<Self, OAuthError> {
        let config = Self {
            client_id: client_id.into(),
            redirect_uri,
            authorization_endpoint,
            token_endpoint,
            device_authorization_endpoint: None,
            revocation_endpoint: None,
            identity_endpoint: None,
            scopes: Vec::new(),
            client_auth: OAuthClientAuth::None,
            grant_type: OAuthGrantType::AuthorizationCode,
            request_encoding: OAuthRequestEncoding::Form,
            authorization_parameters: Vec::new(),
            device_grant: DeviceAuthorizationGrant::Rfc8628,
        };
        config.validate()
    }

    /// Set the optional device authorization endpoint.
    #[must_use]
    pub fn with_device_authorization_endpoint(mut self, endpoint: Url) -> Self {
        self.device_authorization_endpoint = Some(endpoint);
        self
    }

    /// Set the optional revocation endpoint.
    #[must_use]
    pub fn with_revocation_endpoint(mut self, endpoint: Url) -> Self {
        self.revocation_endpoint = Some(endpoint);
        self
    }

    /// Set the optional identity endpoint.
    #[must_use]
    pub fn with_identity_endpoint(mut self, endpoint: Url) -> Self {
        self.identity_endpoint = Some(endpoint);
        self
    }

    /// Set requested OAuth scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Set the client authentication policy.
    #[must_use]
    pub fn with_client_auth(mut self, auth: OAuthClientAuth) -> Self {
        self.client_auth = auth;
        self
    }

    /// Use the client-credentials grant and reacquire access tokens on renewal.
    #[must_use]
    pub const fn with_client_credentials_grant(mut self) -> Self {
        self.grant_type = OAuthGrantType::ClientCredentials;
        self
    }

    /// Use JSON for token and revocation requests when required by a native
    /// provider.
    #[must_use]
    pub const fn with_json_requests(mut self) -> Self {
        self.request_encoding = OAuthRequestEncoding::Json;
        self
    }

    /// Append an authorization-query parameter the provider requires.
    #[must_use]
    pub fn with_authorization_parameter(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.authorization_parameters
            .push((name.into(), value.into()));
        self
    }

    /// Select the device-authorization dialect.
    #[must_use]
    pub const fn with_device_grant(mut self, grant: DeviceAuthorizationGrant) -> Self {
        self.device_grant = grant;
        self
    }

    /// Validate the immutable configuration.
    pub fn validate(&self) -> Result<Self, OAuthError> {
        if self.client_id.is_empty()
            || self.client_id.contains(char::is_whitespace)
            || !valid_endpoint(&self.authorization_endpoint)
            || !valid_endpoint(&self.token_endpoint)
            || !valid_redirect(&self.redirect_uri)
            || self.scopes.iter().any(|scope| scope.is_empty())
            || (self.grant_type == OAuthGrantType::ClientCredentials
                && self.client_auth == OAuthClientAuth::None)
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        for endpoint in [
            self.device_authorization_endpoint.as_ref(),
            self.revocation_endpoint.as_ref(),
            self.identity_endpoint.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !valid_endpoint(endpoint) {
                return Err(OAuthError::InvalidConfiguration);
            }
        }
        Ok(self.clone())
    }
}

fn valid_endpoint(endpoint: &Url) -> bool {
    matches!(endpoint.scheme(), "https" | "http")
        && endpoint.host_str().is_some()
        && endpoint.fragment().is_none()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
}

fn valid_redirect(redirect: &Url) -> bool {
    valid_endpoint(redirect)
        && (redirect.scheme() == "https"
            || redirect.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]"
            }))
}

/// Identity returned by a provider's user-info endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthIdentity {
    /// Provider-stable subject identifier.
    pub subject: String,
    /// Optional provider email claim.
    pub email: Option<String>,
    /// Optional provider display name.
    pub name: Option<String>,
}

/// Device authorization response, with device code held in a redacting type.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceAuthorization {
    device_code: SecretValue,
    user_code: String,
    verification_uri: Url,
    verification_uri_complete: Option<Url>,
    expires_in: Duration,
    interval: Duration,
}

impl DeviceAuthorization {
    /// Construct a device authorization response for deterministic tests.
    pub fn new(
        device_code: impl Into<String>,
        user_code: impl Into<String>,
        verification_uri: Url,
        expires_in: Duration,
        interval: Duration,
    ) -> Result<Self, OAuthError> {
        let device_code = device_code.into();
        let user_code = user_code.into();
        if device_code.is_empty()
            || user_code.is_empty()
            || !valid_endpoint(&verification_uri)
            || expires_in.is_zero()
            || expires_in > DEVICE_AUTHORIZATION_MAX_LIFETIME
        {
            return Err(OAuthError::InvalidResponse);
        }
        Ok(Self {
            device_code: SecretValue::new(device_code),
            user_code,
            verification_uri,
            verification_uri_complete: None,
            expires_in,
            interval,
        })
    }

    /// User-facing short code.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// User-facing verification URI.
    #[must_use]
    pub fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }

    /// Optional provider URI containing the user code.
    #[must_use]
    pub fn verification_uri_complete(&self) -> Option<&Url> {
        self.verification_uri_complete.as_ref()
    }

    /// Maximum time for polling.
    #[must_use]
    pub const fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// Provider-requested initial polling interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    fn device_code(&self) -> &SecretValue {
        &self.device_code
    }
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Narrow boundary for exchanging an authorization code.
pub trait OAuthCodeExchange: Send + Sync {
    /// Exchange a validated code and PKCE verifier for tokens.
    fn exchange_code<'a>(
        &'a self,
        code: &'a AuthorizationCode,
        pkce: &'a PkcePair,
        redirect_uri: &'a Url,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens>;
}

/// Narrow boundary for refreshing a credential.
pub trait OAuthRefresher: Send + Sync {
    /// Exchange a refresh token for a new token set.
    fn refresh<'a>(
        &'a self,
        refresh_token: &'a SecretValue,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens>;

    /// Renew a token set using its refresh token.
    ///
    /// Client-credentials providers override this operation to reacquire a
    /// token because that grant normally does not issue refresh tokens.
    fn renew<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        let Some(refresh_token) = tokens.refresh_token() else {
            return Box::pin(async { Err(OAuthError::NoRefreshToken) });
        };
        self.refresh(refresh_token, cancellation)
    }
}

/// Narrow boundary for the OAuth client-credentials grant.
pub trait OAuthClientCredentials: Send + Sync {
    /// Acquire a service-account access token.
    fn acquire_client_credentials(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, OAuthTokens>;
}

/// Narrow boundary for revoking a credential.
pub trait OAuthRevoker: Send + Sync {
    /// Revoke an access or refresh token when the provider supports it.
    fn revoke<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, ()>;
}

/// Narrow boundary for identity discovery.
pub trait OAuthIdentityProvider: Send + Sync {
    /// Discover a stable provider identity for a token set.
    fn identity<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthIdentity>;
}

/// Narrow boundary for device authorization and polling.
pub trait OAuthDeviceFlow: Send + Sync {
    /// Start a device authorization flow.
    fn start_device_authorization(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, DeviceAuthorization>;

    /// Poll until authorization completes, expires, or is cancelled.
    fn poll_device<'a>(
        &'a self,
        authorization: &'a DeviceAuthorization,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens>;
}

/// Combined provider contract used by native subscription adapters.
pub trait OAuthProvider:
    OAuthCodeExchange + OAuthRefresher + OAuthRevoker + OAuthIdentityProvider + OAuthDeviceFlow
{
    /// Stable provider identifier used in redacted decisions.
    fn provider_id(&self) -> &str;

    /// Build one stateful PKCE browser authorization attempt.
    fn begin_authorization(&self) -> Result<AuthorizationAttempt, OAuthError>;
}

/// Standard OAuth 2.0 provider implementation.
///
/// Provider-specific adapters can wrap this type or implement the narrow
/// traits directly when their endpoints use a different schema.  This type
/// handles the RFC 7636 code flow, RFC 8628 device flow, refresh, revocation,
/// and common OpenID-style identity claims.
#[derive(Clone)]
pub struct StandardOAuthProvider {
    provider_id: Arc<str>,
    config: OAuthClientConfig,
    transport: Arc<dyn OAuthTransport>,
}

impl StandardOAuthProvider {
    /// Construct a provider over an explicit transport.
    pub fn new(
        provider_id: impl Into<Arc<str>>,
        config: OAuthClientConfig,
        transport: Arc<dyn OAuthTransport>,
    ) -> Result<Self, OAuthError> {
        let config = config.validate()?;
        let provider_id = provider_id.into();
        if provider_id.is_empty() {
            return Err(OAuthError::InvalidConfiguration);
        }
        Ok(Self {
            provider_id,
            config,
            transport,
        })
    }

    /// Provider configuration, without resolving or exposing secrets.
    #[must_use]
    pub const fn config(&self) -> &OAuthClientConfig {
        &self.config
    }

    /// Build an authorization attempt from caller-owned state and PKCE.
    ///
    /// The explicit constructor is used by deterministic CLI and integration
    /// tests; production callers should prefer [`OAuthProvider::begin_authorization`]
    /// so state is generated at the provider boundary.
    pub fn begin_authorization_with(
        &self,
        state: OAuthState,
        pkce: PkcePair,
    ) -> Result<AuthorizationAttempt, OAuthError> {
        self.authorization_url(state, pkce)
    }

    fn token_request(&self, mut form: Vec<(String, SecretValue)>) -> OAuthHttpRequest {
        form.push((
            "client_id".to_owned(),
            SecretValue::new(self.config.client_id.clone()),
        ));
        match self.config.request_encoding {
            OAuthRequestEncoding::Form => {
                let request = OAuthHttpRequest::post_form(self.config.token_endpoint.clone(), form);
                self.apply_client_auth(request)
            }
            OAuthRequestEncoding::Json => {
                if let OAuthClientAuth::RequestBody(secret) = &self.config.client_auth {
                    form.push(("client_secret".to_owned(), secret.clone()));
                }
                let request = OAuthHttpRequest::post_json(
                    self.config.token_endpoint.clone(),
                    SecretValue::new(json_form(&form)),
                );
                self.apply_client_auth_json(request)
            }
        }
    }

    fn apply_client_auth(&self, mut request: OAuthHttpRequest) -> OAuthHttpRequest {
        match &self.config.client_auth {
            OAuthClientAuth::None => request,
            OAuthClientAuth::Basic(secret) => {
                request.with_basic_auth(self.config.client_id.clone(), secret.clone())
            }
            OAuthClientAuth::RequestBody(secret) => {
                request
                    .form
                    .push(("client_secret".to_owned(), secret.clone()));
                request
            }
        }
    }

    fn apply_client_auth_json(&self, request: OAuthHttpRequest) -> OAuthHttpRequest {
        match &self.config.client_auth {
            OAuthClientAuth::Basic(secret) => {
                request.with_basic_auth(self.config.client_id.clone(), secret.clone())
            }
            OAuthClientAuth::None | OAuthClientAuth::RequestBody(_) => request,
        }
    }

    fn send(
        &self,
        request: OAuthHttpRequest,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, OAuthHttpResponse> {
        Box::pin(async move {
            self.transport
                .send(request, cancellation)
                .await
                .map_err(OAuthError::Transport)
        })
    }

    async fn send_before_deadline(
        &self,
        request: OAuthHttpRequest,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Result<OAuthHttpResponse, OAuthError> {
        let request_cancellation = cancellation.child_token();
        tokio::select! {
            () = cancellation.cancelled() => {
                request_cancellation.cancel();
                Err(OAuthError::Cancelled)
            }
            result = time::timeout_at(
                deadline,
                self.send(request, request_cancellation.clone()),
            ) => match result {
                Ok(response) => response,
                Err(_) => {
                    request_cancellation.cancel();
                    Err(expired_device_code())
                }
            }
        }
    }

    fn authorization_url(
        &self,
        state: OAuthState,
        pkce: PkcePair,
    ) -> Result<AuthorizationAttempt, OAuthError> {
        if self.config.grant_type != OAuthGrantType::AuthorizationCode {
            return Err(OAuthError::Unsupported);
        }
        let mut url = self.config.authorization_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.config.client_id);
            query.append_pair("redirect_uri", self.config.redirect_uri.as_str());
            query.append_pair("state", state.value());
            query.append_pair("code_challenge", pkce.challenge());
            query.append_pair("code_challenge_method", "S256");
            if !self.config.scopes.is_empty() {
                query.append_pair("scope", &self.config.scopes.join(" "));
            }
            for (name, value) in &self.config.authorization_parameters {
                query.append_pair(name, value);
            }
        }
        Ok(AuthorizationAttempt {
            authorization_url: url,
            state,
            pkce,
            redirect_uri: self.config.redirect_uri.clone(),
        })
    }

    fn start_rfc8628_device_authorization(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, DeviceAuthorization> {
        let Some(endpoint) = self.config.device_authorization_endpoint.clone() else {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        };
        let mut form = vec![(
            "client_id".to_owned(),
            SecretValue::new(self.config.client_id.clone()),
        )];
        if !self.config.scopes.is_empty() {
            form.push((
                "scope".to_owned(),
                SecretValue::new(self.config.scopes.join(" ")),
            ));
        }
        let request = self.apply_client_auth(OAuthHttpRequest::post_form(endpoint, form));
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            Self::parse_device_response(&response)
        })
    }

    fn poll_rfc8628_device<'a>(
        &'a self,
        authorization: &'a DeviceAuthorization,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        Box::pin(async move {
            let started = Instant::now();
            let deadline = started + authorization.expires_in();
            let mut interval = bounded_device_poll_interval(authorization.interval());
            loop {
                if cancellation.is_cancelled() {
                    return Err(OAuthError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(OAuthError::Provider {
                        status: 400,
                        code: OAuthProviderErrorCode::ExpiredToken,
                    });
                }
                let request = self.token_request(vec![
                    (
                        "grant_type".to_owned(),
                        SecretValue::new("urn:ietf:params:oauth:grant-type:device_code"),
                    ),
                    (
                        "device_code".to_owned(),
                        authorization.device_code().clone(),
                    ),
                ]);
                let response = self
                    .send_before_deadline(request, &cancellation, deadline)
                    .await?;
                match Self::classify_device_response(&response) {
                    Ok(tokens) => return Ok(tokens),
                    Err(DevicePollError::Pending) => {}
                    Err(DevicePollError::SlowDown) => {
                        interval = bounded_device_poll_interval(
                            interval.saturating_add(Duration::from_secs(5)),
                        );
                    }
                    Err(DevicePollError::OAuth(error)) => return Err(error),
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(OAuthError::Provider {
                        status: 400,
                        code: OAuthProviderErrorCode::ExpiredToken,
                    });
                }
                tokio::select! {
                    () = cancellation.cancelled() => return Err(OAuthError::Cancelled),
                    () = time::sleep(interval.min(remaining)) => {}
                }
            }
        })
    }

    fn start_codex_device_authorization(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, DeviceAuthorization> {
        let Some(endpoints) = self.codex_device_endpoints() else {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        };
        let request = OAuthHttpRequest::post_json(
            endpoints.usercode,
            SecretValue::new(serde_json::json!({ "client_id": self.config.client_id }).to_string()),
        );
        let verification = endpoints.verification;
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            Self::parse_codex_usercode_response(&response, verification)
        })
    }

    fn poll_codex_device<'a>(
        &'a self,
        authorization: &'a DeviceAuthorization,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        let Some(endpoints) = self.codex_device_endpoints() else {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        };
        Box::pin(async move {
            let started = Instant::now();
            let deadline = started + authorization.expires_in();
            let mut interval = bounded_device_poll_interval(authorization.interval());
            loop {
                if cancellation.is_cancelled() {
                    return Err(OAuthError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(OAuthError::Provider {
                        status: 400,
                        code: OAuthProviderErrorCode::ExpiredToken,
                    });
                }
                let request = OAuthHttpRequest::post_json(
                    endpoints.poll.clone(),
                    SecretValue::new(
                        serde_json::json!({
                            "device_auth_id": authorization.device_code().expose_secret(),
                            "user_code": authorization.user_code(),
                        })
                        .to_string(),
                    ),
                );
                let response = self
                    .send_before_deadline(request, &cancellation, deadline)
                    .await?;
                match Self::classify_codex_device_poll(&response) {
                    Ok(issued) => {
                        let token_request = self.token_request(vec![
                            (
                                "grant_type".to_owned(),
                                SecretValue::new("authorization_code"),
                            ),
                            (
                                "code".to_owned(),
                                SecretValue::new(issued.authorization_code),
                            ),
                            (
                                "redirect_uri".to_owned(),
                                SecretValue::new(endpoints.callback.as_str().to_owned()),
                            ),
                            (
                                "code_verifier".to_owned(),
                                SecretValue::new(issued.code_verifier),
                            ),
                        ]);
                        let token_response = self
                            .send_before_deadline(token_request, &cancellation, deadline)
                            .await?;
                        return Self::parse_token_response(&token_response)
                            .map_err(TokenEndpointError::into_oauth);
                    }
                    Err(DevicePollError::Pending) => {}
                    Err(DevicePollError::SlowDown) => {
                        interval = bounded_device_poll_interval(
                            interval.saturating_add(Duration::from_secs(5)),
                        );
                    }
                    Err(DevicePollError::OAuth(error)) => return Err(error),
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(OAuthError::Provider {
                        status: 400,
                        code: OAuthProviderErrorCode::ExpiredToken,
                    });
                }
                tokio::select! {
                    () = cancellation.cancelled() => return Err(OAuthError::Cancelled),
                    () = time::sleep(interval.min(remaining)) => {}
                }
            }
        })
    }

    fn codex_device_endpoints(&self) -> Option<CodexDeviceEndpoints> {
        if self.config.device_grant != DeviceAuthorizationGrant::CodexAccounts {
            return None;
        }
        let usercode = self.config.device_authorization_endpoint.as_ref()?;
        derive_codex_device_endpoints(usercode).ok()
    }

    fn parse_codex_usercode_response(
        response: &OAuthHttpResponse,
        verification: Url,
    ) -> Result<DeviceAuthorization, OAuthError> {
        let value = parse_json(response)?;
        if !(200..300).contains(&response.status()) {
            return Err(classify_provider_error(response.status(), &value));
        }
        let object = value.as_object().ok_or(OAuthError::InvalidResponse)?;
        let device_auth_id = object
            .get("device_auth_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(OAuthError::InvalidResponse)?;
        let user_code = object
            .get("user_code")
            .or_else(|| object.get("usercode"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(OAuthError::InvalidResponse)?;
        let interval = bounded_device_poll_interval(
            json_duration_secs(object.get("interval")).unwrap_or(Duration::from_secs(5)),
        );
        DeviceAuthorization::new(
            device_auth_id,
            user_code,
            verification,
            Duration::from_secs(15 * 60),
            interval,
        )
    }

    fn classify_codex_device_poll(
        response: &OAuthHttpResponse,
    ) -> Result<CodexIssuedAuthorization, DevicePollError> {
        if matches!(response.status(), 403 | 404) {
            return Err(DevicePollError::Pending);
        }
        let value = parse_json(response).map_err(DevicePollError::OAuth)?;
        if !(200..300).contains(&response.status()) {
            return Err(DevicePollError::OAuth(classify_provider_error(
                response.status(),
                &value,
            )));
        }
        let object = value
            .as_object()
            .ok_or(DevicePollError::OAuth(OAuthError::InvalidResponse))?;
        let authorization_code = object
            .get("authorization_code")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(DevicePollError::OAuth(OAuthError::InvalidResponse))?;
        let code_verifier = object
            .get("code_verifier")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(DevicePollError::OAuth(OAuthError::InvalidResponse))?;
        Ok(CodexIssuedAuthorization {
            authorization_code: authorization_code.to_owned(),
            code_verifier: code_verifier.to_owned(),
        })
    }

    fn parse_token_response(
        response: &OAuthHttpResponse,
    ) -> Result<OAuthTokens, TokenEndpointError> {
        let value = parse_json(response).map_err(TokenEndpointError::OAuth)?;
        if !(200..300).contains(&response.status()) {
            return Err(classify_token_error(response.status(), &value));
        }
        let object = value
            .as_object()
            .ok_or(TokenEndpointError::OAuth(OAuthError::InvalidResponse))?;
        let access_token = object
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or(TokenEndpointError::OAuth(OAuthError::InvalidResponse))?;
        let refresh_token = object
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty());
        let id_token = object
            .get("id_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty());
        let token_type = object
            .get("token_type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("Bearer");
        let expires_at = object
            .get("expires_in")
            .and_then(Value::as_u64)
            .and_then(|seconds| SystemTime::now().checked_add(Duration::from_secs(seconds)));
        Ok(OAuthTokens::new(
            SecretValue::new(access_token.to_owned()),
            refresh_token.map(|token| SecretValue::new(token.to_owned())),
            expires_at,
            token_type.to_owned(),
        )
        .with_id_token(id_token.map(|token| SecretValue::new(token.to_owned()))))
    }

    fn parse_device_response(
        response: &OAuthHttpResponse,
    ) -> Result<DeviceAuthorization, OAuthError> {
        let value = parse_json(response)?;
        if !(200..300).contains(&response.status()) {
            return Err(classify_provider_error(response.status(), &value));
        }
        let object = value.as_object().ok_or(OAuthError::InvalidResponse)?;
        let device_code = object
            .get("device_code")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(OAuthError::InvalidResponse)?;
        let user_code = object
            .get("user_code")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(OAuthError::InvalidResponse)?;
        let verification = object
            .get("verification_uri")
            .or_else(|| object.get("verification_url"))
            .and_then(Value::as_str)
            .ok_or(OAuthError::InvalidResponse)?
            .parse::<Url>()
            .map_err(|_| OAuthError::InvalidResponse)?;
        let expires_in = object
            .get("expires_in")
            .and_then(Value::as_u64)
            .map(Duration::from_secs)
            .filter(|value| !value.is_zero())
            .ok_or(OAuthError::InvalidResponse)?;
        let interval = bounded_device_poll_interval(
            object
                .get("interval")
                .and_then(Value::as_u64)
                .map(Duration::from_secs)
                .unwrap_or_else(|| Duration::from_secs(5)),
        );
        let mut authorization =
            DeviceAuthorization::new(device_code, user_code, verification, expires_in, interval)?;
        authorization.verification_uri_complete = object
            .get("verification_uri_complete")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<Url>().ok())
            .filter(valid_endpoint);
        Ok(authorization)
    }

    fn classify_device_response(
        response: &OAuthHttpResponse,
    ) -> Result<OAuthTokens, DevicePollError> {
        Self::parse_token_response(response).map_err(|error| match error {
            TokenEndpointError::Pending => DevicePollError::Pending,
            TokenEndpointError::SlowDown => DevicePollError::SlowDown,
            TokenEndpointError::Expired => DevicePollError::OAuth(OAuthError::Provider {
                status: response.status(),
                code: OAuthProviderErrorCode::ExpiredToken,
            }),
            TokenEndpointError::OAuth(error) => DevicePollError::OAuth(error),
        })
    }
}

impl fmt::Debug for StandardOAuthProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardOAuthProvider")
            .field("provider_id", &self.provider_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl OAuthProvider for StandardOAuthProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn begin_authorization(&self) -> Result<AuthorizationAttempt, OAuthError> {
        self.authorization_url(OAuthState::random()?, PkcePair::random()?)
    }
}

impl OAuthCodeExchange for StandardOAuthProvider {
    fn exchange_code<'a>(
        &'a self,
        code: &'a AuthorizationCode,
        pkce: &'a PkcePair,
        redirect_uri: &'a Url,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        if self.config.grant_type != OAuthGrantType::AuthorizationCode {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        if redirect_uri != &self.config.redirect_uri {
            return Box::pin(async { Err(OAuthError::RedirectMismatch) });
        }
        let request = self.token_request(vec![
            (
                "grant_type".to_owned(),
                SecretValue::new("authorization_code"),
            ),
            ("code".to_owned(), code.secret().clone()),
            (
                "redirect_uri".to_owned(),
                SecretValue::new(redirect_uri.as_str().to_owned()),
            ),
            ("code_verifier".to_owned(), pkce.verifier().clone()),
        ]);
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            Self::parse_token_response(&response).map_err(TokenEndpointError::into_oauth)
        })
    }
}

impl OAuthRefresher for StandardOAuthProvider {
    fn refresh<'a>(
        &'a self,
        refresh_token: &'a SecretValue,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        if self.config.grant_type != OAuthGrantType::AuthorizationCode {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        let fields = vec![
            ("grant_type".to_owned(), SecretValue::new("refresh_token")),
            ("refresh_token".to_owned(), refresh_token.clone()),
        ];
        let request = if self.config.device_grant == DeviceAuthorizationGrant::CodexAccounts {
            let mut fields = fields;
            fields.push((
                "client_id".to_owned(),
                SecretValue::new(self.config.client_id.clone()),
            ));
            OAuthHttpRequest::post_json(
                self.config.token_endpoint.clone(),
                SecretValue::new(json_form(&fields)),
            )
        } else {
            self.token_request(fields)
        };
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            let tokens =
                Self::parse_token_response(&response).map_err(TokenEndpointError::into_oauth)?;
            if tokens.refresh_token().is_some() {
                return Ok(tokens);
            }
            Ok(OAuthTokens::new(
                SecretValue::new(tokens.access_token().expose_secret().to_owned()),
                Some(refresh_token.clone()),
                tokens.expires_at(),
                tokens.token_type().to_owned(),
            )
            .with_id_token(tokens.id_token().cloned()))
        })
    }

    fn renew<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        match self.config.grant_type {
            OAuthGrantType::ClientCredentials => self.acquire_client_credentials(cancellation),
            OAuthGrantType::AuthorizationCode => {
                let Some(refresh_token) = tokens.refresh_token() else {
                    return Box::pin(async { Err(OAuthError::NoRefreshToken) });
                };
                self.refresh(refresh_token, cancellation)
            }
        }
    }
}

impl OAuthClientCredentials for StandardOAuthProvider {
    fn acquire_client_credentials(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, OAuthTokens> {
        if self.config.grant_type != OAuthGrantType::ClientCredentials {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        let mut fields = vec![(
            "grant_type".to_owned(),
            SecretValue::new("client_credentials"),
        )];
        if !self.config.scopes.is_empty() {
            fields.push((
                "scope".to_owned(),
                SecretValue::new(self.config.scopes.join(" ")),
            ));
        }
        let request = self.token_request(fields);
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            Self::parse_token_response(&response).map_err(TokenEndpointError::into_oauth)
        })
    }
}

impl OAuthRevoker for StandardOAuthProvider {
    fn revoke<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, ()> {
        let Some(endpoint) = self.config.revocation_endpoint.clone() else {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        };
        let mut form = vec![("token".to_owned(), tokens.access_token().clone())];
        form.push((
            "token_type_hint".to_owned(),
            SecretValue::new(tokens.token_type().to_owned()),
        ));
        let request = match self.config.request_encoding {
            OAuthRequestEncoding::Form => {
                self.apply_client_auth(OAuthHttpRequest::post_form(endpoint, form))
            }
            OAuthRequestEncoding::Json => {
                let mut form = form;
                form.push((
                    "client_id".to_owned(),
                    SecretValue::new(self.config.client_id.clone()),
                ));
                if let OAuthClientAuth::RequestBody(secret) = &self.config.client_auth {
                    form.push(("client_secret".to_owned(), secret.clone()));
                }
                self.apply_client_auth_json(OAuthHttpRequest::post_json(
                    endpoint,
                    SecretValue::new(json_form(&form)),
                ))
            }
        };
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            if (200..300).contains(&response.status()) {
                Ok(())
            } else {
                let value = parse_json(&response)?;
                Err(classify_provider_error(response.status(), &value))
            }
        })
    }
}

impl OAuthIdentityProvider for StandardOAuthProvider {
    fn identity<'a>(
        &'a self,
        tokens: &'a OAuthTokens,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthIdentity> {
        let Some(endpoint) = self.config.identity_endpoint.clone() else {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        };
        let request =
            OAuthHttpRequest::get(endpoint).with_bearer_auth(tokens.access_token().clone());
        Box::pin(async move {
            let response = self.send(request, cancellation).await?;
            let value = parse_json(&response)?;
            if !(200..300).contains(&response.status()) {
                return Err(classify_provider_error(response.status(), &value));
            }
            let object = value.as_object().ok_or(OAuthError::InvalidResponse)?;
            let subject = object
                .get("sub")
                .or_else(|| object.get("id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(OAuthError::InvalidResponse)?;
            Ok(OAuthIdentity {
                subject: subject.to_owned(),
                email: object
                    .get("email")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                name: object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            })
        })
    }
}

impl OAuthDeviceFlow for StandardOAuthProvider {
    fn start_device_authorization(
        &self,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'_, DeviceAuthorization> {
        if self.config.grant_type != OAuthGrantType::AuthorizationCode {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        match self.config.device_grant {
            DeviceAuthorizationGrant::Rfc8628 => {
                self.start_rfc8628_device_authorization(cancellation)
            }
            DeviceAuthorizationGrant::CodexAccounts => {
                self.start_codex_device_authorization(cancellation)
            }
        }
    }

    fn poll_device<'a>(
        &'a self,
        authorization: &'a DeviceAuthorization,
        cancellation: CancellationToken,
    ) -> OAuthFuture<'a, OAuthTokens> {
        if self.config.grant_type != OAuthGrantType::AuthorizationCode {
            return Box::pin(async { Err(OAuthError::Unsupported) });
        }
        match self.config.device_grant {
            DeviceAuthorizationGrant::Rfc8628 => {
                self.poll_rfc8628_device(authorization, cancellation)
            }
            DeviceAuthorizationGrant::CodexAccounts => {
                self.poll_codex_device(authorization, cancellation)
            }
        }
    }
}

enum DevicePollError {
    Pending,
    SlowDown,
    OAuth(OAuthError),
}

struct CodexDeviceEndpoints {
    usercode: Url,
    poll: Url,
    verification: Url,
    callback: Url,
}

struct CodexIssuedAuthorization {
    authorization_code: String,
    code_verifier: String,
}

fn derive_codex_device_endpoints(usercode: &Url) -> Result<CodexDeviceEndpoints, OAuthError> {
    let path = usercode.path();
    let poll_path = path
        .strip_suffix("usercode")
        .ok_or(OAuthError::InvalidConfiguration)?;
    let mut poll = usercode.clone();
    poll.set_path(&format!("{poll_path}token"));
    let mut origin = usercode.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let verification = origin
        .join("codex/device")
        .map_err(|_| OAuthError::InvalidConfiguration)?;
    let callback = origin
        .join("deviceauth/callback")
        .map_err(|_| OAuthError::InvalidConfiguration)?;
    if !valid_endpoint(&poll) || !valid_endpoint(&verification) || !valid_endpoint(&callback) {
        return Err(OAuthError::InvalidConfiguration);
    }
    Ok(CodexDeviceEndpoints {
        usercode: usercode.clone(),
        poll,
        verification,
        callback,
    })
}

fn json_duration_secs(value: Option<&Value>) -> Option<Duration> {
    let value = value?;
    let seconds = value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())?;
    Some(Duration::from_secs(seconds))
}

fn bounded_device_poll_interval(interval: Duration) -> Duration {
    interval.clamp(DEVICE_POLL_MIN_INTERVAL, DEVICE_POLL_MAX_INTERVAL)
}

fn expired_device_code() -> OAuthError {
    OAuthError::Provider {
        status: 400,
        code: OAuthProviderErrorCode::ExpiredToken,
    }
}

enum TokenEndpointError {
    Pending,
    SlowDown,
    Expired,
    OAuth(OAuthError),
}

impl TokenEndpointError {
    fn into_oauth(self) -> OAuthError {
        match self {
            Self::Pending => OAuthError::Provider {
                status: 400,
                code: OAuthProviderErrorCode::AuthorizationPending,
            },
            Self::SlowDown => OAuthError::Provider {
                status: 400,
                code: OAuthProviderErrorCode::SlowDown,
            },
            Self::Expired => OAuthError::Provider {
                status: 400,
                code: OAuthProviderErrorCode::ExpiredToken,
            },
            Self::OAuth(error) => error,
        }
    }
}

fn parse_json(response: &OAuthHttpResponse) -> Result<Value, OAuthError> {
    serde_json::from_slice(response.body_bytes()).map_err(|_| OAuthError::InvalidResponse)
}

fn classify_token_error(status: u16, value: &Value) -> TokenEndpointError {
    match value.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => TokenEndpointError::Pending,
        Some("slow_down") => TokenEndpointError::SlowDown,
        Some("expired_token") => TokenEndpointError::Expired,
        Some("invalid_grant") => TokenEndpointError::OAuth(OAuthError::NeedsReauth),
        Some(code) => TokenEndpointError::OAuth(OAuthError::Provider {
            status,
            code: provider_error_code(code),
        }),
        None => TokenEndpointError::OAuth(OAuthError::Provider {
            status,
            code: OAuthProviderErrorCode::Other,
        }),
    }
}

fn classify_provider_error(status: u16, value: &Value) -> OAuthError {
    let code = value
        .get("error")
        .and_then(Value::as_str)
        .map(provider_error_code)
        .unwrap_or(OAuthProviderErrorCode::Other);
    if code == OAuthProviderErrorCode::InvalidGrant {
        OAuthError::NeedsReauth
    } else {
        OAuthError::Provider { status, code }
    }
}

fn provider_error_code(value: &str) -> OAuthProviderErrorCode {
    match value {
        "invalid_grant" => OAuthProviderErrorCode::InvalidGrant,
        "authorization_pending" => OAuthProviderErrorCode::AuthorizationPending,
        "slow_down" => OAuthProviderErrorCode::SlowDown,
        "expired_token" => OAuthProviderErrorCode::ExpiredToken,
        "access_denied" => OAuthProviderErrorCode::AccessDenied,
        "invalid_client" => OAuthProviderErrorCode::InvalidClient,
        _ => OAuthProviderErrorCode::Other,
    }
}

/// A token set paired with its store generation.
#[derive(Clone, Eq, PartialEq)]
pub struct TokenSnapshot {
    generation: u64,
    tokens: OAuthTokens,
}

impl TokenSnapshot {
    /// Create an initial generation snapshot.
    #[must_use]
    pub fn initial(tokens: OAuthTokens) -> Self {
        Self::new(0, tokens)
    }

    /// Reconstruct a persisted snapshot with its store generation.
    #[must_use]
    pub const fn new(generation: u64, tokens: OAuthTokens) -> Self {
        Self { generation, tokens }
    }

    /// Store generation used for compare-and-swap.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrow tokens at the outbound request boundary.
    #[must_use]
    pub fn tokens(&self) -> &OAuthTokens {
        &self.tokens
    }
}

impl fmt::Debug for TokenSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenSnapshot")
            .field("generation", &self.generation)
            .field("tokens", &self.tokens)
            .finish()
    }
}

/// Errors returned by a token store without exposing token material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OAuthStoreError {
    /// The expected generation did not match the current one.
    #[error("oauth token generation conflict")]
    Conflict,
    /// The immutable account/provider configuration no longer matches the
    /// encrypted record being accessed.
    #[error("oauth credential identity conflict")]
    IdentityConflict,
    /// No token record exists for the credential.
    #[error("oauth token record was not found")]
    NotFound,
    /// The backing store is unavailable.
    #[error("oauth token store is unavailable")]
    Unavailable,
}

/// A boxed asynchronous token-store operation.
pub type OAuthStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, OAuthStoreError>> + Send + 'a>>;

/// Persistence boundary for encrypted or owner-private OAuth token stores.
///
/// Implementations must encrypt at rest when persistence leaves process memory,
/// and must never include token material in errors or diagnostics.
pub trait OAuthTokenStore: Send + Sync {
    /// Load the current generation for one credential.
    fn load<'a>(
        &'a self,
        credential: &'a CredentialId,
    ) -> OAuthStoreFuture<'a, Option<TokenSnapshot>>;

    /// Load only when the persisted credential configuration fingerprint
    /// matches the caller's compiled identity. Implementations that do not
    /// persist identity metadata retain the legacy behavior for tests and
    /// explicitly ephemeral stores.
    fn load_for_fingerprint<'a>(
        &'a self,
        credential: &'a CredentialId,
        _fingerprint: &'a str,
    ) -> OAuthStoreFuture<'a, Option<TokenSnapshot>> {
        self.load(credential)
    }

    /// Commit new tokens only when the caller still owns `expected_generation`.
    fn compare_and_swap<'a>(
        &'a self,
        credential: &'a CredentialId,
        expected_generation: u64,
        tokens: OAuthTokens,
    ) -> OAuthStoreFuture<'a, TokenSnapshot>;

    /// Commit new tokens only when both generation and immutable credential
    /// identity still match.
    fn compare_and_swap_for_fingerprint<'a>(
        &'a self,
        credential: &'a CredentialId,
        expected_generation: u64,
        _fingerprint: &'a str,
        tokens: OAuthTokens,
    ) -> OAuthStoreFuture<'a, TokenSnapshot> {
        self.compare_and_swap(credential, expected_generation, tokens)
    }

    /// Remove persisted token material after revocation or account removal.
    fn remove<'a>(&'a self, credential: &'a CredentialId) -> OAuthStoreFuture<'a, ()>;
}

/// Bounded in-memory token store used by tests and process-local deployments.
#[derive(Clone, Default)]
pub struct MemoryOAuthTokenStore {
    records: Arc<Mutex<HashMap<CredentialId, TokenSnapshot>>>,
}

impl MemoryOAuthTokenStore {
    /// Create an empty memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a record for deterministic setup.  The replacement
    /// starts at generation zero because it represents a new credential.
    pub fn insert(&self, credential: CredentialId, tokens: OAuthTokens) -> TokenSnapshot {
        let snapshot = TokenSnapshot::initial(tokens);
        lock_unpoisoned(&self.records).insert(credential, snapshot.clone());
        snapshot
    }

    /// Return the number of records, without exposing IDs or tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        lock_unpoisoned(&self.records).len()
    }

    /// Whether the store has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl OAuthTokenStore for MemoryOAuthTokenStore {
    fn load<'a>(
        &'a self,
        credential: &'a CredentialId,
    ) -> OAuthStoreFuture<'a, Option<TokenSnapshot>> {
        Box::pin(async move { Ok(lock_unpoisoned(&self.records).get(credential).cloned()) })
    }

    fn compare_and_swap<'a>(
        &'a self,
        credential: &'a CredentialId,
        expected_generation: u64,
        tokens: OAuthTokens,
    ) -> OAuthStoreFuture<'a, TokenSnapshot> {
        Box::pin(async move {
            let mut records = lock_unpoisoned(&self.records);
            let current = records.get(credential).ok_or(OAuthStoreError::NotFound)?;
            if current.generation != expected_generation {
                return Err(OAuthStoreError::Conflict);
            }
            let snapshot = TokenSnapshot {
                generation: current.generation.saturating_add(1),
                tokens,
            };
            records.insert(credential.clone(), snapshot.clone());
            Ok(snapshot)
        })
    }

    fn remove<'a>(&'a self, credential: &'a CredentialId) -> OAuthStoreFuture<'a, ()> {
        Box::pin(async move {
            lock_unpoisoned(&self.records).remove(credential);
            Ok(())
        })
    }
}

/// Refresh one persisted credential with a single cancellation-safe lease and
/// an atomic generation commit.
///
/// The store is read inside the leader operation.  Concurrent callers wait on
/// the same provider request; a caller that cancels while waiting does not
/// cancel the leader.  If another writer advances the generation, the refresh
/// result is rejected rather than overwriting newer token material.
pub async fn refresh_with_store(
    coordinator: &RefreshCoordinator,
    provider: &dyn OAuthRefresher,
    store: &dyn OAuthTokenStore,
    credential: CredentialId,
    cancellation: CancellationToken,
) -> Result<TokenSnapshot, OAuthError> {
    refresh_with_store_if_generation(coordinator, provider, store, credential, None, cancellation)
        .await
}

/// Refresh one persisted credential only when its access token still has the
/// supplied generation.
///
/// A request can observe a stale access token, receive a 401, and then lose
/// the refresh lease before it enters the coordinator. Checking the observed
/// generation inside the leased operation lets that request reuse the token
/// already persisted by the winner instead of issuing a second refresh.
pub async fn refresh_with_store_if_generation(
    coordinator: &RefreshCoordinator,
    provider: &dyn OAuthRefresher,
    store: &dyn OAuthTokenStore,
    credential: CredentialId,
    expected_generation: Option<u64>,
    cancellation: CancellationToken,
) -> Result<TokenSnapshot, OAuthError> {
    renew_store_generation(
        coordinator,
        provider,
        store,
        credential,
        expected_generation,
        cancellation,
        RenewalStrategy::RefreshToken,
        None,
    )
    .await
}

/// Refresh one persisted credential under an immutable configuration
/// fingerprint. The fingerprint is part of the singleflight and CAS key.
pub async fn refresh_with_store_if_generation_for_fingerprint(
    coordinator: &RefreshCoordinator,
    provider: &dyn OAuthRefresher,
    store: &dyn OAuthTokenStore,
    credential: CredentialId,
    fingerprint: impl Into<String>,
    expected_generation: Option<u64>,
    cancellation: CancellationToken,
) -> Result<TokenSnapshot, OAuthError> {
    renew_store_generation(
        coordinator,
        provider,
        store,
        credential,
        expected_generation,
        cancellation,
        RenewalStrategy::RefreshToken,
        Some(fingerprint.into()),
    )
    .await
}

/// Renew one persisted credential, reacquiring client-credentials tokens when
/// no refresh token exists, and atomically commit the next generation.
pub async fn renew_with_store_if_generation(
    coordinator: &RefreshCoordinator,
    provider: &dyn OAuthRefresher,
    store: &dyn OAuthTokenStore,
    credential: CredentialId,
    expected_generation: Option<u64>,
    cancellation: CancellationToken,
) -> Result<TokenSnapshot, OAuthError> {
    renew_store_generation(
        coordinator,
        provider,
        store,
        credential,
        expected_generation,
        cancellation,
        RenewalStrategy::GrantAware,
        None,
    )
    .await
}

/// Renew a persisted credential under an immutable configuration fingerprint.
/// Client-credentials and refresh-token rotations share no lease or CAS path
/// with another configuration that reuses the same account ID.
pub async fn renew_with_store_if_generation_for_fingerprint(
    coordinator: &RefreshCoordinator,
    provider: &dyn OAuthRefresher,
    store: &dyn OAuthTokenStore,
    credential: CredentialId,
    fingerprint: impl Into<String>,
    expected_generation: Option<u64>,
    cancellation: CancellationToken,
) -> Result<TokenSnapshot, OAuthError> {
    renew_store_generation(
        coordinator,
        provider,
        store,
        credential,
        expected_generation,
        cancellation,
        RenewalStrategy::GrantAware,
        Some(fingerprint.into()),
    )
    .await
}

#[derive(Clone, Copy)]
enum RenewalStrategy {
    RefreshToken,
    GrantAware,
}

#[allow(clippy::too_many_arguments)] // The explicit fence/cancellation inputs define one atomic refresh.
async fn renew_store_generation(
    coordinator: &RefreshCoordinator,
    provider: &dyn OAuthRefresher,
    store: &dyn OAuthTokenStore,
    credential: CredentialId,
    expected_generation: Option<u64>,
    cancellation: CancellationToken,
    strategy: RenewalStrategy,
    fingerprint: Option<String>,
) -> Result<TokenSnapshot, OAuthError> {
    let operation_credential = credential.clone();
    let operation_cancellation = cancellation.clone();
    let operation_fingerprint = fingerprint.clone();
    let lease_fingerprint = fingerprint.as_deref().unwrap_or("").to_owned();
    coordinator
        .refresh_cancellable_for_fingerprint(
            credential.clone(),
            lease_fingerprint,
            cancellation,
            || async move {
                let snapshot = load_store_snapshot(
                    store,
                    &operation_credential,
                    operation_fingerprint.as_deref(),
                )
                .await
                .map_err(|error| RefreshError::OAuth(OAuthError::Store(error)))?
                .ok_or(RefreshError::OAuth(OAuthError::NoRefreshToken))?;
                if expected_generation.is_some_and(|expected| snapshot.generation() != expected) {
                    return Ok(snapshot.tokens().clone());
                }
                let renewal = match strategy {
                    RenewalStrategy::RefreshToken => {
                        let refresh_token = snapshot
                            .tokens()
                            .refresh_token()
                            .ok_or(RefreshError::OAuth(OAuthError::NoRefreshToken))?
                            .clone();
                        provider
                            .refresh(&refresh_token, operation_cancellation.clone())
                            .await
                    }
                    RenewalStrategy::GrantAware => {
                        provider
                            .renew(snapshot.tokens(), operation_cancellation.clone())
                            .await
                    }
                };
                let tokens = match renewal {
                    Ok(tokens) => tokens,
                    Err(OAuthError::NeedsReauth) => {
                        // A concurrent login may replace a revoked token while the
                        // provider request is in flight. Only the generation that
                        // actually received invalid_grant may require reauthorization.
                        let current = load_store_snapshot(
                            store,
                            &operation_credential,
                            operation_fingerprint.as_deref(),
                        )
                        .await
                        .map_err(|error| RefreshError::OAuth(OAuthError::Store(error)))?
                        .ok_or(RefreshError::OAuth(OAuthError::NoRefreshToken))?;
                        if current.generation() != snapshot.generation() {
                            return Ok(current.tokens().clone());
                        }
                        return Err(RefreshError::NeedsReauth);
                    }
                    Err(error) => return Err(refresh_error(error)),
                };
                let result = match operation_fingerprint.as_deref() {
                    Some(fingerprint) => {
                        store
                            .compare_and_swap_for_fingerprint(
                                &operation_credential,
                                snapshot.generation(),
                                fingerprint,
                                tokens.clone(),
                            )
                            .await
                    }
                    None => {
                        store
                            .compare_and_swap(
                                &operation_credential,
                                snapshot.generation(),
                                tokens.clone(),
                            )
                            .await
                    }
                };
                result.map_err(|error| match error {
                    OAuthStoreError::Conflict => RefreshError::GenerationConflict,
                    other => RefreshError::OAuth(OAuthError::Store(other)),
                })?;
                Ok(tokens)
            },
        )
        .await
        .map_err(oauth_refresh_error)?;
    match fingerprint.as_deref() {
        Some(fingerprint) => store.load_for_fingerprint(&credential, fingerprint).await,
        None => store.load(&credential).await,
    }
    .map_err(OAuthError::Store)?
    .ok_or(OAuthError::NoRefreshToken)
}

async fn load_store_snapshot(
    store: &dyn OAuthTokenStore,
    credential: &CredentialId,
    fingerprint: Option<&str>,
) -> Result<Option<TokenSnapshot>, OAuthStoreError> {
    match fingerprint {
        Some(fingerprint) => store.load_for_fingerprint(credential, fingerprint).await,
        None => store.load(credential).await,
    }
}

fn refresh_error(error: OAuthError) -> RefreshError {
    match error {
        OAuthError::NeedsReauth => RefreshError::NeedsReauth,
        OAuthError::GenerationConflict => RefreshError::GenerationConflict,
        other => RefreshError::OAuth(other),
    }
}

fn oauth_refresh_error(error: RefreshError) -> OAuthError {
    match error {
        RefreshError::Cancelled => OAuthError::Cancelled,
        RefreshError::NeedsReauth => OAuthError::NeedsReauth,
        RefreshError::GenerationConflict => OAuthError::GenerationConflict,
        RefreshError::OAuth(error) => error,
        RefreshError::Failed(_) => OAuthError::Transport(OAuthTransportError::Failed),
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct MockTransport {
        responses: Mutex<VecDeque<Result<OAuthHttpResponse, OAuthTransportError>>>,
        requests: Mutex<Vec<OAuthHttpRequest>>,
    }

    impl MockTransport {
        fn new(responses: impl IntoIterator<Item = OAuthHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(Ok).collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request(&self, index: usize) -> OAuthHttpRequest {
            lock_unpoisoned(&self.requests)[index].clone()
        }
    }

    impl OAuthTransport for MockTransport {
        fn send(
            &self,
            request: OAuthHttpRequest,
            cancellation: CancellationToken,
        ) -> OAuthTransportFuture<'_> {
            let response = lock_unpoisoned(&self.responses)
                .pop_front()
                .unwrap_or(Err(OAuthTransportError::Failed));
            lock_unpoisoned(&self.requests).push(request);
            Box::pin(async move {
                if cancellation.is_cancelled() {
                    Err(OAuthTransportError::Cancelled)
                } else {
                    response
                }
            })
        }
    }

    #[derive(Default)]
    struct BlockingNeedsReauthRefresher {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl OAuthRefresher for BlockingNeedsReauthRefresher {
        fn refresh<'a>(
            &'a self,
            _refresh_token: &'a SecretValue,
            _cancellation: CancellationToken,
        ) -> OAuthFuture<'a, OAuthTokens> {
            Box::pin(async move {
                self.started.notify_one();
                self.release.notified().await;
                Err(OAuthError::NeedsReauth)
            })
        }
    }

    fn config() -> OAuthClientConfig {
        OAuthClientConfig::new(
            "client-id",
            "http://127.0.0.1:1455/callback".parse().unwrap(),
            "https://provider.example/authorize".parse().unwrap(),
            "https://provider.example/token".parse().unwrap(),
        )
        .unwrap()
        .with_scopes(["openid", "profile"])
        .with_device_authorization_endpoint("https://provider.example/device".parse().unwrap())
        .with_revocation_endpoint("https://provider.example/revoke".parse().unwrap())
        .with_identity_endpoint("https://provider.example/me".parse().unwrap())
    }

    fn provider(transport: Arc<MockTransport>) -> StandardOAuthProvider {
        StandardOAuthProvider::new("provider", config(), transport).unwrap()
    }

    #[test]
    fn pkce_matches_rfc7636_s256_example() {
        let pair = PkcePair::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        assert_eq!(
            pair.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(!format!("{pair:?}").contains("dBjft"));
    }

    #[test]
    fn callback_requires_exact_target_and_state() {
        let transport = Arc::new(MockTransport::new([]));
        let provider = provider(transport);
        let attempt = provider.begin_authorization().unwrap();
        let callback: Url = format!(
            "http://127.0.0.1:1455/callback?code=auth-code&state={}",
            attempt.state().value()
        )
        .parse()
        .unwrap();
        assert_eq!(
            attempt
                .validate_callback(&callback)
                .unwrap()
                .secret()
                .expose_secret(),
            "auth-code"
        );
        let wrong_state: Url = "http://127.0.0.1:1455/callback?code=auth-code&state=wrong"
            .parse()
            .unwrap();
        assert_eq!(
            attempt.validate_callback(&wrong_state),
            Err(OAuthError::InvalidState)
        );
        let wrong_path: Url = format!(
            "http://127.0.0.1:1455/other?code=auth-code&state={}",
            attempt.state().value()
        )
        .parse()
        .unwrap();
        assert_eq!(
            attempt.validate_callback(&wrong_path),
            Err(OAuthError::RedirectMismatch)
        );
    }

    #[tokio::test]
    async fn code_exchange_uses_pkce_and_redacts_request() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            200,
            br#"{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":3600}"#,
        )]));
        let provider = provider(Arc::clone(&transport));
        let attempt = provider.begin_authorization().unwrap();
        let code = AuthorizationCode::new("authorization-code").unwrap();
        let tokens = provider
            .exchange_code(
                &code,
                attempt.pkce(),
                attempt.redirect_uri(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(tokens.access_token().expose_secret(), "access-secret");
        let request = transport.request(0);
        assert_eq!(
            request.form_field("grant_type").unwrap().expose_secret(),
            "authorization_code"
        );
        assert_eq!(
            request.form_field("code").unwrap().expose_secret(),
            "authorization-code"
        );
        assert_eq!(
            request.form_field("code_verifier").unwrap().expose_secret(),
            attempt.pkce().verifier().expose_secret()
        );
        let rendered = format!("{request:?}{tokens:?}");
        assert!(!rendered.contains("authorization-code"));
        assert!(!rendered.contains("access-secret"));
        assert!(!rendered.contains("refresh-secret"));
    }

    #[tokio::test]
    async fn code_exchange_rejects_redirect_mismatch_before_transport() {
        let transport = Arc::new(MockTransport::new([]));
        let provider = provider(Arc::clone(&transport));
        let attempt = provider.begin_authorization().unwrap();
        let code = AuthorizationCode::new("authorization-code").unwrap();
        let wrong_redirect: Url = "http://127.0.0.1:1455/other".parse().unwrap();
        let result = provider
            .exchange_code(
                &code,
                attempt.pkce(),
                &wrong_redirect,
                CancellationToken::new(),
            )
            .await;
        assert_eq!(result, Err(OAuthError::RedirectMismatch));
        assert!(lock_unpoisoned(&transport.requests).is_empty());
    }

    #[tokio::test]
    async fn client_credentials_uses_request_body_secret_and_redacts_it() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            200,
            br#"{"access_token":"service-access","token_type":"Bearer","expires_in":3600}"#,
        )]));
        let provider_transport: Arc<dyn OAuthTransport> = transport.clone();
        let config = config()
            .with_client_auth(OAuthClientAuth::RequestBody(SecretValue::new(
                "service-client-secret",
            )))
            .with_client_credentials_grant();
        let provider = StandardOAuthProvider::new("provider", config, provider_transport).unwrap();

        let tokens = provider
            .acquire_client_credentials(CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(tokens.access_token().expose_secret(), "service-access");
        assert!(tokens.refresh_token().is_none());
        assert_eq!(provider.begin_authorization(), Err(OAuthError::Unsupported));

        let request = transport.request(0);
        assert_eq!(
            request.form_field("grant_type").unwrap().expose_secret(),
            "client_credentials"
        );
        assert_eq!(
            request.form_field("client_id").unwrap().expose_secret(),
            "client-id"
        );
        assert_eq!(
            request.form_field("client_secret").unwrap().expose_secret(),
            "service-client-secret"
        );
        assert_eq!(
            request.form_field("scope").unwrap().expose_secret(),
            "openid profile"
        );
        let rendered = format!("{provider:?}{request:?}{tokens:?}");
        assert!(!rendered.contains("service-client-secret"));
        assert!(!rendered.contains("service-access"));
    }

    #[tokio::test]
    async fn client_credentials_renewal_reacquires_and_commits_one_generation() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            200,
            br#"{"access_token":"renewed-service-access","expires_in":3600}"#,
        )]));
        let provider_transport: Arc<dyn OAuthTransport> = transport.clone();
        let provider = StandardOAuthProvider::new(
            "provider",
            config()
                .with_client_auth(OAuthClientAuth::RequestBody(SecretValue::new(
                    "service-client-secret",
                )))
                .with_client_credentials_grant(),
            provider_transport,
        )
        .unwrap();
        let store = MemoryOAuthTokenStore::new();
        let credential = CredentialId::new("service-account").unwrap();
        store.insert(
            credential.clone(),
            OAuthTokens::bearer(
                "expired-service-access",
                None::<String>,
                Some(SystemTime::now()),
            ),
        );

        let renewed = renew_with_store_if_generation(
            &RefreshCoordinator::new(),
            &provider,
            &store,
            credential,
            Some(0),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(renewed.generation(), 1);
        assert_eq!(
            renewed.tokens().access_token().expose_secret(),
            "renewed-service-access"
        );
        assert!(renewed.tokens().refresh_token().is_none());
        assert_eq!(lock_unpoisoned(&transport.requests).len(), 1);
    }

    #[tokio::test]
    async fn json_request_encoding_supports_native_provider_endpoints() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            200,
            br#"{"access_token":"json-access"}"#,
        )]));
        let provider_transport: Arc<dyn OAuthTransport> = transport.clone();
        let json_config = config().with_json_requests();
        let provider =
            StandardOAuthProvider::new("provider", json_config, provider_transport).unwrap();
        let attempt = provider.begin_authorization().unwrap();
        let code = AuthorizationCode::new("json-code").unwrap();
        provider
            .exchange_code(
                &code,
                attempt.pkce(),
                attempt.redirect_uri(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let request = transport.request(0);
        let body = request.json_body().unwrap().expose_secret();
        let value: Value = serde_json::from_str(body).unwrap();
        assert_eq!(value["client_id"], "client-id");
        assert_eq!(value["code"], "json-code");
        assert!(!format!("{request:?}").contains("json-code"));
    }

    #[tokio::test]
    async fn invalid_grant_requires_reauthorization_without_body_leak() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            400,
            br#"{"error":"invalid_grant","error_description":"refresh-secret"}"#,
        )]));
        let provider = provider(transport);
        let error = provider
            .refresh(
                &SecretValue::new("refresh-secret"),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, OAuthError::NeedsReauth);
        assert!(!format!("{error:?}").contains("refresh-secret"));
    }

    #[tokio::test]
    async fn refresh_preserves_previous_refresh_token_when_provider_omits_one() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            200,
            br#"{"access_token":"new-access"}"#,
        )]));
        let provider = provider(transport);
        let tokens = provider
            .refresh(&SecretValue::new("old-refresh"), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(tokens.access_token().expose_secret(), "new-access");
        assert_eq!(
            tokens.refresh_token().unwrap().expose_secret(),
            "old-refresh"
        );
    }

    #[tokio::test]
    async fn revoke_and_identity_keep_authorization_material_at_boundaries() {
        let transport = Arc::new(MockTransport::new([
            OAuthHttpResponse::new(204, Vec::<u8>::new()),
            OAuthHttpResponse::new(
                200,
                br#"{"sub":"user-123","email":"user@example.test","name":"Test User"}"#,
            ),
        ]));
        let provider = provider(Arc::clone(&transport));
        let tokens = OAuthTokens::bearer("access-secret", Some("refresh-secret"), None);
        provider
            .revoke(&tokens, CancellationToken::new())
            .await
            .unwrap();
        let identity = provider
            .identity(&tokens, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(identity.subject, "user-123");
        assert_eq!(identity.email.as_deref(), Some("user@example.test"));
        assert!(!format!("{:?}", transport.request(0)).contains("access-secret"));
        assert!(!format!("{:?}", transport.request(1)).contains("access-secret"));
    }

    #[tokio::test]
    async fn device_flow_polls_pending_then_returns_tokens() {
        let transport = Arc::new(MockTransport::new([
            OAuthHttpResponse::new(
                200,
                br#"{"device_code":"device-secret","user_code":"ABCD","verification_uri":"https://provider.example/verify","expires_in":30,"interval":0}"#,
            ),
            OAuthHttpResponse::new(
                400,
                br#"{"error":"authorization_pending"}"#,
            ),
            OAuthHttpResponse::new(
                200,
                br#"{"access_token":"device-access","refresh_token":"device-refresh"}"#,
            ),
        ]));
        let provider = provider(Arc::clone(&transport));
        let authorization = provider
            .start_device_authorization(CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(authorization.user_code(), "ABCD");
        let tokens = provider
            .poll_device(&authorization, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(tokens.access_token().expose_secret(), "device-access");
        assert_eq!(
            transport
                .request(1)
                .form_field("device_code")
                .unwrap()
                .expose_secret(),
            "device-secret"
        );
        assert!(!format!("{authorization:?}").contains("device-secret"));
    }

    #[tokio::test]
    async fn codex_device_login_polls_accounts_api_then_exchanges_the_code() {
        let transport = Arc::new(MockTransport::new([
            OAuthHttpResponse::new(
                200,
                br#"{"device_auth_id":"device-auth-123","user_code":"CODE-12345","interval":"0"}"#,
            ),
            OAuthHttpResponse::new(404, br#"{}"#),
            OAuthHttpResponse::new(
                200,
                br#"{"authorization_code":"poll-code-321","code_challenge":"ignored","code_verifier":"code-verifier-321"}"#,
            ),
            OAuthHttpResponse::new(
                200,
                br#"{"access_token":"codex-access","refresh_token":"codex-refresh","id_token":"codex-id"}"#,
            ),
        ]));
        let config = OAuthClientConfig::new(
            "app_EMoamEEZ73f0CkXaXp7hrann",
            "http://localhost:1455/auth/callback".parse().unwrap(),
            "https://auth.openai.com/oauth/authorize".parse().unwrap(),
            "https://auth.openai.com/oauth/token".parse().unwrap(),
        )
        .unwrap()
        .with_device_authorization_endpoint(
            "https://auth.openai.com/api/accounts/deviceauth/usercode"
                .parse()
                .unwrap(),
        )
        .with_device_grant(DeviceAuthorizationGrant::CodexAccounts);
        let provider =
            StandardOAuthProvider::new("openai", config, Arc::clone(&transport) as Arc<_>).unwrap();
        let authorization = provider
            .start_device_authorization(CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(authorization.user_code(), "CODE-12345");
        assert_eq!(
            authorization.verification_uri().as_str(),
            "https://auth.openai.com/codex/device"
        );
        let tokens = provider
            .poll_device(&authorization, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(tokens.access_token().expose_secret(), "codex-access");
        assert_eq!(
            transport.request(0).url().as_str(),
            "https://auth.openai.com/api/accounts/deviceauth/usercode"
        );
        assert!(transport.request(0).json_body().is_some());
        assert_eq!(
            transport.request(1).url().as_str(),
            "https://auth.openai.com/api/accounts/deviceauth/token"
        );
        assert_eq!(
            transport.request(3).url().as_str(),
            "https://auth.openai.com/oauth/token"
        );
        assert_eq!(
            transport
                .request(3)
                .form_field("redirect_uri")
                .unwrap()
                .expose_secret(),
            "https://auth.openai.com/deviceauth/callback"
        );
        assert_eq!(
            transport
                .request(3)
                .form_field("code_verifier")
                .unwrap()
                .expose_secret(),
            "code-verifier-321"
        );
        assert!(!format!("{authorization:?}").contains("device-auth-123"));
    }

    #[tokio::test]
    async fn device_poll_cancellation_interrupts_backoff() {
        let transport = Arc::new(MockTransport::new([
            OAuthHttpResponse::new(
                200,
                br#"{"device_code":"device-secret","user_code":"ABCD","verification_uri":"https://provider.example/verify","expires_in":60,"interval":60}"#,
            ),
            OAuthHttpResponse::new(400, br#"{"error":"authorization_pending"}"#),
        ]));
        let provider = provider(transport);
        let authorization = provider
            .start_device_authorization(CancellationToken::new())
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            provider
                .poll_device(&authorization, task_cancellation)
                .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(task.await.unwrap(), Err(OAuthError::Cancelled));
    }

    #[tokio::test]
    async fn refresh_store_commits_one_generation_and_shares_lease() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            200,
            br#"{"access_token":"new-access","refresh_token":"new-refresh"}"#,
        )]));
        let provider = Arc::new(provider(transport));
        let store = Arc::new(MemoryOAuthTokenStore::new());
        let credential = CredentialId::new("oauth-credential").unwrap();
        store.insert(
            credential.clone(),
            OAuthTokens::bearer("old-access", Some("old-refresh"), None),
        );
        let coordinator = RefreshCoordinator::new();
        let first = refresh_with_store(
            &coordinator,
            provider.as_ref(),
            store.as_ref(),
            credential.clone(),
            CancellationToken::new(),
        );
        let second = refresh_with_store(
            &coordinator,
            provider.as_ref(),
            store.as_ref(),
            credential,
            CancellationToken::new(),
        );
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_ok() || second.is_ok());
        assert_eq!(
            store
                .load(&CredentialId::new("oauth-credential").unwrap())
                .await
                .unwrap()
                .unwrap()
                .generation(),
            1
        );
    }

    #[test]
    fn provider_config_accepts_loopback_ports_used_by_native_clients() {
        for port in [1455, 1457] {
            let redirect: Url = format!("http://127.0.0.1:{port}/callback").parse().unwrap();
            assert!(OAuthClientConfig::new(
                "client",
                redirect,
                "https://provider.example/authorize".parse().unwrap(),
                "https://provider.example/token".parse().unwrap(),
            )
            .is_ok());
        }
    }

    #[test]
    fn device_authorization_rejects_excessive_provider_lifetimes() {
        let result = DeviceAuthorization::new(
            "device",
            "user",
            "https://provider.example/device".parse().unwrap(),
            DEVICE_AUTHORIZATION_MAX_LIFETIME + Duration::from_secs(1),
            Duration::from_secs(5),
        );
        assert_eq!(result, Err(OAuthError::InvalidResponse));
    }

    #[tokio::test]
    async fn stale_invalid_grant_preserves_newer_login_generation() {
        let coordinator = RefreshCoordinator::new();
        let provider = Arc::new(BlockingNeedsReauthRefresher::default());
        let store = Arc::new(MemoryOAuthTokenStore::new());
        let credential = CredentialId::new("oauth-concurrent-login").unwrap();
        store.insert(
            credential.clone(),
            OAuthTokens::bearer("old-access", Some("old-refresh"), None),
        );

        let refresh = tokio::spawn({
            let provider = Arc::clone(&provider);
            let store = Arc::clone(&store);
            let credential = credential.clone();
            async move {
                refresh_with_store_if_generation(
                    &coordinator,
                    provider.as_ref(),
                    store.as_ref(),
                    credential,
                    Some(0),
                    CancellationToken::new(),
                )
                .await
            }
        });
        provider.started.notified().await;

        let login = store
            .compare_and_swap(
                &credential,
                0,
                OAuthTokens::bearer("new-access", Some("new-refresh"), None),
            )
            .await
            .unwrap();
        assert_eq!(login.generation(), 1);
        provider.release.notify_one();

        let refreshed = refresh.await.unwrap().unwrap();
        assert_eq!(refreshed.generation(), 1);
        assert_eq!(
            refreshed.tokens().access_token().expose_secret(),
            "new-access"
        );
    }

    #[tokio::test]
    async fn refresh_store_maps_invalid_grant_to_needs_reauth() {
        let transport = Arc::new(MockTransport::new([OAuthHttpResponse::new(
            400,
            br#"{"error":"invalid_grant"}"#,
        )]));
        let provider = Arc::new(provider(transport));
        let store = Arc::new(MemoryOAuthTokenStore::new());
        let credential = CredentialId::new("oauth-invalid-grant").unwrap();
        store.insert(
            credential.clone(),
            OAuthTokens::bearer("old", Some("refresh"), None),
        );
        let result = refresh_with_store(
            &RefreshCoordinator::new(),
            provider.as_ref(),
            store.as_ref(),
            credential,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result, Err(OAuthError::NeedsReauth));
    }
}
