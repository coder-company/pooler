//! Safe CLI credential operations.
//!
//! The CLI owns command parsing and the loopback callback boundary. Token
//! exchange and token persistence stay behind the authentication and storage
//! crates; this module never accepts a token as a command-line argument or
//! writes token bytes to a plaintext file.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use pooler_auth::{
    AuthorizationAttempt, CredentialId, HyperOAuthTransport, OAuthClientConfig, OAuthCodeExchange,
    OAuthIdentityProvider, OAuthProvider, OAuthRevoker, OAuthState, OAuthTokenStore, PkcePair,
    StandardOAuthProvider,
};
use pooler_config::{CompiledConfig, Config, OAuthPlan, DEFAULT_OAUTH_CALLBACK};
use pooler_store::{CredentialState, MasterKey, SqliteOAuthTokenStore, SqliteStore, Store};
use url::Url;

/// The default redirect used by the local OAuth flow.
pub const DEFAULT_CALLBACK: &str = DEFAULT_OAUTH_CALLBACK;
const MAX_CALLBACK_REQUEST_BYTES: usize = 8 * 1024;

/// Credential-management operations.
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Complete an OAuth login from a provider callback response.
    Login {
        /// Configured OAuth upstream/provider ID.
        provider: String,
        /// Loopback callback URI. It must use localhost or an IP loopback address.
        #[arg(long, default_value = DEFAULT_CALLBACK)]
        callback: String,
        /// Expected OAuth state. A state is mandatory when `--response` is used.
        #[arg(long)]
        state: Option<String>,
        /// Callback URL received from the provider. This is deliberately
        /// explicit so non-interactive callers can supply a sanitized test
        /// response without placing a token on the command line.
        #[arg(long)]
        response: Option<String>,
    },
    /// Show redacted local credential metadata.
    Status {
        /// Restrict output to one configured provider.
        provider: Option<String>,
    },
    /// Revoke local credential metadata for one provider.
    Revoke {
        /// Provider whose local credential should be removed.
        provider: String,
    },
}

/// Validate a configured OAuth callback URI.
///
/// Only an explicit HTTP IP loopback address or the conventional `localhost`
/// host is accepted. Public hosts and userinfo are rejected.
pub fn validate_loopback_callback(value: &str) -> Result<Url> {
    let callback = Url::parse(value).context("oauth callback is not a valid URL")?;
    let host = callback
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("oauth callback must include an IP loopback host"))?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false);
    if callback.scheme() != "http"
        || !loopback
        || callback.port().is_none()
        || callback.port() == Some(0)
        || !callback.username().is_empty()
        || callback.password().is_some()
        || callback.query().is_some()
        || callback.fragment().is_some()
    {
        bail!(
            "oauth callback must be HTTP on an explicit IP loopback address with no query, fragment, or userinfo"
        );
    }
    Ok(callback)
}

/// Receive and parse one browser callback without deciding its OAuth state.
///
/// The caller must validate the returned URL with the state and PKCE attempt
/// that initiated the flow.
pub fn receive_callback_url(callback: &Url, attempt: &AuthorizationAttempt) -> Result<Url> {
    let address = callback_socket_address(callback)?;
    let listener = TcpListener::bind(address).context("could not bind oauth callback listener")?;
    let (mut stream, _) = listener
        .accept()
        .context("could not accept oauth callback connection")?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .context("could not set oauth callback timeout")?;
    let request_target = match read_request_target(&mut stream) {
        Ok(target) => target,
        Err(error) => {
            let _ = write_callback_response(&mut stream, false);
            return Err(error);
        }
    };
    let parsed_target = match Url::parse(&format!("http://callback.invalid{request_target}")) {
        Ok(target) => target,
        Err(error) => {
            let _ = write_callback_response(&mut stream, false);
            return Err(
                anyhow::Error::new(error).context("oauth callback request target was invalid")
            );
        }
    };
    let mut response_url = callback.clone();
    response_url.set_path(parsed_target.path());
    response_url.set_query(parsed_target.query());
    if let Err(error) = attempt.validate_callback(&response_url) {
        let _ = write_callback_response(&mut stream, false);
        return Err(anyhow::Error::new(error));
    }
    write_callback_response(&mut stream, true)?;
    Ok(response_url)
}

fn callback_socket_address(callback: &Url) -> Result<String> {
    let callback = validate_loopback_callback(callback.as_str())?;
    let host = callback
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("oauth callback host is missing"))?;
    let port = callback
        .port()
        .ok_or_else(|| anyhow::anyhow!("oauth callback port is missing"))?;
    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn read_request_target(stream: &mut TcpStream) -> Result<String> {
    let mut bytes = [0_u8; MAX_CALLBACK_REQUEST_BYTES];
    let mut length = 0;
    loop {
        let read = stream
            .read(&mut bytes[length..])
            .context("could not read oauth callback request")?;
        if read == 0 {
            break;
        }
        length += read;
        if bytes[..length]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            break;
        }
        if length == bytes.len() {
            bail!("oauth callback request exceeded its size limit");
        }
    }
    let request = std::str::from_utf8(&bytes[..length])
        .context("oauth callback request was not valid HTTP")?;
    let line = request
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("oauth callback request was empty"))?;
    let mut fields = line.split_ascii_whitespace();
    let method = fields.next();
    let target = fields.next();
    let version = fields.next();
    if method != Some("GET") || version != Some("HTTP/1.1") {
        bail!("oauth callback must use an HTTP GET request");
    }
    let target =
        target.ok_or_else(|| anyhow::anyhow!("oauth callback request target was missing"))?;
    if !target.starts_with('/') {
        bail!("oauth callback request target was invalid");
    }
    Ok(target.to_owned())
}

fn write_callback_response(stream: &mut TcpStream, success: bool) -> Result<()> {
    let (status, body) = if success {
        (
            "200 OK",
            "Pooler login complete. You may close this window.",
        )
    } else {
        ("400 Bad Request", "Pooler could not validate this login.")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("could not write oauth callback response")
}

/// Resolve the owner-private credential database path.
pub fn credential_store_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.as_os_str().is_empty() {
            bail!("credential store path must not be empty");
        }
        return Ok(path.to_owned());
    }
    if let Some(path) = std::env::var_os("POOLER_CREDENTIAL_STORE") {
        if path.is_empty() {
            bail!("POOLER_CREDENTIAL_STORE must not be empty");
        }
        return Ok(PathBuf::from(path));
    }
    let state_root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| {
            anyhow::anyhow!("credential store path is required; set --credential-store")
        })?;
    Ok(state_root.join("pooler/credentials.sqlite3"))
}

/// Run one auth operation against the configured immutable plan and local
/// owner-private metadata store.
pub fn run(
    command: AuthCommand,
    config_path: &Path,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    if let AuthCommand::Login {
        state, response, ..
    } = &command
    {
        require_response_state(response.as_deref(), state.as_deref())?;
    }
    let store_path = credential_store_path(explicit_store_path)?;
    match command {
        AuthCommand::Login {
            provider,
            callback,
            state,
            response,
        } => login(
            &provider,
            &callback,
            state.as_deref(),
            response.as_deref(),
            config_path,
            &store_path,
            credential_key_ref,
        ),
        AuthCommand::Status { provider } => {
            status(provider.as_deref(), &store_path, credential_key_ref)
        }
        AuthCommand::Revoke { provider } => {
            revoke(&provider, config_path, &store_path, credential_key_ref)
        }
    }
}

fn login(
    provider: &str,
    callback: &str,
    expected_state: Option<&str>,
    response: Option<&str>,
    config_path: &Path,
    store_path: &Path,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    require_response_state(response, expected_state)?;
    let provider_id = CredentialId::new(provider.to_owned())
        .map_err(|_| anyhow::anyhow!("provider ID is invalid"))?;
    let config = Config::from_path(config_path)?.compile()?;
    let oauth = configured_oauth(&config, provider)?;
    let callback = validate_loopback_callback(callback)?;
    if callback != *oauth.callback() {
        bail!("oauth callback does not match the provider configuration");
    }
    let master_key = load_master_key(credential_key_ref)?;
    let store = SqliteStore::open_encrypted(store_path, master_key)
        .context("could not open encrypted credential store")?;
    let provider_client = build_oauth_provider(provider, oauth, callback.clone())?;
    let attempt = match expected_state {
        Some(state) => provider_client
            .begin_authorization_with(OAuthState::new(state.to_owned())?, PkcePair::random()?)?,
        None => provider_client.begin_authorization()?,
    };
    if response.is_none() {
        println!("open {} to authorize", attempt.authorization_url());
    }
    let callback_url = match response {
        Some(response) => Url::parse(response).context("oauth callback response is invalid")?,
        None => receive_callback_url(&callback, &attempt)?,
    };
    let code = attempt.validate_callback(&callback_url)?;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not initialize OAuth runtime")?;
    let tokens = runtime.block_on(provider_client.exchange_code(
        &code,
        attempt.pkce(),
        attempt.redirect_uri(),
        cancellation,
    ))?;
    let identity = if oauth.identity_endpoint().is_some() {
        Some(runtime.block_on(
            provider_client.identity(&tokens, tokio_util::sync::CancellationToken::new()),
        )?)
    } else {
        None
    };
    let expected_revision = match store
        .credential_state(provider_id.as_str())
        .context("could not read credential metadata")?
    {
        Some(state) => state.revision,
        None => {
            store
                .upsert_credential_state(CredentialState::new(
                    provider_id.as_str(),
                    provider_id.as_str(),
                    true,
                    now_millis(),
                ))
                .context("could not record credential metadata")?
                .revision
        }
    };
    let token_store = SqliteOAuthTokenStore::new(store);
    runtime.block_on(token_store.compare_and_swap(&provider_id, expected_revision, tokens))?;
    if let Some(identity) = identity {
        token_store.set_identity(&provider_id, &identity)?;
    }
    println!("logged in: provider={provider}");
    Ok(())
}

fn require_response_state(response: Option<&str>, expected_state: Option<&str>) -> Result<()> {
    if response.is_some() && expected_state.is_none() {
        bail!("oauth login requires --state when --response is supplied");
    }
    Ok(())
}

pub(crate) fn load_master_key(reference: Option<&str>) -> Result<MasterKey> {
    let reference = reference.ok_or_else(|| {
        anyhow::anyhow!(
            "encrypted credential storage requires --credential-key-ref (use env:, file:, or keyring:)"
        )
    })?;
    let reference = pooler_auth::SecretRef::parse(reference)
        .map_err(|_| anyhow::anyhow!("credential key reference is invalid"))?;
    MasterKey::from_secret_ref(&reference)
        .map_err(|_| anyhow::anyhow!("credential key is unavailable"))
}

fn build_oauth_provider(
    provider: &str,
    oauth: &OAuthPlan,
    callback: Url,
) -> Result<StandardOAuthProvider> {
    let mut config = OAuthClientConfig::new(
        oauth.client_id().to_owned(),
        callback,
        oauth.authorization_endpoint().clone(),
        oauth.token_endpoint().clone(),
    )?
    .with_scopes(oauth.scopes().iter().map(ToString::to_string));
    if let Some(endpoint) = oauth.revocation_endpoint() {
        config = config.with_revocation_endpoint(endpoint.clone());
    }
    if let Some(endpoint) = oauth.identity_endpoint() {
        config = config.with_identity_endpoint(endpoint.clone());
    }
    let transport = HyperOAuthTransport::new(64 * 1024)?;
    StandardOAuthProvider::new(provider.to_owned(), config, Arc::new(transport)).map_err(Into::into)
}

pub(crate) fn configured_oauth<'a>(
    config: &'a CompiledConfig,
    provider: &str,
) -> Result<&'a OAuthPlan> {
    let upstream = config
        .upstreams()
        .get(provider)
        .ok_or_else(|| anyhow::anyhow!("provider `{provider}` is not configured"))?;
    upstream
        .oauth()
        .ok_or_else(|| anyhow::anyhow!("provider `{provider}` is not configured for OAuth"))
}

fn status(
    provider: Option<&str>,
    store_path: &Path,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    if let Some(provider) = provider {
        CredentialId::new(provider.to_owned())
            .map_err(|_| anyhow::anyhow!("provider ID is invalid"))?;
    }
    let store = if let Some(reference) = credential_key_ref {
        SqliteStore::open_encrypted(store_path, load_master_key(Some(reference))?)
            .context("could not open encrypted credential store")?
    } else {
        SqliteStore::open(store_path).context("could not open credential store")?
    };
    let mut count = 0;
    for state in store
        .credential_states()
        .context("could not read credential state")?
    {
        if provider.is_some_and(|expected| expected != state.provider_id) {
            continue;
        }
        let status = if state.enabled { "enabled" } else { "disabled" };
        println!(
            "provider={} credential={} status={status}",
            state.provider_id, state.credential_id
        );
        count += 1;
    }
    if count == 0 {
        println!("no credentials");
    }
    Ok(())
}

fn revoke(
    provider: &str,
    config_path: &Path,
    store_path: &Path,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    CredentialId::new(provider.to_owned())
        .map_err(|_| anyhow::anyhow!("provider ID is invalid"))?;
    let store = if let Some(reference) = credential_key_ref {
        SqliteStore::open_encrypted(store_path, load_master_key(Some(reference))?)
            .context("could not open encrypted credential store")?
    } else {
        SqliteStore::open(store_path).context("could not open credential store")?
    };
    if credential_key_ref.is_some() {
        let config = Config::from_path(config_path)?.compile()?;
        let oauth = configured_oauth(&config, provider)?;
        let callback = validate_loopback_callback(oauth.callback().as_str())?;
        let provider_client = build_oauth_provider(provider, oauth, callback)?;
        let token_store = SqliteOAuthTokenStore::new(store.clone());
        let credential = CredentialId::new(provider.to_owned())
            .map_err(|_| anyhow::anyhow!("provider ID is invalid"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("could not initialize OAuth runtime")?;
        if let Some(snapshot) = runtime.block_on(token_store.load(&credential))? {
            runtime.block_on(provider_client.revoke(
                snapshot.tokens(),
                tokio_util::sync::CancellationToken::new(),
            ))?;
        }
        runtime.block_on(token_store.remove(&credential))?;
    }
    if store
        .remove_credential_state(provider)
        .context("could not revoke credential metadata")?
    {
        println!("revoked local credential: provider={provider}");
    } else {
        println!("no credential for provider={provider}");
    }
    Ok(())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn callback_requires_ip_loopback_and_explicit_port() {
        assert!(validate_loopback_callback(DEFAULT_CALLBACK).is_ok());
        assert!(validate_loopback_callback("http://localhost:8765/callback").is_ok());
        assert!(validate_loopback_callback("https://127.0.0.1:8765/callback").is_err());
        assert!(validate_loopback_callback("http://192.0.2.1:8765/callback").is_err());
        assert!(validate_loopback_callback("http://127.0.0.1/callback").is_err());
        assert!(validate_loopback_callback("http://127.0.0.1:8765/callback?x=y").is_err());
    }

    #[test]
    fn callback_state_is_constant_time_and_code_is_redacted() {
        let callback = validate_loopback_callback(DEFAULT_CALLBACK).expect("callback");
        let response = format!("{DEFAULT_CALLBACK}?code=top-secret-code&state=state-1");
        let state = OAuthState::new("state-1").expect("state");
        let code = pooler_auth::validate_callback(
            &callback,
            &state,
            &Url::parse(&response).expect("response URL"),
        )
        .expect("response");
        assert_eq!(format!("{code:?}"), "AuthorizationCode([REDACTED])");
        assert!(!format!("{code:?}").contains("top-secret-code"));
        assert!(pooler_auth::validate_callback(
            &callback,
            &OAuthState::new("wrong-state").expect("state"),
            &Url::parse(&response).expect("response URL"),
        )
        .is_err());
    }

    #[test]
    fn callback_redirect_and_provider_errors_do_not_echo_values() {
        let callback = validate_loopback_callback(DEFAULT_CALLBACK).expect("callback");
        let wrong_redirect = "http://127.0.0.1:8765/other?code=secret&state=state";
        let error = pooler_auth::validate_callback(
            &callback,
            &OAuthState::new("state").expect("state"),
            &Url::parse(wrong_redirect).expect("redirect"),
        )
        .expect_err("redirect mismatch");
        assert!(!error.to_string().contains("secret"));
        let denied = format!("{DEFAULT_CALLBACK}?error=access_denied&state=state");
        let error = pooler_auth::validate_callback(
            &callback,
            &OAuthState::new("state").expect("state"),
            &Url::parse(&denied).expect("denied"),
        )
        .expect_err("denied");
        assert!(!error.to_string().contains("access_denied"));
    }

    #[test]
    fn callback_listener_accepts_one_bounded_loopback_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("probe port");
        let port = listener.local_addr().expect("port").port();
        drop(listener);
        let callback =
            validate_loopback_callback(&format!("http://127.0.0.1:{port}/oauth/callback"))
                .expect("callback");
        let callback_for_thread = callback.clone();
        let sender = thread::spawn(move || {
            let mut stream = loop {
                match TcpStream::connect(("127.0.0.1", port)) {
                    Ok(stream) => break stream,
                    Err(_) => thread::yield_now(),
                }
            };
            let request = format!(
                "GET {}?code=one-time&state=state-2 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                callback_for_thread.path()
            );
            stream.write_all(request.as_bytes()).expect("request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).expect("response");
            response
        });
        let state = OAuthState::new("state-2").expect("state");
        let oauth_config = OAuthClientConfig::new(
            "client",
            callback.clone(),
            Url::parse("https://auth.example.test/authorize").expect("auth URL"),
            Url::parse("https://auth.example.test/token").expect("token URL"),
        )
        .expect("config");
        let transport = Arc::new(HyperOAuthTransport::new(4 * 1024).expect("transport"));
        let provider =
            StandardOAuthProvider::new("test", oauth_config, transport).expect("provider");
        let attempt = provider
            .begin_authorization_with(
                state,
                PkcePair::from_verifier(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
                )
                .expect("pkce"),
            )
            .expect("attempt");
        let response = receive_callback_url(&callback, &attempt).expect("callback");
        let response_bytes = sender.join().expect("sender");
        assert_eq!(response.path(), callback.path());
        assert_eq!(response.query(), Some("code=one-time&state=state-2"));
        assert!(response_bytes.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[test]
    fn callback_listener_rejects_invalid_state_before_success_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("probe port");
        let port = listener.local_addr().expect("port").port();
        drop(listener);
        let callback =
            validate_loopback_callback(&format!("http://127.0.0.1:{port}/oauth/callback"))
                .expect("callback");
        let state = OAuthState::new("expected-state").expect("state");
        let oauth_config = OAuthClientConfig::new(
            "client",
            callback.clone(),
            Url::parse("https://auth.example.test/authorize").expect("auth URL"),
            Url::parse("https://auth.example.test/token").expect("token URL"),
        )
        .expect("config");
        let transport = Arc::new(HyperOAuthTransport::new(4 * 1024).expect("transport"));
        let provider =
            StandardOAuthProvider::new("test", oauth_config, transport).expect("provider");
        let attempt = provider
            .begin_authorization_with(
                state,
                PkcePair::from_verifier(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
                )
                .expect("pkce"),
            )
            .expect("attempt");
        let sender = thread::spawn(move || {
            let mut stream = loop {
                match TcpStream::connect(("127.0.0.1", port)) {
                    Ok(stream) => break stream,
                    Err(_) => thread::yield_now(),
                }
            };
            stream
                .write_all(b"GET /oauth/callback?code=one-time&state=wrong-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .expect("request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).expect("response");
            response
        });
        let error = receive_callback_url(&callback, &attempt).expect_err("invalid state");
        let response = sender.join().expect("sender");
        assert!(error.to_string().contains("state"));
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request"));
        assert!(!response.windows(3).any(|window| window == b"200"));
    }

    #[test]
    fn callback_requires_state_when_response_is_present() {
        assert!(OAuthState::new("").is_err());
        let error = require_response_state(Some("http://localhost:1455/auth/callback"), None)
            .expect_err("response must require state");
        assert!(error.to_string().contains("--state"));
        require_response_state(None, None).expect("interactive login may generate state");
    }
}
