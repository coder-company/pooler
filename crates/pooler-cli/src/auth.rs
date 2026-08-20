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

use adapter_codex::CodexCredential;
use anyhow::{bail, Context, Result};
use pooler_auth::{
    AuthorizationAttempt, CredentialId, HyperOAuthTransport, OAuthClientConfig,
    OAuthCredentialProfile, OAuthIdentity, OAuthRevoker, OAuthState, OAuthTokenStore, OAuthTokens,
    PkcePair, ProviderLoginRegistry, StandardOAuthProvider,
};
use pooler_config::{
    AccountAuthKind, AccountPlan, CompiledConfig, Config, OAuthPlan, DEFAULT_OAUTH_CALLBACK,
};
use pooler_store::{CredentialState, MasterKey, SqliteOAuthTokenStore, SqliteStore, Store};
use tokio_util::sync::CancellationToken;
use url::Url;

#[path = "auth/command.rs"]
mod command;
#[path = "auth/profile.rs"]
mod profile;
pub use command::{AuthCommand, AuthLoginMethod, OAuthEncodingArgument, OAuthOverrideArgs};
use profile::{
    api_key_guidance, build_login_provider, configured_provider_id, provider_filter_matches,
    providers, selected_profile, validate_login_method, LoginOAuthProvider, ResolvedOAuthSettings,
};
#[cfg(test)]
use profile::{
    render_provider_support, validate_client_and_scopes, TEST_MAX_OAUTH_CLIENT_ID_BYTES,
    TEST_MAX_OAUTH_SCOPE_COUNT,
};

/// The default redirect used by the local OAuth flow.
pub const DEFAULT_CALLBACK: &str = DEFAULT_OAUTH_CALLBACK;
const MAX_CALLBACK_REQUEST_BYTES: usize = 8 * 1024;

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
    match command {
        AuthCommand::Login {
            provider,
            account,
            profile,
            method,
            callback,
            state,
            response,
            oauth,
        } => login(LoginRequest {
            provider: &provider,
            account: account.as_deref(),
            profile: profile.as_deref(),
            method,
            callback: &callback,
            expected_state: state.as_deref(),
            response: response.as_deref(),
            oauth: oauth.as_ref(),
            config_path,
            explicit_store_path,
            credential_key_ref,
        }),
        AuthCommand::Import {
            account,
            profile,
            from_file,
        } => import_openai_profile(
            &account,
            &profile,
            &from_file,
            config_path,
            explicit_store_path,
            credential_key_ref,
        ),
        AuthCommand::Providers { profile } => providers(profile.as_deref()),
        AuthCommand::Status { provider } => status(
            provider.as_deref(),
            config_path,
            &credential_store_path(explicit_store_path)?,
            credential_key_ref,
        ),
        AuthCommand::Revoke { provider } => revoke(
            &provider,
            config_path,
            &credential_store_path(explicit_store_path)?,
            credential_key_ref,
        ),
    }
}

struct LoginRequest<'a> {
    provider: &'a str,
    account: Option<&'a str>,
    profile: Option<&'a str>,
    method: AuthLoginMethod,
    callback: &'a str,
    expected_state: Option<&'a str>,
    response: Option<&'a str>,
    oauth: &'a OAuthOverrideArgs,
    config_path: &'a Path,
    explicit_store_path: Option<&'a Path>,
    credential_key_ref: Option<&'a str>,
}

fn login(request: LoginRequest<'_>) -> Result<()> {
    let registry = ProviderLoginRegistry::builtin();
    let profile = selected_profile(&registry, request.provider, request.profile)?;
    validate_login_method(
        profile,
        request.method,
        request.expected_state,
        request.response,
        request.oauth,
    )?;

    if request.method == AuthLoginMethod::ApiKey {
        println!("{}", api_key_guidance(profile));
        return Ok(());
    }

    let config = Config::from_path(request.config_path)?.compile()?;
    let configured_provider = configured_provider_id(
        &config,
        request.provider,
        profile,
        request.profile.is_some(),
    )?;
    let account = resolve_oauth_account(&config, &configured_provider, request.account)?;
    let credential_id = CredentialId::new(account.id().to_owned())
        .map_err(|_| anyhow::anyhow!("account ID is invalid"))?;
    let oauth = configured_oauth(&config, &configured_provider)?;
    let callback = validate_loopback_callback(request.callback)?;
    if callback != *oauth.callback() {
        bail!("oauth callback does not match the provider configuration");
    }
    let resolved = ResolvedOAuthSettings::new(oauth, callback.clone(), request.oauth, profile)?;
    let provider_client =
        build_login_provider(&configured_provider, profile, request.method, &resolved)?;
    let store_path = credential_store_path(request.explicit_store_path)?;
    let master_key = load_master_key(request.credential_key_ref)?;
    let store = SqliteStore::open_encrypted(&store_path, master_key)
        .context("could not open encrypted credential store")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not initialize OAuth runtime")?;
    let tokens = match request.method {
        AuthLoginMethod::AuthorizationCodePkce => authorization_code_login(
            provider_client.as_ref(),
            &callback,
            request.expected_state,
            request.response,
            &runtime,
        )?,
        AuthLoginMethod::DeviceCode => device_code_login(provider_client.as_ref(), &runtime)?,
        AuthLoginMethod::ApiKey => unreachable!("API-key login returned before OAuth setup"),
    };
    let identity = if provider_client.identity_endpoint_configured() {
        Some(runtime.block_on(provider_client.identity(&tokens, CancellationToken::new()))?)
    } else {
        None
    };
    let provider_profile = profile.map_or(configured_provider.as_str(), |value| value.id());
    persist_login(
        &store,
        &credential_id,
        &configured_provider,
        provider_profile,
        tokens,
        identity,
    )?;
    println!(
        "logged in: provider={configured_provider} account={} kind=oauth",
        account.id()
    );
    Ok(())
}

fn authorization_code_login(
    provider: &dyn LoginOAuthProvider,
    callback: &Url,
    expected_state: Option<&str>,
    response: Option<&str>,
    runtime: &tokio::runtime::Runtime,
) -> Result<OAuthTokens> {
    let attempt = match expected_state {
        Some(state) => provider.begin_authorization_with_cli(
            OAuthState::new(state.to_owned())?,
            PkcePair::random()?,
        )?,
        None => provider.begin_authorization()?,
    };
    if response.is_none() {
        println!("open {} to authorize", attempt.authorization_url());
    }
    let callback_url = match response {
        Some(response) => Url::parse(response).context("oauth callback response is invalid")?,
        None => receive_callback_url(callback, &attempt)?,
    };
    let code = attempt.validate_callback(&callback_url)?;
    runtime
        .block_on(provider.exchange_code(
            &code,
            attempt.pkce(),
            attempt.redirect_uri(),
            CancellationToken::new(),
        ))
        .map_err(Into::into)
}

fn device_code_login(
    provider: &dyn LoginOAuthProvider,
    runtime: &tokio::runtime::Runtime,
) -> Result<OAuthTokens> {
    let authorization =
        runtime.block_on(provider.start_device_authorization(CancellationToken::new()))?;
    if let Some(complete) = authorization.verification_uri_complete() {
        println!("open {complete} to authorize");
    } else {
        println!(
            "open {} and enter code {} to authorize",
            authorization.verification_uri(),
            authorization.user_code()
        );
    }
    runtime
        .block_on(provider.poll_device(&authorization, CancellationToken::new()))
        .map_err(Into::into)
}

fn persist_login(
    store: &SqliteStore,
    credential_id: &CredentialId,
    provider_id: &str,
    provider_profile: &str,
    tokens: OAuthTokens,
    identity: Option<OAuthIdentity>,
) -> Result<()> {
    let expected_revision = match store
        .credential_state(credential_id.as_str())
        .context("could not read credential metadata")?
    {
        Some(state) => {
            if state.provider_id != provider_id {
                bail!("stored account provider does not match configuration");
            }
            state.revision
        }
        None => {
            store
                .upsert_credential_state(CredentialState::new(
                    credential_id.as_str(),
                    provider_id,
                    true,
                    now_millis(),
                ))
                .context("could not record credential metadata")?
                .revision
        }
    };
    let token_store = SqliteOAuthTokenStore::new(store.clone());
    let mut profile = OAuthCredentialProfile::new(provider_profile, tokens);
    if let Some(identity) = identity {
        profile = profile.with_identity(identity);
    }
    token_store.compare_and_swap_profile(credential_id, expected_revision, &profile)?;
    Ok(())
}

fn resolve_oauth_account<'a>(
    config: &'a CompiledConfig,
    provider: &str,
    requested: Option<&str>,
) -> Result<&'a AccountPlan> {
    if let Some(requested) = requested {
        let account = config
            .accounts()
            .get(requested)
            .ok_or_else(|| anyhow::anyhow!("account `{requested}` is not configured"))?;
        if account.provider() != provider {
            bail!("account `{requested}` does not belong to provider `{provider}`");
        }
        if account.auth_kind() != AccountAuthKind::OAuth {
            bail!("account `{requested}` is configured for API-key authentication");
        }
        return Ok(account);
    }

    let mut matches = config.accounts().values().filter(|account| {
        account.provider() == provider && account.auth_kind() == AccountAuthKind::OAuth
    });
    let account = matches.next().ok_or_else(|| {
        anyhow::anyhow!("provider `{provider}` has no configured OAuth account; use --account")
    })?;
    if matches.next().is_some() {
        bail!("provider `{provider}` has multiple OAuth accounts; --account is required");
    }
    Ok(account)
}

fn import_openai_profile(
    account_id: &str,
    requested_profile: &str,
    from_file: &Path,
    config_path: &Path,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    let registry = ProviderLoginRegistry::builtin();
    let profile = registry
        .require(requested_profile)
        .context("unknown provider login profile")?;
    if profile.id() != "openai" {
        bail!("credential import currently supports only the explicit OpenAI/Codex profile");
    }
    let config = Config::from_path(config_path)?.compile()?;
    let account = config
        .accounts()
        .get(account_id)
        .ok_or_else(|| anyhow::anyhow!("account `{account_id}` is not configured"))?;
    if account.auth_kind() != AccountAuthKind::OAuth {
        bail!("account `{account_id}` is not configured with auth_kind: oauth");
    }
    let upstream = &config.upstreams()[account.provider()];
    if upstream.oauth().is_none()
        || !upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
    {
        bail!(
            "OpenAI subscription import requires explicit upstream oauth and native.kind: codex configuration"
        );
    }

    let imported = CodexCredential::from_file(from_file)
        .context("could not read owner-private OpenAI Codex credential profile")?;
    if imported.is_disabled() || imported.is_expired() {
        bail!("imported OpenAI Codex credential is disabled or expired");
    }
    if !matches!(imported.auth_type(), "oauth" | "oauth2" | "codex") {
        bail!("imported OpenAI Codex credential type is unsupported");
    }
    let provider_account_id = imported
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("imported OpenAI Codex credential has no account ID"))?;
    let profile = OAuthCredentialProfile::new("openai", imported.tokens().clone())
        .with_account_id(provider_account_id)
        .with_id_token(imported.id_token().cloned())
        .with_email(imported.email().map(ToOwned::to_owned))
        .with_lifecycle(false, false, imported.last_refresh());

    let store_path = credential_store_path(explicit_store_path)?;
    let store = SqliteStore::open_encrypted(&store_path, load_master_key(credential_key_ref)?)
        .context("could not open encrypted credential store")?;
    let credential = CredentialId::new(account.id().to_owned())
        .map_err(|_| anyhow::anyhow!("account ID is invalid"))?;
    let expected_revision = match store
        .credential_state(account.id())
        .context("could not read credential metadata")?
    {
        Some(state) => {
            if state.provider_id != account.provider() {
                bail!("stored account provider does not match configuration");
            }
            state.revision
        }
        None => {
            store
                .upsert_credential_state(CredentialState::new(
                    account.id(),
                    account.provider(),
                    account.enabled(),
                    now_millis(),
                ))
                .context("could not record credential metadata")?
                .revision
        }
    };
    SqliteOAuthTokenStore::new(store).compare_and_swap_profile(
        &credential,
        expected_revision,
        &profile,
    )?;
    println!(
        "imported credential: provider={} account={} kind=oauth profile=openai account_id=present",
        account.provider(),
        account.id()
    );
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
    config_path: &Path,
    store_path: &Path,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    if let Some(provider) = provider {
        CredentialId::new(provider.to_owned())
            .map_err(|_| anyhow::anyhow!("provider ID is invalid"))?;
    }
    let config = Config::from_path(config_path)?.compile()?;
    let encrypted = credential_key_ref.is_some();
    let store = if let Some(reference) = credential_key_ref {
        SqliteStore::open_encrypted(store_path, load_master_key(Some(reference))?)
            .context("could not open encrypted credential store")?
    } else {
        SqliteStore::open(store_path).context("could not open credential store")?
    };
    let registry = ProviderLoginRegistry::builtin();
    let token_store = encrypted.then(|| SqliteOAuthTokenStore::new(store.clone()));
    let mut count = 0;
    for account in config.accounts().values() {
        if provider.is_some_and(|expected| {
            expected != account.id()
                && !provider_filter_matches(&registry, expected, account.provider())
        }) {
            continue;
        }
        let state = store
            .credential_state(account.id())
            .context("could not read credential state")?;
        let enabled = state
            .as_ref()
            .map_or(account.enabled(), |state| state.enabled);
        let status = if enabled { "enabled" } else { "disabled" };
        let metadata = token_store
            .as_ref()
            .map(|tokens| {
                let credential = CredentialId::new(account.id().to_owned())
                    .map_err(|_| anyhow::anyhow!("account ID is invalid"))?;
                tokens
                    .profile_metadata(&credential)
                    .map_err(anyhow::Error::from)
            })
            .transpose()?
            .flatten();
        if let Some(metadata) = metadata {
            println!(
                "provider={} account={} kind={} profile={} status={status} account_id={} generation={}",
                account.provider(),
                account.id(),
                metadata.auth_kind,
                metadata.provider_profile,
                if metadata.account_id_present { "present" } else { "absent" },
                metadata.generation
            );
        } else {
            println!(
                "provider={} account={} kind={} status={status}",
                account.provider(),
                account.id(),
                account.auth_kind().as_str()
            );
        }
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

    #[test]
    fn provider_support_renders_aliases_guidance_and_fail_closed_status() {
        let registry = ProviderLoginRegistry::builtin();
        let anthropic = render_provider_support(registry.require("claude").expect("Anthropic"));
        assert!(anthropic.contains("provider=anthropic"));
        assert!(anthropic.contains("aliases=claude"));
        assert!(anthropic.contains("api_key_env=ANTHROPIC_API_KEY"));
        assert!(anthropic.contains("method=authorization_code_pkce support=unsupported"));
        assert!(anthropic.contains("code.claude.com"));

        let openai = render_provider_support(registry.require("codex").expect("OpenAI"));
        assert!(openai.contains("support=requires_explicit_configuration"));
        assert!(
            api_key_guidance(Some(registry.require("grok").expect("xAI")))
                .contains("env:XAI_API_KEY")
        );
    }

    #[test]
    fn anthropic_and_xai_oauth_fail_before_config_or_store_access() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for provider in ["claude", "grok"] {
            let store_path = directory.path().join(format!("{provider}.sqlite3"));
            let command = AuthCommand::Login {
                provider: provider.to_owned(),
                account: None,
                profile: None,
                method: AuthLoginMethod::AuthorizationCodePkce,
                callback: DEFAULT_CALLBACK.to_owned(),
                state: None,
                response: None,
                oauth: Box::new(OAuthOverrideArgs {
                    authorization_endpoint: Some(
                        "https://sentinel-attacker.example/authorize".to_owned(),
                    ),
                    token_endpoint: Some("https://sentinel-attacker.example/token".to_owned()),
                    ..OAuthOverrideArgs::default()
                }),
            };
            let error = run(
                command,
                &directory.path().join("missing-config.yaml"),
                Some(&store_path),
                None,
            )
            .expect_err("unsupported OAuth must fail closed");
            let rendered = error.to_string();
            assert!(rendered.contains("does not support"));
            assert!(rendered.contains("API key"));
            assert!(!rendered.contains("sentinel-attacker"));
            assert!(!store_path.exists());
        }
    }

    #[test]
    fn api_key_guidance_never_needs_config_store_or_secret_input() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        run(
            AuthCommand::Login {
                provider: "gemini".to_owned(),
                account: None,
                profile: None,
                method: AuthLoginMethod::ApiKey,
                callback: DEFAULT_CALLBACK.to_owned(),
                state: None,
                response: None,
                oauth: Box::new(OAuthOverrideArgs::default()),
            },
            &directory.path().join("missing-config.yaml"),
            Some(&store_path),
            None,
        )
        .expect("API-key guidance");
        assert!(!store_path.exists());
    }

    #[test]
    fn aliases_select_a_canonical_configured_upstream() {
        let config = pooler_config::compile_yaml(
            "provider-alias.yaml",
            r#"
version: 1
upstreams:
  google:
    url: https://generativelanguage.googleapis.com
    oauth:
      authorization_endpoint: https://accounts.google.com/o/oauth2/v2/auth
      token_endpoint: https://oauth2.googleapis.com/token
      client_id: registered-client
      scopes: [https://www.googleapis.com/auth/cloud-platform]
"#,
        )
        .expect("provider config");
        let registry = ProviderLoginRegistry::builtin();
        let profile = selected_profile(&registry, "gemini", None)
            .expect("profile")
            .expect("Google profile");
        assert_eq!(profile.id(), "google");
        assert_eq!(
            configured_provider_id(&config, "gemini", Some(profile), false)
                .expect("alias resolution"),
            "google"
        );
        assert!(configured_provider_id(&config, "work", Some(profile), true).is_err());
    }

    #[test]
    fn built_in_profile_endpoint_overrides_are_allowlisted() {
        let config = pooler_config::compile_yaml(
            "provider-host.yaml",
            r#"
version: 1
upstreams:
  google:
    url: https://generativelanguage.googleapis.com
    oauth:
      authorization_endpoint: https://accounts.google.com/o/oauth2/v2/auth
      token_endpoint: https://oauth2.googleapis.com/token
      client_id: registered-client
      scopes: [https://www.googleapis.com/auth/cloud-platform]
"#,
        )
        .expect("provider config");
        let oauth = configured_oauth(&config, "google").expect("OAuth config");
        let profile = ProviderLoginRegistry::builtin()
            .require("gemini")
            .expect("Google profile");
        for endpoint in [
            "https://attacker.example/authorize",
            "https://notgoogleapis.com/authorize",
            "https://127.0.0.1/authorize",
            "https://169.254.169.254/authorize",
            "https://10.0.0.1/authorize",
        ] {
            let overrides = OAuthOverrideArgs {
                authorization_endpoint: Some(endpoint.to_owned()),
                ..OAuthOverrideArgs::default()
            };
            let settings = ResolvedOAuthSettings::new(
                oauth,
                validate_loopback_callback(DEFAULT_CALLBACK).expect("callback"),
                &overrides,
                Some(profile),
            )
            .expect("resolved settings");
            let error = build_login_provider(
                "google",
                Some(profile),
                AuthLoginMethod::AuthorizationCodePkce,
                &settings,
            )
            .err()
            .expect("host allowlist");
            assert!(error.to_string().contains("host is not allowed"));
            assert!(!error.to_string().contains(endpoint));
        }
    }

    #[test]
    fn custom_endpoint_overrides_require_the_dangerous_boundary() {
        let config = pooler_config::compile_yaml(
            "custom-provider.yaml",
            r#"
version: 1
upstreams:
  custom:
    url: https://api.operator.example
    oauth:
      authorization_endpoint: https://identity.operator.example/authorize
      token_endpoint: https://identity.operator.example/token
      client_id: registered-client
      scopes: [operator-scope]
"#,
        )
        .expect("custom provider config");
        let oauth = configured_oauth(&config, "custom").expect("OAuth config");
        let mut overrides = OAuthOverrideArgs {
            authorization_endpoint: Some("https://alternate.operator.example/authorize".to_owned()),
            ..OAuthOverrideArgs::default()
        };
        let error = ResolvedOAuthSettings::new(
            oauth,
            validate_loopback_callback(DEFAULT_CALLBACK).expect("callback"),
            &overrides,
            None,
        )
        .expect_err("dangerous boundary");
        assert!(error
            .to_string()
            .contains("--dangerously-allow-custom-oauth-endpoints"));
        overrides.dangerously_allow_custom_oauth_endpoints = true;
        ResolvedOAuthSettings::new(
            oauth,
            validate_loopback_callback(DEFAULT_CALLBACK).expect("callback"),
            &overrides,
            None,
        )
        .expect("explicit custom endpoint trust");
    }

    #[test]
    fn oauth_override_debug_and_errors_never_echo_values() {
        let sentinel = "sentinel-private-override-value";
        let command = AuthCommand::Login {
            provider: "custom".to_owned(),
            account: None,
            profile: None,
            method: AuthLoginMethod::AuthorizationCodePkce,
            callback: format!("http://127.0.0.1:1455/{sentinel}"),
            state: Some(sentinel.to_owned()),
            response: Some(format!("http://127.0.0.1:1455/callback?code={sentinel}")),
            oauth: Box::new(OAuthOverrideArgs {
                client_id: Some(sentinel.to_owned()),
                scopes: vec![sentinel.to_owned()],
                authorization_endpoint: Some(format!("https://example.test/{sentinel}")),
                ..OAuthOverrideArgs::default()
            }),
        };
        let rendered = format!("{command:?}");
        assert!(!rendered.contains(sentinel));
        assert!(rendered.contains("client_id_configured"));
        assert!(rendered.contains("response_configured"));

        let error = validate_client_and_scopes(
            &"x".repeat(TEST_MAX_OAUTH_CLIENT_ID_BYTES + 1),
            &["scope".to_owned()],
        )
        .expect_err("client ID limit");
        assert!(!error.to_string().contains("xxxx"));
        let scopes = (0..=TEST_MAX_OAUTH_SCOPE_COUNT)
            .map(|index| format!("scope-{index}"))
            .collect::<Vec<_>>();
        assert!(validate_client_and_scopes("client", &scopes).is_err());
    }

    #[test]
    fn status_filter_accepts_built_in_provider_aliases() {
        let registry = ProviderLoginRegistry::builtin();
        assert!(provider_filter_matches(&registry, "gemini", "google"));
        assert!(provider_filter_matches(&registry, "codex", "openai"));
        assert!(!provider_filter_matches(&registry, "gemini", "openai"));
        assert!(provider_filter_matches(&registry, "custom", "custom"));
    }
}
