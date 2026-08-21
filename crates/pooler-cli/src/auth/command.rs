use std::fmt;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use pooler_auth::ProviderLoginMethod;

use super::DEFAULT_CALLBACK;

/// Credential-management operations.
#[derive(Subcommand)]
pub enum AuthCommand {
    /// Log in with a provider profile or configured custom OAuth provider.
    Login {
        /// Configured OAuth upstream/provider ID.
        provider: String,
        /// Configured account ID. Required when more than one OAuth account is
        /// configured for the provider.
        #[arg(long)]
        account: Option<String>,
        /// Built-in provider profile ID or alias. By default, infer it from
        /// the configured provider ID and otherwise retain generic OAuth.
        #[arg(long)]
        profile: Option<String>,
        /// Login mechanism. API keys are never accepted as CLI values.
        #[arg(long, value_enum, default_value = "oauth")]
        method: AuthLoginMethod,
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
        /// Explicit OAuth values for this login invocation.
        #[command(flatten)]
        oauth: Box<OAuthOverrideArgs>,
    },
    /// Import an owner-private OpenAI Codex subscription credential file.
    Import {
        /// Configured OAuth account ID that will own the encrypted profile.
        account: String,
        /// Explicit built-in provider profile (`openai` or `codex`).
        #[arg(long)]
        profile: String,
        /// Owner-private bounded credential JSON file.
        #[arg(long = "from-file", value_name = "PATH")]
        from_file: PathBuf,
    },
    /// Show built-in provider login support and safe API-key guidance.
    Providers {
        /// Restrict output to one profile ID or alias.
        profile: Option<String>,
    },
    /// Show redacted local credential metadata.
    Status {
        /// Restrict output to one configured provider.
        provider: Option<String>,
    },
    /// Refresh one configured OAuth account.
    Refresh {
        /// Account ID, or a provider with exactly one OAuth account.
        account: String,
    },
    /// Revoke one configured account and remove its local credential state.
    Revoke {
        /// Account ID, or a provider with exactly one account.
        account: String,
    },
    /// Enable one configured account for selection.
    Enable {
        /// Configured account ID.
        account: String,
    },
    /// Disable one configured account from selection.
    Disable {
        /// Configured account ID.
        account: String,
    },
    /// Select one account and disable its siblings for the same provider.
    Switch {
        /// Configured account ID to select.
        account: String,
    },
}

impl fmt::Debug for AuthCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login {
                provider,
                account,
                profile,
                method,
                state,
                response,
                oauth,
                ..
            } => formatter
                .debug_struct("Login")
                .field("provider", provider)
                .field("account", account)
                .field("profile", profile)
                .field("method", method)
                .field("state_configured", &state.is_some())
                .field("response_configured", &response.is_some())
                .field("oauth", oauth)
                .finish(),
            Self::Import {
                account, profile, ..
            } => formatter
                .debug_struct("Import")
                .field("account", account)
                .field("profile", profile)
                .field("from_file_configured", &true)
                .finish(),
            Self::Providers { profile } => formatter
                .debug_struct("Providers")
                .field("profile", profile)
                .finish(),
            Self::Status { provider } => formatter
                .debug_struct("Status")
                .field("provider", provider)
                .finish(),
            Self::Refresh { account } => formatter
                .debug_struct("Refresh")
                .field("account", account)
                .finish(),
            Self::Revoke { account } => formatter
                .debug_struct("Revoke")
                .field("account", account)
                .finish(),
            Self::Enable { account } => formatter
                .debug_struct("Enable")
                .field("account", account)
                .finish(),
            Self::Disable { account } => formatter
                .debug_struct("Disable")
                .field("account", account)
                .finish(),
            Self::Switch { account } => formatter
                .debug_struct("Switch")
                .field("account", account)
                .finish(),
        }
    }
}

/// Login mechanisms exposed by the CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AuthLoginMethod {
    /// OAuth authorization-code flow with state and S256 PKCE.
    #[value(
        name = "oauth",
        alias = "authorization-code",
        alias = "authorization-code-pkce"
    )]
    AuthorizationCodePkce,
    /// OAuth device authorization flow.
    DeviceCode,
    /// Display safe API-key configuration guidance.
    ApiKey,
}

impl From<AuthLoginMethod> for ProviderLoginMethod {
    fn from(method: AuthLoginMethod) -> Self {
        match method {
            AuthLoginMethod::AuthorizationCodePkce => Self::AuthorizationCodePkce,
            AuthLoginMethod::DeviceCode => Self::DeviceCode,
            AuthLoginMethod::ApiKey => Self::ApiKey,
        }
    }
}

/// Per-invocation OAuth overrides.
///
/// Values are deliberately strings until the authenticated boundary parses
/// them, so command-parser errors and `Debug` output cannot echo them.
#[derive(Clone, Default, Args)]
pub struct OAuthOverrideArgs {
    /// Public OAuth client identifier.
    #[arg(long)]
    pub(super) client_id: Option<String>,
    /// OAuth scope. Repeat the flag to select multiple scopes.
    #[arg(long = "scope")]
    pub(super) scopes: Vec<String>,
    /// Authorization endpoint override.
    #[arg(long)]
    pub(super) authorization_endpoint: Option<String>,
    /// Token endpoint override.
    #[arg(long)]
    pub(super) token_endpoint: Option<String>,
    /// Device authorization endpoint override.
    #[arg(long)]
    pub(super) device_authorization_endpoint: Option<String>,
    /// Token revocation endpoint override.
    #[arg(long)]
    pub(super) revocation_endpoint: Option<String>,
    /// Provider identity endpoint override.
    #[arg(long)]
    pub(super) identity_endpoint: Option<String>,
    /// Token-request encoding required by the registered OAuth client.
    #[arg(long, value_enum, default_value = "form")]
    pub(super) request_encoding: OAuthEncodingArgument,
    /// Permit endpoint overrides for an unprofiled custom provider. This never
    /// bypasses the host allowlist of a built-in provider profile.
    #[arg(long)]
    pub(super) dangerously_allow_custom_oauth_endpoints: bool,
}

impl OAuthOverrideArgs {
    pub(super) fn any_explicit_value(&self) -> bool {
        self.client_id.is_some()
            || !self.scopes.is_empty()
            || self.authorization_endpoint.is_some()
            || self.token_endpoint.is_some()
            || self.device_authorization_endpoint.is_some()
            || self.revocation_endpoint.is_some()
            || self.identity_endpoint.is_some()
            || self.request_encoding != OAuthEncodingArgument::Form
            || self.dangerously_allow_custom_oauth_endpoints
    }

    pub(super) fn any_endpoint_override(&self) -> bool {
        self.authorization_endpoint.is_some()
            || self.token_endpoint.is_some()
            || self.device_authorization_endpoint.is_some()
            || self.revocation_endpoint.is_some()
            || self.identity_endpoint.is_some()
    }
}

impl fmt::Debug for OAuthOverrideArgs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthOverrideArgs")
            .field("client_id_configured", &self.client_id.is_some())
            .field("scope_count", &self.scopes.len())
            .field(
                "authorization_endpoint_configured",
                &self.authorization_endpoint.is_some(),
            )
            .field("token_endpoint_configured", &self.token_endpoint.is_some())
            .field(
                "device_authorization_endpoint_configured",
                &self.device_authorization_endpoint.is_some(),
            )
            .field(
                "revocation_endpoint_configured",
                &self.revocation_endpoint.is_some(),
            )
            .field(
                "identity_endpoint_configured",
                &self.identity_endpoint.is_some(),
            )
            .field("request_encoding", &self.request_encoding)
            .field(
                "dangerous_custom_endpoint_override",
                &self.dangerously_allow_custom_oauth_endpoints,
            )
            .finish()
    }
}

/// OAuth token request encodings accepted by the CLI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OAuthEncodingArgument {
    /// RFC 6749 form encoding.
    #[default]
    Form,
    /// Provider-specific JSON encoding.
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct AuthHarness {
        #[command(subcommand)]
        command: AuthCommand,
    }

    #[test]
    fn provider_support_and_profiled_device_login_parse() {
        let support =
            AuthHarness::try_parse_from(["auth", "providers", "gemini"]).expect("support command");
        assert!(matches!(
            support.command,
            AuthCommand::Providers {
                profile: Some(profile)
            } if profile == "gemini"
        ));

        let login = AuthHarness::try_parse_from([
            "auth",
            "login",
            "work-google",
            "--profile",
            "gemini",
            "--method",
            "device-code",
            "--client-id",
            "registered-client",
            "--scope",
            "scope-one",
            "--device-authorization-endpoint",
            "https://oauth2.googleapis.com/device/code",
        ])
        .expect("profiled login command");
        assert!(matches!(
            login.command,
            AuthCommand::Login {
                profile: Some(profile),
                method: AuthLoginMethod::DeviceCode,
                ..
            } if profile == "gemini"
        ));
    }

    #[test]
    fn named_account_lifecycle_commands_parse() {
        for (verb, expected) in [
            ("refresh", "Refresh"),
            ("revoke", "Revoke"),
            ("enable", "Enable"),
            ("disable", "Disable"),
            ("switch", "Switch"),
        ] {
            let command = AuthHarness::try_parse_from(["auth", verb, "work-account"])
                .expect("account lifecycle command");
            assert!(format!("{:?}", command.command).starts_with(expected));
        }
    }
}
