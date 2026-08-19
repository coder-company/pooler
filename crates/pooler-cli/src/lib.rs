//! Pooler's command-line interface.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use pooler_config::Config;
use pooler_http::NativeRuntime;
use pooler_store::{SqliteOAuthTokenStore, SqliteStore};

mod auth;
pub use auth::AuthCommand;

/// Top-level command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "pooler", version, about = "Composable AI protocol runtime")]
pub struct Cli {
    /// Configuration file to load.
    #[arg(short, long, global = true, default_value = "pooler.yaml")]
    pub config: PathBuf,
    /// Owner-private SQLite credential store. If omitted, use the platform
    /// state directory or `POOLER_CREDENTIAL_STORE`.
    #[arg(long, global = true)]
    pub credential_store: Option<PathBuf>,
    /// Secret reference used to derive the encrypted credential-store key.
    /// Literal values are rejected; use env:, file:, or keyring:.
    #[arg(long, global = true)]
    pub credential_key_ref: Option<String>,
    /// Operation to perform.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Parse and validate the configuration.
    Check,
    /// Print the validated configuration without resolving secrets.
    Config {
        /// Configuration operation.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// List compiled routes in match order.
    Routes,
    /// Start the proxy runtime.
    Serve,
    /// Run local diagnostics.
    Doctor,
    /// List configured public models.
    Models,
    /// Replay sanitized compatibility fixtures.
    Fixture,
    /// Manage provider credentials.
    Auth {
        /// Credential-management operation.
        #[command(subcommand)]
        command: AuthCommand,
    },
}

/// Configuration inspection operations.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the source after validating it.
    Render,
}

/// Runs one CLI command.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Check => {
            load(&cli.config)?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Config {
            command: ConfigCommand::Render,
        } => {
            let rendered = pooler_config::render_path(&cli.config)?;
            Config::from_yaml(cli.config.display().to_string(), &rendered)?.compile()?;
            print!("{rendered}");
            Ok(())
        }
        Command::Routes => {
            let config = load(&cli.config)?;
            for route in config.routes() {
                println!("{}", route.id());
            }
            Ok(())
        }
        Command::Serve => serve(
            &cli.config,
            cli.credential_store.as_deref(),
            cli.credential_key_ref.as_deref(),
        ),
        Command::Doctor => bail!("doctor is not implemented in the engineering baseline"),
        Command::Models => {
            let config = load(&cli.config)?;
            for model in config.models().values() {
                println!("{}", model.id());
            }
            Ok(())
        }
        Command::Fixture => bail!("fixture replay is not implemented in the engineering baseline"),
        Command::Auth { command } => auth::run(
            command,
            &cli.config,
            cli.credential_store.as_deref(),
            cli.credential_key_ref.as_deref(),
        ),
    }
}

fn load(path: &PathBuf) -> Result<pooler_config::CompiledConfig> {
    Config::from_path(path)?.compile().map_err(Into::into)
}

fn serve(
    path: &PathBuf,
    explicit_store_path: Option<&std::path::Path>,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    let config = load(path)?;
    let native = native_runtime(&config, explicit_store_path, credential_key_ref)?;
    pooler_observe::init_tracing().context("failed to initialize structured logging")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize the async runtime")?;
    runtime.block_on(async move {
        let server =
            pooler_server::HttpProxyServer::bind_with_native_runtime(config, native).await?;
        for listener in server.listener_addresses() {
            tracing::info!(
                listener = listener.id(),
                address = listener.address(),
                "listener bound"
            );
        }

        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        tokio::pin!(runner);
        tokio::select! {
            result = &mut runner => {
                result
                    .context("HTTP proxy task panicked")?
                    .map_err(anyhow::Error::from)
            }
            signal = shutdown_signal() => {
                signal?;
                server
                    .drain(Duration::from_secs(30))
                    .await
                    .map_err(anyhow::Error::from)?;
                runner
                    .await
                    .context("HTTP proxy task panicked")?
                    .map_err(anyhow::Error::from)
            }
        }
    })
}

fn native_runtime(
    config: &pooler_config::CompiledConfig,
    explicit_store_path: Option<&std::path::Path>,
    credential_key_ref: Option<&str>,
) -> Result<Arc<NativeRuntime>> {
    let has_codex = config.upstreams().values().any(|upstream| {
        upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
    });
    if !has_codex {
        return Ok(Arc::new(NativeRuntime::disabled()));
    }
    let store_path = auth::credential_store_path(explicit_store_path)?;
    let master_key = auth::load_master_key(credential_key_ref)
        .context("native providers require an encrypted credential-store key")?;
    let store = SqliteStore::open_encrypted(store_path, master_key)
        .context("could not open encrypted credential store")?;
    let token_store = Arc::new(SqliteOAuthTokenStore::new(store));
    Ok(Arc::new(NativeRuntime::new_with_sqlite(
        config,
        token_store,
    )?))
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to wait for Ctrl-C")?;
        }
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to wait for Ctrl-C")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_shape_accepts_check() {
        let cli = Cli::try_parse_from(["pooler", "--config", "example.yaml", "check"])
            .expect("command should parse");
        assert!(matches!(cli.command, Command::Check));
        assert_eq!(cli.config, PathBuf::from("example.yaml"));
    }

    #[test]
    fn serve_command_is_available() {
        let cli = Cli::try_parse_from(["pooler", "serve"]).expect("command should parse");
        let error = run(cli).expect_err("missing default config should be reported");
        assert!(error.to_string().contains("failed to read configuration"));
    }

    #[test]
    fn auth_login_command_requires_explicit_state_and_response_inputs() {
        let cli = Cli::try_parse_from([
            "pooler",
            "--credential-store",
            "/private/credentials.sqlite3",
            "auth",
            "login",
            "codex",
            "--state",
            "state-1",
            "--response",
            "http://localhost:1455/auth/callback?code=redacted&state=state-1",
        ])
        .expect("auth command should parse");
        assert_eq!(
            cli.credential_store,
            Some(PathBuf::from("/private/credentials.sqlite3"))
        );
        assert!(matches!(
            cli.command,
            Command::Auth {
                command: AuthCommand::Login { .. }
            }
        ));
    }

    #[test]
    fn auth_status_and_revoke_commands_are_available() {
        let status = Cli::try_parse_from(["pooler", "auth", "status", "codex"])
            .expect("status command should parse");
        assert!(matches!(
            status.command,
            Command::Auth {
                command: AuthCommand::Status { provider: Some(_) }
            }
        ));
        let revoke = Cli::try_parse_from(["pooler", "auth", "revoke", "codex"])
            .expect("revoke command should parse");
        assert!(matches!(
            revoke.command,
            Command::Auth {
                command: AuthCommand::Revoke { .. }
            }
        ));
    }
}
