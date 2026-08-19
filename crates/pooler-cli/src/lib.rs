//! Pooler's command-line interface.

use std::path::PathBuf;
use std::{fs, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use pooler_config::Config;

/// Top-level command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "pooler", version, about = "Composable AI protocol runtime")]
pub struct Cli {
    /// Configuration file to load.
    #[arg(short, long, global = true, default_value = "pooler.yaml")]
    pub config: PathBuf,
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
    Auth,
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
            let source = read(&cli.config)?;
            Config::from_yaml(cli.config.display().to_string(), &source)?.compile()?;
            print!("{source}");
            Ok(())
        }
        Command::Routes => {
            let config = load(&cli.config)?;
            for route in config.routes() {
                println!("{}", route.id());
            }
            Ok(())
        }
        Command::Serve => serve(&cli.config),
        Command::Doctor => bail!("doctor is not implemented in the engineering baseline"),
        Command::Models => {
            let config = load(&cli.config)?;
            for model in config.models().values() {
                println!("{}", model.id());
            }
            Ok(())
        }
        Command::Fixture => bail!("fixture replay is not implemented in the engineering baseline"),
        Command::Auth => {
            bail!("credential management is not implemented in the engineering baseline")
        }
    }
}

fn read(path: &PathBuf) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read configuration {}", path.display()))
}

fn load(path: &PathBuf) -> Result<pooler_config::CompiledConfig> {
    Config::from_path(path)?.compile().map_err(Into::into)
}

fn serve(path: &PathBuf) -> Result<()> {
    let config = load(path)?;
    pooler_observe::init_tracing().context("failed to initialize structured logging")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize the async runtime")?;
    runtime.block_on(async move {
        let server = pooler_server::HttpProxyServer::bind(config).await?;
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
}
