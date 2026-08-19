//! Pooler's command-line interface.

use std::fs;
use std::path::PathBuf;

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
        Command::Serve => bail!("serve is not implemented in the engineering baseline"),
        Command::Doctor => bail!("doctor is not implemented in the engineering baseline"),
        Command::Models => bail!("models are not implemented in the engineering baseline"),
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
    fn unavailable_command_is_explicit() {
        let cli = Cli::try_parse_from(["pooler", "serve"]).expect("command should parse");
        let error = run(cli).expect_err("serve should not pretend to be implemented");
        assert!(error.to_string().contains("not implemented"));
    }
}
