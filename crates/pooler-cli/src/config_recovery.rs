//! Operator workflow for a blocked managed-configuration transaction.

use std::path::Path;

use anyhow::{Context, Result};
use clap::Subcommand;

/// Safe recovery operations for Pooler's generated configuration sidecar.
#[derive(Debug, Subcommand)]
pub enum ConfigRecoveryCommand {
    /// Inspect marker, identity, digest, permission, generation, and backup state.
    Status {
        /// Emit compact JSON instead of the default pretty JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Verify that the transaction state is complete and safe to operate on.
    Verify {
        /// Emit compact JSON instead of the default pretty JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Accept a complete, digest-verified transaction and clear its marker.
    Resume {
        /// Emit compact JSON instead of the default pretty JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Restore the previous generated revision when exact recovery is provable.
    #[command(visible_alias = "abort")]
    Rollback {
        /// Emit compact JSON instead of the default pretty JSON.
        #[arg(long)]
        compact: bool,
    },
}

pub fn run(path: &Path, command: ConfigRecoveryCommand) -> Result<()> {
    let (value, compact) = match command {
        ConfigRecoveryCommand::Status { compact } => (
            pooler_server::managed_configuration_recovery_status(path)
                .map_err(anyhow::Error::from)
                .context("could not inspect managed-configuration recovery state")?,
            compact,
        ),
        ConfigRecoveryCommand::Verify { compact } => (
            pooler_server::verify_managed_configuration_recovery(path)
                .map_err(anyhow::Error::from)
                .context("managed-configuration recovery verification failed")?,
            compact,
        ),
        ConfigRecoveryCommand::Resume { compact } => (
            pooler_server::resume_managed_configuration_recovery(path)
                .map_err(anyhow::Error::from)
                .context("managed-configuration recovery resume was refused")?,
            compact,
        ),
        ConfigRecoveryCommand::Rollback { compact } => (
            pooler_server::abort_managed_configuration_recovery(path)
                .map_err(anyhow::Error::from)
                .context("managed-configuration recovery rollback was refused")?,
            compact,
        ),
    };
    if compact {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}
