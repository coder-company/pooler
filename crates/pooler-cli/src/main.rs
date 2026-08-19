use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match pooler_cli::run(pooler_cli::Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
