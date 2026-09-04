// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use xtask::validate_profiles_dir;

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate all direct TOML profiles in a directory.
    ValidateProfiles { path: PathBuf },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateProfiles { path } => {
            let mut stdout = std::io::stdout().lock();
            match validate_profiles_dir(&path, &mut stdout) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(error.exit_code())
                }
            }
        }
    }
}
