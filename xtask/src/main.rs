// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use xtask::{source_bundle, source_lock, validate_profiles_dir};

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate an unqualified Fedora candidate from exact runtime RPM evidence.
    GenerateFedoraProfile {
        #[arg(long)]
        rpms: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate all direct TOML profiles in a directory.
    ValidateProfiles { path: PathBuf },
    /// Validate one provider source lock without network access.
    ValidateSourceLock {
        #[arg(long)]
        path: PathBuf,
    },
    /// Bundle already-cached, source-locked Git repositories deterministically.
    BundleSources {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create and hash one explicit archive from an offline source cache.
    HashCachedSource {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::GenerateFedoraProfile { rpms, output } => {
            let result = std::env::current_dir()
                .map_err(|error| error.to_string())
                .and_then(|root| {
                    xtask::fedora_profile::generate_candidate(&rpms, &root, &output)
                        .map_err(|error| error.to_string())
                });
            match result {
                Ok(evidence) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&evidence).expect("serialize evidence")
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(1)
                }
            }
        }
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
        Command::ValidateSourceLock { path } => {
            let repository_root = match std::env::current_dir() {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("error: cannot read current directory: {error}");
                    return ExitCode::from(2);
                }
            };
            match source_lock::validate(&path, &repository_root) {
                Ok(lock) => {
                    println!(
                        "validated {:?} source lock with {} records",
                        lock.status,
                        lock.sources.len()
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(error.exit_code())
                }
            }
        }
        Command::BundleSources {
            lock,
            cache,
            output,
        } => {
            let repository_root = match std::env::current_dir() {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("error: cannot read current directory: {error}");
                    return ExitCode::from(2);
                }
            };
            match source_bundle::bundle_sources(&lock, &repository_root, &cache, &output) {
                Ok(manifest) => {
                    println!("bundled {} source archives", manifest.artifacts.len());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(error.exit_code())
                }
            }
        }
        Command::HashCachedSource {
            repository,
            name,
            commit,
            output,
        } => match source_bundle::hash_cached_source(&repository, &name, &commit, &output) {
            Ok(digest) => {
                println!("{digest}  {}", output.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(error.exit_code())
            }
        },
    }
}
