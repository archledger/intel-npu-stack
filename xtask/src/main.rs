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
