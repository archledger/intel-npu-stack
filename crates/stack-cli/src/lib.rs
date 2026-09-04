// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use stack_core::{Channel, DiagnosticCommand};
use stack_platform::PlatformPaths;
use stack_runtime::RuntimePaths;

mod diagnostic;
mod profiles;

/// Runtime dependencies injected into the read-only CLI.
#[derive(Debug, Clone)]
pub struct AppContext {
    pub platform_paths: PlatformPaths,
    pub profile_dir: PathBuf,
    pub arch: String,
    pub runtime_paths: RuntimePaths,
}

#[derive(Debug, Parser)]
#[command(name = "intel-npu-stack", version, disable_version_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the intel-npu-stack release version.
    Version,
    /// Inspect compatibility and runtime discovery without running inference.
    Status(DiagnosticArgs),
    /// Inspect compatibility and prove direct NPU inference.
    Doctor(DiagnosticArgs),
}

#[derive(Debug, Args)]
struct DiagnosticArgs {
    /// Emit diagnostic schema version 1 as JSON.
    #[arg(long)]
    json: bool,
    /// Select only profiles admitted by this channel.
    #[arg(long, value_enum, default_value_t = CliChannel::Stable)]
    channel: CliChannel,
    /// Explicitly accept that experimental profiles are not stable.
    #[arg(long)]
    accept_experimental_risk: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliChannel {
    Stable,
    Experimental,
}

impl From<CliChannel> for Channel {
    fn from(value: CliChannel) -> Self {
        match value {
            CliChannel::Stable => Self::Stable,
            CliChannel::Experimental => Self::Experimental,
        }
    }
}

/// Runs the CLI using injected platform/profile paths and output streams.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    context: &AppContext,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let rendered = error.render().to_string();
            let result = if error.use_stderr() {
                stderr.write_all(rendered.as_bytes())
            } else {
                stdout.write_all(rendered.as_bytes())
            };
            return if result.is_ok() {
                ExitCode::from(code as u8)
            } else {
                ExitCode::from(2)
            };
        }
    };

    match cli.command {
        Command::Version => match writeln!(stdout, "{}", env!("CARGO_PKG_VERSION")) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(2),
        },
        Command::Status(args) => {
            run_diagnostic(DiagnosticCommand::Status, args, context, stdout, stderr)
        }
        Command::Doctor(args) => {
            run_diagnostic(DiagnosticCommand::Doctor, args, context, stdout, stderr)
        }
    }
}

fn run_diagnostic(
    command: DiagnosticCommand,
    args: DiagnosticArgs,
    context: &AppContext,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    diagnostic::execute(
        diagnostic::Options {
            command,
            json: args.json,
            channel: args.channel.into(),
            accept_experimental_risk: args.accept_experimental_risk,
        },
        context,
        stdout,
        stderr,
    )
}
