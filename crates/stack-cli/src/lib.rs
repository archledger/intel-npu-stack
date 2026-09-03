// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use stack_core::{
    Channel, CheckStatus, DiagnosticCheck, DiagnosticReport, OverallStatus, PlatformSummary,
    SelectionError, SelectionPolicy, select_profile,
};
use stack_platform::{PlatformFacts, PlatformPaths, detect_platform};
use stack_schema::Profile;

/// Runtime dependencies injected into the read-only CLI.
#[derive(Debug, Clone)]
pub struct AppContext {
    pub platform_paths: PlatformPaths,
    pub profile_dir: PathBuf,
    pub arch: String,
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
    /// Report platform/profile compatibility without runtime probing.
    Status(DiagnosticArgs),
    /// Report compatibility and the current runtime-probe readiness.
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
        Command::Status(args) => run_diagnostic(false, args, context, stdout, stderr),
        Command::Doctor(args) => run_diagnostic(true, args, context, stdout, stderr),
    }
}

fn run_diagnostic(
    doctor: bool,
    args: DiagnosticArgs,
    context: &AppContext,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let channel = Channel::from(args.channel);
    if channel == Channel::Stable && args.accept_experimental_risk {
        return write_cli_error(
            stderr,
            "--accept-experimental-risk is only valid with --channel experimental",
        );
    }
    if channel == Channel::Experimental && !args.accept_experimental_risk {
        return write_cli_error(
            stderr,
            "experimental channel requires --accept-experimental-risk",
        );
    }

    let facts = match detect_platform(&context.platform_paths, &context.arch) {
        Ok(facts) => facts,
        Err(error) => return write_cli_error(stderr, &error.to_string()),
    };
    let profiles = match load_profiles(&context.profile_dir) {
        Ok(profiles) => profiles,
        Err(error) => return write_cli_error(stderr, &error),
    };
    let policy = SelectionPolicy {
        channel,
        acknowledge_risk: args.accept_experimental_risk,
    };

    let selection = select_profile(&profiles, &facts, &policy);
    let mut report = base_report(channel, &facts);
    match selection {
        Ok(profile) => {
            report.profile_id = Some(profile.id.clone());
            report.checks.push(DiagnosticCheck {
                id: "platform.profile".to_owned(),
                required: true,
                status: CheckStatus::Pass,
                message: format!("compatible profile {} selected", profile.id),
                details: BTreeMap::new(),
            });
            if doctor {
                add_foundation_runtime_checks(&mut report);
            }
        }
        Err(SelectionError::NoCompatibleProfile) => {
            report.checks.push(DiagnosticCheck {
                id: "platform.profile".to_owned(),
                required: true,
                status: CheckStatus::Fail,
                message: "no compatible profile".to_owned(),
                details: BTreeMap::new(),
            });
        }
        Err(SelectionError::RiskAcknowledgementRequired) => {
            return write_cli_error(
                stderr,
                "experimental channel requires --accept-experimental-risk",
            );
        }
        Err(SelectionError::AmbiguousProfiles(ids)) => {
            return write_cli_error(
                stderr,
                &format!("ambiguous compatible profiles: {}", ids.join(", ")),
            );
        }
    }

    report.finalize();
    let exit_code = ExitCode::from(report.exit_code());
    let output = if args.json {
        write_json(stdout, &report)
    } else {
        write_human(stdout, &report)
    };
    if output.is_ok() {
        exit_code
    } else {
        ExitCode::from(2)
    }
}

fn load_profiles(directory: &Path) -> Result<Vec<Profile>, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read profile directory: {error}"))?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read profile entry: {error}"))?;
        let filename = entry.file_name();
        let display_name = filename.to_string_lossy().into_owned();
        if Path::new(&filename)
            .extension()
            .and_then(|value| value.to_str())
            != Some("toml")
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect profile {display_name}: {error}"))?;
        if file_type.is_symlink() {
            return Err(format!("profile {display_name} is a symlink"));
        }
        if !file_type.is_file() {
            continue;
        }
        candidates.push((display_name, entry.path()));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));

    candidates
        .into_iter()
        .map(|(filename, path)| {
            let input = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read profile {filename}: {error}"))?;
            Profile::parse_toml(&input)
                .map_err(|error| format!("invalid profile {filename}: {error}"))
        })
        .collect()
}

fn base_report(channel: Channel, facts: &PlatformFacts) -> DiagnosticReport {
    DiagnosticReport {
        schema_version: 1,
        stack_version: env!("CARGO_PKG_VERSION").to_owned(),
        profile_id: None,
        channel,
        overall: OverallStatus::Blocked,
        platform: PlatformSummary {
            os_id: facts.os_id.clone(),
            os_version_id: facts.os_version_id.clone(),
            arch: facts.arch.clone(),
            kernel: format!(
                "{}.{}.{}",
                facts.kernel.major, facts.kernel.minor, facts.kernel.patch
            ),
            pci_ids: facts
                .pci_ids
                .iter()
                .map(|id| format!("{}:{}", id.vendor, id.device))
                .collect(),
        },
        checks: Vec::new(),
    }
}

fn add_foundation_runtime_checks(report: &mut DiagnosticReport) {
    for id in ["runtime.level_zero", "runtime.openvino"] {
        report.checks.push(DiagnosticCheck {
            id: id.to_owned(),
            required: true,
            status: CheckStatus::Blocked,
            message: "runtime probe is not implemented in foundation phase".to_owned(),
            details: BTreeMap::new(),
        });
    }
}

fn write_json(output: &mut dyn Write, report: &DiagnosticReport) -> std::io::Result<()> {
    serde_json::to_writer(&mut *output, report).map_err(std::io::Error::other)?;
    writeln!(output)
}

fn write_human(output: &mut dyn Write, report: &DiagnosticReport) -> std::io::Result<()> {
    writeln!(output, "overall: {}", overall_name(report.overall))?;
    writeln!(
        output,
        "profile: {}",
        report.profile_id.as_deref().unwrap_or("none")
    )?;
    for check in &report.checks {
        writeln!(
            output,
            "{} [{}]: {}",
            check.id,
            check_name(check.status),
            check.message
        )?;
    }
    Ok(())
}

fn overall_name(status: OverallStatus) -> &'static str {
    match status {
        OverallStatus::Passed => "passed",
        OverallStatus::Degraded => "degraded",
        OverallStatus::Failed => "failed",
        OverallStatus::Blocked => "blocked",
    }
}

fn check_name(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Fail => "fail",
        CheckStatus::Warning => "warning",
        CheckStatus::Blocked => "blocked",
        CheckStatus::Skipped => "skipped",
    }
}

fn write_cli_error(stderr: &mut dyn Write, message: &str) -> ExitCode {
    let _ = writeln!(stderr, "error: {message}");
    ExitCode::from(2)
}
