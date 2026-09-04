// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;

use stack_core::{
    Channel, CheckStatus, DiagnosticCheck, DiagnosticCommand, DiagnosticReport, OverallStatus,
    PlatformSummary, ProfileSummary, Requirement, SelectionError, SelectionPolicy, select_profile,
};
use stack_platform::{PlatformFacts, detect_platform};
use stack_runtime::{
    FilesystemDeviceInspector, RpmPackageInspector, RuntimeInspector, SysfsActivityInspector,
    SystemProcessRunner,
};

use crate::AppContext;
use crate::profiles::load_profiles;

pub(crate) struct Options {
    pub command: DiagnosticCommand,
    pub json: bool,
    pub channel: Channel,
    pub accept_experimental_risk: bool,
}

pub(crate) fn execute(
    options: Options,
    context: &AppContext,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if options.channel == Channel::Stable && options.accept_experimental_risk {
        return write_cli_error(
            stderr,
            "--accept-experimental-risk is only valid with --channel experimental",
        );
    }
    if options.channel == Channel::Experimental && !options.accept_experimental_risk {
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
        channel: options.channel,
        acknowledge_risk: options.accept_experimental_risk,
    };
    let selection = select_profile(&profiles, &facts, &policy);
    let mut report = base_report(options.command, &facts);

    match selection {
        Ok(profile) => {
            report.profile = Some(ProfileSummary {
                id: profile.id.clone(),
                stack_release: profile.stack_release.clone(),
                status: profile.status,
            });
            let runner = SystemProcessRunner;
            let packages = RpmPackageInspector::new(
                &context.runtime_paths.rpm,
                &context.runtime_paths.root,
                &runner,
            );
            let devices = FilesystemDeviceInspector;
            let activity = SysfsActivityInspector;
            let inspector = RuntimeInspector::new(
                &context.runtime_paths,
                &runner,
                &packages,
                &devices,
                &activity,
            );
            let inspection = match options.command {
                DiagnosticCommand::Status => inspector.inspect_status(profile, &facts),
                DiagnosticCommand::Doctor => inspector.inspect_doctor(profile, &facts),
            };
            report.checks = inspection.checks;
            report.reboot_required = inspection.reboot_required;
            report.relogin_required = inspection.relogin_required;
        }
        Err(SelectionError::NoCompatibleProfile) => {
            report.checks.push(DiagnosticCheck {
                id: "platform.profile".to_owned(),
                status: CheckStatus::Fail,
                summary: "Compatible platform profile is selected".to_owned(),
                details: BTreeMap::new(),
                requirement: Requirement::Required,
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
    let output = if options.json {
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

fn base_report(command: DiagnosticCommand, facts: &PlatformFacts) -> DiagnosticReport {
    DiagnosticReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        command,
        overall: OverallStatus::Blocked,
        profile: None,
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
        reboot_required: false,
        relogin_required: false,
        checks: Vec::new(),
    }
}

fn write_json(output: &mut dyn Write, report: &DiagnosticReport) -> std::io::Result<()> {
    serde_json::to_writer(&mut *output, report).map_err(std::io::Error::other)?;
    writeln!(output)
}

fn write_human(output: &mut dyn Write, report: &DiagnosticReport) -> std::io::Result<()> {
    writeln!(output, "command: {}", command_name(report.command))?;
    writeln!(output, "overall: {}", overall_name(report.overall))?;
    writeln!(
        output,
        "profile: {}",
        report
            .profile
            .as_ref()
            .map_or("none", |profile| &profile.id)
    )?;
    writeln!(output, "reboot required: {}", report.reboot_required)?;
    writeln!(output, "relogin required: {}", report.relogin_required)?;
    for check in &report.checks {
        writeln!(
            output,
            "{} [{}]: {}",
            check.id,
            check_name(check.status),
            check.summary
        )?;
    }
    Ok(())
}

fn command_name(command: DiagnosticCommand) -> &'static str {
    match command {
        DiagnosticCommand::Status => "status",
        DiagnosticCommand::Doctor => "doctor",
    }
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
        CheckStatus::Warn => "warn",
        CheckStatus::Blocked => "blocked",
    }
}

fn write_cli_error(stderr: &mut dyn Write, message: &str) -> ExitCode {
    let _ = writeln!(stderr, "error: {message}");
    ExitCode::from(2)
}
