// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::{io::Write, path::Path, process::ExitCode};

use clap::Parser;
use stack_install::{
    FedoraSources, InstallError, InstallOptions, NativeInventory, PlanReview, PrepareInput,
    PreparedTransaction, ReleaseLocation, SystemConfirmationPrompt, SystemReplayExecutor,
    fetch_release, prepare, review_plan, validate_request, verify_installation,
};
use stack_platform::{PlatformPaths, detect_platform};
use stack_runtime::SystemProcessRunner;

mod trust;

fn main() -> ExitCode {
    let options = InstallOptions::parse();
    match install(options) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "intel-npu-stack-install: {} [{}]",
                error.message,
                error.code
            );
            ExitCode::from(error.exit_code)
        }
    }
}

fn install(options: InstallOptions) -> Result<ExitCode, InstallError> {
    let runner = SystemProcessRunner;
    let release = fetch_release(
        &ReleaseLocation {
            version: trust::VERSION,
            base_url: trust::BASE_URL,
            metadata_sha256: trust::METADATA_SHA256,
            primary_fingerprint: trust::PRIMARY_FINGERPRINT,
            keyring: trust::KEYRING,
        },
        &runner,
    )?;
    let facts =
        detect_platform(&PlatformPaths::system(), std::env::consts::ARCH).map_err(|_| {
            InstallError {
                exit_code: 30,
                code: "INSTALL_PLATFORM_DISCOVERY_FAILED",
                message: "native platform facts could not be discovered",
            }
        })?;
    let profile = release.profile();
    validate_request(&options, &facts, std::slice::from_ref(profile))?;
    let packages = release
        .manifest()
        .selected_packages(options.with_python, options.with_devel)?;
    let fedora = FedoraSources::verify_at(Path::new("/etc"), "44", "x86_64", &runner)?;
    let before = NativeInventory::query(&runner)?;
    let input = PrepareInput {
        manifest: release.manifest(),
        project_key: trust::KEYRING,
        primary_fingerprint: trust::PRIMARY_FINGERPRINT,
        packages: &packages,
        fedora: Some(&fedora),
    };
    let prepared = prepare(&input, &runner).map_err(|failure| {
        report_diagnostics(&failure.diagnostics);
        failure.error
    })?;
    let mut output = std::io::stdout().lock();
    let mut prompt = SystemConfirmationPrompt;
    match review_plan(prepared.plan(), &options, &mut output, &mut prompt)? {
        PlanReview::DryRun => {
            let _ = writeln!(output, "Dry run complete; nothing was installed.");
            Ok(ExitCode::SUCCESS)
        }
        PlanReview::NoChanges => {
            let _ = writeln!(
                output,
                "Nothing to install; the exact profile is already present."
            );
            Ok(ExitCode::SUCCESS)
        }
        PlanReview::Approved(receipt) => {
            display_privileged_steps(&prepared, &mut output);
            match prepared.execute_replay(&receipt, &runner, &SystemReplayExecutor) {
                Ok(()) => {
                    let after = NativeInventory::query(&runner)?;
                    let report = verify_installation(
                        release.manifest(),
                        options.with_python,
                        options.with_devel,
                        profile,
                        &before,
                        &after,
                    )?;
                    let _ = writeln!(
                        output,
                        "Native replay complete; verified {} release package(s).",
                        report.verified.len()
                    );
                    if !report.pending_reboot.is_empty() {
                        let _ = writeln!(
                            output,
                            "Reboot required before these components become active: {}.",
                            report.pending_reboot.join(", ")
                        );
                    }
                    if !report.pending_relogin.is_empty() {
                        let _ = writeln!(
                            output,
                            "Relogin required before these components become active: {}.",
                            report.pending_relogin.join(", ")
                        );
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(failure) => {
                    let retained = prepared.preserve();
                    let _ = writeln!(
                        std::io::stderr(),
                        "intel-npu-stack-install: native exit {:?}; retained {}",
                        failure.status,
                        retained.display()
                    );
                    Err(failure.error)
                }
            }
        }
    }
}

fn display_privileged_steps(prepared: &PreparedTransaction, output: &mut impl Write) {
    let _ = writeln!(
        output,
        "The following privileged steps will now run; the native tools may ask \
         for your password on this terminal:"
    );
    for step in prepared.replay_steps() {
        let rendered = step
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(output, "  {rendered}");
    }
    let _ = output.flush();
}

fn report_diagnostics(diagnostics: &Option<std::path::PathBuf>) {
    if let Some(diagnostics) = diagnostics {
        let _ = writeln!(
            std::io::stderr(),
            "intel-npu-stack-install: retained diagnostics in {}",
            diagnostics.display()
        );
    }
}
