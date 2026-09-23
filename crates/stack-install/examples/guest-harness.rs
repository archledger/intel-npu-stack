// SPDX-License-Identifier: Apache-2.0
//! Test-only guest harness for disposable VM lifecycle scenarios.
//!
//! This example exists exclusively for the isolated Fedora 44 virtual
//! machines of the lifecycle gate. It runs the REAL authenticated release
//! fetch, request validation, staging, review and privileged replay of the
//! pinned test release, but replaces platform DISCOVERY with synthetic
//! allowlisted facts because the virtual machine has no NPU hardware. It
//! must never be distributed or used on real hardware: fabricated facts
//! authorize nothing outside these throwaway test machines, and every other
//! check (pinned trust, signatures, digests, native transaction, exact
//! inventory) stays fully active.
//!
//! Usage mirrors intel-npu-stack-install.

#![forbid(unsafe_code)]

use std::{io::Write, path::Path, process::ExitCode};

use clap::Parser;
use stack_install::{
    FedoraSources, InstallError, InstallOptions, NativeInventory, PlanReview, PrepareInput,
    ReleaseLocation, SystemConfirmationPrompt, SystemReplayExecutor, fetch_release, prepare,
    review_plan, validate_request, verify_installation,
};
use stack_platform::PlatformFacts;
use stack_runtime::SystemProcessRunner;

// The trust seam is shared verbatim with the production entry point; in a
// pinned release build the overlay replaces it and this harness verifies the
// same pinned release. From unpinned repository source both fail closed.
mod trust {
    include!("../src/trust.rs");
}

fn main() -> ExitCode {
    let options = InstallOptions::parse();
    match run(options) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "guest-harness (test-only, synthetic platform facts): {} [{}]",
                error.message,
                error.code
            );
            ExitCode::from(error.exit_code)
        }
    }
}

/// Synthetic facts for a disposable VM guest. The kernel is the profile's own
/// minimum, which is inside the release's half-open kernel window by the
/// profile schema, so the harness follows whatever window the release pins.
fn synthetic_facts(profile: &stack_schema::Profile) -> Result<PlatformFacts, InstallError> {
    let kernel = stack_schema::KernelVersion::parse_release(&profile.kernel.min).map_err(|_| {
        InstallError {
            exit_code: 10,
            code: "INSTALL_PROFILE_UNSUPPORTED",
            message: "profile kernel minimum is not a valid release",
        }
    })?;
    Ok(PlatformFacts {
        os_id: "fedora".into(),
        os_version_id: "44".into(),
        arch: "x86_64".into(),
        kernel,
        pci_ids: vec![stack_schema::PciId {
            vendor: "8086".into(),
            device: "643e".into(),
        }],
        intel_vpu_loaded: true,
        accel_node_present: true,
        effective_root: false,
        boot_time_epoch: 0,
    })
}

fn run(options: InstallOptions) -> Result<ExitCode, InstallError> {
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
    let profile = release.profile();
    let facts = synthetic_facts(profile)?;
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
        if let Some(diagnostics) = &failure.diagnostics {
            let _ = writeln!(
                std::io::stderr(),
                "guest-harness: retained diagnostics in {}",
                diagnostics.display()
            );
        }
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
            for step in prepared.replay_steps() {
                let rendered = step
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");
                let _ = writeln!(output, "  {rendered}");
            }
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
                    for capability in &report.pending_reboot {
                        let _ = writeln!(
                            output,
                            "Reboot required before {capability} becomes active."
                        );
                    }
                    for capability in &report.pending_relogin {
                        let _ = writeln!(
                            output,
                            "Relogin required before {capability} becomes active."
                        );
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(failure) => {
                    let retained = prepared.preserve();
                    let _ = writeln!(
                        std::io::stderr(),
                        "guest-harness: native exit {:?}; retained {}",
                        failure.status,
                        retained.display()
                    );
                    Err(failure.error)
                }
            }
        }
    }
}
