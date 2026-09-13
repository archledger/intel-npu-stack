// SPDX-License-Identifier: Apache-2.0

//! Developer-only candidate observations using actual production boundaries.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use stack_core::{
    CheckStatus, DiagnosticCheck, DiagnosticCommand, DiagnosticReport, OverallStatus,
    PlatformSummary, ProfileSummary, Requirement, platform_matches,
};
use stack_platform::{PlatformFacts, PlatformPaths, detect_platform};
use stack_runtime::{
    FilesystemDeviceInspector, RpmPackageInspector, RuntimeInspector, RuntimePaths,
    SysfsActivityInspector, SystemProcessRunner,
};
use stack_schema::{KernelVersion, Profile, ProfileStatus};

/// Metadata-only preparation versus explicitly requested normal-user probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMode {
    Preflight,
    Probe,
}

/// A single candidate observation, never a qualification/promotion receipt.
#[derive(Debug, Serialize)]
pub struct CandidateObservation {
    pub schema_version: u32,
    pub mode: CollectionMode,
    pub profile_sha256: String,
    pub kernel_release: String,
    pub qualification_complete: bool,
    pub diagnostic: DiagnosticReport,
}

/// Collects one observation after checking candidate status and real platform facts.
///
/// Dependency injection is for tests; the command-line path uses only system
/// discovery, native RPM inspection, fixed installed helper paths and normal-user
/// device access. Preflight never opens a device or launches a runtime helper.
/// Probe mode first requires successful metadata/activation checks.
///
/// # Errors
///
/// Rejects root, non-candidates, incompatible platforms and inconsistent kernels
/// before runtime inspection. Profile bytes are never modified or promoted.
pub fn collect(
    profile_text: &str,
    facts: &PlatformFacts,
    kernel_release: &str,
    mode: CollectionMode,
    inspector: &RuntimeInspector<'_>,
) -> Result<CandidateObservation, String> {
    let profile = Profile::parse_toml(profile_text).map_err(|error| error.to_string())?;
    if profile.status != ProfileStatus::Candidate || profile.qualification.is_some() {
        return Err("collection requires an unqualified candidate".to_owned());
    }
    if facts.effective_root {
        return Err("candidate collection requires a normal user".to_owned());
    }
    if !platform_matches(&profile, facts) {
        return Err("candidate does not match the observed platform".to_owned());
    }
    if KernelVersion::parse_release(kernel_release).map_err(|error| error.to_string())?
        != facts.kernel
    {
        return Err("kernel release is inconsistent with discovered facts".to_owned());
    }
    let preflight = inspector.inspect_preflight(&profile, facts);
    let ready = !preflight.reboot_required
        && !preflight.relogin_required
        && preflight.checks.iter().all(|check| {
            check.requirement != Requirement::Required || check.status == CheckStatus::Pass
        });
    let mut inspection = if mode == CollectionMode::Probe && ready {
        inspector.inspect_doctor(&profile, facts)
    } else {
        preflight
    };
    if mode == CollectionMode::Preflight || !ready {
        inspection.checks.push(DiagnosticCheck {
            id: "qualification.probes".to_owned(),
            status: CheckStatus::Blocked,
            summary: "Hardware probes were not executed".to_owned(),
            details: BTreeMap::from([(
                "error_code".to_owned(),
                json!(if mode == CollectionMode::Preflight {
                    "PREFLIGHT_ONLY"
                } else {
                    "PREFLIGHT_NOT_READY"
                }),
            )]),
            requirement: Requirement::Required,
        });
    }
    let mut diagnostic = DiagnosticReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        command: if mode == CollectionMode::Preflight {
            DiagnosticCommand::Status
        } else {
            DiagnosticCommand::Doctor
        },
        overall: OverallStatus::Blocked,
        profile: Some(ProfileSummary {
            id: profile.id,
            stack_release: profile.stack_release,
            status: profile.status,
        }),
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
                .map(|pci| format!("{}:{}", pci.vendor, pci.device))
                .collect(),
        },
        reboot_required: inspection.reboot_required,
        relogin_required: inspection.relogin_required,
        checks: inspection.checks,
    };
    diagnostic.finalize();
    Ok(CandidateObservation {
        schema_version: 1,
        mode,
        profile_sha256: format!("{:x}", Sha256::digest(profile_text.as_bytes())),
        kernel_release: kernel_release.to_owned(),
        qualification_complete: false,
        diagnostic,
    })
}

/// Runs the candidate collector against the current host with no path overrides.
///
/// # Errors
///
/// Refuses unacknowledged hardware probes, unpinned profiles, invalid input and
/// failed platform discovery. The pinned digest must be independently verified.
pub fn collect_system(
    profile: &Path,
    expected_sha256: &str,
    mode: CollectionMode,
    accept_hardware_probes: bool,
) -> Result<CandidateObservation, String> {
    if mode == CollectionMode::Probe && !accept_hardware_probes {
        return Err("hardware probes require --accept-hardware-probes".to_owned());
    }
    if mode == CollectionMode::Preflight && accept_hardware_probes {
        return Err("preflight does not accept hardware probe acknowledgement".to_owned());
    }
    let text = read_profile(profile)?;
    if format!("{:x}", Sha256::digest(text.as_bytes())) != expected_sha256 {
        return Err("profile digest mismatch".to_owned());
    }
    let facts = detect_platform(&PlatformPaths::system(), std::env::consts::ARCH)
        .map_err(|error| error.to_string())?;
    let mut kernel_release = String::new();
    File::open("/proc/sys/kernel/osrelease")
        .map_err(|error| error.to_string())?
        .take(4097)
        .read_to_string(&mut kernel_release)
        .map_err(|error| error.to_string())?;
    if kernel_release.len() > 4096 {
        return Err("kernel release exceeds byte limit".to_owned());
    }
    let paths = RuntimePaths::system();
    let runner = SystemProcessRunner;
    let packages = RpmPackageInspector::new(&paths.rpm, &paths.root, &runner);
    let devices = FilesystemDeviceInspector;
    let activity = SysfsActivityInspector;
    let inspector = RuntimeInspector::new(&paths, &runner, &packages, &devices, &activity);
    collect(&text, &facts, kernel_release.trim_end(), mode, &inspector)
}

/// Reads a bounded, directly named profile without accepting a symlink or device.
pub(crate) fn read_profile(path: &Path) -> Result<String, String> {
    if !std::fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("profile must be a regular file".to_owned());
    }
    let mut text = String::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(1_048_577)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    if text.len() > 1_048_576 {
        return Err("profile exceeds byte limit".to_owned());
    }
    Ok(text)
}
