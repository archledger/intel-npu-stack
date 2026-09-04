// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use stack_core::{CheckStatus, DiagnosticCheck, DiagnosticCommand, Requirement};
use stack_platform::PlatformFacts;
use stack_schema::Profile;

use crate::{
    ActivationState, BusyCounterSnapshot, DeviceInspection, PackageInspector, ProbeErrorCode,
    ProbeKind, ProbeMode, ProbeObservations, ProbeOutcome, ProbeReport, ProcessError,
    ProcessRequest, ProcessRunner, Termination, evaluate_activity, inspect_activation,
    inspect_devices, parse_probe_output, read_busy_counters,
};

const LEVEL_ZERO_TIMEOUT: Duration = Duration::from_secs(10);
const OPENVINO_ENUMERATE_TIMEOUT: Duration = Duration::from_secs(15);
const OPENVINO_INFER_TIMEOUT: Duration = Duration::from_secs(120);
const PROBE_STDOUT_LIMIT: usize = 65_536;
const PROBE_STDERR_LIMIT: usize = 16_384;

/// Installed and injected paths used by runtime inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    pub root: PathBuf,
    pub level_zero_helper: PathBuf,
    pub openvino_helper: PathBuf,
    pub rpm: PathBuf,
}

impl RuntimePaths {
    /// Returns the fixed package-owned production paths.
    #[must_use]
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            level_zero_helper: PathBuf::from(
                "/usr/libexec/intel-npu-stack/intel-npu-level-zero-probe",
            ),
            openvino_helper: PathBuf::from("/usr/libexec/intel-npu-stack/intel-npu-openvino-probe"),
            rpm: PathBuf::from("/usr/bin/rpm"),
        }
    }
}

/// Structured runtime inspection output independent of presentation.
#[derive(Debug, Clone, PartialEq)]
pub struct InspectionResult {
    pub checks: Vec<DiagnosticCheck>,
    pub reboot_required: bool,
    pub relogin_required: bool,
}

/// Injectable device boundary used by orchestration tests.
pub trait DeviceInspector: Send + Sync {
    fn inspect(
        &self,
        root: &Path,
        effective_root: bool,
        command: DiagnosticCommand,
    ) -> DeviceInspection;
}

/// Production read-only device inspector.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilesystemDeviceInspector;

impl DeviceInspector for FilesystemDeviceInspector {
    fn inspect(
        &self,
        root: &Path,
        effective_root: bool,
        command: DiagnosticCommand,
    ) -> DeviceInspection {
        inspect_devices(root, effective_root, command)
    }
}

/// Injectable activity-counter boundary used by orchestration tests.
pub trait ActivityInspector: Send + Sync {
    fn snapshot(&self, root: &Path) -> BusyCounterSnapshot;
}

/// Production read-only sysfs activity inspector.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysfsActivityInspector;

impl ActivityInspector for SysfsActivityInspector {
    fn snapshot(&self, root: &Path) -> BusyCounterSnapshot {
        read_busy_counters(root)
    }
}

/// Composes structured package, platform, device, activity, and probe evidence.
pub struct RuntimeInspector<'a> {
    paths: &'a RuntimePaths,
    runner: &'a dyn ProcessRunner,
    packages: &'a dyn PackageInspector,
    devices: &'a dyn DeviceInspector,
    activity: &'a dyn ActivityInspector,
}

impl<'a> RuntimeInspector<'a> {
    #[must_use]
    pub fn new(
        paths: &'a RuntimePaths,
        runner: &'a dyn ProcessRunner,
        packages: &'a dyn PackageInspector,
        devices: &'a dyn DeviceInspector,
        activity: &'a dyn ActivityInspector,
    ) -> Self {
        Self {
            paths,
            runner,
            packages,
            devices,
            activity,
        }
    }

    #[must_use]
    pub fn inspect_status(&self, profile: &Profile, facts: &PlatformFacts) -> InspectionResult {
        let mut result = self.inspect_common(profile, facts, DiagnosticCommand::Status);
        let level_zero = self.run_level_zero(profile);
        result.checks.push(level_zero.check);

        if level_zero.unsafe_to_continue {
            result.checks.push(failed_check(
                "runtime.openvino",
                "OpenVINO exposes an NPU device",
                "PROBE_PROCESS_FAILED",
            ));
        } else {
            result.checks.push(self.run_openvino_enumerate());
        }
        finish(result)
    }

    #[must_use]
    pub fn inspect_doctor(&self, profile: &Profile, facts: &PlatformFacts) -> InspectionResult {
        let mut result = self.inspect_common(profile, facts, DiagnosticCommand::Doctor);
        let level_zero = self.run_level_zero(profile);
        result.checks.push(level_zero.check);

        let before = self.activity.snapshot(&self.paths.root);
        if level_zero.unsafe_to_continue {
            result
                .checks
                .extend(openvino_infer_failure("PROBE_PROCESS_FAILED", false));
        } else {
            result.checks.extend(self.run_openvino_infer());
        }
        let after = self.activity.snapshot(&self.paths.root);
        result.checks.push(evaluate_activity(&before, &after));
        finish(result)
    }

    fn inspect_common(
        &self,
        profile: &Profile,
        facts: &PlatformFacts,
        command: DiagnosticCommand,
    ) -> InspectionResult {
        let package_inspection = self.packages.inspect(profile);
        let activation = inspect_activation(
            profile,
            &package_inspection.packages,
            Some(facts.boot_time_epoch),
        );
        let mut checks = vec![check(
            "platform.profile",
            CheckStatus::Pass,
            "Compatible platform profile is selected",
            Requirement::Required,
            BTreeMap::new(),
        )];
        checks.extend(package_inspection.checks.iter().cloned());
        checks.push(kernel_check(facts));
        checks.push(firmware_check(&package_inspection.checks, activation.state));
        checks.extend(
            self.devices
                .inspect(&self.paths.root, facts.effective_root, command)
                .checks,
        );
        InspectionResult {
            checks,
            reboot_required: activation.reboot_required,
            relogin_required: activation.relogin_required,
        }
    }

    fn run_level_zero(&self, profile: &Profile) -> ProbeCheck {
        let probe = self.run_probe(
            &self.paths.level_zero_helper,
            ProbeKind::LevelZero,
            ProbeMode::Enumerate,
            LEVEL_ZERO_TIMEOUT,
        );
        let report = match probe {
            Ok(report) => report,
            Err(failure) => {
                return ProbeCheck {
                    check: failed_check(
                        "runtime.level_zero",
                        "Level Zero exposes an Intel VPU",
                        failure.code,
                    ),
                    unsafe_to_continue: failure.unsafe_to_continue,
                };
            }
        };
        if report.outcome == ProbeOutcome::Fail {
            return ProbeCheck {
                check: failed_check(
                    "runtime.level_zero",
                    "Level Zero exposes an Intel VPU",
                    probe_error_code(report.error_code.expect("validated failed report")),
                ),
                unsafe_to_continue: false,
            };
        }
        let ProbeObservations::LevelZero(observation) = report.observations else {
            return ProbeCheck {
                check: failed_check(
                    "runtime.level_zero",
                    "Level Zero exposes an Intel VPU",
                    "PROBE_OUTPUT_INVALID",
                ),
                unsafe_to_continue: false,
            };
        };
        let matches = observation.vpu_devices.iter().any(|device| {
            profile.hardware.iter().any(|expected| {
                expected.vendor == device.vendor_id && expected.device == device.device_id
            })
        });
        if !matches {
            return ProbeCheck {
                check: failed_check(
                    "runtime.level_zero",
                    "Level Zero exposes an Intel VPU",
                    "LEVEL_ZERO_NO_VPU",
                ),
                unsafe_to_continue: false,
            };
        }
        let pci_ids = observation
            .vpu_devices
            .iter()
            .map(|device| format!("{}:{}", device.vendor_id, device.device_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let driver_versions = observation
            .vpu_devices
            .iter()
            .map(|device| device.driver_version)
            .collect::<Vec<_>>();
        ProbeCheck {
            check: check(
                "runtime.level_zero",
                CheckStatus::Pass,
                "Level Zero exposes an Intel VPU",
                Requirement::Required,
                details([
                    ("count", json!(observation.vpu_devices.len())),
                    ("driver_versions", json!(driver_versions)),
                    ("pci_ids", json!(pci_ids)),
                ]),
            ),
            unsafe_to_continue: false,
        }
    }

    fn run_openvino_enumerate(&self) -> DiagnosticCheck {
        let report = match self.run_probe(
            &self.paths.openvino_helper,
            ProbeKind::OpenVino,
            ProbeMode::Enumerate,
            OPENVINO_ENUMERATE_TIMEOUT,
        ) {
            Ok(report) => report,
            Err(failure) => {
                return failed_check(
                    "runtime.openvino",
                    "OpenVINO exposes an NPU device",
                    failure.code,
                );
            }
        };
        if report.outcome == ProbeOutcome::Fail {
            return failed_check(
                "runtime.openvino",
                "OpenVINO exposes an NPU device",
                probe_error_code(report.error_code.expect("validated failed report")),
            );
        }
        let ProbeObservations::OpenVinoEnumerate(observation) = report.observations else {
            return failed_check(
                "runtime.openvino",
                "OpenVINO exposes an NPU device",
                "PROBE_OUTPUT_INVALID",
            );
        };
        check(
            "runtime.openvino",
            CheckStatus::Pass,
            "OpenVINO exposes an NPU device",
            Requirement::Required,
            details([
                ("available_devices", json!(observation.available_devices)),
                ("runtime_version", json!(observation.runtime_version)),
            ]),
        )
    }

    fn run_openvino_infer(&self) -> Vec<DiagnosticCheck> {
        let report = match self.run_probe(
            &self.paths.openvino_helper,
            ProbeKind::OpenVino,
            ProbeMode::Infer,
            OPENVINO_INFER_TIMEOUT,
        ) {
            Ok(report) => report,
            Err(failure) => return openvino_infer_failure(failure.code, false),
        };
        if report.outcome == ProbeOutcome::Fail {
            let code = probe_error_code(report.error_code.expect("validated failed report"));
            let discovery_passed = matches!(
                report.error_code,
                Some(
                    ProbeErrorCode::OpenVinoCompileFailed
                        | ProbeErrorCode::OpenVinoWrongDevice
                        | ProbeErrorCode::OpenVinoInferenceFailed
                        | ProbeErrorCode::OpenVinoOutputInvalid
                )
            );
            return openvino_infer_failure(code, discovery_passed);
        }
        let ProbeObservations::OpenVinoInfer(observation) = report.observations else {
            return openvino_infer_failure("PROBE_OUTPUT_INVALID", false);
        };
        vec![
            check(
                "runtime.openvino",
                CheckStatus::Pass,
                "OpenVINO exposes an NPU device",
                Requirement::Required,
                details([
                    ("available_devices", json!(observation.available_devices)),
                    ("runtime_version", json!(observation.runtime_version)),
                ]),
            ),
            check(
                "runtime.inference",
                CheckStatus::Pass,
                "Direct NPU inference completed correctly",
                Requirement::Required,
                details([
                    ("execution_devices", json!(observation.execution_devices)),
                    ("graph_id", json!(observation.graph_id)),
                    ("iterations", json!(observation.iterations)),
                    ("tolerance", json!(observation.tolerance)),
                ]),
            ),
        ]
    }

    fn run_probe(
        &self,
        executable: &Path,
        probe: ProbeKind,
        mode: ProbeMode,
        timeout: Duration,
    ) -> Result<ProbeReport, ProbeFailure> {
        if !valid_executable_path(executable) {
            return Err(ProbeFailure::ordinary("PROBE_EXECUTABLE_MISSING"));
        }
        let output = self
            .runner
            .run(&ProcessRequest {
                executable: executable.to_path_buf(),
                args: vec![OsString::from(match mode {
                    ProbeMode::Enumerate => "enumerate",
                    ProbeMode::Infer => "infer",
                })],
                timeout,
                stdout_limit: PROBE_STDOUT_LIMIT,
                stderr_limit: PROBE_STDERR_LIMIT,
                environment: Vec::new(),
            })
            .map_err(ProbeFailure::from_process)?;
        if output.stdout_overflow || output.stderr_overflow {
            return Err(ProbeFailure::ordinary("PROBE_OUTPUT_TOO_LARGE"));
        }
        if output.termination != Termination::Exit(0) {
            return Err(ProbeFailure::ordinary("PROBE_PROCESS_FAILED"));
        }
        parse_probe_output(&output.stdout, probe, mode)
            .map_err(|error| ProbeFailure::ordinary(error.code))
    }
}

struct ProbeCheck {
    check: DiagnosticCheck,
    unsafe_to_continue: bool,
}

struct ProbeFailure {
    code: &'static str,
    unsafe_to_continue: bool,
}

impl ProbeFailure {
    const fn ordinary(code: &'static str) -> Self {
        Self {
            code,
            unsafe_to_continue: false,
        }
    }

    const fn from_process(error: ProcessError) -> Self {
        match error {
            ProcessError::Timeout => Self::ordinary("PROBE_TIMEOUT"),
            ProcessError::InvalidExecutable
            | ProcessError::PipeIo
            | ProcessError::Join
            | ProcessError::InvalidTermination => Self {
                code: "PROBE_PROCESS_FAILED",
                unsafe_to_continue: true,
            },
            ProcessError::Spawn => Self::ordinary("PROBE_PROCESS_FAILED"),
        }
    }
}

fn valid_executable_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn kernel_check(facts: &PlatformFacts) -> DiagnosticCheck {
    if facts.intel_vpu_loaded {
        check(
            "kernel.module",
            CheckStatus::Pass,
            "Intel NPU kernel module is loaded",
            Requirement::Required,
            details([("loaded", json!(true))]),
        )
    } else {
        failed_check(
            "kernel.module",
            "Intel NPU kernel module is loaded",
            "KERNEL_MODULE_MISSING",
        )
    }
}

fn firmware_check(
    package_checks: &[DiagnosticCheck],
    activation: ActivationState,
) -> DiagnosticCheck {
    let Some(provider) = package_checks
        .iter()
        .find(|check| check.id == "package.npu_firmware")
    else {
        return failed_check(
            "firmware.installed",
            "Intel NPU firmware matches the selected profile",
            "PACKAGE_NOT_INSTALLED",
        );
    };
    if provider.status != CheckStatus::Pass {
        return check(
            "firmware.installed",
            provider.status,
            "Intel NPU firmware matches the selected profile",
            Requirement::Required,
            provider.details.clone(),
        );
    }
    if activation == ActivationState::Unknown {
        return check(
            "firmware.installed",
            CheckStatus::Blocked,
            "Intel NPU firmware matches the selected profile",
            Requirement::Required,
            details([("error_code", json!("ACTIVATION_STATE_UNKNOWN"))]),
        );
    }
    check(
        "firmware.installed",
        CheckStatus::Pass,
        "Intel NPU firmware matches the selected profile",
        Requirement::Required,
        provider.details.clone(),
    )
}

fn openvino_infer_failure(code: &'static str, discovery_passed: bool) -> Vec<DiagnosticCheck> {
    let openvino = if discovery_passed {
        check(
            "runtime.openvino",
            CheckStatus::Pass,
            "OpenVINO exposes an NPU device",
            Requirement::Required,
            BTreeMap::new(),
        )
    } else {
        failed_check("runtime.openvino", "OpenVINO exposes an NPU device", code)
    };
    vec![
        openvino,
        failed_check(
            "runtime.inference",
            "Direct NPU inference completed correctly",
            code,
        ),
    ]
}

fn probe_error_code(code: ProbeErrorCode) -> &'static str {
    match code {
        ProbeErrorCode::LevelZeroPermissionDenied => "LEVEL_ZERO_PERMISSION_DENIED",
        ProbeErrorCode::LevelZeroDependencyUnavailable => "LEVEL_ZERO_DEPENDENCY_UNAVAILABLE",
        ProbeErrorCode::LevelZeroNoVpu => "LEVEL_ZERO_NO_VPU",
        ProbeErrorCode::LevelZeroEnumerationFailed => "LEVEL_ZERO_ENUMERATION_FAILED",
        ProbeErrorCode::LevelZeroInternalFailure => "LEVEL_ZERO_INTERNAL_FAILURE",
        ProbeErrorCode::OpenVinoNoNpu => "OPENVINO_NO_NPU",
        ProbeErrorCode::OpenVinoEnumerationFailed => "OPENVINO_ENUMERATION_FAILED",
        ProbeErrorCode::OpenVinoCompileFailed => "OPENVINO_COMPILE_FAILED",
        ProbeErrorCode::OpenVinoWrongDevice => "OPENVINO_WRONG_DEVICE",
        ProbeErrorCode::OpenVinoInferenceFailed => "OPENVINO_INFERENCE_FAILED",
        ProbeErrorCode::OpenVinoOutputInvalid => "OPENVINO_OUTPUT_INVALID",
        ProbeErrorCode::OpenVinoInternalFailure => "OPENVINO_INTERNAL_FAILURE",
    }
}

fn failed_check(id: &str, summary: &str, error_code: &'static str) -> DiagnosticCheck {
    check(
        id,
        CheckStatus::Fail,
        summary,
        Requirement::Required,
        details([("error_code", json!(error_code))]),
    )
}

fn check(
    id: &str,
    status: CheckStatus,
    summary: &str,
    requirement: Requirement,
    details: BTreeMap<String, Value>,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.to_owned(),
        status,
        summary: summary.to_owned(),
        details,
        requirement,
    }
}

fn details<const N: usize>(values: [(&str, Value); N]) -> BTreeMap<String, Value> {
    values
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn finish(mut result: InspectionResult) -> InspectionResult {
    result.checks.sort_by(|left, right| left.id.cmp(&right.id));
    result
}
