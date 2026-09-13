// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};
use stack_core::{CheckStatus, DiagnosticCheck, DiagnosticCommand, Requirement};
use stack_platform::PlatformFacts;
use stack_runtime::{
    ActivityInspector, BusyCounterSnapshot, DeviceInspection, DeviceInspector, InspectionResult,
    InstalledPackage, PackageInspection, PackageInspector, ProcessError, ProcessOutput,
    ProcessRequest, ProcessRunner, RuntimeInspector, RuntimePaths, Termination,
};
use stack_schema::{KernelVersion, PciId, Profile};
use tempfile::TempDir;

const LEVEL_ZERO_PASS: &[u8] = br#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"pass","observations":{"vpu_devices":[{"vendor_id":"8086","device_id":"abcd","driver_version":65536}]},"error_code":null}
"#;
const LEVEL_ZERO_OTHER_VPU: &[u8] = br#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"pass","observations":{"vpu_devices":[{"vendor_id":"8086","device_id":"beef","driver_version":7}]},"error_code":null}
"#;
const OPENVINO_ENUMERATE_PASS: &[u8] = br#"{"schema_version":1,"probe":"openvino","mode":"enumerate","outcome":"pass","observations":{"available_devices":["CPU","NPU"],"runtime_version":"2026.2.0"},"error_code":null}
"#;
const OPENVINO_INFER_PASS: &[u8] = br#"{"schema_version":1,"probe":"openvino","mode":"infer","outcome":"pass","observations":{"available_devices":["CPU","NPU"],"execution_devices":["NPU"],"runtime_version":"2026.2.0","graph_id":"intel-npu-stack-neutral-v1","iterations":8,"tolerance":0.001},"error_code":null}
"#;

struct FakeRunner {
    outputs: Mutex<VecDeque<Result<ProcessOutput, ProcessError>>>,
    requests: Mutex<Vec<ProcessRequest>>,
}

impl FakeRunner {
    fn new(outputs: impl IntoIterator<Item = Result<ProcessOutput, ProcessError>>) -> Self {
        Self {
            outputs: Mutex::new(outputs.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<ProcessRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl ProcessRunner for FakeRunner {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        self.requests
            .lock()
            .expect("request lock")
            .push(request.clone());
        self.outputs
            .lock()
            .expect("output lock")
            .pop_front()
            .expect("one fake output per request")
    }
}

#[derive(Clone)]
struct FakePackages(PackageInspection);

impl PackageInspector for FakePackages {
    fn inspect(&self, _profile: &Profile) -> PackageInspection {
        self.0.clone()
    }
}

#[derive(Default)]
struct FakeDevices {
    result: Mutex<Option<DeviceInspection>>,
    calls: Mutex<Vec<(bool, DiagnosticCommand)>>,
}

impl FakeDevices {
    fn passing() -> Self {
        Self {
            result: Mutex::new(Some(DeviceInspection {
                node_count: 1,
                checks: vec![
                    check(
                        "device.node",
                        CheckStatus::Pass,
                        "NPU accelerator device is present",
                        Requirement::Required,
                        [("count", json!(1))],
                    ),
                    check(
                        "device.access",
                        CheckStatus::Pass,
                        "Normal-user NPU access is available",
                        Requirement::Required,
                        [("count", json!(1))],
                    ),
                ],
            })),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl DeviceInspector for FakeDevices {
    fn inspect(
        &self,
        _root: &Path,
        effective_root: bool,
        command: DiagnosticCommand,
    ) -> DeviceInspection {
        self.calls
            .lock()
            .expect("device call lock")
            .push((effective_root, command));
        let configured = self.result.lock().expect("device result lock").clone();
        if effective_root {
            return DeviceInspection {
                node_count: 1,
                checks: vec![
                    check(
                        "device.node",
                        CheckStatus::Pass,
                        "NPU accelerator device is present",
                        Requirement::Required,
                        [("count", json!(1))],
                    ),
                    check(
                        "device.access",
                        CheckStatus::Blocked,
                        "Normal-user NPU access is available",
                        if command == DiagnosticCommand::Status {
                            Requirement::Optional
                        } else {
                            Requirement::Required
                        },
                        [("error_code", json!("NORMAL_USER_REQUIRED"))],
                    ),
                ],
            };
        }
        configured.expect("configured device inspection")
    }
}

struct FakeActivity {
    snapshots: Mutex<VecDeque<BusyCounterSnapshot>>,
    calls: Mutex<usize>,
}

impl FakeActivity {
    fn new(snapshots: impl IntoIterator<Item = BusyCounterSnapshot>) -> Self {
        Self {
            snapshots: Mutex::new(snapshots.into_iter().collect()),
            calls: Mutex::new(0),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("activity call lock")
    }
}

impl ActivityInspector for FakeActivity {
    fn snapshot(&self, _root: &Path) -> BusyCounterSnapshot {
        *self.calls.lock().expect("activity call lock") += 1;
        self.snapshots
            .lock()
            .expect("activity snapshot lock")
            .pop_front()
            .unwrap_or(BusyCounterSnapshot::Absent)
    }
}

struct Fixture {
    _root: TempDir,
    profile: Profile,
    facts: PlatformFacts,
    paths: RuntimePaths,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().expect("temporary root");
        let helper_dir = root.path().join("usr/libexec/intel-npu-stack");
        fs::create_dir_all(&helper_dir).expect("create helper directory");
        let level_zero_helper = helper_dir.join("intel-npu-level-zero-probe");
        let openvino_helper = helper_dir.join("intel-npu-openvino-probe");
        fs::write(&level_zero_helper, []).expect("create Level Zero helper fixture");
        fs::write(&openvino_helper, []).expect("create OpenVINO helper fixture");
        let rpm = root.path().join("usr/bin/rpm");
        fs::create_dir_all(rpm.parent().expect("rpm parent")).expect("create rpm directory");
        fs::write(&rpm, []).expect("create RPM fixture");
        Self {
            profile: Profile::parse_toml(include_str!(
                "../../../fixtures/profiles/valid-qualified.toml"
            ))
            .expect("fixture profile must parse"),
            facts: PlatformFacts {
                os_id: "testos".to_owned(),
                os_version_id: "1".to_owned(),
                arch: "x86_64".to_owned(),
                kernel: KernelVersion {
                    major: 6,
                    minor: 12,
                    patch: 0,
                },
                pci_ids: vec![PciId {
                    vendor: "8086".to_owned(),
                    device: "abcd".to_owned(),
                }],
                intel_vpu_loaded: true,
                accel_node_present: true,
                effective_root: false,
                boot_time_epoch: 100,
            },
            paths: RuntimePaths {
                root: root.path().to_path_buf(),
                level_zero_helper,
                openvino_helper,
                rpm,
            },
            _root: root,
        }
    }
}

fn passing_packages(profile: &Profile) -> FakePackages {
    let packages = profile
        .components
        .values()
        .map(|component| {
            (
                component.provider.package.clone(),
                InstalledPackage {
                    name: component.provider.package.clone(),
                    version: component.provider.version.clone(),
                    install_time: 50,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let checks = profile
        .components
        .iter()
        .map(|(capability, component)| {
            check(
                &format!("package.{capability}"),
                CheckStatus::Pass,
                "Native provider matches the selected profile",
                Requirement::Required,
                [
                    ("package", json!(&component.provider.package)),
                    ("version", json!(&component.provider.version)),
                ],
            )
        })
        .collect();
    FakePackages(PackageInspection { checks, packages })
}

fn output(stdout: &[u8]) -> Result<ProcessOutput, ProcessError> {
    Ok(ProcessOutput {
        termination: Termination::Exit(0),
        stdout: stdout.to_vec(),
        stdout_overflow: false,
        stderr_overflow: false,
    })
}

fn failed_probe(probe: &str, mode: &str, code: &str) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"probe\":\"{probe}\",\"mode\":\"{mode}\",\"outcome\":\"fail\",\"observations\":{{}},\"error_code\":\"{code}\"}}\n"
    )
    .into_bytes()
}

fn counter(values: &[u128]) -> BusyCounterSnapshot {
    let root = TempDir::new().expect("counter root");
    for (index, value) in values.iter().enumerate() {
        let path = root.path().join(format!(
            "sys/class/accel/accel{index}/device/npu_busy_time_us"
        ));
        fs::create_dir_all(path.parent().expect("counter parent")).expect("create counter dir");
        fs::write(path, value.to_string()).expect("write counter");
    }
    stack_runtime::read_busy_counters(root.path())
}

fn inspect_status(
    fixture: &Fixture,
    runner: &FakeRunner,
    packages: &FakePackages,
    devices: &FakeDevices,
    activity: &FakeActivity,
) -> InspectionResult {
    RuntimeInspector::new(&fixture.paths, runner, packages, devices, activity)
        .inspect_status(&fixture.profile, &fixture.facts)
}

fn inspect_doctor(
    fixture: &Fixture,
    runner: &FakeRunner,
    packages: &FakePackages,
    devices: &FakeDevices,
    activity: &FakeActivity,
) -> InspectionResult {
    RuntimeInspector::new(&fixture.paths, runner, packages, devices, activity)
        .inspect_doctor(&fixture.profile, &fixture.facts)
}

fn diagnostic<'a>(result: &'a InspectionResult, id: &str) -> &'a DiagnosticCheck {
    result
        .checks
        .iter()
        .find(|check| check.id == id)
        .expect("diagnostic check exists")
}

fn code<'a>(result: &'a InspectionResult, id: &str) -> &'a str {
    diagnostic(result, id).details["error_code"]
        .as_str()
        .expect("stable error code")
}

fn check<const N: usize>(
    id: &str,
    status: CheckStatus,
    summary: &str,
    requirement: Requirement,
    details: [(&str, Value); N],
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.to_owned(),
        status,
        summary: summary.to_owned(),
        details: details
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
        requirement,
    }
}

#[test]
fn preflight_checks_packages_and_activation_without_device_or_probe_access() {
    let fixture = Fixture::new();
    let runner = FakeRunner::new([]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::default();
    let activity = FakeActivity::new([]);
    let result = RuntimeInspector::new(&fixture.paths, &runner, &packages, &devices, &activity)
        .inspect_preflight(&fixture.profile, &fixture.facts);

    assert_eq!(
        diagnostic(&result, "package.npu_firmware").status,
        CheckStatus::Pass
    );
    assert_eq!(
        diagnostic(&result, "kernel.module").status,
        CheckStatus::Pass
    );
    assert!(
        runner.requests().is_empty(),
        "preflight must not spawn helpers"
    );
    assert!(
        devices.calls.lock().unwrap().is_empty(),
        "preflight must not open devices"
    );
    assert_eq!(activity.calls(), 0);
    assert!(
        !result
            .checks
            .iter()
            .any(|check| check.id.starts_with("runtime.") || check.id.starts_with("device."))
    );
}

#[test]
fn status_runs_enumeration_but_never_inference() {
    let fixture = Fixture::new();
    let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_ENUMERATE_PASS)]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([]);

    let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);
    let requests = runner.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].executable, fixture.paths.level_zero_helper);
    assert_eq!(requests[0].args, [OsStr::new("enumerate")]);
    assert_eq!(requests[0].timeout, Duration::from_secs(10));
    assert_eq!(requests[1].executable, fixture.paths.openvino_helper);
    assert_eq!(requests[1].args, [OsStr::new("enumerate")]);
    assert_eq!(requests[1].timeout, Duration::from_secs(15));
    assert!(
        result
            .checks
            .iter()
            .all(|check| check.id != "runtime.inference")
    );
    assert!(
        result
            .checks
            .iter()
            .all(|check| check.id != "runtime.activity")
    );
    assert_eq!(activity.calls(), 0);
}

#[test]
fn doctor_runs_exact_level_zero_then_openvino_infer_modes() {
    let fixture = Fixture::new();
    let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_INFER_PASS)]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([counter(&[5]), counter(&[8])]);

    let result = inspect_doctor(&fixture, &runner, &packages, &devices, &activity);
    let requests = runner.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].args, [OsStr::new("enumerate")]);
    assert_eq!(requests[0].timeout, Duration::from_secs(10));
    assert_eq!(requests[1].args, [OsStr::new("infer")]);
    assert_eq!(requests[1].timeout, Duration::from_secs(120));
    assert_eq!(activity.calls(), 2);
    assert_eq!(
        diagnostic(&result, "runtime.activity").status,
        CheckStatus::Pass
    );
}

#[test]
fn missing_helper_library_and_crash_are_required_failures() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.paths.level_zero_helper).expect("remove helper fixture");
    let runner = FakeRunner::new([Ok(ProcessOutput {
        termination: Termination::Signal,
        stdout: Vec::new(),
        stdout_overflow: false,
        stderr_overflow: false,
    })]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([]);

    let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);
    assert_eq!(
        code(&result, "runtime.level_zero"),
        "PROBE_EXECUTABLE_MISSING"
    );
    assert_eq!(code(&result, "runtime.openvino"), "PROBE_PROCESS_FAILED");
    assert_eq!(
        diagnostic(&result, "runtime.level_zero").requirement,
        Requirement::Required
    );
    assert_eq!(runner.requests().len(), 1);
}

#[test]
fn timeout_overflow_and_malformed_output_are_required_failures() {
    let cases = [
        (Err(ProcessError::Timeout), "PROBE_TIMEOUT"),
        (
            Ok(ProcessOutput {
                termination: Termination::Exit(0),
                stdout: LEVEL_ZERO_PASS.to_vec(),
                stdout_overflow: true,
                stderr_overflow: false,
            }),
            "PROBE_OUTPUT_TOO_LARGE",
        ),
        (output(b"not-json"), "PROBE_OUTPUT_INVALID"),
    ];
    for (level_zero, expected) in cases {
        let fixture = Fixture::new();
        let runner = FakeRunner::new([level_zero, output(OPENVINO_ENUMERATE_PASS)]);
        let packages = passing_packages(&fixture.profile);
        let devices = FakeDevices::passing();
        let activity = FakeActivity::new([]);
        let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);
        assert_eq!(code(&result, "runtime.level_zero"), expected);
        assert_eq!(
            diagnostic(&result, "runtime.level_zero").status,
            CheckStatus::Fail
        );
    }
}

#[test]
fn level_zero_no_vpu_or_permission_denied_fail() {
    for expected in ["LEVEL_ZERO_NO_VPU", "LEVEL_ZERO_PERMISSION_DENIED"] {
        let fixture = Fixture::new();
        let failure = failed_probe("level_zero", "enumerate", expected);
        let runner = FakeRunner::new([output(&failure), output(OPENVINO_ENUMERATE_PASS)]);
        let packages = passing_packages(&fixture.profile);
        let devices = FakeDevices::passing();
        let activity = FakeActivity::new([]);
        let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);
        assert_eq!(code(&result, "runtime.level_zero"), expected);
    }
}

#[test]
fn level_zero_vpu_must_match_selected_profile_pci() {
    let fixture = Fixture::new();
    let runner = FakeRunner::new([
        output(LEVEL_ZERO_OTHER_VPU),
        output(OPENVINO_ENUMERATE_PASS),
    ]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([]);
    let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);

    assert_eq!(
        diagnostic(&result, "runtime.level_zero").status,
        CheckStatus::Fail
    );
    assert_eq!(code(&result, "runtime.level_zero"), "LEVEL_ZERO_NO_VPU");
}

#[test]
fn openvino_cpu_only_or_wrong_execution_device_fail() {
    for (code_value, check_id) in [
        ("OPENVINO_NO_NPU", "runtime.openvino"),
        ("OPENVINO_WRONG_DEVICE", "runtime.inference"),
    ] {
        let fixture = Fixture::new();
        let failure = failed_probe("openvino", "infer", code_value);
        let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(&failure)]);
        let packages = passing_packages(&fixture.profile);
        let devices = FakeDevices::passing();
        let activity =
            FakeActivity::new([BusyCounterSnapshot::Absent, BusyCounterSnapshot::Absent]);
        let result = inspect_doctor(&fixture, &runner, &packages, &devices, &activity);
        assert_eq!(diagnostic(&result, check_id).status, CheckStatus::Fail);
        assert_eq!(code(&result, check_id), code_value);
    }
}

#[test]
fn compile_inference_shape_finite_and_tolerance_failures_map_exactly() {
    for expected in [
        "OPENVINO_COMPILE_FAILED",
        "OPENVINO_INFERENCE_FAILED",
        "OPENVINO_OUTPUT_INVALID",
    ] {
        let fixture = Fixture::new();
        let failure = failed_probe("openvino", "infer", expected);
        let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(&failure)]);
        let packages = passing_packages(&fixture.profile);
        let devices = FakeDevices::passing();
        let activity =
            FakeActivity::new([BusyCounterSnapshot::Absent, BusyCounterSnapshot::Absent]);
        let result = inspect_doctor(&fixture, &runner, &packages, &devices, &activity);
        assert_eq!(code(&result, "runtime.inference"), expected);
    }
}

#[test]
fn successful_doctor_has_required_passes_and_optional_activity() {
    let fixture = Fixture::new();
    let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_INFER_PASS)]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([counter(&[100]), counter(&[101])]);
    let result = inspect_doctor(&fixture, &runner, &packages, &devices, &activity);

    let expected = BTreeSet::from([
        "device.access",
        "device.node",
        "firmware.installed",
        "kernel.module",
        "package.level_zero_loader",
        "package.npu_compiler",
        "package.npu_firmware",
        "package.npu_userspace_driver",
        "package.openvino_npu_plugin",
        "package.openvino_runtime",
        "platform.profile",
        "runtime.activity",
        "runtime.inference",
        "runtime.level_zero",
        "runtime.openvino",
    ]);
    let actual = result
        .checks
        .iter()
        .map(|check| check.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert!(
        result
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Pass)
    );
    assert_eq!(
        diagnostic(&result, "runtime.activity").requirement,
        Requirement::Optional
    );
    assert!(
        result
            .checks
            .iter()
            .filter(|check| check.id != "runtime.activity")
            .all(|check| check.requirement == Requirement::Required)
    );
    assert!(!result.reboot_required);
    assert!(!result.relogin_required);
}

#[test]
fn one_check_failure_does_not_hide_independent_safe_checks() {
    let fixture = Fixture::new();
    let mut packages = passing_packages(&fixture.profile);
    packages.0.checks[0] = check(
        "package.level_zero_loader",
        CheckStatus::Fail,
        "Native provider matches the selected profile",
        Requirement::Required,
        [("error_code", json!("PACKAGE_NOT_INSTALLED"))],
    );
    let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_ENUMERATE_PASS)]);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([]);
    let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);

    assert_eq!(
        diagnostic(&result, "package.level_zero_loader").status,
        CheckStatus::Fail
    );
    assert_eq!(diagnostic(&result, "device.node").status, CheckStatus::Pass);
    assert_eq!(
        diagnostic(&result, "runtime.level_zero").status,
        CheckStatus::Pass
    );
    assert_eq!(
        diagnostic(&result, "runtime.openvino").status,
        CheckStatus::Pass
    );
    assert_eq!(runner.requests().len(), 2);
}

#[test]
fn root_invocation_blocks_normal_user_access() {
    let mut fixture = Fixture::new();
    fixture.facts.effective_root = true;
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let status_runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_ENUMERATE_PASS)]);
    let status_activity = FakeActivity::new([]);
    let status = inspect_status(
        &fixture,
        &status_runner,
        &packages,
        &devices,
        &status_activity,
    );
    assert_eq!(
        diagnostic(&status, "device.access").status,
        CheckStatus::Blocked
    );
    assert_eq!(
        diagnostic(&status, "device.access").requirement,
        Requirement::Optional
    );

    let doctor_runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_INFER_PASS)]);
    let doctor_activity =
        FakeActivity::new([BusyCounterSnapshot::Absent, BusyCounterSnapshot::Absent]);
    let doctor = inspect_doctor(
        &fixture,
        &doctor_runner,
        &packages,
        &devices,
        &doctor_activity,
    );
    assert_eq!(
        diagnostic(&doctor, "device.access").status,
        CheckStatus::Blocked
    );
    assert_eq!(
        diagnostic(&doctor, "device.access").requirement,
        Requirement::Required
    );
    assert_eq!(code(&doctor, "device.access"), "NORMAL_USER_REQUIRED");
    assert_eq!(
        devices.calls.lock().expect("device calls").as_slice(),
        [
            (true, DiagnosticCommand::Status),
            (true, DiagnosticCommand::Doctor),
        ]
    );
}

#[test]
fn details_use_only_allowlisted_keys_and_values() {
    let fixture = Fixture::new();
    let runner = FakeRunner::new([output(LEVEL_ZERO_PASS), output(OPENVINO_INFER_PASS)]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([counter(&[10]), counter(&[12])]);
    let result = inspect_doctor(&fixture, &runner, &packages, &devices, &activity);
    let allowed = BTreeSet::from([
        "available_devices",
        "busy_time_delta",
        "count",
        "driver_versions",
        "error_code",
        "execution_devices",
        "graph_id",
        "iterations",
        "loaded",
        "package",
        "pci_ids",
        "runtime_version",
        "tolerance",
        "version",
    ]);
    for check in &result.checks {
        assert!(
            check
                .details
                .keys()
                .all(|key| allowed.contains(key.as_str()))
        );
    }
    let encoded = serde_json::to_string(&result.checks).expect("serialize checks");
    assert!(!encoded.contains(&fixture.paths.root.display().to_string()));
    assert!(!encoded.contains("fixture-lunar-lake-class"));
}

#[test]
fn report_never_contains_raw_stderr_paths_or_identifiers() {
    let fixture = Fixture::new();
    let secret = b"loader: /private/build/libze.so user=person uid=1000 pci=0000:00:0b.0";
    let runner = FakeRunner::new([output(secret), Err(ProcessError::Spawn)]);
    let packages = passing_packages(&fixture.profile);
    let devices = FakeDevices::passing();
    let activity = FakeActivity::new([]);
    let result = inspect_status(&fixture, &runner, &packages, &devices, &activity);
    let encoded = serde_json::to_string(&result.checks).expect("serialize checks");

    for forbidden in [
        "/private/build/libze.so",
        "person",
        "1000",
        "0000:00:0b.0",
        "loader:",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    assert_eq!(code(&result, "runtime.level_zero"), "PROBE_OUTPUT_INVALID");
    assert_eq!(code(&result, "runtime.openvino"), "PROBE_PROCESS_FAILED");
}
