// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use stack_core::{CheckStatus, DiagnosticCommand};
use stack_platform::PlatformFacts;
use stack_runtime::{
    ActivityInspector, BusyCounterSnapshot, DeviceInspection, DeviceInspector, InstalledPackage,
    PackageInspection, PackageInspector, ProcessError, ProcessOutput, ProcessRequest,
    ProcessRunner, RuntimeInspector, RuntimePaths,
};
use stack_schema::{KernelVersion, PciId, Profile};
use xtask::candidate_collection::{CollectionMode, collect};

// The generated candidate as it was before the 0.1.0 promotion; collection accepts only candidates.
const PROFILE: &str = include_str!("fixtures/lunar-lake-x86_64-candidate.toml");

struct Boundaries {
    calls: Mutex<Vec<String>>,
    missing: bool,
    install_time: u64,
}

impl Boundaries {
    fn new(missing: bool, install_time: u64) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            missing,
            install_time,
        }
    }
}

impl PackageInspector for Boundaries {
    fn inspect(&self, profile: &Profile) -> PackageInspection {
        self.calls.lock().unwrap().push("packages".to_owned());
        PackageInspection {
            checks: profile
                .components
                .keys()
                .map(|name| stack_core::DiagnosticCheck {
                    id: format!("package.{name}"),
                    status: if self.missing {
                        CheckStatus::Fail
                    } else {
                        CheckStatus::Pass
                    },
                    summary: "test package observation".to_owned(),
                    details: BTreeMap::new(),
                    requirement: stack_core::Requirement::Required,
                })
                .collect(),
            packages: if self.missing {
                BTreeMap::new()
            } else {
                profile
                    .components
                    .values()
                    .map(|component| {
                        (
                            component.provider.package.clone(),
                            InstalledPackage {
                                name: component.provider.package.clone(),
                                version: component.provider.version.clone(),
                                install_time: self.install_time,
                            },
                        )
                    })
                    .collect()
            },
        }
    }
}

impl ProcessRunner for Boundaries {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("this collection must not launch any runtime helper")
    }
}

impl DeviceInspector for Boundaries {
    fn inspect(&self, _: &Path, _: bool, _: DiagnosticCommand) -> DeviceInspection {
        panic!("this collection must not open an accelerator device")
    }
}

impl ActivityInspector for Boundaries {
    fn snapshot(&self, _: &Path) -> BusyCounterSnapshot {
        panic!("this collection must not sample hardware activity")
    }
}

fn facts() -> PlatformFacts {
    PlatformFacts {
        os_id: "fedora".to_owned(),
        os_version_id: "44".to_owned(),
        arch: "x86_64".to_owned(),
        kernel: KernelVersion {
            major: 7,
            minor: 1,
            patch: 13,
        },
        pci_ids: vec![PciId {
            vendor: "8086".to_owned(),
            device: "643e".to_owned(),
        }],
        intel_vpu_loaded: true,
        accel_node_present: true,
        effective_root: false,
        boot_time_epoch: 100,
    }
}

#[test]
fn preflight_is_explicitly_unqualified_and_does_not_touch_hardware() {
    let boundary = Boundaries::new(false, 50);
    let paths = RuntimePaths::system();
    let inspector = RuntimeInspector::new(&paths, &boundary, &boundary, &boundary, &boundary);
    let result = collect(
        PROFILE,
        &facts(),
        "7.1.13-200.fc44.x86_64",
        CollectionMode::Preflight,
        &inspector,
    )
    .unwrap();
    let json = serde_json::to_value(result).unwrap();
    assert_eq!(json["mode"], "preflight");
    assert_eq!(json["qualification_complete"], false);
    assert_eq!(json["diagnostic"]["profile"]["status"], "candidate");
    assert_eq!(json["diagnostic"]["overall"], "blocked");
    assert_eq!(json["kernel_release"], "7.1.13-200.fc44.x86_64");
    assert_eq!(*boundary.calls.lock().unwrap(), ["packages"]);
}

#[test]
fn incompatible_platform_and_root_are_refused_before_package_or_hardware_calls() {
    for change in 0..7 {
        let mut facts = facts();
        match change {
            0 => facts.os_id = "other".to_owned(),
            1 => facts.os_version_id = "45".to_owned(),
            2 => facts.arch = "aarch64".to_owned(),
            3 => facts.pci_ids.clear(),
            4 => facts.intel_vpu_loaded = false,
            5 => facts.kernel.patch = 14,
            6 => facts.effective_root = true,
            _ => unreachable!(),
        }
        let boundary = Boundaries::new(false, 50);
        let paths = RuntimePaths::system();
        let inspector = RuntimeInspector::new(&paths, &boundary, &boundary, &boundary, &boundary);
        assert!(
            collect(
                PROFILE,
                &facts,
                "7.1.13-200.fc44.x86_64",
                CollectionMode::Probe,
                &inspector
            )
            .is_err()
        );
        assert!(boundary.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn promoted_profile_and_inconsistent_kernel_release_are_refused() {
    let boundary = Boundaries::new(false, 50);
    let paths = RuntimePaths::system();
    let inspector = RuntimeInspector::new(&paths, &boundary, &boundary, &boundary, &boundary);
    let experimental = PROFILE.replace("status = \"candidate\"", "status = \"experimental\"");
    assert!(
        collect(
            &experimental,
            &facts(),
            "7.1.13",
            CollectionMode::Preflight,
            &inspector
        )
        .is_err()
    );
    assert!(
        collect(
            PROFILE,
            &facts(),
            "7.2.4",
            CollectionMode::Preflight,
            &inspector
        )
        .is_err()
    );
    assert!(boundary.calls.lock().unwrap().is_empty());
}

#[test]
fn missing_packages_or_pending_firmware_activation_prevent_probe_execution() {
    for (missing, install_time) in [(true, 50), (false, 150)] {
        let boundary = Boundaries::new(missing, install_time);
        let paths = RuntimePaths::system();
        let inspector = RuntimeInspector::new(&paths, &boundary, &boundary, &boundary, &boundary);
        let result = collect(
            PROFILE,
            &facts(),
            "7.1.13",
            CollectionMode::Probe,
            &inspector,
        )
        .unwrap();
        assert!(!result.qualification_complete);
        assert_eq!(result.diagnostic.exit_code(), 1);
        assert!(result.diagnostic.checks.iter().any(
            |check| check.id == "qualification.probes" && check.status == CheckStatus::Blocked
        ));
        assert_eq!(*boundary.calls.lock().unwrap(), ["packages"]);
    }
}

#[test]
fn cli_requires_exact_profile_digest_and_explicit_hardware_acknowledgement() {
    let profile = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lunar-lake-x86_64-candidate.toml");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["collect-candidate", "--profile"])
        .arg(&profile)
        .args(["--profile-sha256", &"0".repeat(64), "--mode", "preflight"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("profile digest mismatch"));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["collect-candidate", "--profile"])
        .arg(&profile)
        .args(["--profile-sha256", &"0".repeat(64), "--mode", "probe"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("hardware probes require --accept-hardware-probes")
    );
}

#[test]
fn ready_probe_collects_production_diagnostics_without_promoting_the_candidate() {
    struct ProbeRunner(Mutex<Vec<String>>);
    impl ProcessRunner for ProbeRunner {
        fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
            let name = request.executable.file_name().unwrap().to_str().unwrap();
            let mode = request.args[0].to_str().unwrap();
            self.0.lock().unwrap().push(format!("{name}:{mode}"));
            let stdout = match (name, mode) {
                ("level-zero", "enumerate") => br#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"pass","observations":{"vpu_devices":[{"vendor_id":"8086","device_id":"643e","driver_version":65536}]},"error_code":null}"#.to_vec(),
                ("openvino", "infer") => br#"{"schema_version":1,"probe":"openvino","mode":"infer","outcome":"pass","observations":{"available_devices":["CPU","NPU"],"execution_devices":["NPU"],"runtime_version":"2026.2.0","graph_id":"intel-npu-stack-neutral-v1","iterations":8,"tolerance":0.001},"error_code":null}"#.to_vec(),
                _ => panic!("unexpected probe request"),
            };
            Ok(ProcessOutput {
                termination: stack_runtime::Termination::Exit(0),
                stdout,
                stdout_overflow: false,
                stderr_overflow: false,
            })
        }
    }
    let root = tempfile::TempDir::new().unwrap();
    let mut paths = RuntimePaths::system();
    paths.root = root.path().to_owned();
    paths.level_zero_helper = root.path().join("level-zero");
    paths.openvino_helper = root.path().join("openvino");
    std::fs::write(&paths.level_zero_helper, []).unwrap();
    std::fs::write(&paths.openvino_helper, []).unwrap();
    std::fs::create_dir_all(root.path().join("dev/accel")).unwrap();
    std::fs::write(root.path().join("dev/accel/accel0"), []).unwrap();
    let packages = Boundaries::new(false, 50);
    let runner = ProbeRunner(Mutex::new(Vec::new()));
    let devices = stack_runtime::FilesystemDeviceInspector;
    let activity = stack_runtime::SysfsActivityInspector;
    let inspector = RuntimeInspector::new(&paths, &runner, &packages, &devices, &activity);
    let result = collect(
        PROFILE,
        &facts(),
        "7.1.13",
        CollectionMode::Probe,
        &inspector,
    )
    .unwrap();
    assert_eq!(
        *runner.0.lock().unwrap(),
        ["level-zero:enumerate", "openvino:infer"]
    );
    assert!(
        result
            .diagnostic
            .checks
            .iter()
            .any(|check| check.id == "runtime.inference" && check.status == CheckStatus::Pass)
    );
    assert_eq!(result.diagnostic.exit_code(), 0);
    assert!(!result.qualification_complete);
    assert_eq!(
        result.diagnostic.profile.unwrap().status,
        stack_schema::ProfileStatus::Candidate
    );
}
