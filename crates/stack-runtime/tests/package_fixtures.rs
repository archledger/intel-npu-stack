// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use stack_core::{CheckStatus, DiagnosticCheck};
use stack_runtime::{
    InstalledPackage, PackageInspection, PackageInspector, ProcessError, ProcessOutput,
    ProcessRequest, ProcessRunner, RpmPackageInspector, Termination,
};
use stack_schema::{PackageManager, Profile};
use tempfile::TempDir;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const PACKAGE_FORMAT: &str = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\n";
const OWNER_FORMAT: &str = "%{NAME}\n";

#[derive(Default)]
struct FakeRunner {
    requests: Mutex<Vec<ProcessRequest>>,
    packages: Mutex<HashMap<String, Option<InstalledPackage>>>,
    owners: Mutex<HashMap<String, String>>,
    forced: Mutex<HashMap<String, Result<ProcessOutput, ProcessError>>>,
}

impl FakeRunner {
    fn for_profile(profile: &Profile) -> Self {
        let packages = profile
            .components
            .values()
            .map(|component| {
                let provider = &component.provider;
                (
                    provider.package.clone(),
                    Some(InstalledPackage {
                        name: provider.package.clone(),
                        version: provider.version.clone(),
                        install_time: 100,
                    }),
                )
            })
            .collect();
        let owners = profile
            .components
            .values()
            .flat_map(|component| {
                component
                    .provider
                    .files
                    .iter()
                    .map(|file| (file.path.clone(), component.provider.package.clone()))
            })
            .collect();
        Self {
            requests: Mutex::new(Vec::new()),
            packages: Mutex::new(packages),
            owners: Mutex::new(owners),
            forced: Mutex::new(HashMap::new()),
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
        assert_eq!(request.executable, Path::new("/usr/bin/rpm"));
        let args = request
            .args
            .iter()
            .map(|arg| arg.to_str().expect("test argument must be UTF-8"))
            .collect::<Vec<_>>();
        let key = args.last().expect("query data argument").to_string();
        if let Some(result) = self.forced.lock().expect("forced lock").get(&key) {
            return result.clone();
        }

        let stdout = match args.as_slice() {
            ["-q", "--qf", PACKAGE_FORMAT, "--", package] => {
                match self.packages.lock().expect("package lock").get(*package) {
                    Some(Some(installed)) => format!(
                        "{}\t{}\t{}\n",
                        installed.name, installed.version, installed.install_time
                    )
                    .into_bytes(),
                    _ => {
                        return Ok(output(Termination::Exit(1), Vec::new()));
                    }
                }
            }
            ["-qf", "--qf", OWNER_FORMAT, "--", path] => {
                match self.owners.lock().expect("owner lock").get(*path) {
                    Some(owner) => format!("{owner}\n").into_bytes(),
                    None => return Ok(output(Termination::Exit(1), Vec::new())),
                }
            }
            _ => panic!("unexpected RPM arguments: {args:?}"),
        };
        Ok(output(Termination::Exit(0), stdout))
    }
}

fn output(termination: Termination, stdout: Vec<u8>) -> ProcessOutput {
    ProcessOutput {
        termination,
        stdout,
        stdout_overflow: false,
        stderr_overflow: false,
    }
}

fn profile_and_root() -> (Profile, TempDir) {
    let mut profile = Profile::parse_toml(include_str!(
        "../../../fixtures/profiles/valid-qualified.toml"
    ))
    .expect("fixture profile must parse");
    let root = TempDir::new().expect("temporary root");
    for component in profile.components.values_mut() {
        for file in &mut component.provider.files {
            file.sha256 = EMPTY_SHA256.to_owned();
            let host_path = root.path().join(
                Path::new(&file.path)
                    .strip_prefix("/")
                    .expect("validated absolute profile path"),
            );
            fs::create_dir_all(host_path.parent().expect("file parent")).expect("create parent");
            fs::write(host_path, []).expect("create empty critical file");
        }
    }
    (profile, root)
}

fn inspect(profile: &Profile, root: &Path, runner: &FakeRunner) -> PackageInspection {
    RpmPackageInspector::new("/usr/bin/rpm", root, runner).inspect(profile)
}

fn check<'a>(inspection: &'a PackageInspection, id: &str) -> &'a DiagnosticCheck {
    inspection
        .checks
        .iter()
        .find(|check| check.id == id)
        .expect("diagnostic check exists")
}

fn code(check: &DiagnosticCheck) -> &str {
    check.details["error_code"]
        .as_str()
        .expect("stable detail code")
}

#[test]
fn rpm_exact_package_version_and_file_ownership_pass() {
    let (profile, root) = profile_and_root();
    let runner = FakeRunner::for_profile(&profile);
    let result = inspect(&profile, root.path(), &runner);

    assert_eq!(result.packages.len(), 6);
    assert_eq!(result.checks.len(), 6);
    assert!(
        result
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Pass)
    );
    assert!(result.checks.iter().all(|check| {
        check.id.starts_with("package.")
            && check.summary == "Native provider matches the selected profile"
            && !check.details.contains_key("error_code")
    }));
}

#[test]
fn native_rpm_absence_message_is_missing_but_other_output_remains_a_query_failure() {
    let (profile, root) = profile_and_root();
    let provider = &profile.components["npu_firmware"].provider.package;
    for (stdout, expected) in [
        (
            format!("package {provider} is not installed\n"),
            "PACKAGE_NOT_INSTALLED",
        ),
        (
            "package different-name is not installed\n".to_owned(),
            "PACKAGE_QUERY_FAILED",
        ),
        ("rpm database failure\n".to_owned(), "PACKAGE_QUERY_FAILED"),
    ] {
        let runner = FakeRunner::for_profile(&profile);
        runner.forced.lock().unwrap().insert(
            provider.clone(),
            Ok(output(Termination::Exit(1), stdout.into_bytes())),
        );
        let result = inspect(&profile, root.path(), &runner);
        assert_eq!(code(check(&result, "package.npu_firmware")), expected);
        assert!(!result.packages.contains_key(provider));
    }
}

#[test]
fn missing_package_fails_only_its_capability() {
    let (profile, root) = profile_and_root();
    let runner = FakeRunner::for_profile(&profile);
    runner
        .packages
        .lock()
        .expect("package lock")
        .insert("fixture-npu-firmware".to_owned(), None);

    let result = inspect(&profile, root.path(), &runner);
    let failed = result
        .checks
        .iter()
        .filter(|check| check.status == CheckStatus::Fail)
        .collect::<Vec<_>>();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].id, "package.npu_firmware");
    assert_eq!(code(failed[0]), "PACKAGE_NOT_INSTALLED");
}

#[test]
fn version_mismatch_reports_expected_and_actual_without_raw_output() {
    let (profile, root) = profile_and_root();
    let runner = FakeRunner::for_profile(&profile);
    runner
        .packages
        .lock()
        .expect("package lock")
        .get_mut("fixture-npu-firmware")
        .expect("package response")
        .as_mut()
        .expect("installed package")
        .version = "0:9.9.9-1.fc44".to_owned();

    let result = inspect(&profile, root.path(), &runner);
    let firmware = check(&result, "package.npu_firmware");
    assert_eq!(code(firmware), "PACKAGE_VERSION_MISMATCH");
    assert_eq!(firmware.details["expected_version"], "0:1.0.0-1.fc44");
    assert_eq!(firmware.details["actual_version"], "0:9.9.9-1.fc44");
    assert!(
        !serde_json::to_string(firmware)
            .expect("serialize")
            .contains("rpm:")
    );
}

#[test]
fn ownership_mismatch_and_symlinked_file_fail() {
    let (profile, root) = profile_and_root();
    let target = &profile.components["level_zero_loader"].provider.files[0];
    let runner = FakeRunner::for_profile(&profile);
    runner
        .owners
        .lock()
        .expect("owner lock")
        .insert(target.path.clone(), "fixture-wrong-owner".to_owned());
    let mismatch = inspect(&profile, root.path(), &runner);
    assert_eq!(
        code(check(&mismatch, "package.level_zero_loader")),
        "PACKAGE_OWNERSHIP_MISMATCH"
    );

    let runner = FakeRunner::for_profile(&profile);
    let host_path = root.path().join(
        Path::new(&target.path)
            .strip_prefix("/")
            .expect("absolute path"),
    );
    fs::remove_file(&host_path).expect("remove regular fixture");
    symlink("/dev/null", &host_path).expect("create fixture symlink");
    let symlinked = inspect(&profile, root.path(), &runner);
    assert_eq!(
        code(check(&symlinked, "package.level_zero_loader")),
        "PACKAGE_FILE_INVALID"
    );
}

#[test]
fn critical_file_digest_mismatch_fails() {
    let (mut profile, root) = profile_and_root();
    let private_path = profile.components["npu_compiler"].provider.files[0]
        .path
        .clone();
    profile
        .components
        .get_mut("npu_compiler")
        .expect("component")
        .provider
        .files[0]
        .sha256 = "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    let runner = FakeRunner::for_profile(&profile);
    let result = inspect(&profile, root.path(), &runner);
    assert_eq!(
        code(check(&result, "package.npu_compiler")),
        "PACKAGE_DIGEST_MISMATCH"
    );
    let public = serde_json::to_string(check(&result, "package.npu_compiler"))
        .expect("serialize diagnostic check");
    assert!(!public.contains(&private_path));
    assert!(!public.contains(EMPTY_SHA256));
    assert!(!public.contains("0000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn conflicting_installed_package_fails() {
    let (profile, root) = profile_and_root();
    let runner = FakeRunner::for_profile(&profile);
    runner.packages.lock().expect("package lock").insert(
        "fixture-conflicting-driver".to_owned(),
        Some(InstalledPackage {
            name: "fixture-conflicting-driver".to_owned(),
            version: "0:1.0-1".to_owned(),
            install_time: 101,
        }),
    );
    let result = inspect(&profile, root.path(), &runner);
    assert!(
        result.checks.iter().all(|check| {
            check.status == CheckStatus::Fail && code(check) == "PACKAGE_CONFLICT"
        })
    );
}

#[test]
fn duplicate_provider_query_is_deduplicated() {
    let (mut profile, root) = profile_and_root();
    let shared = profile.components["openvino_runtime"]
        .provider
        .package
        .clone();
    profile
        .components
        .get_mut("openvino_npu_plugin")
        .expect("component")
        .provider
        .package = shared.clone();
    let runner = FakeRunner::for_profile(&profile);
    let result = inspect(&profile, root.path(), &runner);
    assert!(
        result
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Pass)
    );
    let package_queries = runner
        .requests()
        .into_iter()
        .filter(|request| {
            request.args.first() == Some(&OsString::from("-q"))
                && request.args.last() == Some(&OsString::from(&shared))
        })
        .count();
    assert_eq!(package_queries, 1);
}

#[test]
fn dpkg_and_pacman_are_blocked_not_guessed() {
    let (mut profile, root) = profile_and_root();
    for manager in [PackageManager::Dpkg, PackageManager::Pacman] {
        profile.package_manager = manager;
        let runner = FakeRunner::for_profile(&profile);
        let result = inspect(&profile, root.path(), &runner);
        assert!(result.packages.is_empty());
        assert_eq!(result.checks.len(), 6);
        assert!(result.checks.iter().all(|check| {
            check.id.starts_with("package.")
                && check.status == CheckStatus::Blocked
                && code(check) == "PACKAGE_INSPECTOR_UNAVAILABLE"
                && check.summary == "Native provider matches the selected profile"
        }));
        assert!(runner.requests().is_empty());
    }
}

#[test]
fn rpm_arguments_are_atomic_and_never_use_shell() {
    let (profile, root) = profile_and_root();
    let runner = FakeRunner::for_profile(&profile);
    inspect(&profile, root.path(), &runner);

    for request in runner.requests() {
        assert_eq!(request.executable, Path::new("/usr/bin/rpm"));
        assert_eq!(request.timeout, Duration::from_secs(10));
        assert_eq!(request.stdout_limit, 65_536);
        assert_eq!(request.stderr_limit, 16_384);
        let args = request
            .args
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<_>>();
        assert_eq!(args.len(), 5);
        assert_eq!(args[1], OsStr::new("--qf"));
        assert_eq!(args[3], OsStr::new("--"));
        assert!(!args[4].is_empty());
        match args[0].to_str().expect("query mode") {
            "-q" => assert_eq!(args[2], OsStr::new(PACKAGE_FORMAT)),
            "-qf" => assert_eq!(args[2], OsStr::new(OWNER_FORMAT)),
            other => panic!("unexpected query mode: {other}"),
        }
    }
}

#[test]
fn rpm_timeout_or_malformed_output_is_structured() {
    let (profile, root) = profile_and_root();
    let runner = FakeRunner::for_profile(&profile);
    runner.forced.lock().expect("forced lock").insert(
        "fixture-npu-firmware".to_owned(),
        Err(ProcessError::Timeout),
    );
    let timed_out = inspect(&profile, root.path(), &runner);
    assert_eq!(
        code(check(&timed_out, "package.npu_firmware")),
        "PACKAGE_QUERY_FAILED"
    );

    runner.forced.lock().expect("forced lock").insert(
        "fixture-npu-firmware".to_owned(),
        Ok(output(
            Termination::Exit(0),
            b"arbitrary rpm prose\n".to_vec(),
        )),
    );
    let malformed = inspect(&profile, root.path(), &runner);
    let firmware = check(&malformed, "package.npu_firmware");
    assert_eq!(code(firmware), "PACKAGE_OUTPUT_INVALID");
    assert!(
        !serde_json::to_string(firmware)
            .expect("serialize")
            .contains("arbitrary rpm prose")
    );
}
