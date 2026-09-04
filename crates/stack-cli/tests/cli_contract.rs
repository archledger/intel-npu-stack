// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;
use stack_cli::{AppContext, run};
use stack_platform::PlatformPaths;
use tempfile::TempDir;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture path has parent"))
        .expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}

fn profile_toml(status: &str) -> String {
    let qualification = if status == "qualified" {
        format!(
            r#"
[qualification]
evidence_id = "fixture-evidence-001"
evidence_sha256 = "{HASH}"
qualified_at = "2026-09-03T19:00:00Z"
hardware_class = "fixture-lunar-lake-class"
test_suite_version = "fixture-suite-v1"
"#
        )
    } else {
        String::new()
    };
    let mut components = String::new();
    for name in [
        "npu_firmware",
        "level_zero_loader",
        "npu_userspace_driver",
        "npu_compiler",
        "openvino_runtime",
        "openvino_npu_plugin",
    ] {
        components.push_str(&format!(
            "\n[components.{name}]\nversion = \"1.0.0\"\nsource = \"https://example.invalid/{name}\"\nsha256 = \"{HASH}\"\n\n[components.{name}.provider]\npackage = \"fixture-{name}\"\nversion = \"0:1.0.0-1.fc44\"\nactivation = \"immediate\"\n\n[[components.{name}.provider.files]]\npath = \"/usr/lib64/{name}.fixture.so\"\nsha256 = \"{HASH}\"\n\n[components.{name}.license]\nexpression = \"Apache-2.0\"\nredistribution = \"allowed\"\nevidence_sha256 = \"{HASH}\"\n"
        ));
    }
    format!(
        r#"schema_version = 1
id = "testos-profile"
stack_release = "0.1.0"
status = "{status}"
package_manager = "rpm"

[[conflicts]]
package = "fixture-conflicting-driver"
resolution = "remove"

[platform]
id = "testos"
version_id = "1"
arch = "x86_64"

[[hardware]]
vendor = "8086"
device = "abcd"

[kernel]
min = "6.10.0"
max_exclusive = "6.20.0"
module = "intel_vpu"
{components}{qualification}"#
    )
}

struct Fixture {
    _root: TempDir,
    context: AppContext,
}

impl Fixture {
    fn new(profile: Option<&str>) -> Self {
        let root = tempfile::tempdir().expect("create CLI fixture");
        write(
            root.path(),
            "platform/etc/os-release",
            "ID=testos\nVERSION_ID=1\n",
        );
        write(
            root.path(),
            "platform/proc/sys/kernel/osrelease",
            "6.17.3-testos\n",
        );
        write(
            root.path(),
            "platform/proc/modules",
            "intel_vpu 1 0 - Live 0x0\n",
        );
        write(
            root.path(),
            "platform/sys/bus/pci/devices/0000:00:0b.0/vendor",
            "0x8086\n",
        );
        write(
            root.path(),
            "platform/sys/bus/pci/devices/0000:00:0b.0/device",
            "0xabcd\n",
        );
        write(root.path(), "platform/dev/accel/accel0", "");
        let profile_dir = root.path().join("profiles");
        fs::create_dir(&profile_dir).expect("create profile directory");
        if let Some(profile) = profile {
            write(root.path(), "profiles/test.toml", profile);
        }

        let context = AppContext {
            platform_paths: PlatformPaths {
                root: root.path().join("platform"),
            },
            profile_dir,
            arch: "x86_64".to_owned(),
        };
        Self {
            _root: root,
            context,
        }
    }
}

fn invoke(fixture: &Fixture, args: &[&str]) -> (ExitCode, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        args.iter().map(OsString::from),
        &fixture.context,
        &mut stdout,
        &mut stderr,
    );
    (
        code,
        String::from_utf8(stdout).expect("stdout must be UTF-8"),
        String::from_utf8(stderr).expect("stderr must be UTF-8"),
    )
}

#[test]
fn version_prints_only_the_package_version() {
    let fixture = Fixture::new(None);
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "version"]);
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(stdout, "0.1.0\n");
    assert_eq!(stderr, "");
}

#[test]
fn status_human_reports_no_compatible_profile() {
    let fixture = Fixture::new(None);
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status"]);
    assert_eq!(code, ExitCode::from(1));
    assert!(stdout.contains("overall: failed\n"));
    assert!(stdout.contains("platform.profile [fail]: Compatible platform profile is selected"));
    assert_eq!(stderr, "");
}

#[test]
fn status_json_matches_schema_version_one() {
    let profile = profile_toml("qualified");
    let fixture = Fixture::new(Some(&profile));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("stdout must be one JSON value");

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool_version"], "0.1.0");
    assert_eq!(value["command"], "status");
    assert_eq!(value["profile"]["id"], "testos-profile");
    assert_eq!(value["profile"]["stack_release"], "0.1.0");
    assert_eq!(value["profile"]["status"], "qualified");
    assert_eq!(value["reboot_required"], false);
    assert_eq!(value["relogin_required"], false);
    assert_eq!(value["overall"], "passed");
    assert_eq!(stderr, "");
    assert!(stdout.ends_with('\n'));
}

#[test]
fn doctor_is_honestly_blocked_before_runtime_probe_exists() {
    let profile = profile_toml("qualified");
    let fixture = Fixture::new(Some(&profile));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor"]);
    assert_eq!(code, ExitCode::from(1));
    assert!(stdout.contains("overall: blocked\n"));
    assert!(stdout.contains("runtime.level_zero [blocked]"));
    assert!(stdout.contains("runtime.openvino [blocked]"));
    assert!(!stdout.contains("NPU works"));
    assert_eq!(stderr, "");
}

#[test]
fn doctor_json_contains_two_blocked_runtime_checks() {
    let profile = profile_toml("qualified");
    let fixture = Fixture::new(Some(&profile));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("stdout must be one JSON value");
    let runtime = value["checks"]
        .as_array()
        .expect("checks must be an array")
        .iter()
        .filter(|check| check["id"] == "runtime.level_zero" || check["id"] == "runtime.openvino")
        .collect::<Vec<_>>();

    assert_eq!(code, ExitCode::from(1));
    assert_eq!(value["overall"], "blocked");
    assert_eq!(runtime.len(), 2);
    assert!(runtime.iter().all(|check| check["status"] == "blocked"));
    assert!(runtime.iter().all(|check| check.get("required").is_none()));
    assert!(runtime.iter().all(|check| check.get("message").is_none()));
    assert_eq!(runtime[0].as_object().expect("check object").len(), 4);
    assert_eq!(stderr, "");
}

#[test]
fn malformed_profile_returns_exit_two_without_panic() {
    let fixture = Fixture::new(Some("not = [valid TOML"));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("test.toml"));
    assert!(stderr.contains("PROFILE_TOML_INVALID"));
}

#[test]
fn experimental_channel_requires_accept_experimental_risk() {
    let profile = profile_toml("experimental");
    let fixture = Fixture::new(Some(&profile));
    let (code, stdout, stderr) = invoke(
        &fixture,
        &["intel-npu-stack", "status", "--channel", "experimental"],
    );
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("--accept-experimental-risk"));

    let (code, stdout, stderr) = invoke(
        &fixture,
        &[
            "intel-npu-stack",
            "status",
            "--channel",
            "experimental",
            "--accept-experimental-risk",
            "--json",
        ],
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(
        serde_json::from_str::<Value>(&stdout).unwrap()["overall"],
        "passed"
    );
    assert_eq!(stderr, "");
}

#[test]
fn stable_channel_rejects_accept_experimental_risk() {
    let profile = profile_toml("qualified");
    let fixture = Fixture::new(Some(&profile));
    let (code, stdout, stderr) = invoke(
        &fixture,
        &["intel-npu-stack", "status", "--accept-experimental-risk"],
    );
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("only valid with --channel experimental"));
}

#[test]
fn json_output_is_deterministic_and_sanitized() {
    let profile = profile_toml("qualified");
    let fixture = Fixture::new(Some(&profile));
    let (_, first, _) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    let (_, second, _) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    assert_eq!(first, second);
    for forbidden in [
        "hostname",
        "username",
        "serial",
        "mac",
        "ip_address",
        "bus_address",
        "0000:00:0b.0",
        &fixture.context.platform_paths.root.display().to_string(),
    ] {
        assert!(!first.contains(forbidden), "leaked value: {forbidden}");
    }
}

#[cfg(unix)]
#[test]
fn symlinked_profile_returns_exit_two() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(None);
    let external = fixture._root.path().join("external.toml");
    fs::write(&external, profile_toml("qualified")).expect("write external profile");
    symlink(&external, fixture.context.profile_dir.join("linked.toml"))
        .expect("create profile symlink");

    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status"]);
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("linked.toml"));
    assert!(stderr.contains("symlink"));
}

#[test]
fn help_and_unknown_command_follow_clap_exit_semantics() {
    let fixture = Fixture::new(None);
    let (help_code, help_stdout, help_stderr) = invoke(&fixture, &["intel-npu-stack", "--help"]);
    assert_eq!(help_code, ExitCode::SUCCESS);
    assert!(help_stdout.contains("Usage:"));
    assert_eq!(help_stderr, "");

    let (bad_code, bad_stdout, bad_stderr) = invoke(&fixture, &["intel-npu-stack", "unknown"]);
    assert_eq!(bad_code, ExitCode::from(2));
    assert_eq!(bad_stdout, "");
    assert!(bad_stderr.contains("unrecognized subcommand"));
}
