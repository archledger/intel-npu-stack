// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::Value;
use stack_cli::{AppContext, run};
use stack_platform::PlatformPaths;
use stack_runtime::RuntimePaths;
use tempfile::TempDir;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const COMPONENTS: [&str; 6] = [
    "npu_firmware",
    "level_zero_loader",
    "npu_userspace_driver",
    "npu_compiler",
    "openvino_runtime",
    "openvino_npu_plugin",
];

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture path has parent"))
        .expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}

fn write_executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("executable path has parent"))
        .expect("create executable parent");
    fs::write(path, contents).expect("write executable fixture");
    let mut permissions = fs::metadata(path)
        .expect("stat executable fixture")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("mark fixture executable");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\"'\"'"))
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
    for name in COMPONENTS {
        components.push_str(&format!(
            "\n[components.{name}]\nversion = \"1.0.0\"\nsource = \"https://example.invalid/{name}\"\nsha256 = \"{HASH}\"\n\n[components.{name}.provider]\npackage = \"fixture-{name}\"\nversion = \"0:1.0.0-1.fc44\"\nactivation = \"immediate\"\n\n[[components.{name}.provider.files]]\npath = \"/usr/lib64/{name}.fixture.so\"\nsha256 = \"{EMPTY_HASH}\"\n\n[components.{name}.license]\nexpression = \"Apache-2.0\"\nredistribution = \"allowed\"\nevidence_sha256 = \"{HASH}\"\n"
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
    root: TempDir,
    context: AppContext,
    level_zero_marker: PathBuf,
    openvino_marker: PathBuf,
    environment_marker: PathBuf,
    activity_counter: PathBuf,
}

impl Fixture {
    fn new(profile: Option<&str>) -> Self {
        let root = tempfile::tempdir().expect("create CLI fixture");
        let platform_root = root.path().join("platform");
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
            "platform/proc/self/status",
            "Name:\tfixture\nUid:\t1000\t1000\t1000\t1000\n",
        );
        write(
            root.path(),
            "platform/proc/stat",
            "cpu 1 2 3 4\nbtime 1700000000\n",
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
        let activity_counter = platform_root.join("sys/class/accel/accel0/device/npu_busy_time_us");
        write(
            root.path(),
            "platform/sys/class/accel/accel0/device/npu_busy_time_us",
            "1\n",
        );
        for component in COMPONENTS {
            write(
                root.path(),
                &format!("platform/usr/lib64/{component}.fixture.so"),
                "",
            );
        }

        let profile_dir = root.path().join("profiles");
        fs::create_dir(&profile_dir).expect("create profile directory");
        if let Some(profile) = profile {
            write(root.path(), "profiles/test.toml", profile);
        }

        let level_zero_marker = root.path().join("markers/level-zero");
        let openvino_marker = root.path().join("markers/openvino");
        let environment_marker = root.path().join("markers/environment");
        fs::create_dir(root.path().join("markers")).expect("create marker directory");
        let level_zero_helper = root.path().join("bin/level-zero-probe");
        let openvino_helper = root.path().join("bin/openvino-probe");
        let rpm = root.path().join("bin/rpm");

        write_executable(
            &level_zero_helper,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> {}\nprintf '%s|%s|%s\\n' \"${{PATH-unset}}\" \"${{HOME-unset}}\" \"${{LC_ALL-unset}}\" > {}\nprintf '%s\\n' 'private-helper-stderr' >&2\nprintf '%s\\n' '{{\"schema_version\":1,\"probe\":\"level_zero\",\"mode\":\"enumerate\",\"outcome\":\"pass\",\"observations\":{{\"vpu_devices\":[{{\"vendor_id\":\"8086\",\"device_id\":\"abcd\",\"driver_version\":1}}]}},\"error_code\":null}}'\n",
                shell_quote(&level_zero_marker),
                shell_quote(&environment_marker),
            ),
        );
        write_executable(
            &openvino_helper,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> {}\nprintf '%s\\n' 'private-openvino-stderr' >&2\nif [ \"$1\" = infer ]; then\n  printf '2\\n' > {}\n  printf '%s\\n' '{{\"schema_version\":1,\"probe\":\"openvino\",\"mode\":\"infer\",\"outcome\":\"pass\",\"observations\":{{\"available_devices\":[\"CPU\",\"NPU\"],\"execution_devices\":[\"NPU\"],\"runtime_version\":\"2026.2.0\",\"graph_id\":\"intel-npu-stack-neutral-v1\",\"iterations\":8,\"tolerance\":0.001}},\"error_code\":null}}'\nelse\n  printf '%s\\n' '{{\"schema_version\":1,\"probe\":\"openvino\",\"mode\":\"enumerate\",\"outcome\":\"pass\",\"observations\":{{\"available_devices\":[\"CPU\",\"NPU\"],\"runtime_version\":\"2026.2.0\"}},\"error_code\":null}}'\nfi\n",
                shell_quote(&openvino_marker),
                shell_quote(&activity_counter),
            ),
        );
        write_executable(&rpm, &rpm_script());

        let context = AppContext {
            platform_paths: PlatformPaths {
                root: platform_root.clone(),
            },
            profile_dir,
            arch: "x86_64".to_owned(),
            runtime_paths: RuntimePaths {
                root: platform_root,
                level_zero_helper,
                openvino_helper,
                rpm,
            },
        };
        Self {
            root,
            context,
            level_zero_marker,
            openvino_marker,
            environment_marker,
            activity_counter,
        }
    }

    fn helper_invocations(&self) -> (String, String) {
        (
            fs::read_to_string(&self.level_zero_marker).unwrap_or_default(),
            fs::read_to_string(&self.openvino_marker).unwrap_or_default(),
        )
    }

    fn reset_activity(&self) {
        fs::write(&self.activity_counter, "1\n").expect("reset activity counter");
    }

    fn replace_level_zero(&self, report: &str) {
        write_executable(
            &self.context.runtime_paths.level_zero_helper,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> {}\nprintf '%s\\n' '{}'\n",
                shell_quote(&self.level_zero_marker),
                report
            ),
        );
    }

    fn replace_openvino(&self, report: &str) {
        write_executable(
            &self.context.runtime_paths.openvino_helper,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> {}\nprintf '%s\\n' '{}'\n",
                shell_quote(&self.openvino_marker),
                report
            ),
        );
    }
}

fn rpm_script() -> String {
    let mut owners = String::new();
    for component in COMPONENTS {
        owners.push_str(&format!(
            "    /usr/lib64/{component}.fixture.so) printf '%s\\n' 'fixture-{component}' ;;\n"
        ));
    }
    format!(
        "#!/bin/sh\nlast=\nfor argument do last=$argument; done\nif [ \"$1\" = -qf ]; then\n  case \"$last\" in\n{owners}    *) exit 1 ;;\n  esac\nelse\n  case \"$last\" in\n    fixture-conflicting-driver) exit 1 ;;\n    fixture-*) printf '%s\\t%s\\t%s\\n' \"$last\" '0:1.0.0-1.fc44' '1600000000' ;;\n    *) exit 1 ;;\n  esac\nfi\n"
    )
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

fn json_checks(value: &Value) -> BTreeMap<String, String> {
    value["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .map(|check| {
            (
                check["id"].as_str().expect("check id").to_owned(),
                check["status"].as_str().expect("check status").to_owned(),
            )
        })
        .collect()
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
fn status_never_invokes_openvino_infer() {
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    let (code, _, stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);
    let (level_zero, openvino) = fixture.helper_invocations();

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(level_zero, "enumerate\n");
    assert_eq!(openvino, "enumerate\n");
    assert!(!openvino.contains("infer"));
    assert_eq!(stderr, "");
}

#[test]
fn status_success_emits_exact_version_one_json() {
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("one JSON value");
    let keys = value
        .as_object()
        .expect("report object")
        .keys()
        .collect::<Vec<_>>();
    let checks = json_checks(&value);

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(
        keys,
        vec![
            "checks",
            "command",
            "overall",
            "platform",
            "profile",
            "reboot_required",
            "relogin_required",
            "schema_version",
            "tool_version",
        ]
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool_version"], "0.1.0");
    assert_eq!(value["command"], "status");
    assert_eq!(value["overall"], "passed");
    assert_eq!(value["profile"]["id"], "testos-profile");
    assert_eq!(checks["runtime.level_zero"], "pass");
    assert_eq!(checks["runtime.openvino"], "pass");
    assert!(!checks.contains_key("runtime.inference"));
    assert!(!checks.contains_key("runtime.activity"));
    assert!(stdout.ends_with('\n'));
    assert_eq!(stderr, "");
}

#[test]
fn doctor_success_requires_direct_npu_inference() {
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("one JSON value");
    let checks = json_checks(&value);
    let inference = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "runtime.inference")
        .expect("inference check");

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(value["overall"], "passed");
    assert_eq!(checks["runtime.inference"], "pass");
    assert_eq!(
        inference["details"]["execution_devices"],
        serde_json::json!(["NPU"])
    );
    assert_eq!(inference["details"]["iterations"], 8);
    assert_eq!(fixture.helper_invocations().1, "infer\n");
    assert_eq!(stderr, "");
}

#[test]
fn doctor_failure_matrix_preserves_exit_one() {
    let cases = [
        (
            "level_zero",
            r#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"fail","observations":{},"error_code":"LEVEL_ZERO_NO_VPU"}"#,
            "LEVEL_ZERO_NO_VPU",
        ),
        (
            "openvino",
            r#"{"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":"OPENVINO_WRONG_DEVICE"}"#,
            "OPENVINO_WRONG_DEVICE",
        ),
    ];
    for (probe, report, expected_code) in cases {
        let fixture = Fixture::new(Some(&profile_toml("qualified")));
        if probe == "level_zero" {
            fixture.replace_level_zero(report);
        } else {
            fixture.replace_openvino(report);
        }
        let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
        let value: Value = serde_json::from_str(&stdout).expect("one JSON value");

        assert_eq!(code, ExitCode::from(1), "case {probe}");
        assert_eq!(value["overall"], "failed", "case {probe}");
        assert!(stdout.contains(expected_code), "case {probe}: {stdout}");
        assert_eq!(stderr, "");
    }
}

#[test]
fn invalid_installed_profile_stops_before_helpers_with_exit_two() {
    let fixture = Fixture::new(Some("not = [valid TOML"));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);

    assert_eq!(code, ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("test.toml"));
    assert!(stderr.contains("PROFILE_TOML_INVALID"));
    assert_eq!(fixture.helper_invocations(), (String::new(), String::new()));
}

#[test]
fn no_compatible_profile_does_not_run_helpers() {
    let fixture = Fixture::new(None);
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("one JSON value");

    assert_eq!(code, ExitCode::from(1));
    assert_eq!(value["overall"], "failed");
    assert_eq!(fixture.helper_invocations(), (String::new(), String::new()));
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
fn root_doctor_cannot_claim_normal_user_access() {
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    write(
        fixture.root.path(),
        "platform/proc/self/status",
        "Name:\tfixture\nUid:\t0\t0\t0\t0\n",
    );
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("one JSON value");
    let access = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "device.access")
        .expect("device access check");

    assert_eq!(code, ExitCode::from(1));
    assert_eq!(access["status"], "blocked");
    assert_eq!(access["details"]["error_code"], "NORMAL_USER_REQUIRED");
    assert_ne!(value["overall"], "passed");
    assert_eq!(stderr, "");
}

#[test]
fn reboot_and_activity_states_render_truthfully() {
    let profile = profile_toml("qualified").replacen(
        "activation = \"immediate\"",
        "activation = \"reboot\"",
        1,
    );
    let fixture = Fixture::new(Some(&profile));
    write(
        fixture.root.path(),
        "platform/proc/stat",
        "cpu 1 2 3 4\nbtime 1500000000\n",
    );
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    let value: Value = serde_json::from_str(&stdout).expect("one JSON value");
    let activity = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "runtime.activity")
        .expect("activity check");

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(value["reboot_required"], true);
    assert_eq!(value["relogin_required"], false);
    assert_eq!(activity["status"], "pass");
    assert_eq!(activity["details"]["busy_time_delta"], 1);
    assert_eq!(stderr, "");
}

#[test]
fn human_and_json_modes_contain_equivalent_checks() {
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    let (human_code, human, human_stderr) = invoke(&fixture, &["intel-npu-stack", "status"]);
    let (json_code, json, json_stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);
    let value: Value = serde_json::from_str(&json).expect("one JSON value");
    let human_checks = human
        .lines()
        .filter_map(|line| {
            let (id, remainder) = line.split_once(" [")?;
            let (status, _) = remainder.split_once("]: ")?;
            Some((id.to_owned(), status.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(human_code, json_code);
    assert_eq!(human_checks, json_checks(&value));
    assert_eq!(human_stderr, "");
    assert_eq!(json_stderr, "");
}

#[test]
fn native_stderr_and_environment_never_reach_output() {
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    let (code, stdout, stderr) = invoke(&fixture, &["intel-npu-stack", "status", "--json"]);
    let environment = fs::read_to_string(&fixture.environment_marker).expect("environment marker");
    let fields = environment.trim_end().split('|').collect::<Vec<_>>();

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[1], "unset");
    assert_eq!(fields[2], "C");
    assert!(!stdout.contains("private-helper-stderr"));
    assert!(!stdout.contains("private-openvino-stderr"));
    assert!(!stdout.contains(&fixture.root.path().display().to_string()));
    assert_eq!(stderr, "");
}

#[test]
fn experimental_channel_requires_accept_experimental_risk() {
    let fixture = Fixture::new(Some(&profile_toml("experimental")));
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
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
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
    let fixture = Fixture::new(Some(&profile_toml("qualified")));
    let (_, first, _) = invoke(&fixture, &["intel-npu-stack", "doctor", "--json"]);
    fixture.reset_activity();
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

#[test]
fn symlinked_profile_returns_exit_two() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(None);
    let external = fixture.root.path().join("external.toml");
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
