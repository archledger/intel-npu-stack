// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn serializes_debug_processing_without_reducing_build_jobs_or_dropping_checks() {
    let root = tempfile::tempdir().expect("fixture directory");
    let recorder = root.path().join("find-debuginfo");
    let arguments = root.path().join("arguments");
    fs::write(
        &recorder,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DEBUG_ARGS\"\n",
    )
    .expect("write argument recorder");
    fs::set_permissions(&recorder, fs::Permissions::from_mode(0o700)).expect("recorder mode");
    let production = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../packaging/fedora/44/rpm/openvino/openvino.spec");
    let mut contents = fs::read_to_string(production).expect("read real spec");
    contents.push_str("\n%{echo:DEBUG_COMMAND_BEGIN}\n%{echo:%{__debug_install_post}}\n%{echo:DEBUG_COMMAND_END}\n%{echo:BUILD_JOBS=%{_smp_build_ncpus}}\n");
    let spec = root.path().join("probe.spec");
    fs::write(&spec, contents).expect("write probed spec");
    let output = Command::new("/usr/bin/rpmspec")
        .args(["--define", "_smp_build_ncpus 10", "--define"])
        .arg(format!("__find_debuginfo {}", recorder.display()))
        .args(["--parse"])
        .arg(spec)
        .output()
        .expect("expand real RPM debug command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expanded = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(expanded.contains("BUILD_JOBS=10"));
    let command = expanded
        .split("DEBUG_COMMAND_BEGIN\n")
        .nth(1)
        .expect("expanded command start")
        .split("DEBUG_COMMAND_END")
        .next()
        .expect("expanded command end");
    let result = Command::new("/bin/sh")
        .args(["-ec", command])
        .env("DEBUG_ARGS", &arguments)
        .output()
        .expect("execute expanded command");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let args = fs::read_to_string(arguments).expect("captured debug arguments");
    let args: Vec<_> = args.lines().collect();
    let jobs: Vec<_> = args
        .iter()
        .filter_map(|arg| arg.strip_prefix("-j"))
        .collect();
    assert_eq!(jobs.first(), Some(&"10"), "normal build job expansion");
    assert_eq!(jobs.last(), Some(&"1"), "debug workers must be serialized");
    for required in [
        "--run-dwz",
        "--strict-build-id",
        "--unique-debug-suffix",
        "--unique-debug-src-base",
        "--dwz-low-mem-die-limit",
        "--dwz-max-die-limit",
    ] {
        assert!(args.contains(&required), "preserve debug option {required}");
    }
}
