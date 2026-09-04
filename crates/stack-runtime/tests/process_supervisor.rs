// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use stack_runtime::{
    ProcessError, ProcessRequest, ProcessRunner, SystemProcessRunner, Termination,
};
use tempfile::TempDir;

fn script(root: &Path, name: &str, body: &str) -> PathBuf {
    let path = root.join(name);
    let draft = root.join(format!(".{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&draft)
        .expect("create fixture draft");
    file.write_all(format!("#!/bin/sh\nset -eu\n{body}\n").as_bytes())
        .expect("write fixture script");
    file.sync_all().expect("sync fixture script");
    drop(file);
    let mut permissions = fs::metadata(&draft).expect("script metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&draft, permissions).expect("make fixture executable");
    fs::rename(draft, &path).expect("publish fixture executable");
    File::open(root)
        .expect("open fixture directory")
        .sync_all()
        .expect("sync fixture directory");
    thread::sleep(Duration::from_millis(50));
    path
}

fn request(executable: impl Into<PathBuf>) -> ProcessRequest {
    ProcessRequest {
        executable: executable.into(),
        args: Vec::new(),
        timeout: Duration::from_secs(3),
        stdout_limit: 65_536,
        stderr_limit: 16_384,
    }
}

#[test]
fn reject_relative_executable() {
    let error = SystemProcessRunner
        .run(&request("relative-helper"))
        .expect_err("relative executable must be rejected");
    assert_eq!(error, ProcessError::InvalidExecutable);
}

#[test]
fn clear_environment_and_set_only_c_locale() {
    let output = SystemProcessRunner
        .run(&request("/usr/bin/env"))
        .expect("run environment inspection");
    assert_eq!(output.termination, Termination::Exit(0));
    assert_eq!(output.stdout, b"LC_ALL=C\n");
}

#[test]
fn capture_success_without_using_path_or_shell() {
    let fixture = TempDir::new().expect("temporary directory");
    let helper = script(fixture.path(), "success", "printf 'fixture-success'");
    let output = SystemProcessRunner
        .run(&request(helper))
        .expect("run exact fixture path");
    assert_eq!(output.termination, Termination::Exit(0));
    assert_eq!(output.stdout, b"fixture-success");
    assert!(!output.stdout_overflow);
    assert!(!output.stderr_overflow);
}

#[test]
fn classify_missing_executable() {
    let fixture = TempDir::new().expect("temporary directory");
    let error = SystemProcessRunner
        .run(&request(fixture.path().join("absent")))
        .expect_err("missing helper must fail");
    assert_eq!(error, ProcessError::Spawn);
}

#[test]
fn classify_nonzero_exit_and_signal() {
    let fixture = TempDir::new().expect("temporary directory");
    let nonzero = script(fixture.path(), "nonzero", "exit 7");
    let signal = script(fixture.path(), "signal", "kill -TERM $$");

    let exited = SystemProcessRunner
        .run(&request(nonzero))
        .expect("capture nonzero exit");
    assert_eq!(exited.termination, Termination::Exit(7));

    let signaled = SystemProcessRunner
        .run(&request(signal))
        .expect("capture signal");
    assert_eq!(signaled.termination, Termination::Signal);
}

#[test]
fn timeout_kills_and_reaps_child() {
    let fixture = TempDir::new().expect("temporary directory");
    let pid_file = fixture.path().join("pid");
    let helper = script(
        fixture.path(),
        "timeout",
        "printf '%s' \"$$\" > \"$1\"\nexec /usr/bin/sleep 5",
    );
    let mut request = request(helper);
    request.args = vec![OsString::from(&pid_file)];
    request.timeout = Duration::from_millis(100);

    let started = Instant::now();
    let error = SystemProcessRunner
        .run(&request)
        .expect_err("fixture must time out");
    assert_eq!(error, ProcessError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));

    let pid = fs::read_to_string(pid_file).expect("read fixture PID");
    assert!(pid.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "child survived timeout"
    );
}

#[test]
fn drain_large_stdout_and_stderr_without_deadlock() {
    let fixture = TempDir::new().expect("temporary directory");
    let helper = script(
        fixture.path(),
        "large-output",
        "i=0\nwhile [ \"$i\" -lt 8192 ]; do printf '0123456789abcdef'; printf 'fedcba9876543210' >&2; i=$((i + 1)); done",
    );
    let output = SystemProcessRunner
        .run(&request(helper))
        .expect("large output must drain");
    assert_eq!(output.termination, Termination::Exit(0));
    assert_eq!(output.stdout.len(), 65_536);
    assert!(output.stdout_overflow);
    assert!(output.stderr_overflow);
}

#[test]
fn mark_stdout_and_stderr_overflow() {
    let fixture = TempDir::new().expect("temporary directory");
    let helper = script(
        fixture.path(),
        "small-limits",
        "printf '12345'; printf 'abcdef' >&2",
    );
    let mut request = request(helper);
    request.stdout_limit = 4;
    request.stderr_limit = 5;
    let output = SystemProcessRunner
        .run(&request)
        .expect("overflow fixture must run");
    assert_eq!(output.stdout, b"1234");
    assert!(output.stdout_overflow);
    assert!(output.stderr_overflow);
}

#[test]
fn stdin_is_null() {
    let fixture = TempDir::new().expect("temporary directory");
    let helper = script(
        fixture.path(),
        "stdin",
        "if read -r line; then exit 8; fi\nprintf 'closed'",
    );
    let output = SystemProcessRunner
        .run(&request(helper))
        .expect("run stdin fixture");
    assert_eq!(output.termination, Termination::Exit(0));
    assert_eq!(output.stdout, b"closed");
}
