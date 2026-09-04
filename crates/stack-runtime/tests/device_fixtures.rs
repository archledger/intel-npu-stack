// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use stack_core::{CheckStatus, DiagnosticCommand, Requirement};
use stack_runtime::{DeviceInspection, inspect_devices};
use tempfile::TempDir;

fn accel_dir(root: &Path) -> std::path::PathBuf {
    let directory = root.join("dev/accel");
    fs::create_dir_all(&directory).expect("create accelerator directory");
    directory
}

fn check<'a>(inspection: &'a DeviceInspection, id: &str) -> &'a stack_core::DiagnosticCheck {
    inspection
        .checks
        .iter()
        .find(|check| check.id == id)
        .expect("device check exists")
}

#[test]
fn enumerate_only_direct_accel_decimal_names() {
    let root = TempDir::new().expect("temporary root");
    let directory = accel_dir(root.path());
    for name in ["accel0", "accel12", "accel", "accelA", "render0"] {
        fs::write(directory.join(name), b"preserve").expect("write node fixture");
    }
    fs::create_dir_all(directory.join("nested")).expect("create nested directory");
    fs::write(directory.join("nested/accel2"), b"nested").expect("write nested fixture");

    let result = inspect_devices(root.path(), false, DiagnosticCommand::Status);
    assert_eq!(result.node_count, 2);
    assert_eq!(check(&result, "device.node").status, CheckStatus::Pass);
    assert_eq!(check(&result, "device.node").details["count"], 2);
    assert_eq!(check(&result, "device.access").status, CheckStatus::Pass);
}

#[test]
fn reject_symlinked_device_node() {
    let root = TempDir::new().expect("temporary root");
    let directory = accel_dir(root.path());
    fs::write(root.path().join("target"), b"target").expect("write target");
    symlink(root.path().join("target"), directory.join("accel0")).expect("create symlink");

    let result = inspect_devices(root.path(), false, DiagnosticCommand::Doctor);
    assert_eq!(result.node_count, 0);
    assert_eq!(check(&result, "device.node").status, CheckStatus::Fail);
    assert_eq!(
        check(&result, "device.node").details["error_code"],
        "DEVICE_ACCESS_FAILED"
    );
}

#[test]
fn reject_non_device_special_file_without_opening() {
    let root = TempDir::new().expect("temporary root");
    let fifo_path = accel_dir(root.path()).join("accel0");
    let status = Command::new("/usr/bin/mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("create FIFO fixture");
    assert!(status.success());

    let result = inspect_devices(root.path(), false, DiagnosticCommand::Doctor);
    assert_eq!(result.node_count, 0);
    assert_eq!(check(&result, "device.node").status, CheckStatus::Fail);
    assert!(fifo_path.exists());
}

#[test]
fn open_read_write_without_create_or_truncate() {
    let root = TempDir::new().expect("temporary root");
    let directory = accel_dir(root.path());
    let node = directory.join("accel0");
    fs::write(&node, b"must remain unchanged").expect("write fixture node");

    let result = inspect_devices(root.path(), false, DiagnosticCommand::Doctor);
    assert_eq!(check(&result, "device.access").status, CheckStatus::Pass);
    assert_eq!(
        fs::read(node).expect("read fixture node"),
        b"must remain unchanged"
    );
    assert_eq!(fs::read_dir(directory).expect("read directory").count(), 1);
}

#[test]
fn distinguish_missing_denied_and_other_device_errors() {
    let missing_root = TempDir::new().expect("temporary root");
    let missing = inspect_devices(missing_root.path(), false, DiagnosticCommand::Doctor);
    assert_eq!(
        check(&missing, "device.node").details["error_code"],
        "DEVICE_NODE_MISSING"
    );

    let denied_root = TempDir::new().expect("temporary root");
    let denied_node = accel_dir(denied_root.path()).join("accel0");
    fs::write(&denied_node, []).expect("write denied fixture");
    fs::set_permissions(&denied_node, fs::Permissions::from_mode(0o000))
        .expect("deny fixture access");
    let denied = inspect_devices(denied_root.path(), false, DiagnosticCommand::Doctor);
    assert_eq!(
        check(&denied, "device.access").details["error_code"],
        "DEVICE_ACCESS_DENIED"
    );

    let other_root = TempDir::new().expect("temporary root");
    fs::create_dir_all(accel_dir(other_root.path()).join("accel0")).expect("create non-file node");
    let other = inspect_devices(other_root.path(), false, DiagnosticCommand::Doctor);
    assert_eq!(
        check(&other, "device.access").details["error_code"],
        "DEVICE_ACCESS_FAILED"
    );
}

#[test]
fn root_doctor_access_is_blocked() {
    let root = TempDir::new().expect("temporary root");
    fs::write(accel_dir(root.path()).join("accel0"), []).expect("write fixture node");

    let doctor = inspect_devices(root.path(), true, DiagnosticCommand::Doctor);
    let access = check(&doctor, "device.access");
    assert_eq!(access.status, CheckStatus::Blocked);
    assert_eq!(access.requirement, Requirement::Required);
    assert_eq!(access.details["error_code"], "NORMAL_USER_REQUIRED");

    let status = inspect_devices(root.path(), true, DiagnosticCommand::Status);
    assert_eq!(
        check(&status, "device.access").requirement,
        Requirement::Optional
    );
}
