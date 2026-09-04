// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{self, FileType, OpenOptions};
use std::path::Path;

use serde_json::{Value, json};
use stack_core::{CheckStatus, DiagnosticCheck, DiagnosticCommand, Requirement};

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceInspection {
    pub node_count: usize,
    pub checks: Vec<DiagnosticCheck>,
}

#[must_use]
pub fn inspect_devices(
    root: &Path,
    effective_root: bool,
    command: DiagnosticCommand,
) -> DeviceInspection {
    let directory = root.join("dev/accel");
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return missing_inspection();
        }
        Err(_) => return failed_inspection("DEVICE_ACCESS_FAILED"),
    };

    let mut candidates = Vec::new();
    let mut invalid_candidate = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return failed_inspection("DEVICE_ACCESS_FAILED"),
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_accel_name(name) {
            continue;
        }
        match fs::symlink_metadata(entry.path()) {
            Ok(metadata) if is_supported_node_type(&metadata.file_type()) => {
                candidates.push((name.to_owned(), entry.path()));
            }
            Ok(_) => invalid_candidate = true,
            Err(_) => invalid_candidate = true,
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    if candidates.is_empty() {
        return if invalid_candidate {
            failed_inspection("DEVICE_ACCESS_FAILED")
        } else {
            missing_inspection()
        };
    }

    let node_count = candidates.len();
    let node_check = check(
        "device.node",
        CheckStatus::Pass,
        "NPU accelerator device is present",
        Requirement::Required,
        details([("count", json!(node_count))]),
    );
    let access_requirement = if effective_root && command == DiagnosticCommand::Status {
        Requirement::Optional
    } else {
        Requirement::Required
    };
    let access_check = if effective_root {
        check(
            "device.access",
            CheckStatus::Blocked,
            "Normal-user NPU access is available",
            access_requirement,
            details([("error_code", json!("NORMAL_USER_REQUIRED"))]),
        )
    } else {
        let mut denied = false;
        let mut failed = false;
        let mut opened = false;
        for (_, path) in candidates {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => {
                    drop(file);
                    opened = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => denied = true,
                Err(_) => failed = true,
            }
        }
        if opened {
            check(
                "device.access",
                CheckStatus::Pass,
                "Normal-user NPU access is available",
                Requirement::Required,
                details([("count", json!(node_count))]),
            )
        } else {
            let error_code = if failed {
                "DEVICE_ACCESS_FAILED"
            } else if denied {
                "DEVICE_ACCESS_DENIED"
            } else {
                "DEVICE_ACCESS_FAILED"
            };
            check(
                "device.access",
                CheckStatus::Fail,
                "Normal-user NPU access is available",
                Requirement::Required,
                details([("error_code", json!(error_code))]),
            )
        }
    };

    DeviceInspection {
        node_count,
        checks: vec![node_check, access_check],
    }
}

fn missing_inspection() -> DeviceInspection {
    DeviceInspection {
        node_count: 0,
        checks: vec![
            check(
                "device.node",
                CheckStatus::Fail,
                "NPU accelerator device is present",
                Requirement::Required,
                details([("error_code", json!("DEVICE_NODE_MISSING"))]),
            ),
            check(
                "device.access",
                CheckStatus::Blocked,
                "Normal-user NPU access is available",
                Requirement::Required,
                details([("error_code", json!("DEVICE_NODE_MISSING"))]),
            ),
        ],
    }
}

fn failed_inspection(error_code: &'static str) -> DeviceInspection {
    DeviceInspection {
        node_count: 0,
        checks: vec![
            check(
                "device.node",
                CheckStatus::Fail,
                "NPU accelerator device is present",
                Requirement::Required,
                details([("error_code", json!(error_code))]),
            ),
            check(
                "device.access",
                CheckStatus::Fail,
                "Normal-user NPU access is available",
                Requirement::Required,
                details([("error_code", json!(error_code))]),
            ),
        ],
    }
}

fn is_accel_name(name: &str) -> bool {
    name.strip_prefix("accel").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(unix)]
fn is_supported_node_type(file_type: &FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;

    file_type.is_file() || file_type.is_char_device()
}

#[cfg(not(unix))]
fn is_supported_node_type(file_type: &FileType) -> bool {
    file_type.is_file()
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
