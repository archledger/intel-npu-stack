// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde_json::{Value, json};
use stack_core::{CheckStatus, DiagnosticCheck, Requirement};
use stack_schema::{ActivationRequirement, Profile};

use crate::InstalledPackage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusyCounters {
    names: Vec<String>,
    values: Vec<u128>,
}

impl BusyCounters {
    #[must_use]
    pub fn values(&self) -> &[u128] {
        &self.values
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusyCounterSnapshot {
    Counters(BusyCounters),
    Absent,
    Unavailable,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationState {
    Ready,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationInspection {
    pub state: ActivationState,
    pub reboot_required: bool,
    pub relogin_required: bool,
    pub error_code: Option<&'static str>,
}

#[must_use]
pub fn read_busy_counters(root: &Path) -> BusyCounterSnapshot {
    let entries = match fs::read_dir(root.join("sys/class/accel")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return BusyCounterSnapshot::Absent;
        }
        Err(_) => return BusyCounterSnapshot::Unavailable,
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return BusyCounterSnapshot::Unavailable,
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_accel_name(name) {
            paths.push((
                name.to_owned(),
                entry.path().join("device/npu_busy_time_us"),
            ));
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    if paths.is_empty() {
        return BusyCounterSnapshot::Absent;
    }

    let mut names = Vec::new();
    let mut values = Vec::new();
    let mut missing = 0_usize;
    for (name, path) in paths {
        match read_counter(&path) {
            Ok(Some(value)) => {
                names.push(name);
                values.push(value);
            }
            Ok(None) => missing += 1,
            Err(CounterError::Unavailable) => return BusyCounterSnapshot::Unavailable,
            Err(CounterError::Invalid) => return BusyCounterSnapshot::Invalid,
        }
    }
    if values.is_empty() {
        BusyCounterSnapshot::Absent
    } else if missing != 0 {
        BusyCounterSnapshot::Unavailable
    } else {
        BusyCounterSnapshot::Counters(BusyCounters { names, values })
    }
}

#[must_use]
pub fn evaluate_activity(
    before: &BusyCounterSnapshot,
    after: &BusyCounterSnapshot,
) -> DiagnosticCheck {
    let result = match (before, after) {
        (BusyCounterSnapshot::Invalid, _) | (_, BusyCounterSnapshot::Invalid) => {
            Err("ACTIVITY_COUNTER_INVALID")
        }
        (BusyCounterSnapshot::Counters(before), BusyCounterSnapshot::Counters(after))
            if before.names == after.names =>
        {
            let mut delta = 0_u128;
            for (before, after) in before.values.iter().zip(&after.values) {
                if after < before {
                    return activity_warning("ACTIVITY_COUNTER_DECREASED");
                }
                let Some(next) = delta.checked_add(after - before) else {
                    return activity_warning("ACTIVITY_COUNTER_INVALID");
                };
                delta = next;
            }
            if delta == 0 {
                Err("ACTIVITY_NOT_OBSERVED")
            } else {
                u64::try_from(delta).map_err(|_| "ACTIVITY_COUNTER_INVALID")
            }
        }
        _ => Err("ACTIVITY_COUNTER_UNAVAILABLE"),
    };
    match result {
        Ok(delta) => DiagnosticCheck {
            id: "runtime.activity".to_owned(),
            status: CheckStatus::Pass,
            summary: "NPU activity was observed during inference".to_owned(),
            details: details([("busy_time_delta", json!(delta))]),
            requirement: Requirement::Optional,
        },
        Err(code) => activity_warning(code),
    }
}

#[must_use]
pub fn inspect_activation(
    profile: &Profile,
    packages: &BTreeMap<String, InstalledPackage>,
    boot_time_epoch: Option<u64>,
) -> ActivationInspection {
    let reboot_providers = profile
        .components
        .values()
        .filter(|component| component.provider.activation == ActivationRequirement::Reboot)
        .collect::<Vec<_>>();
    if reboot_providers.is_empty() {
        return activation_ready(false);
    }
    let Some(boot_time_epoch) = boot_time_epoch else {
        return activation_unknown();
    };
    let mut reboot_required = false;
    for component in reboot_providers {
        let Some(package) = packages.get(&component.provider.package) else {
            return activation_unknown();
        };
        if package.version != component.provider.version {
            return activation_unknown();
        }
        reboot_required |= package.install_time > boot_time_epoch;
    }
    activation_ready(reboot_required)
}

fn activation_ready(reboot_required: bool) -> ActivationInspection {
    ActivationInspection {
        state: ActivationState::Ready,
        reboot_required,
        relogin_required: false,
        error_code: None,
    }
}

fn activation_unknown() -> ActivationInspection {
    ActivationInspection {
        state: ActivationState::Unknown,
        reboot_required: false,
        relogin_required: false,
        error_code: Some("ACTIVATION_STATE_UNKNOWN"),
    }
}

fn activity_warning(error_code: &'static str) -> DiagnosticCheck {
    DiagnosticCheck {
        id: "runtime.activity".to_owned(),
        status: CheckStatus::Warn,
        summary: "NPU activity was observed during inference".to_owned(),
        details: details([("error_code", json!(error_code))]),
        requirement: Requirement::Optional,
    }
}

enum CounterError {
    Unavailable,
    Invalid,
}

fn read_counter(path: &Path) -> Result<Option<u128>, CounterError> {
    const LIMIT: usize = 128;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CounterError::Unavailable),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CounterError::Unavailable)?;
    if bytes.len() > LIMIT {
        return Err(CounterError::Invalid);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| CounterError::Invalid)?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CounterError::Invalid);
    }
    value.parse().map(Some).map_err(|_| CounterError::Invalid)
}

fn is_accel_name(name: &str) -> bool {
    name.strip_prefix("accel").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn details<const N: usize>(values: [(&str, Value); N]) -> BTreeMap<String, Value> {
    values
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}
