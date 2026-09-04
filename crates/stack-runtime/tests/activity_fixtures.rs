// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use stack_core::CheckStatus;
use stack_runtime::{
    ActivationState, BusyCounterSnapshot, InstalledPackage, evaluate_activity, inspect_activation,
    read_busy_counters,
};
use stack_schema::Profile;
use tempfile::TempDir;

fn counter(root: &Path, name: &str, value: &str) {
    let path = root
        .join("sys/class/accel")
        .join(name)
        .join("device/npu_busy_time_us");
    fs::create_dir_all(path.parent().expect("counter parent")).expect("create counter parent");
    fs::write(path, value).expect("write counter");
}

fn code(check: &stack_core::DiagnosticCheck) -> &str {
    check.details["error_code"]
        .as_str()
        .expect("stable error code")
}

fn profile_and_packages() -> (Profile, BTreeMap<String, InstalledPackage>) {
    let profile = Profile::parse_toml(include_str!(
        "../../../fixtures/profiles/valid-qualified.toml"
    ))
    .expect("fixture profile must parse");
    let packages = profile
        .components
        .values()
        .map(|component| {
            (
                component.provider.package.clone(),
                InstalledPackage {
                    name: component.provider.package.clone(),
                    version: component.provider.version.clone(),
                    install_time: 100,
                },
            )
        })
        .collect();
    (profile, packages)
}

#[test]
fn read_sorted_decimal_busy_counters() {
    let root = TempDir::new().expect("temporary root");
    counter(root.path(), "accel9", "9\n");
    counter(root.path(), "accel1", "1\n");
    counter(root.path(), "not-an-accelerator", "999\n");
    let BusyCounterSnapshot::Counters(counters) = read_busy_counters(root.path()) else {
        panic!("valid counters must be returned");
    };
    assert_eq!(counters.values(), &[1, 9]);
}

#[test]
fn missing_busy_counter_is_optional_warning() {
    let root = TempDir::new().expect("temporary root");
    fs::create_dir_all(root.path().join("sys/class/accel/accel0/device"))
        .expect("create counter directory");
    let snapshot = read_busy_counters(root.path());
    assert_eq!(snapshot, BusyCounterSnapshot::Absent);
    let check = evaluate_activity(&snapshot, &snapshot);
    assert_eq!(check.status, CheckStatus::Warn);
    assert_eq!(code(&check), "ACTIVITY_COUNTER_UNAVAILABLE");
}

#[test]
fn decreasing_or_unchanged_counter_is_warning() {
    let before_root = TempDir::new().expect("temporary root");
    let after_root = TempDir::new().expect("temporary root");
    counter(before_root.path(), "accel0", "10");
    counter(after_root.path(), "accel0", "9");
    let decreased = evaluate_activity(
        &read_busy_counters(before_root.path()),
        &read_busy_counters(after_root.path()),
    );
    assert_eq!(decreased.status, CheckStatus::Warn);
    assert_eq!(code(&decreased), "ACTIVITY_COUNTER_DECREASED");

    counter(after_root.path(), "accel0", "10");
    let unchanged = evaluate_activity(
        &read_busy_counters(before_root.path()),
        &read_busy_counters(after_root.path()),
    );
    assert_eq!(unchanged.status, CheckStatus::Warn);
    assert_eq!(code(&unchanged), "ACTIVITY_NOT_OBSERVED");
}

#[test]
fn positive_aggregate_delta_passes() {
    let before_root = TempDir::new().expect("temporary root");
    let after_root = TempDir::new().expect("temporary root");
    counter(before_root.path(), "accel0", "5");
    counter(before_root.path(), "accel1", "8");
    counter(after_root.path(), "accel0", "7");
    counter(after_root.path(), "accel1", "11");
    let check = evaluate_activity(
        &read_busy_counters(before_root.path()),
        &read_busy_counters(after_root.path()),
    );
    assert_eq!(check.status, CheckStatus::Pass);
    assert_eq!(check.details["busy_time_delta"], 5);
    assert!(!check.details.contains_key("error_code"));
}

#[test]
fn reboot_required_only_for_post_boot_reboot_provider() {
    let (profile, mut packages) = profile_and_packages();
    packages
        .get_mut("fixture-npu-firmware")
        .expect("firmware package")
        .install_time = 101;
    packages
        .get_mut("fixture-openvino-runtime")
        .expect("immediate package")
        .install_time = 999;
    let pending = inspect_activation(&profile, &packages, Some(100));
    assert_eq!(pending.state, ActivationState::Ready);
    assert!(pending.reboot_required);

    packages
        .get_mut("fixture-npu-firmware")
        .expect("firmware package")
        .install_time = 100;
    let active = inspect_activation(&profile, &packages, Some(100));
    assert!(!active.reboot_required);
}

#[test]
fn unknown_activation_time_blocks_instead_of_guessing() {
    let (profile, mut packages) = profile_and_packages();
    packages.remove("fixture-npu-firmware");
    let missing = inspect_activation(&profile, &packages, Some(100));
    assert_eq!(missing.state, ActivationState::Unknown);
    assert!(!missing.reboot_required);
    assert_eq!(missing.error_code, Some("ACTIVATION_STATE_UNKNOWN"));

    let (_, complete) = profile_and_packages();
    let missing_boot = inspect_activation(&profile, &complete, None);
    assert_eq!(missing_boot.state, ActivationState::Unknown);
}

#[test]
fn relogin_remains_false_in_phase_two() {
    let (profile, mut packages) = profile_and_packages();
    packages
        .get_mut("fixture-npu-userspace-driver")
        .expect("relogin provider")
        .install_time = 999;
    let activation = inspect_activation(&profile, &packages, Some(100));
    assert!(!activation.relogin_required);
}
