// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};
use stack_install::{NativeInventory, NativePlan, ReleaseManifest, ReleasePackage};
use stack_runtime::{
    ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, SystemProcessRunner,
};
use std::fmt::Write;

const UPGRADE: &[u8] = include_bytes!("fixtures/dnf/upgrade.json");
const BEFORE: &[u8] = include_bytes!("fixtures/dnf/installed-before-upgrade.txt");

fn expected() -> Vec<ReleasePackage> {
    let mut v: Value = serde_json::from_slice(include_bytes!("fixtures/release.json")).unwrap();
    v["packages"].as_array_mut().unwrap().push(json!({"name":"openvino-devel","nevr":"0:2026.2.0-1.intelnpu.fc44","arch":"x86_64","filename":"openvino-devel-2026.2.0-1.intelnpu.fc44.x86_64.rpm","sha256":"e046d6e2b5d200b2aabbe83a8d6c8828f1e10fc0a1b2e412a8c6f0757e3c7c04","role":"devel"}));
    ReleaseManifest::parse_json(&serde_json::to_vec(&v).unwrap())
        .unwrap()
        .selected_packages(false, true)
        .unwrap()
        .into_iter()
        .cloned()
        .collect()
}

fn parse(
    bytes: Option<&[u8]>,
    packages: &[ReleasePackage],
    inventory: &NativeInventory,
) -> Result<NativePlan, stack_install::InstallError> {
    NativePlan::parse_update(
        bytes,
        &packages.iter().collect::<Vec<_>>(),
        inventory,
        "intel-npu-test",
        &SystemProcessRunner,
    )
}

fn changed(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(UPGRADE).unwrap();
    edit(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn captured_upgrade_pairs_every_replaced_provider_with_exact_new_content() {
    let state = NativeInventory::parse_query(BEFORE).unwrap();
    let plan = parse(Some(UPGRADE), &expected(), &state).unwrap();
    let preview = plan.preview();
    assert_eq!(
        preview
            .lines()
            .filter(|l| l.starts_with("Install "))
            .count(),
        3
    );
    assert_eq!(
        preview
            .lines()
            .filter(|l| l.starts_with("Upgrade "))
            .count(),
        11
    );
    assert!(preview.contains("Upgrade intel-npu-driver-1.32.0-1.fc44.x86_64 -> intel-npu-driver-1.35.0-1.intelnpu.fc44.x86_64 sha256:fe61bf40595679a56ec3d73e2528e3aeb9ef3604e285373a356892d252b33ad7\n"));
    assert!(!preview.contains("oneapi-level-zero"));
}

#[test]
fn downgrade_is_refused_even_when_the_native_row_claims_upgrade() {
    let mut packages = expected();
    let driver = packages
        .iter_mut()
        .find(|p| p.name == "intel-npu-driver")
        .unwrap();
    driver.nevr = "0:1.31.0-1.fc44".into();
    driver.filename = "intel-npu-driver-1.31.0-1.fc44.x86_64.rpm".into();
    let bytes = changed(|v| {
        for row in v["rpms"].as_array_mut().unwrap() {
            if row["action"] == "Upgrade"
                && row["nevra"]
                    .as_str()
                    .unwrap()
                    .starts_with("intel-npu-driver-")
            {
                row["nevra"] = "intel-npu-driver-1.31.0-1.fc44.x86_64".into();
            }
        }
    });
    assert_eq!(
        parse(
            Some(&bytes),
            &packages,
            &NativeInventory::parse_query(BEFORE).unwrap()
        )
        .unwrap_err()
        .exit_code,
        30
    );
}

#[test]
fn stale_missing_or_extra_replacements_are_refused() {
    let state = NativeInventory::parse_query(BEFORE).unwrap();
    for bytes in [
        changed(|v| {
            v["rpms"].as_array_mut().unwrap().retain(|r| {
                !(r["action"] == "Replaced"
                    && r["nevra"]
                        .as_str()
                        .unwrap()
                        .starts_with("intel-npu-driver-"))
            });
        }),
        changed(|v| {
            for r in v["rpms"].as_array_mut().unwrap() {
                if r["action"] == "Replaced" {
                    r["nevra"] = "intel-npu-driver-1.31.0-1.fc44.x86_64".into();
                    break;
                }
            }
        }),
        changed(|v| {
            let row = v["rpms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["action"] == "Replaced")
                .unwrap()
                .clone();
            v["rpms"].as_array_mut().unwrap().push(row);
        }),
    ] {
        assert!(parse(Some(&bytes), &expected(), &state).is_err());
    }
    let altered = String::from_utf8(BEFORE.to_vec())
        .unwrap()
        .replace("intel-npu-driver|0:1.32.0", "intel-npu-driver|0:1.33.0");
    assert!(
        parse(
            Some(UPGRADE),
            &expected(),
            &NativeInventory::parse_query(altered.as_bytes()).unwrap()
        )
        .is_err()
    );
}

#[test]
fn destructive_unknown_and_unreviewed_repository_rows_are_refused() {
    let state = NativeInventory::parse_query(BEFORE).unwrap();
    for bytes in [
        changed(|v| v["rpms"][0]["action"] = "Remove".into()),
        changed(|v| v["rpms"][0]["repo_id"] = "@stored_transaction(unreviewed)".into()),
        changed(|v| v["rpms"][0]["reason"] = "unknown".into()),
        changed(|v| v["rpms"][0]["package_path"] = "./packages/../outside.rpm".into()),
        changed(|v| {
            for r in v["rpms"].as_array_mut().unwrap() {
                if r["action"] == "Replaced" {
                    r["package_path"] = "./packages/old.rpm".into();
                    break;
                }
            }
        }),
        changed(|v| {
            v["rpms"][0]["nevra"] = "intel-npu-unreviewed-provider-1.0-1.fc44.x86_64".into()
        }),
    ] {
        assert!(parse(Some(&bytes), &expected(), &state).is_err());
    }
}

struct MustNotRun;
impl ProcessRunner for MustNotRun {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("exact unchanged versions need no comparison process")
    }
}

#[test]
fn no_op_requires_every_requested_exact_version_and_absent_native_plan() {
    let packages = expected();
    let mut state = String::new();
    for package in &packages {
        writeln!(
            state,
            "{}|{}|{}|0",
            package.name, package.nevr, package.arch
        )
        .unwrap();
    }
    let inventory = NativeInventory::parse_query(state.as_bytes()).unwrap();
    let plan = NativePlan::parse_update(
        None,
        &packages.iter().collect::<Vec<_>>(),
        &inventory,
        "intel-npu-test",
        &MustNotRun,
    )
    .unwrap();
    assert_eq!(plan.preview(), "No package changes.\n");
    assert!(plan.is_empty());
    assert!(
        parse(
            None,
            &packages,
            &NativeInventory::parse_query(BEFORE).unwrap()
        )
        .is_err()
    );
    assert!(
        parse(
            Some(br#"{"version":"1.0","rpms":[]}"#),
            &packages,
            &inventory
        )
        .is_err()
    );
}

#[test]
fn captured_fedora_dependency_plan_binds_only_the_verified_input_set() {
    let packages: Vec<ReleasePackage> =
        serde_json::from_slice(include_bytes!("fixtures/dnf/dependency-inputs.json")).unwrap();
    let state = NativeInventory::parse_query(b"rpm|0:6.0.2-1.fc44|x86_64|0\n").unwrap();
    let native = include_bytes!("fixtures/dnf/dependencies.json");
    let plan = parse(Some(native), &packages, &state).unwrap();
    assert_eq!(plan.preview().lines().count(), 3);
    assert!(
        plan.preview()
            .contains("Install drpm-0.5.3-2.fc44.x86_64 sha256:")
    );
    assert!(parse(Some(native), &packages[..2], &state).is_err());
}
