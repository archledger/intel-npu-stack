// SPDX-License-Identifier: Apache-2.0
//! Post-transaction lifecycle verification contract.
//!
//! The installer must never claim success from a replay exit alone: the
//! release inventory is re-observed and compared, unselected release
//! packages must not move, and reboot/relogin activation requirements are
//! reported honestly instead of being hidden behind a success exit.

use stack_install::{LifecycleReport, NativeInventory, ReleaseManifest, verify_installation};
use stack_schema::Profile;

const METAPACKAGE: &str = r#"{"name":"intel-npu-stack","nevr":"0:0.1.0-1.intelnpu.fc44","arch":"noarch","filename":"intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch.rpm","sha256":"0000000000000000000000000000000000000000000000000000000000000001","role":"runtime"}"#;
const TOOLS: &str = r#"{"name":"intel-npu-stack-tools","nevr":"0:0.1.0-1.intelnpu.fc44","arch":"x86_64","filename":"intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm","sha256":"0000000000000000000000000000000000000000000000000000000000000002","role":"runtime"}"#;
const FIRMWARE: &str = r#"{"name":"intel-npu-stack-firmware","nevr":"0:1.35.0-1.intelnpu.fc44","arch":"noarch","filename":"intel-npu-stack-firmware-1.35.0-1.intelnpu.fc44.noarch.rpm","sha256":"0000000000000000000000000000000000000000000000000000000000000003","role":"runtime"}"#;
const LOADER: &str = r#"{"name":"oneapi-level-zero","nevr":"0:1.28.6-1.fc44","arch":"x86_64","filename":"oneapi-level-zero-1.28.6-1.fc44.x86_64.rpm","sha256":"0000000000000000000000000000000000000000000000000000000000000004","role":"runtime"}"#;
const DEVEL: &str = r#"{"name":"openvino-devel","nevr":"0:2026.2.0-1.intelnpu.fc44","arch":"x86_64","filename":"openvino-devel-2026.2.0-1.intelnpu.fc44.x86_64.rpm","sha256":"0000000000000000000000000000000000000000000000000000000000000005","role":"devel"}"#;

fn manifest(packages: &[&str]) -> ReleaseManifest {
    let entries = packages
        .iter()
        .map(|package| format!("    {package}"))
        .collect::<Vec<_>>()
        .join(",\n");
    let text = format!(
        "{{\n  \"schema_version\": 1,\n  \"stack_release\": \"0.1.0\",\n  \
         \"profile_sha256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\n  \
         \"repository\": {{\"id\": \"intel-npu-stack-0.1.0\", \"base_url\": \
         \"https://downloads.example.invalid/intel-npu-stack/0.1.0/fedora/44/x86_64/\", \
         \"repomd_sha256\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}},\n  \
         \"packages\": [\n{entries}\n  ]\n}}\n"
    );
    ReleaseManifest::parse_json(text.as_bytes()).expect("valid synthetic manifest")
}

fn profile(activation: &str) -> Profile {
    let fixture = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/profile.toml"
    ))
    .expect("fixture profile");
    let anchor = "version = \"0:1.35.0-1.intelnpu.fc44\"\nactivation = \"reboot\"";
    let replacement =
        format!("version = \"0:1.35.0-1.intelnpu.fc44\"\nactivation = \"{activation}\"");
    assert!(fixture.contains(anchor), "firmware provider anchor drifted");
    Profile::parse_toml(&fixture.replace(anchor, &replacement)).expect("valid profile")
}

fn inventory(rows: &[(&str, &str, &str, u64)]) -> NativeInventory {
    let mut query = String::new();
    for (name, evr, arch, time) in rows {
        query.push_str(&format!("{name}|{evr}|{arch}|{time}\n"));
    }
    NativeInventory::parse_query(query.as_bytes()).expect("valid synthetic inventory")
}

/// An observation without any release packages; rpm cannot answer an empty query.
fn empty_inventory() -> NativeInventory {
    inventory(&[("bash", "0:5.2.26-1.fc44", "x86_64", 100)])
}

fn full_set() -> Vec<(&'static str, &'static str, &'static str, u64)> {
    vec![
        ("intel-npu-stack", "0:0.1.0-1.intelnpu.fc44", "noarch", 500),
        (
            "intel-npu-stack-tools",
            "0:0.1.0-1.intelnpu.fc44",
            "x86_64",
            500,
        ),
        (
            "intel-npu-stack-firmware",
            "0:1.35.0-1.intelnpu.fc44",
            "noarch",
            500,
        ),
        ("oneapi-level-zero", "0:1.28.6-1.fc44", "x86_64", 400),
        (
            "openvino-devel",
            "0:2026.2.0-1.intelnpu.fc44",
            "x86_64",
            300,
        ),
    ]
}

#[test]
fn exact_install_reports_verified_packages_without_pending_actions() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = inventory(&full_set());
    let after = inventory(&full_set());
    let report = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect("unchanged state verifies");
    assert_eq!(
        report.verified,
        vec![
            "intel-npu-stack",
            "intel-npu-stack-firmware",
            "intel-npu-stack-tools",
            "oneapi-level-zero"
        ]
    );
    assert!(report.pending_reboot.is_empty());
    assert!(report.pending_relogin.is_empty());
}

#[test]
fn fresh_install_reports_reboot_pending_for_changed_firmware() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = inventory(&[
        ("intel-npu-stack", "0:0.1.0-1.intelnpu.fc44", "noarch", 100),
        (
            "intel-npu-stack-tools",
            "0:0.1.0-1.intelnpu.fc44",
            "x86_64",
            100,
        ),
        ("oneapi-level-zero", "0:1.28.6-1.fc44", "x86_64", 100),
        (
            "openvino-devel",
            "0:2026.2.0-1.intelnpu.fc44",
            "x86_64",
            300,
        ),
    ]);
    let after = inventory(&full_set());
    let report = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect("installation verifies");
    assert_eq!(report.pending_reboot, vec!["npu_firmware"]);
    assert!(report.pending_relogin.is_empty());
}

#[test]
fn relogin_activation_is_reported_separately() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = inventory(&[
        ("intel-npu-stack", "0:0.1.0-1.intelnpu.fc44", "noarch", 100),
        (
            "intel-npu-stack-tools",
            "0:0.1.0-1.intelnpu.fc44",
            "x86_64",
            100,
        ),
        ("oneapi-level-zero", "0:1.28.6-1.fc44", "x86_64", 100),
        (
            "openvino-devel",
            "0:2026.2.0-1.intelnpu.fc44",
            "x86_64",
            300,
        ),
    ]);
    let after = inventory(&full_set());
    let report = verify_installation(
        &manifest,
        false,
        false,
        &profile("relogin"),
        &before,
        &after,
    )
    .expect("installation verifies");
    assert_eq!(report.pending_relogin, vec!["npu_firmware"]);
    assert!(report.pending_reboot.is_empty());
}

#[test]
fn immediate_activation_never_reports_pending() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = inventory(&[
        ("intel-npu-stack", "0:0.1.0-1.intelnpu.fc44", "noarch", 100),
        (
            "intel-npu-stack-tools",
            "0:0.1.0-1.intelnpu.fc44",
            "x86_64",
            100,
        ),
        ("oneapi-level-zero", "0:1.28.6-1.fc44", "x86_64", 100),
        (
            "openvino-devel",
            "0:2026.2.0-1.intelnpu.fc44",
            "x86_64",
            300,
        ),
    ]);
    let after = inventory(&full_set());
    let report = verify_installation(
        &manifest,
        false,
        false,
        &profile("immediate"),
        &before,
        &after,
    )
    .expect("installation verifies");
    assert!(report.pending_reboot.is_empty() && report.pending_relogin.is_empty());
}

#[test]
fn missing_expected_package_is_refused() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = empty_inventory();
    let mut rows = full_set();
    rows.retain(|(name, _, _, _)| *name != "oneapi-level-zero");
    let after = inventory(&rows);
    let error = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect_err("missing provider must fail");
    assert_eq!(error.exit_code, 21);
    assert_eq!(error.code, "INSTALL_VERIFY_FAILED");
}

#[test]
fn wrong_version_of_expected_package_is_refused() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = empty_inventory();
    let mut rows = full_set();
    rows[3].1 = "0:1.28.5-1.fc44";
    let after = inventory(&rows);
    let error = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect_err("version drift must fail");
    assert_eq!(error.code, "INSTALL_VERIFY_FAILED");
}

#[test]
fn duplicate_name_with_different_version_is_refused() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = empty_inventory();
    let mut rows = full_set();
    rows.push(("oneapi-level-zero", "0:1.28.5-1.fc44", "x86_64", 500));
    let after = inventory(&rows);
    let error = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect_err("name drift must fail");
    assert_eq!(error.code, "INSTALL_VERIFY_FAILED");
}

#[test]
fn unselected_release_package_change_is_refused() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let mut before_rows = full_set();
    before_rows[4] = (
        "openvino-devel",
        "0:2026.1.0-1.intelnpu.fc44",
        "x86_64",
        100,
    );
    let before = inventory(&before_rows);
    let after = inventory(&full_set());
    let error = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect_err("unselected package movement must fail");
    assert_eq!(error.code, "INSTALL_VERIFY_FAILED");
}

#[test]
fn unselected_unchanged_release_package_is_accepted() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    let before = inventory(&full_set());
    let after = inventory(&full_set());
    let report = verify_installation(&manifest, false, true, &profile("reboot"), &before, &after)
        .expect("devel selected and unchanged verifies");
    assert!(report.verified.iter().any(|name| name == "openvino-devel"));
}

#[test]
fn requesting_absent_devel_capability_is_refused() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER]);
    let before = inventory(&full_set());
    let after = inventory(&full_set());
    let error = verify_installation(&manifest, false, true, &profile("reboot"), &before, &after)
        .expect_err("missing devel role must fail through selection");
    assert_eq!(error.exit_code, 10);
}

#[test]
fn report_is_deterministic_for_sorted_output() {
    let manifest = manifest(&[METAPACKAGE, TOOLS, FIRMWARE, LOADER, DEVEL]);
    assert_eq!(profile("reboot").components.len(), 6);
    let mut before_rows = full_set();
    before_rows.retain(|(name, _, _, _)| *name != "intel-npu-stack-firmware");
    let before = inventory(&before_rows);
    let after = inventory(&full_set());
    let first = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect("verifies");
    let second = verify_installation(&manifest, false, false, &profile("reboot"), &before, &after)
        .expect("verifies");
    assert_eq!(first, second);
    let _: LifecycleReport = first;
}
