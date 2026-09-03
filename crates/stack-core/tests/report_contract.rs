// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use stack_core::{
    Channel, CheckStatus, DiagnosticCheck, DiagnosticReport, OverallStatus, PlatformSummary,
};

fn check(id: &str, required: bool, status: CheckStatus) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.to_owned(),
        required,
        status,
        message: format!("result for {id}"),
        details: BTreeMap::from([("provider".to_owned(), json!("fixture"))]),
    }
}

fn report(checks: Vec<DiagnosticCheck>) -> DiagnosticReport {
    DiagnosticReport {
        schema_version: 1,
        stack_version: "0.1.0".to_owned(),
        profile_id: Some("testos-profile".to_owned()),
        channel: Channel::Stable,
        overall: OverallStatus::Blocked,
        platform: PlatformSummary {
            os_id: "testos".to_owned(),
            os_version_id: "1".to_owned(),
            arch: "x86_64".to_owned(),
            kernel: "6.17.3".to_owned(),
            pci_ids: vec!["8086:abcd".to_owned()],
        },
        checks,
    }
}

#[test]
fn report_serializes_schema_version_one_and_required_fields() {
    let mut report = report(vec![check("platform.profile", true, CheckStatus::Pass)]);
    report.finalize();
    let value = serde_json::to_value(&report).expect("report must serialize");
    let object = value.as_object().expect("report must be an object");
    let actual = object.keys().cloned().collect::<BTreeSet<_>>();
    let expected = [
        "channel",
        "checks",
        "overall",
        "platform",
        "profile_id",
        "schema_version",
        "stack_version",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["channel"], "stable");
    assert_eq!(value["overall"], "passed");
    assert_eq!(value["checks"][0]["status"], "pass");
}

#[test]
fn report_check_order_is_deterministic() {
    let mut report = report(vec![
        check("runtime.openvino", true, CheckStatus::Blocked),
        check("platform.profile", true, CheckStatus::Pass),
        check("runtime.level_zero", true, CheckStatus::Blocked),
    ]);
    report.platform.pci_ids = vec!["8086:ffff".to_owned(), "1234:0001".to_owned()];
    report.finalize();

    let ids = report
        .checks
        .iter()
        .map(|check| check.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        ["platform.profile", "runtime.level_zero", "runtime.openvino"]
    );
    assert_eq!(report.platform.pci_ids, ["1234:0001", "8086:ffff"]);
}

#[test]
fn required_failure_sets_overall_failed_and_exit_one() {
    let mut report = report(vec![
        check("a.blocked", true, CheckStatus::Blocked),
        check("b.failed", true, CheckStatus::Fail),
    ]);
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Failed);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn blocked_required_check_sets_overall_blocked_and_exit_one() {
    let mut report = report(vec![check("runtime", true, CheckStatus::Blocked)]);
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Blocked);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn skipped_required_check_is_blocked_and_cannot_report_success() {
    let mut report = report(vec![check("runtime", true, CheckStatus::Skipped)]);
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Blocked);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn optional_warning_sets_overall_degraded_and_exit_zero() {
    let mut report = report(vec![
        check("required", true, CheckStatus::Pass),
        check("optional", false, CheckStatus::Warning),
    ]);
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Degraded);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn clean_report_sets_overall_passed_and_exit_zero() {
    let mut report = report(vec![check("required", true, CheckStatus::Pass)]);
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Passed);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn platform_summary_omits_identifying_fields() {
    let mut report = report(vec![check("required", true, CheckStatus::Pass)]);
    report.finalize();
    let json = serde_json::to_string(&report).expect("report must serialize");

    for forbidden in [
        "hostname",
        "username",
        "serial",
        "mac",
        "ip_address",
        "bus_address",
        "/home/test-user",
        "0000:00:0b.0",
    ] {
        assert!(!json.contains(forbidden), "leaked field: {forbidden}");
    }
}
