// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use stack_core::{
    CheckStatus, DiagnosticCheck, DiagnosticCommand, DiagnosticReport, OverallStatus,
    PlatformSummary, ProfileSummary, Requirement,
};
use stack_schema::ProfileStatus;

fn check(id: &str, requirement: Requirement, status: CheckStatus) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.to_owned(),
        status,
        summary: format!("result for {id}"),
        details: BTreeMap::from([("provider".to_owned(), json!("fixture"))]),
        requirement,
    }
}

fn report(command: DiagnosticCommand, checks: Vec<DiagnosticCheck>) -> DiagnosticReport {
    DiagnosticReport {
        schema_version: 1,
        tool_version: "0.1.0".to_owned(),
        command,
        overall: OverallStatus::Blocked,
        profile: Some(ProfileSummary {
            id: "testos-profile".to_owned(),
            stack_release: "0.1.0".to_owned(),
            status: ProfileStatus::Qualified,
        }),
        platform: PlatformSummary {
            os_id: "testos".to_owned(),
            os_version_id: "1".to_owned(),
            arch: "x86_64".to_owned(),
            kernel: "6.17.3".to_owned(),
            pci_ids: vec!["8086:abcd".to_owned()],
        },
        reboot_required: false,
        relogin_required: false,
        checks,
    }
}

fn keys(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("value must be an object")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn report_serializes_exact_approved_version_one_keys() {
    let mut report = report(
        DiagnosticCommand::Status,
        vec![check(
            "platform.profile",
            Requirement::Required,
            CheckStatus::Pass,
        )],
    );
    report.finalize();
    let value = serde_json::to_value(&report).expect("report must serialize");

    assert_eq!(
        keys(&value),
        [
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
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool_version"], "0.1.0");
    assert_eq!(value["command"], "status");
    assert_eq!(value["overall"], "passed");
    assert_eq!(
        keys(&value["profile"]),
        ["id", "stack_release", "status"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}

#[test]
fn check_serializes_exact_id_status_summary_details() {
    let value = serde_json::to_value(check(
        "runtime.level_zero",
        Requirement::Required,
        CheckStatus::Blocked,
    ))
    .expect("check must serialize");

    assert_eq!(
        keys(&value),
        ["details", "id", "status", "summary"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(value["status"], "blocked");
    assert_eq!(value["summary"], "result for runtime.level_zero");
}

#[test]
fn warn_spelling_is_stable() {
    let value = serde_json::to_value(check(
        "runtime.activity",
        Requirement::Optional,
        CheckStatus::Warn,
    ))
    .expect("warning check must serialize");
    assert_eq!(value["status"], "warn");
}

#[test]
fn phase_one_accidental_names_never_serialize() {
    let json = serde_json::to_string(&report(DiagnosticCommand::Doctor, Vec::new()))
        .expect("report must serialize");
    for forbidden in [
        "stack_version",
        "profile_id",
        "channel",
        "message",
        "warning",
        "skipped",
    ] {
        assert!(
            !json.contains(forbidden),
            "serialized old name: {forbidden}"
        );
    }
}

#[test]
fn requiredness_is_internal_only() {
    let required =
        serde_json::to_value(check("required", Requirement::Required, CheckStatus::Pass))
            .expect("serialize required check");
    let optional =
        serde_json::to_value(check("optional", Requirement::Optional, CheckStatus::Pass))
            .expect("serialize optional check");
    assert_eq!(keys(&required), keys(&optional));
    assert!(required.get("required").is_none());
    assert!(required.get("requirement").is_none());
    assert!(optional.get("required").is_none());
    assert!(optional.get("requirement").is_none());
}

#[test]
fn status_and_doctor_commands_serialize_distinctly() {
    let status = serde_json::to_value(report(DiagnosticCommand::Status, Vec::new()))
        .expect("serialize status");
    let doctor = serde_json::to_value(report(DiagnosticCommand::Doctor, Vec::new()))
        .expect("serialize doctor");
    assert_eq!(status["command"], "status");
    assert_eq!(doctor["command"], "doctor");
}

#[test]
fn reboot_and_relogin_are_explicit_booleans() {
    let mut diagnostic = report(DiagnosticCommand::Status, Vec::new());
    diagnostic.reboot_required = true;
    diagnostic.relogin_required = false;
    let value = serde_json::to_value(diagnostic).expect("serialize activation flags");
    assert_eq!(value["reboot_required"], true);
    assert_eq!(value["relogin_required"], false);
}

#[test]
fn report_check_order_is_deterministic() {
    let mut report = report(
        DiagnosticCommand::Doctor,
        vec![
            check(
                "runtime.openvino",
                Requirement::Required,
                CheckStatus::Blocked,
            ),
            check("platform.profile", Requirement::Required, CheckStatus::Pass),
            check(
                "runtime.level_zero",
                Requirement::Required,
                CheckStatus::Blocked,
            ),
        ],
    );
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
    let mut report = report(
        DiagnosticCommand::Doctor,
        vec![
            check("a.blocked", Requirement::Required, CheckStatus::Blocked),
            check("b.failed", Requirement::Required, CheckStatus::Fail),
        ],
    );
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Failed);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn blocked_required_check_sets_overall_blocked_and_exit_one() {
    let mut report = report(
        DiagnosticCommand::Doctor,
        vec![check(
            "runtime",
            Requirement::Required,
            CheckStatus::Blocked,
        )],
    );
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Blocked);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn optional_warning_failure_or_blocked_sets_degraded_and_exit_zero() {
    for status in [CheckStatus::Warn, CheckStatus::Fail, CheckStatus::Blocked] {
        let mut report = report(
            DiagnosticCommand::Doctor,
            vec![
                check("required", Requirement::Required, CheckStatus::Pass),
                check("optional", Requirement::Optional, status),
            ],
        );
        report.finalize();
        assert_eq!(
            report.overall,
            OverallStatus::Degraded,
            "status: {status:?}"
        );
        assert_eq!(report.exit_code(), 0);
    }
}

#[test]
fn clean_report_sets_overall_passed_and_exit_zero() {
    let mut report = report(
        DiagnosticCommand::Status,
        vec![check("required", Requirement::Required, CheckStatus::Pass)],
    );
    report.finalize();
    assert_eq!(report.overall, OverallStatus::Passed);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn platform_summary_omits_identifying_fields() {
    let mut report = report(
        DiagnosticCommand::Status,
        vec![check("required", Requirement::Required, CheckStatus::Pass)],
    );
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
