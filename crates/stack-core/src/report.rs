// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use stack_schema::ProfileStatus;

/// Diagnostic operation that produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCommand {
    Status,
    Doctor,
}

/// Outcome of one diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Blocked,
}

/// Internal aggregation weight for one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    Required,
    Optional,
}

/// Aggregate diagnostic outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    Passed,
    Degraded,
    Failed,
    Blocked,
}

/// One deterministic, machine-readable diagnostic result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiagnosticCheck {
    pub id: String,
    pub status: CheckStatus,
    pub summary: String,
    pub details: BTreeMap<String, Value>,
    #[serde(skip)]
    pub requirement: Requirement,
}

/// Selected profile identity included in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileSummary {
    pub id: String,
    pub stack_release: String,
    pub status: ProfileStatus,
}

/// Privacy-preserving subset of platform facts included in reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlatformSummary {
    pub os_id: String,
    pub os_version_id: String,
    pub arch: String,
    pub kernel: String,
    pub pci_ids: Vec<String>,
}

/// Versioned diagnostic report shared by human and JSON CLI modes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiagnosticReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub command: DiagnosticCommand,
    pub overall: OverallStatus,
    pub profile: Option<ProfileSummary>,
    pub platform: PlatformSummary,
    pub reboot_required: bool,
    pub relogin_required: bool,
    pub checks: Vec<DiagnosticCheck>,
}

impl DiagnosticReport {
    /// Sorts collection fields and derives the aggregate status.
    pub fn finalize(&mut self) {
        self.checks.sort_by(|left, right| left.id.cmp(&right.id));
        self.platform.pci_ids.sort();
        self.platform.pci_ids.dedup();

        self.overall = if self.checks.iter().any(|check| {
            check.requirement == Requirement::Required && check.status == CheckStatus::Fail
        }) {
            OverallStatus::Failed
        } else if self.checks.iter().any(|check| {
            check.requirement == Requirement::Required && check.status == CheckStatus::Blocked
        }) {
            OverallStatus::Blocked
        } else if self
            .checks
            .iter()
            .any(|check| check.status != CheckStatus::Pass)
        {
            OverallStatus::Degraded
        } else {
            OverallStatus::Passed
        };
    }

    /// Returns the stable diagnostic exit code after finalization.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.overall {
            OverallStatus::Passed | OverallStatus::Degraded => 0,
            OverallStatus::Failed | OverallStatus::Blocked => 1,
        }
    }
}
