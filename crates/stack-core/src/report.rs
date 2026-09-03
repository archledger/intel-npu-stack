// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Channel;

/// Outcome of one diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warning,
    Blocked,
    Skipped,
}

/// Aggregate diagnostic outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    Passed,
    Degraded,
    Failed,
    Blocked,
}

/// One deterministic, machine-readable diagnostic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticCheck {
    pub id: String,
    pub required: bool,
    pub status: CheckStatus,
    pub message: String,
    pub details: BTreeMap<String, Value>,
}

/// Privacy-preserving subset of platform facts included in reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformSummary {
    pub os_id: String,
    pub os_version_id: String,
    pub arch: String,
    pub kernel: String,
    pub pci_ids: Vec<String>,
}

/// Versioned diagnostic report shared by human and JSON CLI modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticReport {
    pub schema_version: u32,
    pub stack_version: String,
    pub profile_id: Option<String>,
    pub channel: Channel,
    pub overall: OverallStatus,
    pub platform: PlatformSummary,
    pub checks: Vec<DiagnosticCheck>,
}

impl DiagnosticReport {
    /// Sorts collection fields and derives the aggregate status.
    pub fn finalize(&mut self) {
        self.checks.sort_by(|left, right| left.id.cmp(&right.id));
        self.platform.pci_ids.sort();
        self.platform.pci_ids.dedup();

        self.overall = if self
            .checks
            .iter()
            .any(|check| check.required && check.status == CheckStatus::Fail)
        {
            OverallStatus::Failed
        } else if self.checks.iter().any(|check| {
            check.required && matches!(check.status, CheckStatus::Blocked | CheckStatus::Skipped)
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
    pub fn exit_code(&self) -> u8 {
        match self.overall {
            OverallStatus::Passed | OverallStatus::Degraded => 0,
            OverallStatus::Failed | OverallStatus::Blocked => 1,
        }
    }
}
