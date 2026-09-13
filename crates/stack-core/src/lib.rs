// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod matching;
mod report;

pub use matching::{Channel, SelectionError, SelectionPolicy, platform_matches, select_profile};
pub use report::{
    CheckStatus, DiagnosticCheck, DiagnosticCommand, DiagnosticReport, OverallStatus,
    PlatformSummary, ProfileSummary, Requirement,
};
