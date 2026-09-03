// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod matching;
mod report;

pub use matching::{Channel, SelectionError, SelectionPolicy, select_profile};
pub use report::{CheckStatus, DiagnosticCheck, DiagnosticReport, OverallStatus, PlatformSummary};
