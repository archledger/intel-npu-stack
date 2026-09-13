// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod dnf;
mod fedora;
mod fedora_rpm;
mod inventory;
mod lifecycle;
mod manifest;
mod policy;
mod prepare;
mod project_rpm;
mod review;
mod signature;
mod transport;

pub use dnf::{DnfPlanningFailure, DnfPlanningOutput, DnfPlanningRequest, plan_downloads};
pub use fedora::NativePlan;
pub use fedora_rpm::FedoraRpm;
pub use inventory::{InstalledRpm, NativeInventory, compare_rpm_versions};
pub use lifecycle::{LifecycleReport, verify_installation};
pub use manifest::{PackageRole, ReleaseManifest, ReleasePackage, ReleaseRepository};
pub use policy::{InstallOptions, validate_request};
pub use prepare::{
    FedoraSources, NativePlanner, PrepareFailure, PrepareInput, PreparedTransaction,
    ReplayExecutor, ReplayFailure, ReplayStatus, SystemNativePlanner, SystemReplayExecutor,
    prepare, prepare_with,
};
pub use project_rpm::{ProjectRpm, ProjectRpmTrust};
pub use review::{
    ApprovedPlan, ConfirmationPrompt, PlanReview, SystemConfirmationPrompt, review_plan,
};
pub use signature::{ReleaseTrust, verify_detached, verify_signature_status};
pub use transport::{ReleaseLocation, VerifiedRelease, fetch_release};

/// Stable installer failure category; parsing does not authorize installation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct InstallError {
    pub exit_code: u8,
    pub code: &'static str,
    pub message: &'static str,
}

impl InstallError {
    pub(crate) fn integrity(message: &'static str) -> Self {
        Self {
            exit_code: 20,
            code: "INSTALL_INTEGRITY_FAILED",
            message,
        }
    }

    pub(crate) fn metadata(message: &'static str) -> Self {
        Self {
            exit_code: 20,
            code: "INSTALL_METADATA_INVALID",
            message,
        }
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            exit_code: 10,
            code: "INSTALL_CAPABILITY_UNAVAILABLE",
            message: "the release does not provide the requested optional capability",
        }
    }
}
