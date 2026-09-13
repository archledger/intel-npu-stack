// SPDX-License-Identifier: Apache-2.0
//! Post-transaction installation-state verification.
//!
//! A replay exit is never treated as success by itself: the native package
//! database is re-observed and compared with the release manifest and the
//! pre-transaction observation. Unselected release packages must not move,
//! and activation requirements are reported honestly instead of being hidden
//! behind a success exit. This module never claims qualification or hardware
//! readiness.

use std::collections::BTreeSet;

use stack_schema::{ActivationRequirement, Profile};

use crate::{InstallError, NativeInventory, ReleaseManifest};

/// Honest installation state after the native transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleReport {
    /// Release packages present at their exact identity, sorted by name.
    pub verified: Vec<String>,
    /// Capabilities whose changed providers need a reboot before activation.
    pub pending_reboot: Vec<String>,
    /// Capabilities whose changed providers need a relogin before activation.
    pub pending_relogin: Vec<String>,
}

/// Verifies the observed inventory against the release selection and reports
/// pending activation work. `before` and `after` are independent observations;
/// neither is treated as a lock or a database transaction.
pub fn verify_installation(
    manifest: &ReleaseManifest,
    with_python: bool,
    with_devel: bool,
    profile: &Profile,
    before: &NativeInventory,
    after: &NativeInventory,
) -> Result<LifecycleReport, InstallError> {
    let selected = manifest.selected_packages(with_python, with_devel)?;
    let mut verified = Vec::new();
    let mut changed = BTreeSet::new();
    for package in &selected {
        let entries = after
            .packages()
            .iter()
            .filter(|rpm| rpm.name == package.name)
            .collect::<Vec<_>>();
        let exact = entries
            .iter()
            .find(|rpm| rpm.evr == package.nevr && rpm.arch == package.arch);
        if exact.is_none() || entries.iter().any(|rpm| rpm.evr != package.nevr) {
            return Err(InstallError {
                exit_code: 21,
                code: "INSTALL_VERIFY_FAILED",
                message: "an expected release package is missing, at the wrong version, or duplicated",
            });
        }
        let matched = exact.expect("non-empty because exact.is_none() was checked");
        let untouched = before.packages().iter().any(|rpm| {
            rpm.name == matched.name
                && rpm.evr == matched.evr
                && rpm.arch == matched.arch
                && rpm.install_time == matched.install_time
        });
        if !untouched {
            changed.insert(matched.name.clone());
        }
        verified.push(package.name.clone());
    }

    let selected_names = selected
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    for package in manifest.packages() {
        if selected_names.contains(package.name.as_str()) {
            continue;
        }
        let snapshot = |inventory: &NativeInventory| {
            inventory
                .packages()
                .iter()
                .filter(|rpm| rpm.name == package.name)
                .map(|rpm| (rpm.evr.clone(), rpm.arch.clone(), rpm.install_time))
                .collect::<Vec<_>>()
        };
        if snapshot(before) != snapshot(after) {
            return Err(InstallError {
                exit_code: 21,
                code: "INSTALL_VERIFY_FAILED",
                message: "a release package outside the selection changed during the transaction",
            });
        }
    }

    let mut pending_reboot = Vec::new();
    let mut pending_relogin = Vec::new();
    for (capability, component) in &profile.components {
        if !changed.contains(&component.provider.package) {
            continue;
        }
        match component.provider.activation {
            ActivationRequirement::Reboot => pending_reboot.push(capability.clone()),
            ActivationRequirement::Relogin => pending_relogin.push(capability.clone()),
            ActivationRequirement::Immediate => {}
        }
    }
    Ok(LifecycleReport {
        verified,
        pending_reboot,
        pending_relogin,
    })
}
