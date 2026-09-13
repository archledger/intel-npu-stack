// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use stack_runtime::ProcessRunner;

use crate::{
    FedoraRpm, InstallError, NativeInventory, ProjectRpm, ProjectRpmTrust, ReleasePackage,
    compare_rpm_versions, manifest::validate_package,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTransaction {
    version: String,
    rpms: Vec<StoredRpm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRpm {
    nevra: String,
    action: String,
    reason: String,
    repo_id: String,
    #[serde(default, deserialize_with = "present_path")]
    package_path: Option<String>,
}

#[derive(Debug)]
struct BoundRpm {
    native: StoredRpm,
    sha256: String,
    replaces: Option<String>,
    expected: ReleasePackage,
    authority: RpmAuthority,
}

#[derive(Debug)]
enum RpmAuthority {
    Project,
    Fedora,
}

/// Exact installation actions bound to independently authenticated RPM inputs.
///
/// Accepts captured DNF5 5.4.2.1 Install and Upgrade/Replaced records. Parsing
/// and content inspection neither authenticate supplied inputs, verify RPM
/// signatures, nor authorize replay. Callers must supply a complete verified
/// input set, including dependencies, and recheck state before execution.
#[derive(Debug)]
pub struct NativePlan {
    packages: Vec<BoundRpm>,
    transaction_sha256: Option<String>,
    inventory_fingerprint: Option<String>,
}

impl NativePlan {
    /// Requires one native Install action for every supplied authenticated input.
    /// Unknown actions, repositories, fields, duplicates and paths are refused.
    pub fn parse_install(bytes: &[u8], expected: &[&ReleasePackage]) -> Result<Self, InstallError> {
        if bytes.len() > 1_048_576 || expected.is_empty() || expected.len() > 128 {
            return Err(transaction_error());
        }
        let document: StoredTransaction =
            serde_json::from_slice(bytes).map_err(|_| transaction_error())?;
        if document.version != "1.0" || document.rpms.len() != expected.len() {
            return Err(transaction_error());
        }
        let mut expected_names = BTreeSet::new();
        for package in expected {
            validate_package(package)?;
            if !expected_names.insert(&package.name) {
                return Err(transaction_error());
            }
        }
        let mut identities = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut packages = Vec::with_capacity(document.rpms.len());
        for native in document.rpms {
            if native.action != "Install"
                || native.reason != "User"
                || native.repo_id != "@stored_transaction(@commandline)"
                || !native
                    .package_path
                    .as_deref()
                    .is_some_and(safe_package_path)
                || !identities.insert(native.nevra.clone())
                || !paths.insert(native.package_path.clone())
            {
                return Err(transaction_error());
            }
            let package = expected
                .iter()
                .find(|package| {
                    let nevr = package.nevr.strip_prefix("0:").unwrap_or(&package.nevr);
                    native.nevra == format!("{}-{nevr}.{}", package.name, package.arch)
                })
                .ok_or_else(transaction_error)?;
            packages.push(BoundRpm {
                native,
                sha256: package.sha256.clone(),
                replaces: None,
                expected: (*package).clone(),
                authority: RpmAuthority::Project,
            });
        }
        packages.sort_by(|a, b| a.native.nevra.cmp(&b.native.nevra));
        Ok(Self {
            packages,
            transaction_sha256: Some(format!("{:x}", Sha256::digest(bytes))),
            inventory_fingerprint: None,
        })
    }

    /// Binds every native action to exact requested inputs and observed state.
    /// The repository ID is a trusted caller configuration, not native output.
    /// Absence of a transaction file is accepted only for an exact no-op.
    pub fn parse_update(
        bytes: Option<&[u8]>,
        expected: &[&ReleasePackage],
        inventory: &NativeInventory,
        repository_id: &str,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        if expected.is_empty() {
            return Err(transaction_error());
        }
        Self::parse_with_dependencies(bytes, expected, &[], inventory, repository_id, runner)
    }

    /// Includes native Fedora-signed dependencies without treating them as
    /// project release packages. Release manifest limits and Fedora release
    /// tags still apply to every project input; the complete native plan has
    /// a separate 4096-package resource bound. Inputs cannot overlap by name.
    pub fn parse_with_dependencies(
        bytes: Option<&[u8]>,
        expected: &[&ReleasePackage],
        dependencies: &[crate::FedoraRpm],
        inventory: &NativeInventory,
        repository_id: &str,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        if expected.len() > 128 || expected.len() + dependencies.len() > 4096 {
            return Err(transaction_error());
        }
        for package in expected {
            validate_package(package)?;
        }
        let inputs = expected
            .iter()
            .copied()
            .chain(dependencies.iter().map(crate::FedoraRpm::package))
            .collect::<Vec<_>>();
        Self::parse_inputs(bytes, &inputs, expected, inventory, repository_id, runner)
    }

    fn parse_inputs(
        bytes: Option<&[u8]>,
        expected: &[&ReleasePackage],
        project_inputs: &[&ReleasePackage],
        inventory: &NativeInventory,
        repository_id: &str,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        if expected.is_empty()
            || repository_id.is_empty()
            || repository_id.len() > 128
            || !repository_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(transaction_error());
        }
        let mut names = BTreeSet::new();
        let mut incoming = BTreeMap::new();
        let mut replacements = BTreeSet::new();
        for package in expected {
            if !names.insert(&package.name) {
                return Err(transaction_error());
            }
            let installed = inventory
                .packages()
                .iter()
                .filter(|old| old.name == package.name && old.arch == package.arch)
                .collect::<Vec<_>>();
            let replaces = match installed.as_slice() {
                [] => None,
                [old] if old.evr == package.nevr => continue,
                [old] => {
                    if compare_rpm_versions(&old.evr, &package.nevr, runner)? != Ordering::Less {
                        return Err(transaction_error());
                    }
                    let identity = native_identity(&old.name, &old.evr, &old.arch);
                    replacements.insert(identity.clone());
                    Some(identity)
                }
                _ => return Err(transaction_error()),
            };
            incoming.insert(
                native_identity(&package.name, &package.nevr, &package.arch),
                (*package, replaces),
            );
        }
        let Some(bytes) = bytes else {
            return if incoming.is_empty() {
                Ok(Self {
                    packages: Vec::new(),
                    transaction_sha256: None,
                    inventory_fingerprint: Some(inventory.fingerprint().to_owned()),
                })
            } else {
                Err(transaction_error())
            };
        };
        if incoming.is_empty() || bytes.len() > 8_388_608 {
            return Err(transaction_error());
        }
        let document: StoredTransaction =
            serde_json::from_slice(bytes).map_err(|_| transaction_error())?;
        if document.version != "1.0" || document.rpms.len() != incoming.len() + replacements.len() {
            return Err(transaction_error());
        }
        let repositories = ["@commandline", "fedora", "updates", repository_id]
            .map(|id| format!("@stored_transaction({id})"));
        let mut paths = BTreeSet::new();
        let mut packages = Vec::with_capacity(incoming.len());
        for native in document.rpms {
            if !matches!(native.reason.as_str(), "User" | "Dependency") {
                return Err(transaction_error());
            }
            if native.action == "Replaced" {
                if native.repo_id != "@System"
                    || native.package_path.is_some()
                    || !replacements.remove(&native.nevra)
                {
                    return Err(transaction_error());
                }
                continue;
            }
            let (package, replaces) = incoming
                .remove(&native.nevra)
                .ok_or_else(transaction_error)?;
            let path = native
                .package_path
                .as_deref()
                .ok_or_else(transaction_error)?;
            let action = if replaces.is_some() {
                "Upgrade"
            } else {
                "Install"
            };
            if native.action != action
                || !repositories.contains(&native.repo_id)
                || !safe_package_path(path)
                || path != format!("./packages/{}", package.filename)
                || !paths.insert(path.to_owned())
            {
                return Err(transaction_error());
            }
            packages.push(BoundRpm {
                native,
                sha256: package.sha256.clone(),
                replaces,
                expected: package.clone(),
                authority: if project_inputs.iter().any(|p| p.name == package.name) {
                    RpmAuthority::Project
                } else {
                    RpmAuthority::Fedora
                },
            });
        }
        if !incoming.is_empty() || !replacements.is_empty() {
            return Err(transaction_error());
        }
        packages.sort_by(|a, b| a.native.nevra.cmp(&b.native.nevra));
        Ok(Self {
            packages,
            transaction_sha256: Some(format!("{:x}", Sha256::digest(bytes))),
            inventory_fingerprint: Some(inventory.fingerprint().to_owned()),
        })
    }

    /// Identity of the exact parsed native JSON bytes; absent for a no-op.
    pub fn transaction_sha256(&self) -> Option<&str> {
        self.transaction_sha256.as_deref()
    }

    /// Verifies every incoming stored RPM against its original input authority,
    /// using native signatures, payload digests and exact queried identities.
    /// Native repository labels cannot change project trust into Fedora trust.
    /// The caller supplies the independently pinned project key; this does not
    /// authenticate that choice, review the transaction, or lock native state.
    pub fn verify_signatures(
        &self,
        root: &Path,
        project_trust: &ProjectRpmTrust,
        runner: &dyn ProcessRunner,
    ) -> Result<(), InstallError> {
        self.verify_packages(root)?;
        for package in &self.packages {
            let path = root.join(
                package
                    .native
                    .package_path
                    .as_deref()
                    .ok_or_else(transaction_error)?,
            );
            match package.authority {
                RpmAuthority::Project => {
                    ProjectRpm::verify(&path, &package.expected, project_trust, runner)?;
                }
                RpmAuthority::Fedora => {
                    let verified = FedoraRpm::verify(&path, &package.sha256, runner)?;
                    if verified.package() != &package.expected {
                        return Err(transaction_error());
                    }
                }
            }
        }
        Ok(())
    }

    /// Rechecks exact stored bytes, RPM content and the observed package state.
    /// Requires a plan parsed against NativeInventory; legacy parse_install
    /// has no state observation and cannot pass this replay precondition.
    /// This read-only check is neither a signature verdict nor an atomic RPM
    /// database lock. Native DNF still owns locking and transaction recovery.
    pub fn verify_stored(
        &self,
        root: &Path,
        runner: &dyn ProcessRunner,
    ) -> Result<(), InstallError> {
        let invalid = || InstallError {
            exit_code: 30,
            code: "INSTALL_TRANSACTION_CHANGED",
            message: "stored native transaction no longer matches the observed plan",
        };
        let fingerprint = self.inventory_fingerprint.as_deref().ok_or_else(invalid)?;
        let expected = self.transaction_sha256().ok_or_else(invalid)?;
        if !fs::symlink_metadata(root).map_err(|_| invalid())?.is_dir() {
            return Err(invalid());
        }
        let path = root.join("transaction.json");
        let metadata = fs::symlink_metadata(&path).map_err(|_| invalid())?;
        const MAX_TRANSACTION_BYTES: u64 = 8_388_608;
        if !metadata.is_file() || metadata.len() > MAX_TRANSACTION_BYTES {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .map_err(|_| invalid())?
            .take(MAX_TRANSACTION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() as u64 != metadata.len()
            || format!("{:x}", Sha256::digest(&bytes)) != expected
        {
            return Err(invalid());
        }
        self.verify_packages(root)?;
        if NativeInventory::query(runner)?.fingerprint() != fingerprint {
            return Err(InstallError {
                exit_code: 30,
                code: "INSTALL_STATE_CHANGED",
                message: "installed packages changed after planning",
            });
        }
        Ok(())
    }

    /// True only for an independently checked exact installed-state no-op.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Displays every bound action and content identity in deterministic order.
    pub fn preview(&self) -> String {
        if self.is_empty() {
            return "No package changes.\n".to_owned();
        }
        let mut preview = String::new();
        for package in &self.packages {
            preview.push_str(&package.native.action);
            preview.push(' ');
            if let Some(old) = &package.replaces {
                preview.push_str(old);
                preview.push_str(" -> ");
            }
            preview.push_str(&package.native.nevra);
            preview.push_str(" sha256:");
            preview.push_str(&package.sha256);
            preview.push('\n');
        }
        preview
    }

    /// Checks current bytes in a caller-owned private transaction directory.
    ///
    /// DNF's stored JSON alone does not contain its referenced local RPMs.
    /// This is a bounded read-only content check, not an immutable file handle
    /// or a replacement for native signatures and a recheck before execution.
    pub fn verify_packages(&self, root: &Path) -> Result<(), InstallError> {
        if self.is_empty() {
            return Ok(());
        }
        let invalid = || InstallError::integrity("stored transaction RPM content is invalid");
        for directory in [root.to_path_buf(), root.join("packages")] {
            if !fs::symlink_metadata(directory)
                .map_err(|_| invalid())?
                .file_type()
                .is_dir()
            {
                return Err(invalid());
            }
        }
        for package in &self.packages {
            let path = root.join(package.native.package_path.as_deref().ok_or_else(invalid)?);
            let metadata = fs::symlink_metadata(&path).map_err(|_| invalid())?;
            const MAX_RPM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
            if !metadata.file_type().is_file() || metadata.len() > MAX_RPM_BYTES {
                return Err(invalid());
            }
            let file = fs::File::open(path).map_err(|_| invalid())?;
            let mut input = file.take(MAX_RPM_BYTES + 1);
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 65536];
            let mut size = 0_u64;
            loop {
                let count = input.read(&mut buffer).map_err(|_| invalid())?;
                if count == 0 {
                    break;
                }
                size += count as u64;
                hash.update(&buffer[..count]);
            }
            if size != metadata.len() || format!("{:x}", hash.finalize()) != package.sha256 {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn native_identity(name: &str, evr: &str, arch: &str) -> String {
    let evr = evr.strip_prefix("0:").unwrap_or(evr);
    format!("{name}-{evr}.{arch}")
}

// Missing paths are valid only on Replaced records; explicit null is invalid.
fn present_path<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn safe_package_path(path: &str) -> bool {
    let Some(filename) = path.strip_prefix("./packages/") else {
        return false;
    };
    filename.len() <= 512
        && filename.ends_with(".rpm")
        && filename.as_bytes()[0].is_ascii_alphanumeric()
        && filename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+~^".contains(&b))
}

fn transaction_error() -> InstallError {
    InstallError {
        exit_code: 30,
        code: "INSTALL_TRANSACTION_INVALID",
        message: "native transaction does not match the supported exact installation plan",
    }
}
