// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use stack_schema::{PackageManager, Profile, RedistributionVerdict};

use crate::InstallError;

const MAX_METADATA_BYTES: usize = 1_048_576;
const MAX_PACKAGES: usize = 128;

/// Requested purpose of a release artifact, separate from its native identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageRole {
    Runtime,
    Python,
    Devel,
    Profile,
}

/// Exact RPM identity from release metadata. It is not proof of authenticity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePackage {
    pub name: String,
    pub nevr: String,
    pub arch: String,
    pub filename: String,
    pub sha256: String,
    pub role: PackageRole,
}

/// Versioned repository location and expected metadata bytes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRepository {
    pub id: String,
    pub base_url: String,
    pub repomd_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    schema_version: u32,
    stack_release: String,
    profile_sha256: String,
    repository: ReleaseRepository,
    packages: Vec<ReleasePackage>,
}

/// Structurally validated, but unauthenticated, release metadata.
///
/// Callers must verify its externally pinned digest and signature before using
/// it for network acquisition, native planning or installation. Fields remain
/// private so parsed invariants cannot be changed through this API.
#[derive(Debug)]
pub struct ReleaseManifest {
    document: ManifestDocument,
}

impl ReleaseManifest {
    /// Parses bounded JSON and validates exact Fedora 44 artifact identities.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, InstallError> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(InstallError::metadata(
                "release metadata exceeds its byte limit",
            ));
        }
        let document: ManifestDocument = serde_json::from_slice(bytes).map_err(|_| {
            InstallError::metadata("release metadata is not strict schema-one JSON")
        })?;
        if document.schema_version != 1
            || !release_version(&document.stack_release)
            || !digest(&document.profile_sha256)
            || !identifier(&document.repository.id)
            || !digest(&document.repository.repomd_sha256)
            || !repository_url(&document.repository.base_url, &document.stack_release)
        {
            return Err(InstallError::metadata(
                "invalid release or repository identity",
            ));
        }
        if document.packages.is_empty() || document.packages.len() > MAX_PACKAGES {
            return Err(InstallError::metadata(
                "release package count is out of range",
            ));
        }
        let mut names = BTreeSet::new();
        let mut filenames = BTreeSet::new();
        for package in &document.packages {
            validate_package(package)?;
            if !names.insert(&package.name) || !filenames.insert(&package.filename) {
                return Err(InstallError::metadata("duplicate release package identity"));
            }
        }
        for name in ["intel-npu-stack", "intel-npu-stack-tools"] {
            if !document
                .packages
                .iter()
                .any(|package| package.name == name && package.role == PackageRole::Runtime)
            {
                return Err(InstallError::metadata(
                    "required runtime tools or metapackage is absent",
                ));
            }
        }
        Ok(Self { document })
    }

    /// Binds exact profile bytes and every component to the release inventory.
    /// This does not change candidate status or apply channel admission policy.
    pub fn bind_profile(&self, bytes: &[u8]) -> Result<Profile, InstallError> {
        if bytes.len() > MAX_METADATA_BYTES
            || format!("{:x}", Sha256::digest(bytes)) != self.document.profile_sha256
        {
            return Err(InstallError::metadata(
                "profile bytes do not match release metadata",
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| InstallError::metadata("profile is not UTF-8"))?;
        let profile = Profile::parse_toml(text)
            .map_err(|_| InstallError::metadata("profile validation failed"))?;
        if profile.stack_release != self.document.stack_release
            || profile.package_manager != PackageManager::Rpm
            || profile.platform.id != "fedora"
            || profile.platform.version_id != "44"
            || profile.platform.arch != "x86_64"
        {
            return Err(InstallError::metadata(
                "profile does not match this Fedora release",
            ));
        }
        for (capability, component) in &profile.components {
            let Some(package) = self
                .document
                .packages
                .iter()
                .find(|package| package.name == component.provider.package)
            else {
                return Err(InstallError::metadata(
                    "profile component is absent from release packages",
                ));
            };
            if package.role != PackageRole::Runtime
                || package.nevr != component.provider.version
                || package.sha256 != component.sha256
                || component.license.redistribution == RedistributionVerdict::Forbidden
                || (component.license.redistribution == RedistributionVerdict::ExternalOnly
                    && (capability != "level_zero_loader" || package.name != "oneapi-level-zero"))
            {
                return Err(InstallError::metadata(
                    "profile component identity or redistribution mismatch",
                ));
            }
        }
        Ok(profile)
    }

    /// Returns exact requested artifacts, sorted independently of JSON order.
    pub fn selected_packages(
        &self,
        with_python: bool,
        with_devel: bool,
    ) -> Result<Vec<&ReleasePackage>, InstallError> {
        for (requested, role) in [
            (with_python, PackageRole::Python),
            (with_devel, PackageRole::Devel),
        ] {
            if requested
                && !self
                    .document
                    .packages
                    .iter()
                    .any(|package| package.role == role)
            {
                return Err(InstallError::unavailable());
            }
        }
        let mut packages = self
            .document
            .packages
            .iter()
            .filter(|package| match package.role {
                PackageRole::Runtime | PackageRole::Profile => true,
                PackageRole::Python => with_python,
                PackageRole::Devel => with_devel,
            })
            .collect::<Vec<_>>();
        packages.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(packages)
    }

    /// Validated repository fields; authenticity is a separate gate.
    pub fn repository(&self) -> &ReleaseRepository {
        &self.document.repository
    }

    /// Every validated package identity, in manifest order; not a selection.
    pub fn packages(&self) -> &[ReleasePackage] {
        &self.document.packages
    }

    /// Returns the exact release version bound to the profile.
    pub fn stack_release(&self) -> &str {
        &self.document.stack_release
    }
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
}

pub(crate) fn release_version(value: &str) -> bool {
    // Releases are numeric triples; no mutable channel names are accepted here.
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u32>().is_ok()
        })
}

pub(crate) fn repository_url(url: &str, version: &str) -> bool {
    if url.len() > 2048 {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let Some((host, path)) = rest.split_once('/') else {
        return false;
    };
    if host.len() > 253
        || !host.contains('.')
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return false;
    }
    let Some(path) = path.strip_suffix('/') else {
        return false;
    };
    let segments = path.split('/').collect::<Vec<_>>();
    (segments.contains(&version) || segments.contains(&format!("v{version}").as_str()))
        && segments.iter().all(|part| {
            identifier(part)
                && *part != "."
                && *part != ".."
                && !matches!(*part, "latest" | "current" | "stable" | "experimental")
        })
}

pub(crate) fn validate_package(package: &ReleasePackage) -> Result<(), InstallError> {
    if !identifier(&package.name)
        || !digest(&package.sha256)
        || !matches!(package.arch.as_str(), "x86_64" | "noarch")
        || package.nevr.len() > 256
    {
        return Err(InstallError::metadata("invalid RPM package identity"));
    }
    let Some((epoch, vr)) = package.nevr.split_once(':') else {
        return Err(InstallError::metadata(
            "RPM identity requires an explicit epoch",
        ));
    };
    let Some((version, release)) = vr.split_once('-') else {
        return Err(InstallError::metadata(
            "RPM identity requires version and release",
        ));
    };
    let rpm_scalar = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+~^".contains(&b))
    };
    if epoch.is_empty()
        || !epoch.bytes().all(|b| b.is_ascii_digit())
        || epoch.parse::<u32>().is_err()
        || (epoch.len() > 1 && epoch.starts_with('0'))
        || !rpm_scalar(version)
        || !rpm_scalar(release)
        || !release.ends_with(".fc44")
        || package.filename != format!("{}-{version}-{release}.{}.rpm", package.name, package.arch)
    {
        return Err(InstallError::metadata(
            "RPM NEVR, filename or Fedora release mismatch",
        ));
    }
    Ok(())
}
