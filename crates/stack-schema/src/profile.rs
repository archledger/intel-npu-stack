// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{KernelVersion, PROFILE_SCHEMA_VERSION, SchemaError};

const REQUIRED_COMPONENTS: [&str; 6] = [
    "level_zero_loader",
    "npu_compiler",
    "npu_firmware",
    "npu_userspace_driver",
    "openvino_npu_plugin",
    "openvino_runtime",
];

const MAX_PROFILE_BYTES: usize = 1_048_576;
const MAX_SCALAR_BYTES: usize = 4096;
const MAX_HARDWARE_IDS: usize = 64;
const MAX_CONFLICTS: usize = 32;
const MAX_PROVIDER_FILES: usize = 16;
const APPROVED_FILE_PREFIXES: [&str; 6] = [
    "/usr/bin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/usr/share/",
    "/usr/lib/firmware/",
];

/// Qualification lifecycle state recorded in a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Candidate,
    Experimental,
    Qualified,
    Unsupported,
    Deprecated,
}

/// Native package database used by a distribution profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Rpm,
    Dpkg,
    Pacman,
}

/// Host action needed before an installed provider becomes active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationRequirement {
    Immediate,
    Reboot,
    Relogin,
}

/// Qualification-time redistribution decision for one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedistributionVerdict {
    Allowed,
    ExternalOnly,
    Forbidden,
}

/// The only conflict resolution represented by schema version one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    Remove,
}

/// Exact operating-system selector for a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformSelector {
    pub id: String,
    pub version_id: String,
    pub arch: String,
}

/// Normalized PCI vendor and device identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PciId {
    pub vendor: String,
    pub device: String,
}

/// Inclusive minimum and exclusive maximum supported kernel release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRange {
    pub min: String,
    pub max_exclusive: String,
    pub module: String,
}

/// One package-owned file whose content was fixed by qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledFile {
    pub path: String,
    pub sha256: String,
}

/// Exact native package expected to provide one logical component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProvider {
    pub package: String,
    pub version: String,
    pub activation: ActivationRequirement,
    pub files: Vec<InstalledFile>,
}

/// License and reviewed provenance binding for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseRecord {
    pub expression: String,
    pub redistribution: RedistributionVerdict,
    pub evidence_sha256: String,
}

/// Native package that must be absent before a future installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageConflict {
    pub package: String,
    pub resolution: ConflictResolution,
}

/// Exact version and immutable source identity for one logical capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRequirement {
    pub version: String,
    pub source: String,
    pub sha256: String,
    pub provider: NativeProvider,
    pub license: LicenseRecord,
}

/// Evidence binding required before a profile can be marked qualified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRecord {
    pub evidence_id: String,
    pub evidence_sha256: String,
    pub qualified_at: String,
    pub hardware_class: String,
    pub test_suite_version: String,
}

/// Versioned, independently qualified compatibility matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub id: String,
    pub stack_release: String,
    pub status: ProfileStatus,
    pub package_manager: PackageManager,
    pub conflicts: Vec<PackageConflict>,
    pub platform: PlatformSelector,
    pub hardware: Vec<PciId>,
    pub kernel: KernelRange,
    pub components: BTreeMap<String, ComponentRequirement>,
    pub qualification: Option<QualificationRecord>,
}

impl Profile {
    /// Parses a TOML document and applies all schema-version-one validation.
    pub fn parse_toml(input: &str) -> Result<Self, SchemaError> {
        if input.len() > MAX_PROFILE_BYTES {
            return Err(resource_limit("profile input exceeds 1048576 bytes"));
        }
        let profile = toml::from_str::<Self>(input).map_err(|error| {
            SchemaError::new("PROFILE_TOML_INVALID", format!("invalid TOML: {error}"))
        })?;
        profile.validate()?;
        Ok(profile)
    }

    /// Validates semantic constraints that TOML deserialization cannot express.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(SchemaError::new(
                "PROFILE_SCHEMA_UNSUPPORTED",
                format!("unsupported schema version {}", self.schema_version),
            ));
        }

        if self.hardware.len() > MAX_HARDWARE_IDS {
            return Err(resource_limit(
                "profile has more than 64 hardware identifiers",
            ));
        }
        if self.conflicts.len() > MAX_CONFLICTS {
            return Err(resource_limit("profile has more than 32 conflicts"));
        }
        self.validate_scalar_limits()?;

        require_nonempty("profile id", &self.id)?;
        require_nonempty("stack release", &self.stack_release)?;
        require_nonempty("platform id", &self.platform.id)?;
        require_nonempty("platform version", &self.platform.version_id)?;
        require_nonempty("platform architecture", &self.platform.arch)?;

        if self.hardware.is_empty() {
            return Err(SchemaError::new(
                "PROFILE_PCI_ID_INVALID",
                "at least one PCI identifier is required",
            ));
        }

        let mut previous_conflict: Option<&str> = None;
        for conflict in &self.conflicts {
            if !is_package_name(&conflict.package) {
                return Err(package_invalid("conflict package name is invalid"));
            }
            if previous_conflict.is_some_and(|previous| previous >= conflict.package.as_str()) {
                return Err(package_invalid(
                    "conflict package names must be sorted and unique",
                ));
            }
            previous_conflict = Some(&conflict.package);
        }
        for pci_id in &self.hardware {
            if !is_lower_hex_quad(&pci_id.vendor) || !is_lower_hex_quad(&pci_id.device) {
                return Err(SchemaError::new(
                    "PROFILE_PCI_ID_INVALID",
                    format!("invalid PCI identifier {}:{}", pci_id.vendor, pci_id.device),
                ));
            }
        }

        if self.kernel.module != "intel_vpu" {
            return Err(SchemaError::new(
                "PROFILE_FIELD_INVALID",
                "kernel module must be intel_vpu",
            ));
        }
        let minimum = KernelVersion::parse_release(&self.kernel.min)?;
        let maximum = KernelVersion::parse_release(&self.kernel.max_exclusive)?;
        if minimum >= maximum {
            return Err(SchemaError::new(
                "PROFILE_KERNEL_RANGE_INVALID",
                "kernel minimum must be lower than the exclusive maximum",
            ));
        }

        let actual = self
            .components
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let required = REQUIRED_COMPONENTS.into_iter().collect::<BTreeSet<_>>();
        if let Some(missing) = required.difference(&actual).next() {
            return Err(SchemaError::new(
                "PROFILE_COMPONENT_MISSING",
                format!("required component {missing} is missing"),
            ));
        }
        if let Some(extra) = actual.difference(&required).next() {
            return Err(SchemaError::new(
                "PROFILE_FIELD_INVALID",
                format!("unknown component {extra}"),
            ));
        }

        for (name, component) in &self.components {
            require_nonempty(&format!("component {name} version"), &component.version)?;
            if !is_https_source(&component.source) {
                return Err(SchemaError::new(
                    "PROFILE_FIELD_INVALID",
                    format!("component {name} source must be a nonempty HTTPS URL"),
                ));
            }
            if !is_sha256(&component.sha256) {
                return Err(SchemaError::new(
                    "PROFILE_HASH_INVALID",
                    format!("component {name} SHA-256 must be 64 lowercase hexadecimal digits"),
                ));
            }

            if !is_package_name(&component.provider.package) {
                return Err(package_invalid(format!(
                    "component {name} provider package is invalid"
                )));
            }
            if !is_package_version(&component.provider.version) {
                return Err(package_invalid(format!(
                    "component {name} provider version is invalid"
                )));
            }
            if component.provider.files.is_empty()
                || component.provider.files.len() > MAX_PROVIDER_FILES
            {
                return Err(resource_limit(format!(
                    "component {name} must have between 1 and 16 critical files"
                )));
            }
            for file in &component.provider.files {
                if !is_approved_file_path(&file.path) {
                    return Err(SchemaError::new(
                        "PROFILE_PATH_INVALID",
                        format!("component {name} critical file path is invalid"),
                    ));
                }
                if !is_sha256(&file.sha256) {
                    return Err(SchemaError::new(
                        "PROFILE_HASH_INVALID",
                        format!(
                            "component {name} critical file SHA-256 must be 64 lowercase hexadecimal digits"
                        ),
                    ));
                }
            }

            require_nonempty(
                &format!("component {name} license expression"),
                &component.license.expression,
            )?;
            if !is_sha256(&component.license.evidence_sha256) {
                return Err(provenance_invalid(format!(
                    "component {name} license evidence SHA-256 is invalid"
                )));
            }
        }

        if self.status == ProfileStatus::Qualified {
            let evidence = self.qualification.as_ref().ok_or_else(|| {
                SchemaError::new(
                    "PROFILE_QUALIFICATION_MISSING",
                    "qualified profile requires qualification evidence",
                )
            })?;
            require_qualification_text("qualification evidence id", &evidence.evidence_id)?;
            if !is_sha256(&evidence.evidence_sha256) {
                return Err(provenance_invalid(
                    "qualification evidence SHA-256 is invalid",
                ));
            }
            require_qualification_text("qualification timestamp", &evidence.qualified_at)?;
            require_qualification_text("qualification hardware class", &evidence.hardware_class)?;
            require_qualification_text(
                "qualification test suite version",
                &evidence.test_suite_version,
            )?;
            if self.components.values().any(|component| {
                component.license.redistribution == RedistributionVerdict::Forbidden
            }) {
                return Err(provenance_invalid(
                    "qualified profile contains a forbidden redistribution verdict",
                ));
            }
        }

        Ok(())
    }

    fn validate_scalar_limits(&self) -> Result<(), SchemaError> {
        for value in [
            self.id.as_str(),
            self.stack_release.as_str(),
            self.platform.id.as_str(),
            self.platform.version_id.as_str(),
            self.platform.arch.as_str(),
            self.kernel.min.as_str(),
            self.kernel.max_exclusive.as_str(),
            self.kernel.module.as_str(),
        ] {
            check_scalar_limit(value)?;
        }
        for hardware in &self.hardware {
            check_scalar_limit(&hardware.vendor)?;
            check_scalar_limit(&hardware.device)?;
        }
        for conflict in &self.conflicts {
            check_scalar_limit(&conflict.package)?;
        }
        for (name, component) in &self.components {
            for value in [
                name.as_str(),
                component.version.as_str(),
                component.source.as_str(),
                component.sha256.as_str(),
                component.provider.package.as_str(),
                component.provider.version.as_str(),
                component.license.expression.as_str(),
                component.license.evidence_sha256.as_str(),
            ] {
                check_scalar_limit(value)?;
            }
            for file in &component.provider.files {
                check_scalar_limit(&file.path)?;
                check_scalar_limit(&file.sha256)?;
            }
        }
        if let Some(evidence) = &self.qualification {
            for value in [
                evidence.evidence_id.as_str(),
                evidence.evidence_sha256.as_str(),
                evidence.qualified_at.as_str(),
                evidence.hardware_class.as_str(),
                evidence.test_suite_version.as_str(),
            ] {
                check_scalar_limit(value)?;
            }
        }
        Ok(())
    }
}

fn check_scalar_limit(value: &str) -> Result<(), SchemaError> {
    if value.len() > MAX_SCALAR_BYTES {
        return Err(resource_limit("profile scalar exceeds 4096 bytes"));
    }
    Ok(())
}

fn resource_limit(message: impl Into<String>) -> SchemaError {
    SchemaError::new("PROFILE_RESOURCE_LIMIT", message)
}

fn package_invalid(message: impl Into<String>) -> SchemaError {
    SchemaError::new("PROFILE_PACKAGE_INVALID", message)
}

fn provenance_invalid(message: impl Into<String>) -> SchemaError {
    SchemaError::new("PROFILE_PROVENANCE_INVALID", message)
}

fn require_nonempty(field: &str, value: &str) -> Result<(), SchemaError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(SchemaError::new(
            "PROFILE_FIELD_INVALID",
            format!("{field} must be nonempty and contain no surrounding whitespace or controls"),
        ));
    }
    Ok(())
}

fn require_qualification_text(field: &str, value: &str) -> Result<(), SchemaError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(SchemaError::new(
            "PROFILE_QUALIFICATION_MISSING",
            format!("{field} must be nonempty and contain no surrounding whitespace or controls"),
        ));
    }
    Ok(())
}

fn is_lower_hex_quad(value: &str) -> bool {
    value.len() == 4
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_https_source(value: &str) -> bool {
    value.strip_prefix("https://").is_some_and(|remainder| {
        !remainder.is_empty() && !remainder.chars().any(char::is_whitespace)
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_package_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
}

fn is_package_version(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'+' | b'-' | b'_' | b':' | b'~' | b'^')
        })
}

fn is_approved_file_path(value: &str) -> bool {
    APPROVED_FILE_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}
