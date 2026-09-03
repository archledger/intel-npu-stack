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

/// Exact version and immutable source identity for one logical capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRequirement {
    pub version: String,
    pub source: String,
    pub sha256: String,
}

/// Evidence binding required before a profile can be marked qualified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRecord {
    pub evidence_id: String,
    pub qualified_at: String,
}

/// Versioned, independently qualified compatibility matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub id: String,
    pub stack_release: String,
    pub status: ProfileStatus,
    pub platform: PlatformSelector,
    pub hardware: Vec<PciId>,
    pub kernel: KernelRange,
    pub components: BTreeMap<String, ComponentRequirement>,
    pub qualification: Option<QualificationRecord>,
}

impl Profile {
    /// Parses a TOML document and applies all schema-version-one validation.
    pub fn parse_toml(input: &str) -> Result<Self, SchemaError> {
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
            if component.sha256.len() != 64
                || !component
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(SchemaError::new(
                    "PROFILE_HASH_INVALID",
                    format!("component {name} SHA-256 must be 64 lowercase hexadecimal digits"),
                ));
            }
        }

        if self.status == ProfileStatus::Qualified {
            let evidence = self.qualification.as_ref().ok_or_else(|| {
                SchemaError::new(
                    "PROFILE_QUALIFICATION_MISSING",
                    "qualified profile requires qualification evidence",
                )
            })?;
            require_nonempty("qualification evidence id", &evidence.evidence_id)?;
            require_nonempty("qualification timestamp", &evidence.qualified_at)?;
        }

        Ok(())
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), SchemaError> {
    if value.is_empty() || value.trim() != value {
        return Err(SchemaError::new(
            "PROFILE_FIELD_INVALID",
            format!("{field} must be nonempty and have no surrounding whitespace"),
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
