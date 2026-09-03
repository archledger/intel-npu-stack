// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use stack_schema::{KernelVersion, PciId};

use crate::{PlatformError, parse_os_release};

/// Filesystem root used for Linux fact discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPaths {
    pub root: PathBuf,
}

impl PlatformPaths {
    /// Uses the running system's filesystem root.
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }
}

/// Sanitized platform facts used for profile matching and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformFacts {
    pub os_id: String,
    pub os_version_id: String,
    pub arch: String,
    pub kernel: KernelVersion,
    pub pci_ids: Vec<PciId>,
    pub intel_vpu_loaded: bool,
    pub accel_node_present: bool,
}

/// Reads Linux facts only through the supplied filesystem root.
pub fn detect_platform(paths: &PlatformPaths, arch: &str) -> Result<PlatformFacts, PlatformError> {
    if arch.is_empty() || arch.trim() != arch {
        return Err(PlatformError::new(
            "PLATFORM_OS_RELEASE_INVALID",
            "architecture must be nonempty",
        ));
    }

    let os_release = read(paths, "etc/os-release")?;
    let os = parse_os_release(&os_release)?;

    let kernel_release = read(paths, "proc/sys/kernel/osrelease")?;
    let kernel = KernelVersion::parse_release(kernel_release.trim_end())
        .map_err(|error| PlatformError::new("PLATFORM_KERNEL_INVALID", error.to_string()))?;

    let modules = read(paths, "proc/modules")?;
    let intel_vpu_loaded = modules.lines().any(|line| {
        line.split_ascii_whitespace()
            .next()
            .is_some_and(|name| name == "intel_vpu")
    });

    let mut pci_ids = read_pci_ids(&paths.root.join("sys/bus/pci/devices"))?;
    pci_ids.sort();
    pci_ids.dedup();

    let accel_node_present = has_accel_node(&paths.root.join("dev/accel"))?;

    Ok(PlatformFacts {
        os_id: os.id,
        os_version_id: os.version_id,
        arch: arch.to_owned(),
        kernel,
        pci_ids,
        intel_vpu_loaded,
        accel_node_present,
    })
}

fn read(paths: &PlatformPaths, relative: &str) -> Result<String, PlatformError> {
    fs::read_to_string(paths.root.join(relative)).map_err(|error| {
        PlatformError::new(
            "PLATFORM_IO_ERROR",
            format!("cannot read required platform fact {relative}: {error}"),
        )
    })
}

fn read_pci_ids(devices: &Path) -> Result<Vec<PciId>, PlatformError> {
    let entries = match fs::read_dir(devices) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(PlatformError::new(
                "PLATFORM_IO_ERROR",
                format!("cannot enumerate PCI devices: {error}"),
            ));
        }
    };

    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            PlatformError::new(
                "PLATFORM_IO_ERROR",
                format!("cannot enumerate a PCI device: {error}"),
            )
        })?;
        let vendor = fs::read_to_string(entry.path().join("vendor")).map_err(|error| {
            PlatformError::new(
                "PLATFORM_IO_ERROR",
                format!("cannot read a PCI vendor identifier: {error}"),
            )
        })?;
        let device = fs::read_to_string(entry.path().join("device")).map_err(|error| {
            PlatformError::new(
                "PLATFORM_IO_ERROR",
                format!("cannot read a PCI device identifier: {error}"),
            )
        })?;
        ids.push(PciId {
            vendor: normalize_pci_id(&vendor)?,
            device: normalize_pci_id(&device)?,
        });
    }
    Ok(ids)
}

fn normalize_pci_id(value: &str) -> Result<String, PlatformError> {
    let value = value.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PlatformError::new(
            "PLATFORM_PCI_INVALID",
            "PCI identifiers must contain exactly four hexadecimal digits",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn has_accel_node(directory: &Path) -> Result<bool, PlatformError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(PlatformError::new(
                "PLATFORM_IO_ERROR",
                format!("cannot enumerate accelerator nodes: {error}"),
            ));
        }
    };

    for entry in entries {
        let name = entry
            .map_err(|error| {
                PlatformError::new(
                    "PLATFORM_IO_ERROR",
                    format!("cannot enumerate an accelerator node: {error}"),
                )
            })?
            .file_name();
        let name = name.to_string_lossy();
        if name
            .strip_prefix("accel")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
