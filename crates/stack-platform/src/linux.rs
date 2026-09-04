// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::Read;
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
    pub effective_root: bool,
    pub boot_time_epoch: u64,
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
    let process_status = read_bounded(paths, "proc/self/status", "PLATFORM_PROCESS_INVALID")?;
    let effective_root = parse_effective_root(&process_status)?;
    let proc_stat = read_bounded(paths, "proc/stat", "PLATFORM_BOOT_TIME_INVALID")?;
    let boot_time_epoch = parse_boot_time(&proc_stat)?;

    Ok(PlatformFacts {
        os_id: os.id,
        os_version_id: os.version_id,
        arch: arch.to_owned(),
        kernel,
        pci_ids,
        intel_vpu_loaded,
        accel_node_present,
        effective_root,
        boot_time_epoch,
    })
}

fn read_bounded(
    paths: &PlatformPaths,
    relative: &str,
    invalid_code: &'static str,
) -> Result<String, PlatformError> {
    const LIMIT: usize = 1_048_576;
    let mut file = File::open(paths.root.join(relative)).map_err(|error| {
        PlatformError::new(
            "PLATFORM_IO_ERROR",
            format!("cannot read required platform fact {relative}: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PlatformError::new(
                "PLATFORM_IO_ERROR",
                format!("cannot read required platform fact {relative}: {error}"),
            )
        })?;
    if bytes.len() > LIMIT {
        return Err(PlatformError::new(
            invalid_code,
            "platform fact exceeds its byte limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| PlatformError::new(invalid_code, "platform fact is not valid UTF-8"))
}

fn parse_effective_root(status: &str) -> Result<bool, PlatformError> {
    let rows = status
        .lines()
        .filter_map(|line| line.strip_prefix("Uid:"))
        .collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(PlatformError::new(
            "PLATFORM_PROCESS_INVALID",
            "process status must contain exactly one UID row",
        ));
    }
    let fields = rows[0].split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 4
        || fields
            .iter()
            .any(|field| field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(PlatformError::new(
            "PLATFORM_PROCESS_INVALID",
            "process UID row is malformed",
        ));
    }
    let effective = fields[1].parse::<u32>().map_err(|_| {
        PlatformError::new("PLATFORM_PROCESS_INVALID", "effective UID is out of range")
    })?;
    Ok(effective == 0)
}

fn parse_boot_time(stat: &str) -> Result<u64, PlatformError> {
    let rows = stat
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            (fields.next() == Some("btime")).then(|| fields.collect::<Vec<_>>())
        })
        .collect::<Vec<_>>();
    if rows.len() != 1 || rows[0].len() != 1 {
        return Err(PlatformError::new(
            "PLATFORM_BOOT_TIME_INVALID",
            "process statistics must contain one exact boot-time row",
        ));
    }
    let value = rows[0][0];
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PlatformError::new(
            "PLATFORM_BOOT_TIME_INVALID",
            "boot time is malformed",
        ));
    }
    value
        .parse()
        .map_err(|_| PlatformError::new("PLATFORM_BOOT_TIME_INVALID", "boot time is out of range"))
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
