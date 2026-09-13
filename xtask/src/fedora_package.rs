// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use stack_runtime::{ProcessRequest, ProcessRunner, SystemProcessRunner, Termination};
use thiserror::Error;

const RPM: &str = "/usr/bin/rpm";
const RPM_OUTPUT_LIMIT: usize = 4_194_304;
const RPM_STDERR_LIMIT: usize = 65_536;
const MAX_RPM_BYTES: u64 = 4_294_967_296;

const DRIVER_NAME: &str = "intel-npu-driver";
const DRIVER_ARCH: &str = "x86_64";
const DRIVER_LICENSE: &str = "/usr/share/licenses/intel-npu-driver/LICENSE.md";
const DRIVER_SONAME: &str = "/usr/lib64/libze_intel_npu.so.1";
const DRIVER_VERSIONED: &str = "/usr/lib64/libze_intel_npu.so.1.35.0";
const DRIVER_UNVERSIONED: &str = "/usr/lib64/libze_intel_npu.so";
const FIRMWARE_NAME: &str = "intel-npu-stack-firmware";
const FIRMWARE_ARCH: &str = "noarch";
const FIRMWARE_LICENSE_DIRECTORY: &str = "/usr/share/licenses/intel-npu-stack-firmware";
const FIRMWARE_NOTICE_MANIFEST: &str = "/usr/share/licenses/intel-npu-stack-firmware/SHA256.json";
const FIRMWARE_LICENSE: &str = "/usr/share/licenses/intel-npu-stack-firmware/COPYRIGHT";
const FIRMWARE_PATH: &str = "/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin";
const FIRMWARE_PROVIDE: &str = "intel-npu-firmware";
const FIRMWARE_PROVIDE_VERSION: &str = "1.35.0";

/// Exact Fedora driver/firmware package files to inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedoraDriverPackagePaths {
    pub driver: PathBuf,
    pub firmware: PathBuf,
}

/// Exact package identities and content binding expected by one build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverPackagePolicy {
    pub driver_nevr: String,
    pub loader_requirement: String,
    pub firmware_nevr: String,
    pub firmware_sha256: String,
}

/// Stable failure returned by Fedora package inspection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct FedoraPackageError {
    pub code: String,
    pub message: String,
}

impl FedoraPackageError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct RpmIdentity {
    name: String,
    nevr: String,
    architecture: String,
    file_digest_algorithm: String,
}

#[derive(Debug)]
struct RpmRelation {
    name: String,
    operator: String,
    version: Option<String>,
}

#[derive(Debug)]
struct RpmFile {
    path: String,
    mode: u32,
    digest: String,
    flags: String,
}

/// Validates one candidate Fedora driver and firmware RPM pair without installing it.
///
/// The inspector invokes `/usr/bin/rpm` directly with fixed argument arrays,
/// cleared environment, bounded output, and a deadline. It never executes RPM
/// scriptlets or modifies the RPM database.
///
/// # Errors
///
/// Returns a stable [`FedoraPackageError`] for an unsafe input path, failed or
/// malformed RPM query, wrong identity/dependency/script/file contract, absent
/// license evidence, or wrong firmware mode/digest.
pub fn validate_fedora_driver_packages(
    paths: &FedoraDriverPackagePaths,
    policy: &DriverPackagePolicy,
) -> Result<(), FedoraPackageError> {
    validate_policy(policy)?;
    let driver = require_rpm(&paths.driver)?;
    let firmware = require_rpm(&paths.firmware)?;

    validate_identity(
        &query_identity(&driver)?,
        DRIVER_NAME,
        &policy.driver_nevr,
        DRIVER_ARCH,
    )?;
    validate_identity(
        &query_identity(&firmware)?,
        FIRMWARE_NAME,
        &policy.firmware_nevr,
        FIRMWARE_ARCH,
    )?;

    require_relation(
        &query_relations(&driver, RelationKind::Requires)?,
        &policy.loader_requirement,
    )?;
    require_relation(
        &query_relations(&firmware, RelationKind::Provides)?,
        &format!("{FIRMWARE_PROVIDE} = {FIRMWARE_PROVIDE_VERSION}"),
    )?;
    reject_scripts(&driver)?;
    reject_scripts(&firmware)?;
    validate_driver_files(&query_files(&driver)?)?;
    validate_firmware_files(&query_files(&firmware)?, &policy.firmware_sha256)
}

fn validate_policy(policy: &DriverPackagePolicy) -> Result<(), FedoraPackageError> {
    if !safe_scalar(&policy.driver_nevr)
        || !safe_scalar(&policy.loader_requirement)
        || !safe_scalar(&policy.firmware_nevr)
        || !is_lower_hex(&policy.firmware_sha256, 64)
    {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_POLICY_INVALID",
            "package policy contains an invalid identity or digest",
        ));
    }
    Ok(())
}

fn require_rpm(path: &Path) -> Result<PathBuf, FedoraPackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        FedoraPackageError::new("FEDORA_PACKAGE_PATH_INVALID", "RPM input is unavailable")
    })?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RPM_BYTES
    {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_PATH_INVALID",
            "RPM input must be an absolute, bounded, regular non-symlink file",
        ));
    }
    path.canonicalize().map_err(|_| {
        FedoraPackageError::new(
            "FEDORA_PACKAGE_PATH_INVALID",
            "RPM input cannot be canonicalized",
        )
    })
}

fn query_identity(path: &Path) -> Result<RpmIdentity, FedoraPackageError> {
    let format = concat!(
        "%{NAME:json}\\n",
        "%{EPOCHNUM}\\n",
        "%{VERSION:json}\\n",
        "%{RELEASE:json}\\n",
        "%{ARCH:json}\\n",
        "%{FILEDIGESTALGO:hashalgo}\\n"
    );
    let output = rpm_query(path, &["--queryformat", format])?;
    let lines = text_lines(&output, 6)?;
    let name = json_string(lines[0])?;
    let epoch = lines[1];
    let version = json_string(lines[2])?;
    let release = json_string(lines[3])?;
    let architecture = json_string(lines[4])?;
    if !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(query_malformed());
    }
    Ok(RpmIdentity {
        name,
        nevr: format!("{epoch}:{version}-{release}"),
        architecture,
        file_digest_algorithm: lines[5].to_owned(),
    })
}

fn validate_identity(
    actual: &RpmIdentity,
    name: &str,
    nevr: &str,
    architecture: &str,
) -> Result<(), FedoraPackageError> {
    if actual.name != name
        || actual.nevr != nevr
        || actual.architecture != architecture
        || actual.file_digest_algorithm != "SHA256"
    {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_IDENTITY_INVALID",
            "RPM name, NEVR, architecture, or file digest algorithm is invalid",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RelationKind {
    Requires,
    Provides,
}

fn query_relations(
    path: &Path,
    kind: RelationKind,
) -> Result<Vec<RpmRelation>, FedoraPackageError> {
    let format = match kind {
        RelationKind::Requires => {
            "[%{REQUIRENAME:json}\\t%{REQUIREFLAGS:depflags}\\t%{REQUIREVERSION:json}\\n]"
        }
        RelationKind::Provides => {
            "[%{PROVIDENAME:json}\\t%{PROVIDEFLAGS:depflags}\\t%{PROVIDEVERSION:json}\\n]"
        }
    };
    let output = rpm_query(path, &["--queryformat", format])?;
    let text = std::str::from_utf8(&output).map_err(|_| query_malformed())?;
    let mut relations = Vec::new();
    for line in text.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(query_malformed());
        }
        let name = json_string(fields[0])?;
        let operator = fields[1].to_owned();
        let version = json_optional_string(fields[2])?;
        if !safe_scalar(&name)
            || operator.len() > 4
            || !operator
                .bytes()
                .all(|byte| matches!(byte, b'<' | b'=' | b'>'))
            || version.as_deref().is_some_and(|value| !safe_scalar(value))
        {
            return Err(query_malformed());
        }
        relations.push(RpmRelation {
            name,
            operator,
            version,
        });
    }
    Ok(relations)
}

fn require_relation(relations: &[RpmRelation], expected: &str) -> Result<(), FedoraPackageError> {
    let found = relations.iter().any(|relation| {
        let Some(version) = relation.version.as_deref() else {
            return false;
        };
        format!("{} {} {}", relation.name, relation.operator, version) == expected
    });
    if !found {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_DEPENDENCY_INVALID",
            "RPM is missing an exact required dependency or provide",
        ));
    }
    Ok(())
}

fn reject_scripts(path: &Path) -> Result<(), FedoraPackageError> {
    for option in ["--scripts", "--triggers", "--filetriggers"] {
        if !rpm_query(path, &[option])?.is_empty() {
            return Err(FedoraPackageError::new(
                "FEDORA_PACKAGE_SCRIPT_INVALID",
                "provider RPMs must not contain maintainer or trigger scripts",
            ));
        }
    }
    Ok(())
}

fn query_files(path: &Path) -> Result<Vec<RpmFile>, FedoraPackageError> {
    let format =
        "[%{FILENAMES:json}\\t%{FILEMODES:octal}\\t%{FILEDIGESTS:json}\\t%{FILEFLAGS:fflags}\\n]";
    let output = rpm_query(path, &["--queryformat", format])?;
    let text = std::str::from_utf8(&output).map_err(|_| query_malformed())?;
    let mut files = Vec::new();
    for line in text.lines() {
        let fields = line.splitn(4, '\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(query_malformed());
        }
        let path = json_string(fields[0])?;
        let mode = u32::from_str_radix(fields[1].trim_start_matches('0'), 8)
            .map_err(|_| query_malformed())?;
        let digest = json_string(fields[2])?;
        let flags = fields[3].to_owned();
        if !path.starts_with('/')
            || path.chars().any(char::is_control)
            || (!digest.is_empty() && !is_lower_hex(&digest, 64))
            || flags.chars().any(char::is_control)
        {
            return Err(query_malformed());
        }
        files.push(RpmFile {
            path,
            mode,
            digest,
            flags,
        });
    }
    Ok(files)
}

fn validate_driver_files(files: &[RpmFile]) -> Result<(), FedoraPackageError> {
    if files.iter().any(|file| {
        file.path == DRIVER_UNVERSIONED
            || !(file.path == "/usr/lib/.build-id"
                || file.path == "/usr/share/doc/intel-npu-driver"
                || file.path == "/usr/share/licenses/intel-npu-driver"
                || file.path.starts_with("/usr/lib64/libze_intel_npu.so.1")
                || file.path.starts_with("/usr/lib/.build-id/")
                || file.path.starts_with("/usr/share/doc/intel-npu-driver/")
                || file
                    .path
                    .starts_with("/usr/share/licenses/intel-npu-driver/"))
    }) || !has_file(files, DRIVER_SONAME)
        || !has_file(files, DRIVER_VERSIONED)
    {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_FILE_INVALID",
            "driver RPM owns an unapproved path or lacks its versioned SONAME files",
        ));
    }
    require_license(files, DRIVER_LICENSE)
}

fn validate_firmware_files(
    files: &[RpmFile],
    expected_sha256: &str,
) -> Result<(), FedoraPackageError> {
    if files.iter().any(|file| match file.path.as_str() {
        FIRMWARE_PATH | FIRMWARE_LICENSE => false,
        FIRMWARE_LICENSE_DIRECTORY => file.mode != 0o040755,
        FIRMWARE_NOTICE_MANIFEST => {
            file.mode != 0o100644 || !file.flags.contains('l') || !is_lower_hex(&file.digest, 64)
        }
        _ => true,
    }) {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_FILE_INVALID",
            "firmware RPM owns a path outside the approved firmware and license files",
        ));
    }
    require_license(files, FIRMWARE_LICENSE)?;
    let Some(firmware) = files.iter().find(|file| file.path == FIRMWARE_PATH) else {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_FIRMWARE_INVALID",
            "firmware RPM lacks the Lunar Lake firmware payload",
        ));
    };
    if firmware.mode != 0o100644 || firmware.digest != expected_sha256 {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_FIRMWARE_INVALID",
            "firmware mode or SHA-256 does not match the locked payload",
        ));
    }
    Ok(())
}

fn require_license(files: &[RpmFile], path: &str) -> Result<(), FedoraPackageError> {
    if files
        .iter()
        .any(|file| file.path == path && file.flags.contains('l'))
    {
        Ok(())
    } else {
        Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_LICENSE_INVALID",
            "RPM lacks its required packaged license evidence",
        ))
    }
}

fn has_file(files: &[RpmFile], path: &str) -> bool {
    files.iter().any(|file| file.path == path)
}

fn rpm_query(path: &Path, options: &[&str]) -> Result<Vec<u8>, FedoraPackageError> {
    let mut args = vec![OsString::from("--noplugins"), OsString::from("-qp")];
    args.extend(options.iter().map(OsString::from));
    args.push(path.as_os_str().to_owned());
    let output = SystemProcessRunner
        .run(&ProcessRequest {
            executable: PathBuf::from(RPM),
            args,
            timeout: Duration::from_secs(10),
            stdout_limit: RPM_OUTPUT_LIMIT,
            stderr_limit: RPM_STDERR_LIMIT,
            environment: Vec::new(),
        })
        .map_err(|_| {
            FedoraPackageError::new("FEDORA_PACKAGE_QUERY_FAILED", "bounded RPM query failed")
        })?;
    if output.termination != Termination::Exit(0)
        || output.stdout_overflow
        || output.stderr_overflow
    {
        return Err(FedoraPackageError::new(
            "FEDORA_PACKAGE_QUERY_FAILED",
            "RPM rejected a package or exceeded its query bounds",
        ));
    }
    Ok(output.stdout)
}

fn text_lines(bytes: &[u8], expected: usize) -> Result<Vec<&str>, FedoraPackageError> {
    let text = std::str::from_utf8(bytes).map_err(|_| query_malformed())?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != expected {
        return Err(query_malformed());
    }
    Ok(lines)
}

fn json_string(value: &str) -> Result<String, FedoraPackageError> {
    serde_json::from_str::<String>(value).map_err(|_| query_malformed())
}

fn json_optional_string(value: &str) -> Result<Option<String>, FedoraPackageError> {
    if value == "(none)" {
        Ok(None)
    } else {
        serde_json::from_str::<Option<String>>(value)
            .map(|value| value.filter(|text| !text.is_empty()))
            .map_err(|_| query_malformed())
    }
}

fn query_malformed() -> FedoraPackageError {
    FedoraPackageError::new(
        "FEDORA_PACKAGE_QUERY_MALFORMED",
        "RPM query returned malformed metadata",
    )
}

fn safe_scalar(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
