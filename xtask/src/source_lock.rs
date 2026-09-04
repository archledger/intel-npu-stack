// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SOURCE_LOCK_SCHEMA_VERSION: u32 = 1;
const MAX_SOURCE_LOCK_BYTES: usize = 1_048_576;
const MAX_SCALAR_BYTES: usize = 4096;
const MAX_SOURCES: usize = 256;
const MAX_LICENSE_FILES: usize = 64;
const MAX_GITLINKS: usize = 256;

/// Lifecycle state for a provider source lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLockStatus {
    /// Source discovery is incomplete and the lock cannot feed packaging.
    Draft,
    /// Every required source and evidence file has been reviewed and pinned.
    Sealed,
}

/// Supported immutable Git identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A lightweight tag whose ref must resolve directly to `commit`.
    GitTag,
    /// An annotated tag whose tag object and peeled commit are both pinned.
    GitAnnotatedTag,
    /// A commit used directly where no release tag exists.
    GitCommit,
}

/// Reviewed redistribution decision for a source record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRedistribution {
    /// The reviewed license permits the intended redistribution.
    Allowed,
    /// The source may be referenced but must not be redistributed by the project.
    ExternalOnly,
}

/// Exact target to which a provider source lock applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTarget {
    pub distribution_id: String,
    pub version_id: String,
    pub architecture: String,
    pub pci_vendor: String,
    pub pci_device: String,
}

/// One gitlink declared by a parent source record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceGitlinkDisposition {
    /// The gitlink is supplied by another source record and archive.
    Bundled,
    /// The gitlink is replaced by one exact Fedora package build dependency.
    System,
    /// The gitlink belongs to a component disabled by the recorded build option.
    Disabled,
}

/// One exact Fedora binary package used to replace a source gitlink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSystemPackage {
    pub name: String,
    pub nevr: String,
}

/// One gitlink declared by a parent source record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceGitlink {
    pub path: PathBuf,
    pub commit: String,
    pub disposition: SourceGitlinkDisposition,
    pub source: Option<String>,
    #[serde(default)]
    pub packages: Vec<SourceSystemPackage>,
    pub build_option: Option<String>,
}

/// One exact source input and its reviewed license evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    pub name: String,
    pub role: String,
    pub kind: SourceKind,
    pub url: String,
    pub tag: Option<String>,
    pub tag_object: Option<String>,
    pub commit: String,
    pub archive_sha256: String,
    pub license_expression: String,
    pub license_files: Vec<PathBuf>,
    pub license_evidence_sha256: String,
    pub redistribution: SourceRedistribution,
    #[serde(default)]
    pub gitlinks: Vec<SourceGitlink>,
}

/// Validated source lock safe for later acquisition or packaging policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedSourceLock {
    pub schema_version: u32,
    pub status: SourceLockStatus,
    pub profile_id: String,
    pub target: SourceTarget,
    pub sources: Vec<SourceRecord>,
}

/// Stable validation error with a machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct SourceLockError {
    pub code: String,
    pub message: String,
}

impl SourceLockError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }

    /// Returns the CLI exit class for this error.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.code == "SOURCE_LOCK_IO" { 2 } else { 1 }
    }
}

/// Parses and validates one source lock without network access or subprocesses.
///
/// # Errors
///
/// Returns a stable [`SourceLockError`] when the lock, its path, or its license
/// evidence violates the version-one contract.
pub fn validate(
    path: &Path,
    repository_root: &Path,
) -> Result<ValidatedSourceLock, SourceLockError> {
    reject_symlink(path, "source lock")?;
    let repository_root = repository_root
        .canonicalize()
        .map_err(|error| io_error("canonicalize repository root", error))?;
    let canonical_path = path
        .canonicalize()
        .map_err(|error| io_error("canonicalize source lock", error))?;
    if !canonical_path.starts_with(&repository_root) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_PATH_INVALID",
            "source lock must be inside the repository root",
        ));
    }

    let bytes = fs::read(&canonical_path).map_err(|error| io_error("read source lock", error))?;
    if bytes.len() > MAX_SOURCE_LOCK_BYTES {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_RESOURCE_LIMIT",
            "source lock exceeds 1048576 bytes",
        ));
    }
    let input = std::str::from_utf8(&bytes).map_err(|_| {
        SourceLockError::new("SOURCE_LOCK_TOML_INVALID", "source lock is not UTF-8")
    })?;
    let lock = toml::from_str::<ValidatedSourceLock>(input).map_err(|error| {
        SourceLockError::new(
            "SOURCE_LOCK_TOML_INVALID",
            format!("invalid source-lock TOML: {error}"),
        )
    })?;

    validate_lock(&lock, &repository_root)?;
    Ok(lock)
}

fn validate_lock(
    lock: &ValidatedSourceLock,
    repository_root: &Path,
) -> Result<(), SourceLockError> {
    if lock.schema_version != SOURCE_LOCK_SCHEMA_VERSION {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_SCHEMA_UNSUPPORTED",
            format!("unsupported source-lock schema {}", lock.schema_version),
        ));
    }
    for value in [
        lock.profile_id.as_str(),
        lock.target.distribution_id.as_str(),
        lock.target.version_id.as_str(),
        lock.target.architecture.as_str(),
        lock.target.pci_vendor.as_str(),
        lock.target.pci_device.as_str(),
    ] {
        require_scalar(value)?;
    }
    if !is_lower_hex_quad(&lock.target.pci_vendor) || !is_lower_hex_quad(&lock.target.pci_device) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_TARGET_INVALID",
            "PCI vendor and device must be four lowercase hexadecimal digits",
        ));
    }
    if lock.sources.len() > MAX_SOURCES {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_RESOURCE_LIMIT",
            "source lock has more than 256 records",
        ));
    }
    if lock.status == SourceLockStatus::Sealed && lock.sources.is_empty() {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_EMPTY",
            "a sealed source lock must contain at least one record",
        ));
    }

    let mut previous_name: Option<&str> = None;
    for source in &lock.sources {
        validate_source(source, repository_root)?;
        if previous_name.is_some_and(|previous| previous >= source.name.as_str()) {
            return Err(SourceLockError::new(
                "SOURCE_LOCK_NAME_INVALID",
                "source names must be sorted and unique",
            ));
        }
        previous_name = Some(&source.name);
    }
    Ok(())
}

fn validate_source(source: &SourceRecord, repository_root: &Path) -> Result<(), SourceLockError> {
    for value in [
        source.name.as_str(),
        source.role.as_str(),
        source.url.as_str(),
        source.commit.as_str(),
        source.archive_sha256.as_str(),
        source.license_expression.as_str(),
        source.license_evidence_sha256.as_str(),
    ] {
        require_scalar(value)?;
    }
    if !is_identifier(&source.name) || !is_identifier(&source.role) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_NAME_INVALID",
            "source names and roles must use lowercase ASCII identifiers",
        ));
    }
    if !is_https_url(&source.url) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_URL_INVALID",
            "source URL must use HTTPS without control characters",
        ));
    }
    if !is_lower_hex(&source.commit, 40) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_COMMIT_INVALID",
            "Git commit must be exactly 40 lowercase hexadecimal digits",
        ));
    }
    validate_git_identity(source)?;
    if !is_nonzero_sha256(&source.archive_sha256) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_ARCHIVE_HASH_INVALID",
            "archive SHA-256 must be nonzero lowercase hexadecimal",
        ));
    }
    if source.license_files.is_empty() || source.license_files.len() > MAX_LICENSE_FILES {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_LICENSE_PATH_INVALID",
            "each source requires between 1 and 64 license evidence files",
        ));
    }
    if !is_nonzero_sha256(&source.license_evidence_sha256) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_LICENSE_EVIDENCE_INVALID",
            "license evidence SHA-256 must be nonzero lowercase hexadecimal",
        ));
    }

    let actual = hash_license_evidence(&source.license_files, repository_root)?;
    if actual != source.license_evidence_sha256 {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_LICENSE_EVIDENCE_INVALID",
            format!("license evidence digest mismatch for {}", source.name),
        ));
    }
    validate_gitlinks(&source.gitlinks)?;
    Ok(())
}

fn validate_gitlinks(gitlinks: &[SourceGitlink]) -> Result<(), SourceLockError> {
    if gitlinks.len() > MAX_GITLINKS {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_RESOURCE_LIMIT",
            "source record has more than 256 gitlinks",
        ));
    }
    let mut previous: Option<&Path> = None;
    for gitlink in gitlinks {
        if gitlink.path.is_absolute()
            || gitlink
                .path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || previous.is_some_and(|value| value >= gitlink.path.as_path())
        {
            return Err(SourceLockError::new(
                "SOURCE_LOCK_GITLINK_INVALID",
                "gitlink paths must be sorted, unique, relative normal paths",
            ));
        }
        if !is_lower_hex(&gitlink.commit, 40) {
            return Err(SourceLockError::new(
                "SOURCE_LOCK_GITLINK_INVALID",
                "gitlink commit is invalid",
            ));
        }
        validate_gitlink_disposition(gitlink)?;
        previous = Some(&gitlink.path);
    }
    Ok(())
}

fn validate_gitlink_disposition(gitlink: &SourceGitlink) -> Result<(), SourceLockError> {
    let valid = match gitlink.disposition {
        SourceGitlinkDisposition::Bundled => {
            gitlink.source.as_deref().is_some_and(is_identifier)
                && gitlink.packages.is_empty()
                && gitlink.build_option.is_none()
        }
        SourceGitlinkDisposition::System => {
            gitlink.source.is_none()
                && valid_system_packages(&gitlink.packages)
                && gitlink.build_option.is_none()
        }
        SourceGitlinkDisposition::Disabled => {
            gitlink.source.is_none()
                && gitlink.packages.is_empty()
                && gitlink.build_option.as_deref().is_some_and(is_build_option)
        }
    };
    if !valid {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_GITLINK_INVALID",
            "gitlink disposition fields are incomplete or ambiguous",
        ));
    }
    Ok(())
}

fn valid_system_packages(packages: &[SourceSystemPackage]) -> bool {
    if packages.is_empty() || packages.len() > 16 {
        return false;
    }
    let mut previous: Option<&str> = None;
    for package in packages {
        if !is_package_name(&package.name)
            || !is_nevr(&package.nevr)
            || previous.is_some_and(|name| name >= package.name.as_str())
        {
            return false;
        }
        previous = Some(&package.name);
    }
    true
}

fn validate_git_identity(source: &SourceRecord) -> Result<(), SourceLockError> {
    match source.kind {
        SourceKind::GitTag => {
            require_tag(source.tag.as_deref())?;
            if source.tag_object.is_some() {
                return Err(SourceLockError::new(
                    "SOURCE_LOCK_TAG_OBJECT_INVALID",
                    "a lightweight tag must not have a tag object",
                ));
            }
        }
        SourceKind::GitAnnotatedTag => {
            require_tag(source.tag.as_deref())?;
            if !source
                .tag_object
                .as_deref()
                .is_some_and(|value| is_lower_hex(value, 40))
            {
                return Err(SourceLockError::new(
                    "SOURCE_LOCK_TAG_OBJECT_INVALID",
                    "an annotated tag requires its exact 40-digit tag object",
                ));
            }
        }
        SourceKind::GitCommit => {
            if source.tag.is_some() || source.tag_object.is_some() {
                return Err(SourceLockError::new(
                    "SOURCE_LOCK_TAG_OBJECT_INVALID",
                    "a direct commit source must not declare tag fields",
                ));
            }
        }
    }
    Ok(())
}

fn require_tag(tag: Option<&str>) -> Result<(), SourceLockError> {
    let Some(tag) = tag else {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_TAG_INVALID",
            "a tagged source requires a tag name",
        ));
    };
    require_scalar(tag)?;
    if tag.starts_with('-') || tag.chars().any(char::is_control) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_TAG_INVALID",
            "tag name is not safe for fixed-argument Git invocation",
        ));
    }
    Ok(())
}

fn hash_license_evidence(
    paths: &[PathBuf],
    repository_root: &Path,
) -> Result<String, SourceLockError> {
    let mut previous: Option<&Path> = None;
    let mut seen = BTreeSet::new();
    let mut hasher = Sha256::new();

    for relative in paths {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || previous.is_some_and(|value| value >= relative.as_path())
            || !seen.insert(relative)
        {
            return Err(SourceLockError::new(
                "SOURCE_LOCK_LICENSE_PATH_INVALID",
                "license evidence paths must be sorted, unique, relative normal paths",
            ));
        }
        previous = Some(relative);

        let candidate = repository_root.join(relative);
        reject_symlink(&candidate, "license evidence")?;
        let canonical = candidate.canonicalize().map_err(|error| {
            SourceLockError::new(
                "SOURCE_LOCK_LICENSE_PATH_INVALID",
                format!("cannot resolve license evidence: {error}"),
            )
        })?;
        if !canonical.starts_with(repository_root) || !canonical.is_file() {
            return Err(SourceLockError::new(
                "SOURCE_LOCK_LICENSE_PATH_INVALID",
                "license evidence must be a regular file inside the repository",
            ));
        }
        let bytes =
            fs::read(&canonical).map_err(|error| io_error("read license evidence", error))?;
        hasher.update(bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), SourceLockError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error("inspect path", error))?;
    if metadata.file_type().is_symlink() {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_LICENSE_PATH_INVALID",
            format!("{label} must not be a symlink"),
        ));
    }
    Ok(())
}

fn require_scalar(value: &str) -> Result<(), SourceLockError> {
    if value.is_empty() || value.len() > MAX_SCALAR_BYTES || value.chars().any(char::is_control) {
        return Err(SourceLockError::new(
            "SOURCE_LOCK_FIELD_INVALID",
            "source-lock scalar is empty, oversized, or contains control characters",
        ));
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn is_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCALAR_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'+')
        })
}

fn is_nevr(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCALAR_BYTES
        && value.contains(':')
        && value.contains('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b':' | b'-' | b'_' | b'.' | b'+' | b'~' | b'^')
        })
}

fn is_build_option(value: &str) -> bool {
    let Some((name, setting)) = value.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name.len() <= MAX_SCALAR_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && setting == "OFF"
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() > "https://".len()
        && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_hex_quad(value: &str) -> bool {
    is_lower_hex(value, 4)
}

fn is_nonzero_sha256(value: &str) -> bool {
    is_lower_hex(value, 64) && value.bytes().any(|byte| byte != b'0')
}

fn io_error(context: &str, error: std::io::Error) -> SourceLockError {
    SourceLockError::new("SOURCE_LOCK_IO", format!("{context}: {error}"))
}
