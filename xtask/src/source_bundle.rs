// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, SystemProcessRunner, Termination};
use thiserror::Error;

use crate::source_lock::{
    self, SourceGitlink, SourceGitlinkDisposition, SourceKind, SourceLockStatus, SourceRecord,
    SourceRedistribution, ValidatedSourceLock,
};

const GIT: &str = "/usr/bin/git";
const MAX_GIT_OUTPUT_BYTES: usize = 33_554_432;
const MAX_LFS_POINTER_BYTES: u64 = 1024;
const MAX_LFS_OBJECT_BYTES: u64 = 1_073_741_824;

/// One deterministic source archive emitted by a bundle operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleArtifact {
    pub filename: String,
    pub sha256: String,
}

/// Accepted source-bundle output in source-name order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleManifest {
    pub artifacts: Vec<BundleArtifact>,
}

/// Stable failure returned by deterministic source bundling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct SourceBundleError {
    pub code: String,
    pub message: String,
}

impl SourceBundleError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }

    /// Returns the command-line exit class for this error.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.code == "SOURCE_BUNDLE_IO" {
            2
        } else {
            1
        }
    }
}

/// Verifies cached Git repositories and writes deterministic source archives.
///
/// The cache and output directory must already exist as real directories. The
/// output directory must be empty. This function performs no network access.
///
/// # Errors
///
/// Returns a stable [`SourceBundleError`] before accepting any mismatched
/// source identity, gitlink, origin, archive digest, or unsafe path.
pub fn bundle_sources(
    lock_path: &Path,
    repository_root: &Path,
    cache_dir: &Path,
    output_dir: &Path,
) -> Result<BundleManifest, SourceBundleError> {
    let lock = source_lock::validate(lock_path, repository_root)
        .map_err(|error| SourceBundleError::new(&error.code, error.message))?;
    if lock.status != SourceLockStatus::Sealed {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LOCK_UNSEALED",
            "source bundles require a sealed source lock",
        ));
    }
    let cache_dir = require_real_directory(cache_dir, "source cache")?;
    let output_dir = require_empty_output(output_dir)?;
    let staging = output_dir.join(".source-bundle-staging");
    fs::create_dir(&staging).map_err(|error| io_error("create staging directory", error))?;

    let result = bundle_into_staging(&lock, &cache_dir, &staging).and_then(|manifest| {
        for artifact in &manifest.artifacts {
            fs::rename(
                staging.join(&artifact.filename),
                output_dir.join(&artifact.filename),
            )
            .map_err(|error| io_error("publish source archive", error))?;
        }
        fs::rename(staging.join("SHA256SUMS"), output_dir.join("SHA256SUMS"))
            .map_err(|error| io_error("publish source checksums", error))?;
        Ok(manifest)
    });

    let _ = fs::remove_dir_all(&staging);
    result
}

fn bundle_into_staging(
    lock: &ValidatedSourceLock,
    cache_dir: &Path,
    staging: &Path,
) -> Result<BundleManifest, SourceBundleError> {
    let sources = lock
        .sources
        .iter()
        .map(|source| (source.name.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let mut artifacts = Vec::with_capacity(lock.sources.len());

    for source in &lock.sources {
        let repository = require_real_directory(&cache_dir.join(&source.name), "cached source")?;
        verify_safe_local_config(&repository)?;
        verify_origin(&repository, source)?;
        verify_identity(&repository, source)?;
        verify_gitlinks(&repository, source, &sources)?;

        let filename = format!("{}.tar", source.name);
        let archive = staging.join(&filename);
        create_archive(&repository, source, &archive)?;
        let digest = hash_file(&archive)?;
        if digest != source.archive_sha256 {
            return Err(SourceBundleError::new(
                "SOURCE_BUNDLE_ARCHIVE_MISMATCH",
                format!("archive digest mismatch for {}", source.name),
            ));
        }
        if source.redistribution == SourceRedistribution::Allowed {
            artifacts.push(BundleArtifact {
                filename,
                sha256: digest,
            });
        } else {
            fs::remove_file(&archive)
                .map_err(|error| io_error("remove external-only source archive", error))?;
        }
    }

    let mut checksums = fs::File::create(staging.join("SHA256SUMS"))
        .map_err(|error| io_error("create checksum manifest", error))?;
    for artifact in &artifacts {
        writeln!(checksums, "{}  {}", artifact.sha256, artifact.filename)
            .map_err(|error| io_error("write checksum manifest", error))?;
    }
    checksums
        .sync_all()
        .map_err(|error| io_error("sync checksum manifest", error))?;

    Ok(BundleManifest { artifacts })
}

fn verify_safe_local_config(repository: &Path) -> Result<(), SourceBundleError> {
    let output = git_bytes(
        repository,
        &[
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--name-only",
            "--get-regexp",
            ".*",
        ],
    )?;
    for raw_name in output
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = std::str::from_utf8(raw_name).map_err(|_| {
            SourceBundleError::new(
                "SOURCE_BUNDLE_CACHE_CONFIG_INVALID",
                "cached repository configuration key is not UTF-8",
            )
        })?;
        let normalized = name.to_ascii_lowercase();
        if normalized.starts_with("filter.")
            || normalized.starts_with("tar.")
            || normalized.starts_with("include.")
            || normalized.starts_with("includeif.")
            || normalized == "core.alternaterefscommand"
        {
            return Err(SourceBundleError::new(
                "SOURCE_BUNDLE_CACHE_CONFIG_INVALID",
                "cached repository defines an archive-affecting command",
            ));
        }
    }
    verify_safe_cache_metadata(repository)
}

fn verify_safe_cache_metadata(repository: &Path) -> Result<(), SourceBundleError> {
    let git_dir = safe_git_dir(repository)?;
    for path in [
        git_dir.join("info/attributes"),
        git_dir.join("objects/info/alternates"),
        git_dir.join("objects/info/http-alternates"),
    ] {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() == 0 => {}
            Ok(_) => {
                return Err(SourceBundleError::new(
                    "SOURCE_BUNDLE_CACHE_CONFIG_INVALID",
                    "cached repository contains mutable archive or object metadata",
                ));
            }
            Err(error) => return Err(io_error("inspect cached Git metadata", error)),
        }
    }
    Ok(())
}

fn verify_origin(repository: &Path, source: &SourceRecord) -> Result<(), SourceBundleError> {
    let actual = git_text(repository, &["remote", "get-url", "origin"])?;
    if actual != source.url {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_ORIGIN_MISMATCH",
            format!("cached origin mismatch for {}", source.name),
        ));
    }
    Ok(())
}

fn verify_identity(repository: &Path, source: &SourceRecord) -> Result<(), SourceBundleError> {
    match source.kind {
        SourceKind::GitTag => {
            let tag = source.tag.as_deref().expect("validated lightweight tag");
            let reference = format!("refs/tags/{tag}");
            if git_text(repository, &["cat-file", "-t", &reference])? != "commit"
                || git_text(repository, &["rev-parse", &reference])? != source.commit
            {
                return Err(tag_moved(source));
            }
        }
        SourceKind::GitAnnotatedTag => {
            let tag = source.tag.as_deref().expect("validated annotated tag");
            let reference = format!("refs/tags/{tag}");
            let peeled = format!("{reference}^{{commit}}");
            if git_text(repository, &["cat-file", "-t", &reference])? != "tag"
                || git_text(repository, &["rev-parse", &reference])?
                    != source.tag_object.as_deref().expect("validated tag object")
                || git_text(repository, &["rev-parse", &peeled])? != source.commit
            {
                return Err(tag_moved(source));
            }
        }
        SourceKind::GitCommit => {
            let commit_object = format!("{}^{{commit}}", source.commit);
            if git_text(repository, &["rev-parse", &commit_object])? != source.commit {
                return Err(SourceBundleError::new(
                    "SOURCE_BUNDLE_COMMIT_MISMATCH",
                    format!("commit is unavailable for {}", source.name),
                ));
            }
        }
    }
    Ok(())
}

fn tag_moved(source: &SourceRecord) -> SourceBundleError {
    SourceBundleError::new(
        "SOURCE_BUNDLE_TAG_MOVED",
        format!("tag identity mismatch for {}", source.name),
    )
}

fn verify_gitlinks(
    repository: &Path,
    source: &SourceRecord,
    sources: &BTreeMap<&str, &SourceRecord>,
) -> Result<(), SourceBundleError> {
    let actual = list_gitlinks(repository, &source.commit)?;
    let declared = source
        .gitlinks
        .iter()
        .map(|gitlink| (gitlink.path.clone(), gitlink.commit.clone()))
        .collect::<BTreeMap<_, _>>();

    for (path, oid) in &actual {
        match declared.get(path) {
            None => {
                return Err(SourceBundleError::new(
                    "SOURCE_BUNDLE_GITLINK_UNDECLARED",
                    format!("undeclared gitlink in {}", source.name),
                ));
            }
            Some(expected) if expected != oid => return Err(gitlink_mismatch(source)),
            Some(_) => {}
        }
    }
    if actual.len() != declared.len() {
        return Err(gitlink_mismatch(source));
    }
    for gitlink in &source.gitlinks {
        if gitlink.disposition == SourceGitlinkDisposition::Bundled {
            verify_gitlink_source(gitlink, sources, source)?;
        }
    }
    Ok(())
}

fn verify_gitlink_source(
    gitlink: &SourceGitlink,
    sources: &BTreeMap<&str, &SourceRecord>,
    parent: &SourceRecord,
) -> Result<(), SourceBundleError> {
    let child_name = gitlink
        .source
        .as_deref()
        .expect("validated bundled gitlink");
    let Some(child) = sources.get(child_name) else {
        return Err(gitlink_mismatch(parent));
    };
    if child.commit != gitlink.commit {
        return Err(gitlink_mismatch(parent));
    }
    Ok(())
}

fn gitlink_mismatch(source: &SourceRecord) -> SourceBundleError {
    SourceBundleError::new(
        "SOURCE_BUNDLE_GITLINK_MISMATCH",
        format!("gitlink identity mismatch for {}", source.name),
    )
}

fn list_gitlinks(
    repository: &Path,
    commit: &str,
) -> Result<BTreeMap<PathBuf, String>, SourceBundleError> {
    let output = git_bytes(repository, &["ls-tree", "-r", "-z", commit])?;
    let mut links = BTreeMap::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let text = std::str::from_utf8(record).map_err(|_| {
            SourceBundleError::new(
                "SOURCE_BUNDLE_GIT_OUTPUT_INVALID",
                "git tree output is not UTF-8",
            )
        })?;
        let Some((metadata, path)) = text.split_once('\t') else {
            return Err(SourceBundleError::new(
                "SOURCE_BUNDLE_GIT_OUTPUT_INVALID",
                "git tree record is malformed",
            ));
        };
        let fields = metadata.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(SourceBundleError::new(
                "SOURCE_BUNDLE_GIT_OUTPUT_INVALID",
                "git tree metadata is malformed",
            ));
        }
        if fields[0] == "160000" {
            let path = PathBuf::from(path);
            if !safe_relative_path(&path) || !is_lower_hex(fields[2], 40) {
                return Err(SourceBundleError::new(
                    "SOURCE_BUNDLE_GIT_OUTPUT_INVALID",
                    "gitlink path or object ID is invalid",
                ));
            }
            links.insert(path, fields[2].to_owned());
        }
    }
    Ok(links)
}

fn create_archive(
    repository: &Path,
    source: &SourceRecord,
    archive: &Path,
) -> Result<(), SourceBundleError> {
    create_archive_from_commit(repository, &source.name, &source.commit, archive)
}

/// Creates and hashes one explicit archive from an already-cached commit.
///
/// This is the offline bootstrap operation used to establish an archive hash
/// before a reviewed source record can be sealed. It performs the same cache
/// configuration and LFS safety checks as [`bundle_sources`].
///
/// # Errors
///
/// Returns a stable [`SourceBundleError`] for an unsafe identity, unavailable
/// commit, unsafe cache/output path, configured filter, malformed archive, or
/// missing/mismatched Git LFS object.
pub fn hash_cached_source(
    repository: &Path,
    source_name: &str,
    commit: &str,
    archive: &Path,
) -> Result<String, SourceBundleError> {
    if !is_identifier(source_name) || !is_lower_hex(commit, 40) {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_IDENTITY_INVALID",
            "source name or commit identity is invalid",
        ));
    }
    if fs::symlink_metadata(archive).is_ok() {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_OUTPUT_INVALID",
            "explicit archive output must not already exist",
        ));
    }
    let parent = archive.parent().ok_or_else(|| {
        SourceBundleError::new(
            "SOURCE_BUNDLE_OUTPUT_INVALID",
            "explicit archive output requires a parent directory",
        )
    })?;
    let _ = require_real_directory(parent, "archive parent")?;
    let repository = require_real_directory(repository, "cached source")?;
    verify_safe_local_config(&repository)?;
    let commit_object = format!("{commit}^{{commit}}");
    if git_text(&repository, &["rev-parse", &commit_object])? != commit {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_COMMIT_MISMATCH",
            "explicit commit is unavailable from the cached source",
        ));
    }
    create_archive_from_commit(&repository, source_name, commit, archive)?;
    hash_file(archive)
}

fn create_archive_from_commit(
    repository: &Path,
    source_name: &str,
    commit: &str,
    archive: &Path,
) -> Result<(), SourceBundleError> {
    let prefix = format!("{source_name}/");
    let raw_archive = archive.with_extension("raw.tar");
    match fs::symlink_metadata(&raw_archive) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(SourceBundleError::new(
                "SOURCE_BUNDLE_OUTPUT_INVALID",
                "temporary raw archive path must not already exist",
            ));
        }
        Err(error) => return Err(io_error("inspect temporary raw archive path", error)),
    }
    let raw_archive_text = raw_archive.to_str().ok_or_else(|| {
        SourceBundleError::new("SOURCE_BUNDLE_OUTPUT_INVALID", "archive path is not UTF-8")
    })?;
    let archive_result = run_git(
        repository,
        &[
            "archive",
            "--format=tar",
            "--prefix",
            &prefix,
            "--output",
            raw_archive_text,
            commit,
        ],
    );
    if let Err(error) = archive_result {
        let _ = fs::remove_file(&raw_archive);
        return Err(error);
    }
    let result = materialize_lfs_archive(repository, &raw_archive, archive);
    let _ = fs::remove_file(&raw_archive);
    result
}

/// Rewrites Git LFS pointer entries using already-cached, hash-verified objects.
///
/// This function never invokes a content filter, checks out a tree, or performs
/// network access. Non-LFS tar entries retain their Git-generated metadata.
///
/// # Errors
///
/// Returns a stable [`SourceBundleError`] for malformed archives, pointers,
/// missing objects, hash/size mismatches, unsafe Git directories, or I/O.
pub fn materialize_lfs_archive(
    repository: &Path,
    raw_archive: &Path,
    output: &Path,
) -> Result<(), SourceBundleError> {
    let git_dir = safe_git_dir(repository)?;

    let draft = output.with_extension("materializing.tar");
    let result = if archive_has_lfs_pointers(raw_archive)? {
        let raw =
            fs::File::open(raw_archive).map_err(|error| io_error("open raw archive", error))?;
        materialize_entries(raw, &git_dir, &draft)
    } else {
        copy_raw_archive(raw_archive, &draft)
    }
    .and_then(|()| {
        fs::rename(&draft, output).map_err(|error| io_error("publish materialized archive", error))
    });
    if result.is_err() {
        let _ = fs::remove_file(&draft);
    }
    result
}

fn copy_raw_archive(raw_archive: &Path, draft: &Path) -> Result<(), SourceBundleError> {
    let mut raw =
        fs::File::open(raw_archive).map_err(|error| io_error("open raw archive", error))?;
    let mut output = create_draft(draft)?;
    std::io::copy(&mut raw, &mut output)
        .map_err(|error| io_error("copy filter-free raw archive", error))?;
    output
        .sync_all()
        .map_err(|error| io_error("sync filter-free raw archive", error))
}

fn archive_has_lfs_pointers(raw_archive: &Path) -> Result<bool, SourceBundleError> {
    let raw = fs::File::open(raw_archive).map_err(|error| io_error("open raw archive", error))?;
    let mut archive = tar::Archive::new(raw);
    let entries = archive
        .entries()
        .map_err(|error| io_error("read raw archive", error))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| io_error("read raw archive entry", error))?;
        let header = entry.header();
        if header.entry_type().is_file()
            && header
                .size()
                .map_err(|error| io_error("read archive entry size", error))?
                <= MAX_LFS_POINTER_BYTES
        {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| io_error("read possible LFS pointer", error))?;
            if parse_lfs_pointer(&bytes)?.is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn materialize_entries(
    raw: fs::File,
    git_dir: &Path,
    draft: &Path,
) -> Result<(), SourceBundleError> {
    let output = create_draft(draft)?;
    let mut archive = tar::Archive::new(raw);
    let mut builder = tar::Builder::new(output);
    let entries = archive
        .entries()
        .map_err(|error| io_error("read raw archive", error))?;

    for entry in entries {
        let mut entry = entry.map_err(|error| io_error("read raw archive entry", error))?;
        let mut header = entry.header().clone();
        if header.entry_type().is_file()
            && header
                .size()
                .map_err(|error| io_error("read archive entry size", error))?
                <= MAX_LFS_POINTER_BYTES
        {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| io_error("read possible LFS pointer", error))?;
            if let Some(pointer) = parse_lfs_pointer(&bytes)? {
                let object_file = open_verified_lfs_object(git_dir, &pointer)?;
                header.set_size(pointer.size);
                header.set_cksum();
                builder
                    .append(&header, object_file)
                    .map_err(|error| io_error("append materialized LFS object", error))?;
            } else {
                builder
                    .append(&header, bytes.as_slice())
                    .map_err(|error| io_error("append source archive entry", error))?;
            }
        } else {
            builder
                .append(&header, &mut entry)
                .map_err(|error| io_error("append source archive entry", error))?;
        }
    }

    builder
        .finish()
        .map_err(|error| io_error("finish materialized archive", error))?;
    let output = builder
        .into_inner()
        .map_err(|error| io_error("close materialized archive", error))?;
    output
        .sync_all()
        .map_err(|error| io_error("sync materialized archive", error))
}

fn create_draft(path: &Path) -> Result<fs::File, SourceBundleError> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SourceBundleError::new(
                    "SOURCE_BUNDLE_OUTPUT_INVALID",
                    "temporary materialized archive path must not already exist",
                )
            } else {
                io_error("create materialized archive", error)
            }
        })
}

struct LfsPointer {
    oid: String,
    size: u64,
}

fn parse_lfs_pointer(bytes: &[u8]) -> Result<Option<LfsPointer>, SourceBundleError> {
    if !bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_POINTER_INVALID",
            "Git LFS pointer is not UTF-8",
        )
    })?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 3 || !text.ends_with('\n') {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_POINTER_INVALID",
            "Git LFS pointer does not use the supported canonical form",
        ));
    }
    let Some(oid) = lines[1].strip_prefix("oid sha256:") else {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_POINTER_INVALID",
            "Git LFS pointer has no SHA-256 object ID",
        ));
    };
    let Some(size) = lines[2].strip_prefix("size ") else {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_POINTER_INVALID",
            "Git LFS pointer has no object size",
        ));
    };
    let size = size.parse::<u64>().map_err(|_| {
        SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_POINTER_INVALID",
            "Git LFS pointer size is invalid",
        )
    })?;
    if !is_lower_hex(oid, 64) || size > MAX_LFS_OBJECT_BYTES {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_POINTER_INVALID",
            "Git LFS object identity or size is invalid",
        ));
    }
    Ok(Some(LfsPointer {
        oid: oid.to_owned(),
        size,
    }))
}

fn lfs_object_path(git_dir: &Path, oid: &str) -> Result<PathBuf, SourceBundleError> {
    let object_root = git_dir.join("lfs/objects");
    let canonical_root = object_root.canonicalize().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SourceBundleError::new(
                "SOURCE_BUNDLE_LFS_OBJECT_MISSING",
                "a source-locked Git LFS object is absent from the offline cache",
            )
        } else {
            io_error("canonicalize Git LFS object directory", error)
        }
    })?;
    if !canonical_root.starts_with(git_dir) {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_OBJECT_INVALID",
            "Git LFS object directory must remain inside the cached source",
        ));
    }

    let path = object_root.join(&oid[..2]).join(&oid[2..4]).join(oid);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SourceBundleError::new(
                "SOURCE_BUNDLE_LFS_OBJECT_MISSING",
                "a source-locked Git LFS object is absent from the offline cache",
            )
        } else {
            io_error("inspect Git LFS object", error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_OBJECT_INVALID",
            "Git LFS object must be a regular non-symlink file",
        ));
    }
    let canonical_path = path
        .canonicalize()
        .map_err(|error| io_error("canonicalize Git LFS object", error))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_OBJECT_INVALID",
            "Git LFS object must remain inside the object directory",
        ));
    }
    Ok(canonical_path)
}

fn open_verified_lfs_object(
    git_dir: &Path,
    pointer: &LfsPointer,
) -> Result<fs::File, SourceBundleError> {
    let path = lfs_object_path(git_dir, &pointer.oid)?;
    let descriptor = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        io_error(
            "open Git LFS object without following symlinks",
            error.into(),
        )
    })?;
    let mut file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| io_error("read Git LFS object metadata", error))?;
    if !metadata.is_file()
        || metadata.len() != pointer.size
        || hash_reader(&mut file)? != pointer.oid
    {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_LFS_OBJECT_INVALID",
            "Git LFS object size or SHA-256 does not match its pointer",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind verified Git LFS object", error))?;
    Ok(file)
}

fn git_text(repository: &Path, args: &[&str]) -> Result<String, SourceBundleError> {
    let bytes = git_bytes(repository, args)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        SourceBundleError::new(
            "SOURCE_BUNDLE_GIT_OUTPUT_INVALID",
            "git output is not UTF-8",
        )
    })?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

fn git_bytes(repository: &Path, args: &[&str]) -> Result<Vec<u8>, SourceBundleError> {
    let output = run_git(repository, args)?;
    if output.stdout_overflow || output.stderr_overflow {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_GIT_OUTPUT_INVALID",
            format!("git output exceeded {MAX_GIT_OUTPUT_BYTES} bytes"),
        ));
    }
    Ok(output.stdout)
}

fn run_git(
    repository: &Path,
    args: &[&str],
) -> Result<stack_runtime::ProcessOutput, SourceBundleError> {
    let mut git_args = vec![
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("core.attributesFile=/dev/null"),
        OsString::from("-c"),
        OsString::from("advice.detachedHead=false"),
        OsString::from("-C"),
        repository.as_os_str().to_owned(),
    ];
    git_args.extend(args.iter().map(OsString::from));
    let request = ProcessRequest {
        executable: PathBuf::from(GIT),
        args: git_args,
        timeout: Duration::from_secs(30),
        stdout_limit: MAX_GIT_OUTPUT_BYTES,
        stderr_limit: MAX_GIT_OUTPUT_BYTES,
        environment: vec![
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/dev/null"),
            ),
            (OsString::from("GIT_LFS_SKIP_SMUDGE"), OsString::from("1")),
            (
                OsString::from("GIT_NO_REPLACE_OBJECTS"),
                OsString::from("1"),
            ),
        ],
    };
    let output = SystemProcessRunner.run(&request).map_err(|error| {
        SourceBundleError::new(
            "SOURCE_BUNDLE_GIT_FAILED",
            format!("bounded git execution failed: {error}"),
        )
    })?;
    if output.termination != Termination::Exit(0) {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_GIT_FAILED",
            "git rejected a source identity or archive operation",
        ));
    }
    Ok(output)
}

fn require_real_directory(path: &Path, label: &str) -> Result<PathBuf, SourceBundleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect directory", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_PATH_INVALID",
            format!("{label} must be a real directory"),
        ));
    }
    path.canonicalize()
        .map_err(|error| io_error("canonicalize directory", error))
}

fn safe_git_dir(repository: &Path) -> Result<PathBuf, SourceBundleError> {
    let git_dir = PathBuf::from(git_text(repository, &["rev-parse", "--absolute-git-dir"])?);
    let git_dir = require_real_directory(&git_dir, "Git object directory")?;
    let repository = repository
        .canonicalize()
        .map_err(|error| io_error("canonicalize cached source", error))?;
    if git_dir != repository && !git_dir.starts_with(&repository) {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_PATH_INVALID",
            "Git object directory must be inside the cached source",
        ));
    }
    Ok(git_dir)
}

fn require_empty_output(path: &Path) -> Result<PathBuf, SourceBundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error("inspect output", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_OUTPUT_INVALID",
            "output must be a real directory",
        ));
    }
    let mut entries = fs::read_dir(path).map_err(|error| io_error("read output", error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| io_error("read output", error))?
        .is_some()
    {
        return Err(SourceBundleError::new(
            "SOURCE_BUNDLE_OUTPUT_INVALID",
            "output directory must be empty",
        ));
    }
    path.canonicalize()
        .map_err(|error| io_error("canonicalize output", error))
}

fn hash_file(path: &Path) -> Result<String, SourceBundleError> {
    let mut file = fs::File::open(path).map_err(|error| io_error("open source archive", error))?;
    hash_reader(&mut file)
}

fn hash_reader(reader: &mut impl Read) -> Result<String, SourceBundleError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("read source archive", error))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn io_error(context: &str, error: std::io::Error) -> SourceBundleError {
    SourceBundleError::new("SOURCE_BUNDLE_IO", format!("{context}: {error}"))
}
