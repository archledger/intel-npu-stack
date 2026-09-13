// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, Termination};
use stack_schema::Profile;

use crate::manifest::{digest, release_version, repository_url};
use crate::signature::fingerprint;
use crate::{InstallError, ReleaseManifest, ReleaseTrust, verify_detached};

/// Release identity supplied by the independently verified bootstrap/installer.
/// The downloaded release document cannot choose its own trust anchor.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseLocation<'a> {
    pub version: &'a str,
    pub base_url: &'a str,
    pub metadata_sha256: &'a str,
    pub primary_fingerprint: &'a str,
    pub keyring: &'a [u8],
}

/// Authenticated metadata and its byte-bound profile, still subject to channel
/// admission, hardware compatibility and native transaction validation.
#[derive(Debug)]
pub struct VerifiedRelease {
    manifest: ReleaseManifest,
    profile: Profile,
}

impl VerifiedRelease {
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }
}

/// Fetches bounded release data, verifies trust, then binds the exact profile.
/// This function performs no installed-state or privileged mutation.
pub fn fetch_release(
    location: &ReleaseLocation<'_>,
    runner: &dyn ProcessRunner,
) -> Result<VerifiedRelease, InstallError> {
    if !release_version(location.version)
        || !repository_url(location.base_url, location.version)
        || !digest(location.metadata_sha256)
        || !fingerprint(location.primary_fingerprint)
        || location.keyring.is_empty()
        || location.keyring.len() > 1_048_576
    {
        return Err(InstallError::integrity(
            "invalid independently pinned release location",
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix("intel-npu-release-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| {
            InstallError::integrity("cannot create private metadata download directory")
        })?;
    let metadata = download(
        location.base_url,
        "release.json",
        1_048_576,
        directory.path(),
        runner,
    )?;
    if format!("{:x}", Sha256::digest(&metadata)) != location.metadata_sha256 {
        return Err(InstallError::integrity(
            "downloaded release metadata checksum mismatch",
        ));
    }
    let signature = download(
        location.base_url,
        "release.json.sig",
        65_536,
        directory.path(),
        runner,
    )?;
    verify_detached(
        &metadata,
        &signature,
        &ReleaseTrust {
            sha256: location.metadata_sha256,
            primary_fingerprint: location.primary_fingerprint,
            keyring: location.keyring,
        },
        runner,
    )?;
    let manifest = ReleaseManifest::parse_json(&metadata)?;
    if manifest.stack_release() != location.version {
        return Err(InstallError::integrity(
            "authenticated metadata names a different release",
        ));
    }
    let bytes = download(
        location.base_url,
        "profile.toml",
        1_048_576,
        directory.path(),
        runner,
    )?;
    let profile = manifest.bind_profile(&bytes)?;
    Ok(VerifiedRelease { manifest, profile })
}

fn download(
    base: &str,
    filename: &str,
    limit: usize,
    directory: &Path,
    runner: &dyn ProcessRunner,
) -> Result<Vec<u8>, InstallError> {
    let path = directory.join(filename);
    let output = runner
        .run(&ProcessRequest {
            executable: PathBuf::from("/usr/bin/curl"),
            args: vec![
                "--disable".into(),
                "--fail".into(),
                "--location".into(),
                "--proto".into(),
                "=https".into(),
                "--proto-redir".into(),
                "=https".into(),
                "--connect-timeout".into(),
                "15".into(),
                "--max-time".into(),
                "60".into(),
                "--max-filesize".into(),
                limit.to_string().into(),
                "--output".into(),
                path.as_os_str().into(),
                "--".into(),
                format!("{base}{filename}").into(),
            ],
            timeout: Duration::from_secs(65),
            stdout_limit: 4_096,
            stderr_limit: 16_384,
            environment: Vec::new(),
        })
        .map_err(|_| InstallError::integrity("metadata download process failed"))?;
    if output.termination != Termination::Exit(0)
        || output.stdout_overflow
        || output.stderr_overflow
    {
        return Err(InstallError::integrity(
            "metadata download did not complete within limits",
        ));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| InstallError::integrity("downloaded metadata file is missing"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(InstallError::integrity(
            "downloaded metadata is not a bounded regular file",
        ));
    }
    let file = File::open(&path)
        .map_err(|_| InstallError::integrity("cannot open downloaded metadata"))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallError::integrity("cannot read downloaded metadata"))?;
    if bytes.len() > limit {
        return Err(InstallError::integrity(
            "downloaded metadata grew beyond its byte limit",
        ));
    }
    Ok(bytes)
}
