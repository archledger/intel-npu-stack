// SPDX-License-Identifier: Apache-2.0

use crate::{InstallError, NativeInventory, PackageRole, ReleasePackage, manifest::digest};
use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, Termination};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

const MAX_RPM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const FEDORA_SIGNATURE: &str = "Header OpenPGP V4 RSA/SHA256 signature, key fingerprint: 36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6: OK";

/// A native dependency whose exact bytes and header passed Fedora 44's pinned
/// signature verification. This does not admit it to a project release or
/// assert that the current Fedora repositories select this version.
#[derive(Debug)]
pub struct FedoraRpm {
    package: ReleasePackage,
}

impl FedoraRpm {
    /// Verifies a private snapshot with native RPM 6's full-fingerprint output.
    /// The caller supplies the checksum from authenticated repository metadata.
    /// No key import, host mutation, package installation or network is used.
    pub fn verify(
        path: &Path,
        expected_sha256: &str,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        Ok(Self {
            package: verify_native_rpm(
                path,
                expected_sha256,
                runner,
                None,
                &[FEDORA_SIGNATURE.to_owned()],
            )?,
        })
    }

    /// Exact authenticated native identity. Older distribution tags are valid
    /// for Fedora-signed dependencies; this is not a release-manifest entry.
    pub fn package(&self) -> &ReleasePackage {
        &self.package
    }
}

pub(crate) fn verify_native_rpm(
    path: &Path,
    expected_sha256: &str,
    runner: &dyn ProcessRunner,
    database: Option<&Path>,
    allowed_signatures: &[String],
) -> Result<ReleasePackage, InstallError> {
    if !digest(expected_sha256) {
        return Err(invalid());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(invalid)?;
    if !metadata.is_file()
        || metadata.len() > MAX_RPM_BYTES
        || !filename.ends_with(".rpm")
        || filename.len() > 512
        || !filename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+~^".contains(&b))
    {
        return Err(invalid());
    }
    let private = tempfile::Builder::new()
        .prefix("intel-npu-rpm-snapshot-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| invalid())?;
    let snapshot = private.path().join(filename);
    let input = fs::File::open(path).map_err(|_| invalid())?;
    let mut output = fs::File::create(&snapshot).map_err(|_| invalid())?;
    if io::copy(&mut input.take(MAX_RPM_BYTES + 1), &mut output).map_err(|_| invalid())?
        != metadata.len()
    {
        return Err(invalid());
    }
    drop(output);
    verify_hash(&snapshot, expected_sha256)?;
    let signature = native(
        runner,
        "/usr/bin/rpmkeys",
        &["--checksig", "--verbose"],
        &snapshot,
        database,
    )?;
    let text = std::str::from_utf8(&signature).map_err(|_| invalid())?;
    if !allowed_signatures.iter().any(|signature| {
        text == format!(
            "{}:\n    {signature}\n    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n",
            snapshot.display()
        )
    }) {
        return Err(invalid());
    }
    let identity = native(
        runner,
        "/usr/bin/rpm",
        &[
            "-qp",
            "--qf",
            "%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|0\n",
        ],
        &snapshot,
        database,
    )?;
    let inventory = NativeInventory::parse_query(&identity)?;
    let [identity] = inventory.packages() else {
        return Err(invalid());
    };
    if !matches!(identity.arch.as_str(), "x86_64" | "noarch") {
        return Err(invalid());
    }
    let (_, vr) = identity.evr.split_once(':').ok_or_else(invalid)?;
    if filename != format!("{}-{vr}.{}.rpm", identity.name, identity.arch) {
        return Err(invalid());
    }
    verify_hash(&snapshot, expected_sha256)?;
    Ok(ReleasePackage {
        name: identity.name.clone(),
        nevr: identity.evr.clone(),
        arch: identity.arch.clone(),
        filename: filename.into(),
        sha256: expected_sha256.into(),
        role: PackageRole::Runtime,
    })
}

fn verify_hash(path: &Path, expected: &str) -> Result<(), InstallError> {
    let mut input = fs::File::open(path)
        .map_err(|_| invalid())?
        .take(MAX_RPM_BYTES + 1);
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
    if size > MAX_RPM_BYTES || format!("{:x}", hash.finalize()) != expected {
        return Err(invalid());
    }
    Ok(())
}

fn native(
    runner: &dyn ProcessRunner,
    executable: &str,
    args: &[&str],
    path: &Path,
    database: Option<&Path>,
) -> Result<Vec<u8>, InstallError> {
    let mut argv = vec![
        "--macros".into(),
        "/usr/lib/rpm/macros".into(),
        "--noplugins".into(),
    ];
    if let Some(database) = database {
        argv.push("--dbpath".into());
        argv.push(database.as_os_str().into());
    }
    argv.extend(args.iter().map(Into::into));
    argv.push(path.as_os_str().into());
    let output = runner
        .run(&ProcessRequest {
            executable: executable.into(),
            args: argv,
            timeout: Duration::from_secs(120),
            stdout_limit: 16384,
            stderr_limit: 16384,
            environment: Vec::new(),
        })
        .map_err(|_| invalid())?;
    if output.termination != Termination::Exit(0)
        || output.stdout_overflow
        || output.stderr_overflow
    {
        return Err(invalid());
    }
    Ok(output.stdout)
}

fn invalid() -> InstallError {
    InstallError::integrity("RPM content, native identity or pinned signature verification failed")
}
