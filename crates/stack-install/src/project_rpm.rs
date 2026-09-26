// SPDX-License-Identifier: Apache-2.0

use crate::{
    InstallError, ReleasePackage, fedora_rpm::verify_native_rpm, manifest::validate_package,
    signature::fingerprint,
};
use stack_runtime::{ProcessRequest, ProcessRunner, Termination};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

/// Temporary native public-key trust for one independently pinned release key.
/// It is removed on drop; no host keyring or installed package database changes.
#[derive(Debug)]
pub struct ProjectRpmTrust {
    directory: tempfile::TempDir,
    primary: String,
}

impl ProjectRpmTrust {
    /// Imports only an armored public key into a private native RPM database,
    /// requiring exactly the pinned primary fingerprint after native decoding.
    /// The key and fingerprint must come from independent release trust, never
    /// from an RPM or unverified metadata that is being checked.
    pub fn from_armored_key(
        key: &[u8],
        primary: &str,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        let text = std::str::from_utf8(key).map_err(|_| invalid())?;
        if key.is_empty()
            || key.len() > 1_048_576
            || !fingerprint(primary)
            || !text.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
            || !text
                .trim_end()
                .ends_with("-----END PGP PUBLIC KEY BLOCK-----")
        {
            return Err(invalid());
        }
        let directory = tempfile::Builder::new()
            .prefix("intel-npu-rpm-trust-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .map_err(|_| invalid())?;
        let trust = Self {
            directory,
            primary: primary.to_ascii_lowercase(),
        };
        fs::create_dir(trust.database()).map_err(|_| invalid())?;
        let file = trust.directory.path().join("public.asc");
        fs::write(&file, key).map_err(|_| invalid())?;
        // rpmkeys creates the database. `rpm --initdb` would run /usr/bin/rpmdb, which SELinux confines to
        // rpmdb_t on Fedora: that domain may not create files under /tmp, so the key could never be imported.
        trust.run(
            "/usr/bin/rpmkeys",
            vec!["--import".into(), file.into_os_string()],
            runner,
        )?;
        let identity = trust.run(
            "/usr/bin/rpm",
            vec!["-qa".into(), "--qf".into(), "%{VERSION}\n".into()],
            runner,
        )?;
        if identity != (trust.primary.clone() + "\n").as_bytes() {
            return Err(invalid());
        }
        Ok(trust)
    }

    fn database(&self) -> PathBuf {
        self.directory.path().join("rpmdb")
    }

    fn run(
        &self,
        executable: &str,
        args: Vec<OsString>,
        runner: &dyn ProcessRunner,
    ) -> Result<Vec<u8>, InstallError> {
        let mut argv = vec![
            "--macros".into(),
            "/usr/lib/rpm/macros".into(),
            "--noplugins".into(),
            "--dbpath".into(),
            self.database().into_os_string(),
        ];
        argv.extend(args);
        let output = runner
            .run(&ProcessRequest {
                executable: executable.into(),
                args: argv,
                timeout: Duration::from_secs(10),
                stdout_limit: 65536,
                stderr_limit: 65536,
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
}

/// Exact project artifact authenticated against the release's pinned native key
/// and package identity. It does not prove platform qualification or authorize
/// installation; current staged bytes still need rechecking before replay.
#[derive(Debug)]
pub struct ProjectRpm {
    package: ReleasePackage,
}

impl ProjectRpm {
    pub fn verify(
        path: &Path,
        expected: &ReleasePackage,
        trust: &ProjectRpmTrust,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        validate_package(expected)?;
        let signatures =
            ["RSA/SHA256", "RSA/SHA384", "RSA/SHA512", "EdDSA/SHA512"].map(|algorithm| {
                format!(
                    "Header OpenPGP V4 {algorithm} signature, key fingerprint: {}: OK",
                    trust.primary
                )
            });
        let identity = verify_native_rpm(
            path,
            &expected.sha256,
            runner,
            Some(&trust.database()),
            &signatures,
        )?;
        if identity.name != expected.name
            || identity.nevr != expected.nevr
            || identity.arch != expected.arch
            || identity.filename != expected.filename
        {
            return Err(invalid());
        }
        Ok(Self {
            package: expected.clone(),
        })
    }

    pub fn package(&self) -> &ReleasePackage {
        &self.package
    }
}

fn invalid() -> InstallError {
    InstallError::integrity(
        "project RPM signature, release identity or private pinned trust is invalid",
    )
}
