// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, Termination};

use crate::InstallError;

/// Trust supplied by an independently authenticated, version-pinned release.
/// Never construct this from the metadata currently being verified.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseTrust<'a> {
    pub sha256: &'a str,
    pub primary_fingerprint: &'a str,
    pub keyring: &'a [u8],
}

/// Verifies exact bounded metadata bytes with a pinned OpenPGP primary key.
///
/// Production must use `SystemProcessRunner`. Injection permits tests without
/// changing executable paths, trust anchors or the clock through public flags.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    trust: &ReleaseTrust<'_>,
    runner: &dyn ProcessRunner,
) -> Result<(), InstallError> {
    if data.is_empty()
        || data.len() > 1_048_576
        || signature.is_empty()
        || signature.len() > 65_536
        || trust.keyring.is_empty()
        || trust.keyring.len() > 1_048_576
        || !fingerprint(trust.primary_fingerprint)
        || trust.sha256.len() != 64
        || !trust
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || format!("{:x}", Sha256::digest(data)) != trust.sha256
    {
        return Err(InstallError::integrity(
            "metadata size, digest or trust identity is invalid",
        ));
    }
    // A fixed sticky system temporary parent avoids trusting an inherited TMPDIR.
    // The private directory and its regular files disappear on every return path.
    let directory = tempfile::Builder::new()
        .prefix("intel-npu-signature-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| InstallError::integrity("cannot create private verification directory"))?;
    let metadata_path = directory.path().join("release.json");
    let signature_path = directory.path().join("release.sig");
    let public_key_path = directory.path().join("public-key");
    for (path, bytes) in [
        (&metadata_path, data),
        (&signature_path, signature),
        (&public_key_path, trust.keyring),
    ] {
        fs::write(path, bytes)
            .map_err(|_| InstallError::integrity("cannot stage verification input"))?;
    }
    // The pinned key arrives as an OpenPGP public-key envelope (armored or
    // binary); import it into this throwaway homedir so verification cannot
    // depend on a coincidentally compatible --keyring file format.
    let import: Vec<OsString> = vec![
        "--no-options".into(),
        "--batch".into(),
        "--no-auto-key-retrieve".into(),
        "--homedir".into(),
        directory.path().as_os_str().into(),
        "--import".into(),
        public_key_path.into_os_string(),
    ];
    let imported = runner
        .run(&ProcessRequest {
            executable: PathBuf::from("/usr/bin/gpg"),
            args: import,
            timeout: Duration::from_secs(10),
            stdout_limit: 65_536,
            stderr_limit: 65_536,
            environment: Vec::new(),
        })
        .map_err(|_| InstallError::integrity("signature verification process failed"))?;
    if imported.stdout_overflow
        || imported.stderr_overflow
        || imported.termination != Termination::Exit(0)
    {
        return Err(InstallError::integrity(
            "pinned release key could not be imported",
        ));
    }
    let args: Vec<OsString> = vec![
        "--no-options".into(),
        "--batch".into(),
        "--no-auto-key-retrieve".into(),
        "--no-auto-key-import".into(),
        "--homedir".into(),
        directory.path().as_os_str().into(),
        "--status-fd".into(),
        "1".into(),
        "--verify".into(),
        signature_path.into_os_string(),
        metadata_path.into_os_string(),
    ];
    let output = runner
        .run(&ProcessRequest {
            executable: PathBuf::from("/usr/bin/gpg"),
            args,
            timeout: Duration::from_secs(10),
            stdout_limit: 65_536,
            stderr_limit: 65_536,
            environment: Vec::new(),
        })
        .map_err(|_| InstallError::integrity("signature verification process failed"))?;
    if output.stdout_overflow
        || output.stderr_overflow
        || output.termination != Termination::Exit(0)
    {
        return Err(InstallError::integrity(
            "signature verification failed or exceeded output limits",
        ));
    }
    verify_signature_status(0, &output.stdout, trust.primary_fingerprint)
}

/// Applies release policy to actual GnuPG machine status, not human diagnostics.
///
/// A zero exit alone permits an expired or different trusted signer. Accept one
/// binary detached signature from the pinned primary key using SHA256 or better;
/// refuse expiry, revocation, errors, unknown records and additional signatures.
pub fn verify_signature_status(
    exit_code: i32,
    status: &[u8],
    expected_primary: &str,
) -> Result<(), InstallError> {
    let invalid =
        || InstallError::integrity("signature does not satisfy the pinned release-key policy");
    if exit_code != 0 || status.len() > 65_536 || !fingerprint(expected_primary) {
        return Err(invalid());
    }
    let text = std::str::from_utf8(status).map_err(|_| invalid())?;
    let mut starts = 0;
    let mut good_key = None;
    let mut valid_key = None;
    for line in text.lines() {
        let record = line.strip_prefix("[GNUPG:] ").ok_or_else(invalid)?;
        let fields = record.split_ascii_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("NEWSIG") => {
                starts += 1;
            }
            Some("GOODSIG") if fields.len() >= 3 && good_key.is_none() => {
                if fields[1].len() != 16
                    || !fields[1]
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
                {
                    return Err(invalid());
                }
                good_key = Some(fields[1]);
            }
            Some("VALIDSIG") if fields.len() == 11 && valid_key.is_none() => {
                if !fingerprint(fields[1])
                    || fields[10] != expected_primary
                    || fields[5] != "4"
                    || fields[6] != "0"
                    || !matches!(fields[8], "8" | "9" | "10")
                    || fields[9] != "00"
                {
                    return Err(invalid());
                }
                valid_key = Some(fields[1]);
            }
            // Web-of-trust ratings do not establish our trust: the separately
            // pinned primary fingerprint does. Error/expiry records are absent
            // from this allowlist, even if GnuPG also emitted VALIDSIG.
            Some(
                "KEY_CONSIDERED" | "SIG_ID" | "TRUST_UNDEFINED" | "TRUST_NEVER" | "TRUST_MARGINAL"
                | "TRUST_FULLY" | "TRUST_ULTIMATE",
            ) => {}
            _ => return Err(invalid()),
        }
    }
    match (starts, good_key, valid_key) {
        (1, Some(short), Some(full)) if full.ends_with(short) => Ok(()),
        _ => Err(invalid()),
    }
}

pub(crate) fn fingerprint(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
}
