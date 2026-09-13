// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use stack_install::{PackageRole, ProjectRpm, ProjectRpmTrust, ReleasePackage};
use stack_runtime::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, Termination};
use std::{fs, path::PathBuf, sync::Mutex};

const PRIMARY: &str = "1EB5A90BFC6D62690BD80767D981218E0FD4DBF3";
const PUBLIC: &[u8] =
    b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n";
struct Native {
    bad: &'static str,
    databases: Mutex<Vec<PathBuf>>,
}
impl Native {
    fn new(bad: &'static str) -> Self {
        Self {
            bad,
            databases: Mutex::new(Vec::new()),
        }
    }
}
impl ProcessRunner for Native {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        assert!(request.environment.is_empty());
        let args = request
            .args
            .iter()
            .map(|x| x.to_str().unwrap())
            .collect::<Vec<_>>();
        let db = args.windows(2).find(|x| x[0] == "--dbpath").unwrap()[1];
        assert!(db.starts_with("/tmp/intel-npu-rpm-trust-"));
        use std::os::unix::fs::PermissionsExt;
        let home = std::path::Path::new(db).parent().unwrap();
        assert_eq!(
            fs::metadata(home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        self.databases.lock().unwrap().push(db.into());
        let mut stdout = String::new();
        let mut code = 0;
        if args.contains(&"--initdb") || args.contains(&"--import") {
            if self.bad == "import" {
                code = 1;
            }
        } else if args.contains(&"-qa") {
            stdout = PRIMARY.to_lowercase() + "\n";
            if self.bad == "key" {
                stdout = "0".repeat(40) + "\n";
            }
        } else if args.contains(&"--checksig") {
            stdout = format!(
                "{}:\n    Header OpenPGP V4 EdDSA/SHA512 signature, key fingerprint: {}: OK\n    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n",
                args.last().unwrap(),
                PRIMARY.to_lowercase()
            );
            if self.bad == "signer" {
                stdout = stdout.replace("1eb5a90b", "00000000");
            }
            if self.bad == "weak" {
                stdout = stdout.replace("SHA512", "SHA1");
            }
            if self.bad == "extra" {
                stdout.push_str("    extra: OK\n");
            }
        } else if args.contains(&"-qp") {
            stdout = "intel-npu-stack-tools|0:0.1.0-1.intelnpu.fc44|x86_64|0\n".into();
            if self.bad == "identity" {
                stdout = stdout.replace("0.1.0", "0.2.0");
            }
        } else {
            panic!("unexpected native operation")
        }
        Ok(ProcessOutput {
            termination: Termination::Exit(code),
            stdout: stdout.into_bytes(),
            stdout_overflow: false,
            stderr_overflow: false,
        })
    }
}
fn package() -> ReleasePackage {
    ReleasePackage {
        name: "intel-npu-stack-tools".into(),
        nevr: "0:0.1.0-1.intelnpu.fc44".into(),
        arch: "x86_64".into(),
        filename: "intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm".into(),
        sha256: format!("{:x}", Sha256::digest(b"test RPM bytes")),
        role: PackageRole::Runtime,
    }
}
#[test]
fn project_rpm_binds_native_signature_identity_and_bytes_to_release_input() {
    let native = Native::new("");
    let root = tempfile::tempdir().unwrap();
    let expected = package();
    let file = root.path().join(&expected.filename);
    fs::write(&file, b"test RPM bytes").unwrap();
    let trust = ProjectRpmTrust::from_armored_key(PUBLIC, PRIMARY, &native).unwrap();
    let rpm = ProjectRpm::verify(&file, &expected, &trust, &native).unwrap();
    assert_eq!(rpm.package(), &expected);
    let databases = native.databases.lock().unwrap().clone();
    assert!(databases.iter().all(|p| p.is_dir()));
    drop(trust);
    assert!(databases.iter().all(|p| !p.exists()));
}
#[test]
fn wrong_signer_weak_signature_extra_output_or_wrong_header_is_refused() {
    for bad in ["signer", "weak", "extra", "identity"] {
        let native = Native::new(bad);
        let trust = ProjectRpmTrust::from_armored_key(PUBLIC, PRIMARY, &native).unwrap();
        let root = tempfile::tempdir().unwrap();
        let expected = package();
        let file = root.path().join(&expected.filename);
        fs::write(&file, b"test RPM bytes").unwrap();
        assert!(ProjectRpm::verify(&file, &expected, &trust, &native).is_err());
    }
}
#[test]
fn invalid_or_failed_trust_does_not_leave_a_native_key_database() {
    for bad in ["key", "import"] {
        let native = Native::new(bad);
        assert!(ProjectRpmTrust::from_armored_key(PUBLIC, PRIMARY, &native).is_err());
        assert!(native.databases.lock().unwrap().iter().all(|p| !p.exists()));
    }
}
struct MustNotRun;
impl ProcessRunner for MustNotRun {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("invalid input must stop before native process")
    }
}
#[test]
fn malformed_public_key_identity_or_rpm_bytes_stop_before_verification() {
    for key in [
        b"".as_slice(),
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret\n-----END PGP PRIVATE KEY BLOCK-----\n",
    ] {
        assert!(ProjectRpmTrust::from_armored_key(key, PRIMARY, &MustNotRun).is_err());
    }
    assert!(ProjectRpmTrust::from_armored_key(PUBLIC, "untrusted", &MustNotRun).is_err());
    let native = Native::new("");
    let trust = ProjectRpmTrust::from_armored_key(PUBLIC, PRIMARY, &native).unwrap();
    let root = tempfile::tempdir().unwrap();
    let expected = package();
    let file = root.path().join(&expected.filename);
    fs::write(&file, b"wrong bytes").unwrap();
    assert!(ProjectRpm::verify(&file, &expected, &trust, &MustNotRun).is_err());
}
