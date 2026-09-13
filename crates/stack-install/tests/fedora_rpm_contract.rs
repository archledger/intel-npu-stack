// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use sha2::{Digest, Sha256};
use stack_install::{FedoraRpm, NativeInventory, NativePlan, ProjectRpmTrust};
use stack_runtime::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, Termination};
use std::{fs, path::PathBuf};

// Native process responses are captured-format fixtures. These tiny file bytes
// test the orchestration boundary, not cryptography; real RPM verification is
// additionally exercised against all 434 approved remote inputs.
struct NativeFixture {
    identity: String,
    signature: String,
    path: PathBuf,
    mutate: bool,
}
impl ProcessRunner for NativeFixture {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        assert!(request.environment.is_empty());
        use std::os::unix::fs::PermissionsExt;
        let snapshot = std::path::Path::new(request.args.last().unwrap());
        assert_eq!(
            fs::metadata(snapshot.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(
            request
                .args
                .windows(2)
                .any(|a| a == ["--macros", "/usr/lib/rpm/macros"])
        );
        assert!(request.args.iter().any(|a| a == "--noplugins"));
        let stdout = if request.executable.to_str() == Some("/usr/bin/rpmkeys") {
            format!(
                "{}:\n{}",
                request.args.last().unwrap().to_str().unwrap(),
                self.signature
            )
        } else {
            assert_eq!(request.executable.to_str(), Some("/usr/bin/rpm"));
            if self.mutate {
                fs::write(request.args.last().unwrap(), b"changed").unwrap();
            }
            self.identity.clone()
        };
        Ok(ProcessOutput {
            termination: Termination::Exit(0),
            stdout: stdout.into_bytes(),
            stdout_overflow: false,
            stderr_overflow: false,
        })
    }
}

fn signature() -> String {
    "    Header OpenPGP V4 RSA/SHA256 signature, key fingerprint: 36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6: OK\n    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n".into()
}
fn fixture() -> (tempfile::TempDir, NativeFixture, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zeromq-4.3.5-22.fc43.x86_64.rpm");
    fs::write(&path, b"native process fixture").unwrap();
    let digest = format!("{:x}", Sha256::digest(b"native process fixture"));
    (
        dir,
        NativeFixture {
            identity: "zeromq|0:4.3.5-22.fc43|x86_64|0\n".into(),
            signature: signature(),
            path,
            mutate: false,
        },
        digest,
    )
}

#[test]
fn fedora_signed_dependency_can_have_an_older_distribution_tag() {
    let (_dir, runner, digest) = fixture();
    let rpm = FedoraRpm::verify(&runner.path, &digest, &runner).unwrap();
    assert_eq!(rpm.package().nevr, "0:4.3.5-22.fc43");
    assert_eq!(rpm.package().sha256, digest);
    // It remains invalid as a project release package.
    let state = NativeInventory::parse_query(b"rpm|0:6.0.2-1.fc44|x86_64|0\n").unwrap();
    assert!(
        NativePlan::parse_update(None, &[rpm.package()], &state, "intel-npu-test", &runner)
            .is_err()
    );
}

#[test]
fn stored_fedora_dependency_keeps_its_signature_authority_after_input_lists_are_combined() {
    struct ProjectTrustFixture;
    impl ProcessRunner for ProjectTrustFixture {
        fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
            Ok(ProcessOutput {
                termination: Termination::Exit(0),
                stdout: if request.args.iter().any(|a| a == "-qa") {
                    b"1eb5a90bfc6d62690bd80767d981218e0fd4dbf3\n".to_vec()
                } else {
                    Vec::new()
                },
                stdout_overflow: false,
                stderr_overflow: false,
            })
        }
    }
    let (_input, runner, digest) = fixture();
    let dependency = FedoraRpm::verify(&runner.path, &digest, &runner).unwrap();
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("packages")).unwrap();
    fs::copy(
        &runner.path,
        root.path()
            .join("packages")
            .join(&dependency.package().filename),
    )
    .unwrap();
    let bytes = br#"{"version":"1.0","rpms":[{"nevra":"zeromq-4.3.5-22.fc43.x86_64","action":"Install","reason":"Dependency","repo_id":"@stored_transaction(intel-npu-test)","package_path":"./packages/zeromq-4.3.5-22.fc43.x86_64.rpm"}]}"#;
    let inventory = NativeInventory::parse_query(b"rpm|0:6.0.2-1.fc44|x86_64|0\n").unwrap();
    let plan = NativePlan::parse_with_dependencies(
        Some(bytes),
        &[],
        &[dependency],
        &inventory,
        "intel-npu-test",
        &runner,
    )
    .unwrap();
    let project = ProjectRpmTrust::from_armored_key(
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n",
        "1EB5A90BFC6D62690BD80767D981218E0FD4DBF3",
        &ProjectTrustFixture,
    )
    .unwrap();
    // Even an untrusted native project-repository label cannot change the
    // independently verified Fedora input into a project-signed package.
    plan.verify_signatures(root.path(), &project, &runner)
        .unwrap();
}

#[test]
fn wrong_unsigned_incomplete_or_ambiguous_native_signature_is_refused() {
    for bad in [
        signature().replace("36f612dc", "00000000"),
        signature().replace("signature,", "signature, UNKNOWN"),
        signature().replace("Payload SHA256 digest: OK\n", ""),
        signature() + "    unexpected: OK\n",
        signature().replace("RSA/SHA256", "RSA/SHA1"),
        signature() + &signature(),
    ] {
        let (_dir, mut runner, digest) = fixture();
        runner.signature = bad;
        assert!(FedoraRpm::verify(&runner.path, &digest, &runner).is_err());
    }
}

struct MustNotRun;
impl ProcessRunner for MustNotRun {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("bad file must stop before native process")
    }
}

#[test]
fn changed_symlink_oversized_or_wrong_hash_input_is_refused() {
    let (dir, mut runner, digest) = fixture();
    assert!(FedoraRpm::verify(&runner.path, &"0".repeat(64), &MustNotRun).is_err());
    let link = dir.path().join("link.rpm");
    std::os::unix::fs::symlink(&runner.path, &link).unwrap();
    assert!(FedoraRpm::verify(&link, &digest, &MustNotRun).is_err());
    runner.mutate = true;
    assert!(FedoraRpm::verify(&runner.path, &digest, &runner).is_err());
    fs::File::create(&runner.path)
        .unwrap()
        .set_len(2 * 1024 * 1024 * 1024 + 1)
        .unwrap();
    assert!(FedoraRpm::verify(&runner.path, &digest, &MustNotRun).is_err());
}

#[test]
fn invalid_or_filename_mismatched_native_identity_is_refused() {
    for identity in [
        "other|0:4.3.5-22.fc43|x86_64|0\n",
        "zeromq|0:4.3.5-22.fc43|src|0\n",
        "zeromq|0:4.3.5-22.fc43|x86_64|0",
        "zeromq|0:4.3.5-22.fc43|x86_64|0\nextra|0:1-1|x86_64|0\n",
    ] {
        let (_dir, mut runner, digest) = fixture();
        runner.identity = identity.into();
        assert!(FedoraRpm::verify(&runner.path, &digest, &runner).is_err());
    }
}

#[test]
fn complete_captured_434_dependency_plan_is_not_limited_to_project_manifest_size() {
    let records: Vec<Value> = serde_json::from_slice(include_bytes!(
        "fixtures/dnf/fedora-dependency-identities.json"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut packages = Vec::new();
    for row in records {
        let path = dir.path().join(row["filename"].as_str().unwrap());
        fs::write(&path, b"native process fixture").unwrap();
        let runner = NativeFixture {
            identity: format!(
                "{}|{}|{}|0\n",
                row["name"].as_str().unwrap(),
                row["evr"].as_str().unwrap(),
                row["arch"].as_str().unwrap()
            ),
            signature: signature(),
            path,
            mutate: false,
        };
        packages.push(
            FedoraRpm::verify(
                &runner.path,
                &format!("{:x}", Sha256::digest(b"native process fixture")),
                &runner,
            )
            .unwrap(),
        );
    }
    let state = NativeInventory::parse_query(b"rpm|0:6.0.2-1.fc44|x86_64|0\n").unwrap();
    let bytes = include_bytes!("fixtures/dnf/full-dependency-install.json");
    let plan = NativePlan::parse_with_dependencies(
        Some(bytes),
        &[],
        &packages,
        &state,
        "intel-npu-test",
        &MustNotRun,
    )
    .unwrap();
    assert_eq!(plan.preview().lines().count(), 434);
    assert!(plan.preview().contains("zeromq-4.3.5-22.fc43"));
    assert!(
        NativePlan::parse_with_dependencies(
            Some(bytes),
            &[],
            &packages[..433],
            &state,
            "intel-npu-test",
            &MustNotRun
        )
        .is_err()
    );
}
