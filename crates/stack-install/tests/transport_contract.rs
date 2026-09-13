// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use stack_install::{ReleaseLocation, fetch_release};
use stack_runtime::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, Termination};

const METADATA: &[u8] = include_bytes!("fixtures/release.json");
const PROFILE: &[u8] = include_bytes!("fixtures/profile.toml");
const KEYRING: &[u8] = include_bytes!("fixtures/signatures/good.gpg");
const PRIMARY: &str = "92D23A3F6FE4F172A0BFD4DDD239EC95BC71556B";

struct FixtureTransport {
    fault: &'static str,
    metadata: Vec<u8>,
    requests: Mutex<Vec<ProcessRequest>>,
    files: Mutex<Vec<PathBuf>>,
}

impl FixtureTransport {
    fn new(fault: &'static str) -> Self {
        Self {
            fault,
            metadata: METADATA.to_vec(),
            requests: Mutex::new(Vec::new()),
            files: Mutex::new(Vec::new()),
        }
    }
}

impl ProcessRunner for FixtureTransport {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        self.requests.lock().unwrap().push(request.clone());
        assert!(request.environment.is_empty());
        let mut stdout = Vec::new();
        let mut termination = Termination::Exit(0);
        let mut stdout_overflow = false;
        match request.executable.to_str().unwrap() {
            "/usr/bin/curl" => {
                assert_eq!(request.args[0], "--disable");
                for flag in ["--proto", "--proto-redir"] {
                    let index = request.args.iter().position(|a| a == flag).unwrap();
                    assert_eq!(request.args[index + 1], "=https");
                }
                assert!(request.args.iter().any(|a| a == "--max-filesize"));
                let url = request.args.last().unwrap().to_str().unwrap();
                let output_index = request.args.iter().position(|a| a == "--output").unwrap();
                let output = PathBuf::from(&request.args[output_index + 1]);
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(output.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                self.files.lock().unwrap().push(output.clone());
                let bytes = if url.ends_with("release.json.sig") {
                    b"synthetic detached signature".to_vec()
                } else if url.ends_with("release.json") {
                    self.metadata.clone()
                } else if url.ends_with("profile.toml") {
                    if self.fault == "profile" {
                        b"changed profile".to_vec()
                    } else {
                        PROFILE.to_vec()
                    }
                } else {
                    panic!("unexpected metadata URL")
                };
                if self.fault == "oversized" {
                    fs::write(&output, vec![b'x'; 1_048_577]).unwrap();
                } else if self.fault == "symlink" {
                    std::os::unix::fs::symlink("/dev/null", &output).unwrap();
                } else {
                    fs::write(&output, bytes).unwrap();
                }
                if self.fault == "download" {
                    termination = Termination::Exit(18);
                }
                if self.fault == "timeout" {
                    return Err(ProcessError::Timeout);
                }
            }
            "/usr/bin/gpg" => {
                if request.args.iter().any(|a| a == "--import") {
                    assert_eq!(
                        fs::read(PathBuf::from(request.args.last().unwrap())).unwrap(),
                        KEYRING
                    );
                    return Ok(ProcessOutput {
                        termination: Termination::Exit(if self.fault == "key-import" {
                            1
                        } else {
                            0
                        }),
                        stdout: Vec::new(),
                        stdout_overflow: false,
                        stderr_overflow: false,
                    });
                }
                assert!(request.args.iter().any(|a| a == "--verify"));
                let records: serde_json::Value =
                    serde_json::from_str(include_str!("fixtures/signatures/gpg-results.json"))
                        .unwrap();
                let key = match self.fault {
                    "signer" => "wrong-valid-signer",
                    "expired" => "expired-key",
                    _ => "valid",
                };
                stdout = records[key]["stdout"].as_str().unwrap().as_bytes().to_vec();
                if self.fault == "gpg-overflow" {
                    stdout_overflow = true;
                }
                if self.fault == "gpg-timeout" {
                    return Err(ProcessError::Timeout);
                }
                // The primitive's real cryptography is tested separately. Here
                // bind the orchestration fixture to exactly the bytes supplied.
                assert_eq!(
                    fs::read(PathBuf::from(request.args.last().unwrap())).unwrap(),
                    self.metadata
                );
            }
            _ => panic!("transport attempted an unexpected executable"),
        }
        Ok(ProcessOutput {
            termination,
            stdout,
            stdout_overflow,
            stderr_overflow: false,
        })
    }
}

fn location<'a>(digest: &'a str, base: &'a str) -> ReleaseLocation<'a> {
    ReleaseLocation {
        version: "0.1.0",
        base_url: base,
        metadata_sha256: digest,
        primary_fingerprint: PRIMARY,
        keyring: KEYRING,
    }
}

#[test]
fn exact_release_is_authenticated_and_bound_before_it_can_be_used() {
    let digest = format!("{:x}", Sha256::digest(METADATA));
    for base in [
        "https://downloads.example.invalid/0.1.0/",
        "https://github.com/example/project/releases/download/v0.1.0/",
    ] {
        let runner = FixtureTransport::new("");
        let release = fetch_release(&location(&digest, base), &runner).unwrap();
        assert_eq!(
            release
                .manifest()
                .selected_packages(false, false)
                .unwrap()
                .len(),
            14
        );
        assert_eq!(
            release.profile().status,
            stack_schema::ProfileStatus::Candidate
        );
        let calls = runner.requests.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .map(|r| r.executable.to_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "/usr/bin/curl",
                "/usr/bin/curl",
                "/usr/bin/gpg",
                "/usr/bin/gpg",
                "/usr/bin/curl"
            ]
        );
        assert!(runner.files.lock().unwrap().iter().all(|p| !p.exists()));
    }
}

#[test]
fn unsafe_release_location_is_rejected_before_any_process() {
    let digest = format!("{:x}", Sha256::digest(METADATA));
    for base in [
        "http://example.invalid/0.1.0/",
        "https://example.invalid/latest/",
        "https://example.invalid/0.1.0/../",
    ] {
        let runner = FixtureTransport::new("");
        assert_eq!(
            fetch_release(&location(&digest, base), &runner)
                .unwrap_err()
                .exit_code,
            20
        );
        assert!(runner.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn wrong_metadata_digest_stops_before_signature_or_profile_fetch() {
    let runner = FixtureTransport::new("");
    assert!(
        fetch_release(
            &location(&"0".repeat(64), "https://example.invalid/0.1.0/"),
            &runner
        )
        .is_err()
    );
    assert_eq!(runner.requests.lock().unwrap().len(), 1);
    assert!(runner.files.lock().unwrap().iter().all(|p| !p.exists()));
}

#[test]
fn transfer_file_and_signature_failures_never_produce_a_verified_release() {
    let digest = format!("{:x}", Sha256::digest(METADATA));
    for fault in [
        "download",
        "timeout",
        "oversized",
        "symlink",
        "profile",
        "signer",
        "expired",
        "gpg-overflow",
        "gpg-timeout",
        "key-import",
    ] {
        let runner = FixtureTransport::new(fault);
        assert_eq!(
            fetch_release(
                &location(&digest, "https://example.invalid/0.1.0/"),
                &runner
            )
            .unwrap_err()
            .exit_code,
            20,
            "{fault}"
        );
        assert!(runner.files.lock().unwrap().iter().all(|p| !p.exists()));
    }
}

#[test]
fn authenticated_but_invalid_or_different_release_metadata_is_rejected() {
    for changed in [
        b"{}".to_vec(),
        String::from_utf8(METADATA.to_vec())
            .unwrap()
            .replace("0.1.0", "0.2.0")
            .into_bytes(),
    ] {
        let mut runner = FixtureTransport::new("");
        runner.metadata = changed;
        let digest = format!("{:x}", Sha256::digest(&runner.metadata));
        assert!(
            fetch_release(
                &location(&digest, "https://example.invalid/0.1.0/"),
                &runner
            )
            .is_err()
        );
        assert_eq!(
            runner
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.executable == PathBuf::from("/usr/bin/curl"))
                .count(),
            2,
            "profile fetch must not occur"
        );
    }
}
