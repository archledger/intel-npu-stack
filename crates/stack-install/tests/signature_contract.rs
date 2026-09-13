// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use stack_install::{ReleaseTrust, verify_detached, verify_signature_status};
use stack_runtime::{
    ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, SystemProcessRunner,
};

const DATA: &[u8] = include_bytes!("fixtures/signatures/release.json");
const SIGNATURE: &[u8] = include_bytes!("fixtures/signatures/good.sig");
const KEYRING: &[u8] = include_bytes!("fixtures/signatures/good.gpg");
const PRIMARY: &str = "92D23A3F6FE4F172A0BFD4DDD239EC95BC71556B";

fn status(name: &str) -> (i32, Vec<u8>) {
    let results: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/signatures/gpg-results.json")).unwrap();
    (
        results[name]["returncode"].as_i64().unwrap() as i32,
        results[name]["stdout"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
    )
}

#[test]
fn only_the_pinned_valid_signer_is_accepted() {
    let (code, text) = status("valid");
    verify_signature_status(code, &text, PRIMARY).unwrap();
    let (code, text) = status("wrong-valid-signer");
    assert_eq!(code, 0, "cryptographic validity alone is insufficient");
    assert_eq!(
        verify_signature_status(code, &text, PRIMARY)
            .unwrap_err()
            .exit_code,
        20
    );
}

#[test]
fn expired_key_is_rejected_even_when_gnupg_returns_zero() {
    let (code, text) = status("expired-key");
    assert_eq!(code, 0);
    assert!(verify_signature_status(code, &text, PRIMARY).is_err());
}

#[test]
fn missing_duplicate_weak_and_malformed_status_is_rejected() {
    let (_, text) = status("valid");
    let valid = String::from_utf8(text).unwrap();
    for text in [
        String::new(),
        valid.repeat(2),
        valid.replace("VALIDSIG", "UNKNOWN"),
        valid.replace(" 22 10 00 ", " 22 2 00 "),
        valid.replace(" 22 10 00 ", " 22 10 01 "),
        valid.clone() + "[GNUPG:] REVKEYSIG unexpected\n",
        valid.clone() + "[GNUPG:] FAILURE unexpected\n",
        "x".repeat(65_537),
    ] {
        assert!(verify_signature_status(0, text.as_bytes(), PRIMARY).is_err());
    }
    assert!(verify_signature_status(1, valid.as_bytes(), PRIMARY).is_err());
    assert!(verify_signature_status(0, &[0xff], PRIMARY).is_err());
    assert!(verify_signature_status(0, valid.as_bytes(), "short").is_err());
}

struct NoProcess(AtomicUsize);
impl ProcessRunner for NoProcess {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ProcessError::Spawn)
    }
}

#[test]
fn wrong_digest_and_oversized_input_fail_before_process_execution() {
    let runner = NoProcess(AtomicUsize::new(0));
    let wrong = "0".repeat(64);
    let trust = ReleaseTrust {
        sha256: &wrong,
        primary_fingerprint: PRIMARY,
        keyring: KEYRING,
    };
    assert!(verify_detached(DATA, SIGNATURE, &trust, &runner).is_err());
    assert!(verify_detached(&vec![b'x'; 1_048_577], SIGNATURE, &trust, &runner).is_err());
    assert!(verify_detached(DATA, &vec![b'x'; 65_537], &trust, &runner).is_err());
    assert_eq!(runner.0.load(Ordering::SeqCst), 0);
}

struct FixtureClock {
    timestamp: u64,
}
impl ProcessRunner for FixtureClock {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        assert_eq!(request.executable, std::path::Path::new("/usr/bin/gpg"));
        assert!(!request.args.iter().any(|a| a == "--faked-system-time"));
        assert!(request.environment.is_empty());
        assert!(request.args.iter().any(|a| a == "--no-auto-key-retrieve"));
        assert!(!request.args.iter().any(|a| a == "--keyring"));
        use std::os::unix::fs::PermissionsExt;
        let index = request.args.iter().position(|a| a == "--homedir").unwrap();
        let home = std::path::Path::new(&request.args[index + 1]);
        assert_eq!(
            std::fs::metadata(home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut fixture = request.clone();
        fixture.args.splice(
            0..0,
            [
                OsString::from("--faked-system-time"),
                OsString::from(format!("{}!", self.timestamp)),
            ],
        );
        SystemProcessRunner.run(&fixture)
    }
}

#[test]
fn real_gnupg_validates_exact_bytes_and_rejects_wrong_signer_and_expiry() {
    let digest = format!("{:x}", Sha256::digest(DATA));
    let trust = ReleaseTrust {
        sha256: &digest,
        primary_fingerprint: PRIMARY,
        keyring: KEYRING,
    };
    let clock = FixtureClock {
        timestamp: 1_789_149_347,
    };
    verify_detached(DATA, SIGNATURE, &trust, &clock).unwrap();
    let armored = ReleaseTrust {
        keyring: include_bytes!("fixtures/signatures/good.asc"),
        ..trust
    };
    // Release assembly pins the armored public-key envelope; the installer
    // must import it itself instead of handing raw armor to --keyring.
    verify_detached(DATA, SIGNATURE, &armored, &clock)
        .unwrap_or_else(|error| panic!("armored pinned key must verify: {error:?}"));
    let both = ReleaseTrust {
        keyring: include_bytes!("fixtures/signatures/both.gpg"),
        ..trust
    };
    assert!(
        verify_detached(
            DATA,
            include_bytes!("fixtures/signatures/wrong.sig"),
            &both,
            &clock
        )
        .is_err()
    );
    assert!(
        verify_detached(
            DATA,
            SIGNATURE,
            &trust,
            &FixtureClock {
                timestamp: 1_789_322_147
            }
        )
        .is_err()
    );
    assert!(verify_detached(DATA, b"malformed", &trust, &clock).is_err());
    let mut changed = DATA.to_vec();
    changed.push(b'\n');
    let changed_digest = format!("{:x}", Sha256::digest(&changed));
    let changed_trust = ReleaseTrust {
        sha256: &changed_digest,
        ..trust
    };
    assert!(verify_detached(&changed, SIGNATURE, &changed_trust, &clock).is_err());
}
