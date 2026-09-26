// SPDX-License-Identifier: Apache-2.0

use stack_schema::{Profile, ProfileStatus};
use xtask::kernel_candidate::retarget;

// The generated candidate as it was before the 0.1.0 promotion; retargeting accepts only candidates.
const ORIGINAL: &str = include_str!("fixtures/lunar-lake-x86_64-candidate.toml");

#[test]
fn new_kernel_candidate_preserves_all_provider_and_license_bindings() {
    let output = retarget(
        ORIGINAL,
        "fedora-44-lunar-lake-x86_64-kernel-7.2.4",
        "7.2.4-200.fc44.x86_64",
    )
    .unwrap();
    let original = Profile::parse_toml(ORIGINAL).unwrap();
    let candidate = Profile::parse_toml(&output).unwrap();
    assert_eq!(candidate.id, "fedora-44-lunar-lake-x86_64-kernel-7.2.4");
    assert_eq!(candidate.kernel.min, "7.2.4");
    assert_eq!(candidate.kernel.max_exclusive, "7.2.5");
    assert_eq!(candidate.status, ProfileStatus::Candidate);
    assert!(candidate.qualification.is_none());
    let mut restored = candidate;
    restored.id = original.id.clone();
    restored.kernel = original.kernel.clone();
    assert_eq!(restored, original);
    // The source-lock comment must survive retargeting verbatim; its value is
    // branch state, so derive the expectation from the input profile.
    let lock_comment = ORIGINAL
        .lines()
        .find(|line| line.starts_with("# source_lock_sha256 = "))
        .expect("base profile carries a source lock comment");
    assert!(output.contains(lock_comment));
}

#[test]
fn candidate_retarget_refuses_reused_identity_invalid_kernel_and_promoted_input() {
    assert!(retarget(ORIGINAL, "fedora-44-lunar-lake-x86_64", "7.2.4").is_err());
    assert!(retarget(ORIGINAL, "new-candidate", "not-a-kernel").is_err());
    assert!(
        retarget(
            &ORIGINAL.replace("status = \"candidate\"", "status = \"experimental\""),
            "new-candidate",
            "7.2.4"
        )
        .is_err()
    );
    assert!(retarget(ORIGINAL, "bad\"\nid", "7.2.4").is_err());
}

#[test]
fn cli_creates_new_candidate_and_refuses_to_overwrite_it() {
    let root = tempfile::TempDir::new().unwrap();
    let source = root.path().join("old.toml");
    let output = root.path().join("new.toml");
    std::fs::write(&source, ORIGINAL).unwrap();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["retarget-candidate", "--candidate"])
            .arg(&source)
            .args([
                "--id",
                "new-kernel-candidate",
                "--kernel-release",
                "7.2.4-200.fc44.x86_64",
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(std::fs::read_to_string(&source).unwrap(), ORIGINAL);
    let bytes = std::fs::read(&output).unwrap();
    assert!(!run().status.success());
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
}
