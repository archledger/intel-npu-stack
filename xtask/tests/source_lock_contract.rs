// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use xtask::source_lock::{SourceGitlinkDisposition, SourceLockStatus, validate};

const EVIDENCE_SHA256: &str = "a7c6bf8df7d8fb707af606599f275e0eb192cd28492c95593b0608ca966c8df1";

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture path has parent"))
        .expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}

fn source_record(name: &str) -> String {
    format!(
        r#"[[sources]]
name = "{name}"
role = "npu_userspace_driver"
kind = "git_tag"
url = "https://example.invalid/{name}.git"
tag = "v1.2.3"
commit = "0123456789abcdef0123456789abcdef01234567"
archive_sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
license_expression = "MIT"
license_files = ["evidence/LICENSE.fixture"]
license_evidence_sha256 = "{EVIDENCE_SHA256}"
redistribution = "allowed"
"#
    )
}

fn valid_lock() -> String {
    format!(
        r#"schema_version = 1
status = "sealed"
profile_id = "fedora-44-x86_64-8086-643e-candidate"

[target]
distribution_id = "fedora"
version_id = "44"
architecture = "x86_64"
pci_vendor = "8086"
pci_device = "643e"

{}
"#,
        source_record("intel-linux-npu-driver")
    )
}

fn validate_text(input: &str) -> Result<xtask::source_lock::ValidatedSourceLock, String> {
    let fixture = TempDir::new().expect("create source-lock fixture");
    write(
        fixture.path(),
        "evidence/LICENSE.fixture",
        "fixture license\n",
    );
    write(fixture.path(), "provider-sources.toml", input);
    validate(
        &fixture.path().join("provider-sources.toml"),
        fixture.path(),
    )
    .map_err(|error| error.code)
}

#[test]
fn accepts_a_sealed_sorted_source_lock() {
    let validated = validate_text(&valid_lock()).expect("valid source lock");
    assert_eq!(validated.status, SourceLockStatus::Sealed);
    assert_eq!(validated.profile_id, "fedora-44-x86_64-8086-643e-candidate");
    assert_eq!(validated.sources.len(), 1);
    assert_eq!(validated.sources[0].name, "intel-linux-npu-driver");
    assert_eq!(
        validated.sources[0].commit,
        "0123456789abcdef0123456789abcdef01234567"
    );
}

#[test]
fn accepts_an_empty_draft_but_not_an_empty_sealed_lock() {
    let draft = valid_lock()
        .replace("status = \"sealed\"", "status = \"draft\"")
        .replace("[target]", "sources = []\n\n[target]")
        .replace(&source_record("intel-linux-npu-driver"), "");
    let validated = validate_text(&draft).expect("empty draft is an explicit staging state");
    assert_eq!(validated.status, SourceLockStatus::Draft);
    assert!(validated.sources.is_empty());

    let sealed = draft.replace("status = \"draft\"", "status = \"sealed\"");
    assert_eq!(validate_text(&sealed), Err("SOURCE_LOCK_EMPTY".to_owned()));
}

#[test]
fn rejects_duplicate_or_unsorted_source_names() {
    let duplicate = valid_lock().replace(
        &source_record("intel-linux-npu-driver"),
        &format!(
            "{}\n{}",
            source_record("intel-linux-npu-driver"),
            source_record("intel-linux-npu-driver")
        ),
    );
    assert_eq!(
        validate_text(&duplicate),
        Err("SOURCE_LOCK_NAME_INVALID".to_owned())
    );

    let unsorted = valid_lock().replace(
        &source_record("intel-linux-npu-driver"),
        &format!(
            "{}\n{}",
            source_record("z-source"),
            source_record("a-source")
        ),
    );
    assert_eq!(
        validate_text(&unsorted),
        Err("SOURCE_LOCK_NAME_INVALID".to_owned())
    );
}

#[test]
fn rejects_unpinned_and_incomplete_annotated_git_sources() {
    let bad_commit = valid_lock().replace("0123456789abcdef0123456789abcdef01234567", "main");
    assert_eq!(
        validate_text(&bad_commit),
        Err("SOURCE_LOCK_COMMIT_INVALID".to_owned())
    );

    let annotated_without_object =
        valid_lock().replace("kind = \"git_tag\"", "kind = \"git_annotated_tag\"");
    assert_eq!(
        validate_text(&annotated_without_object),
        Err("SOURCE_LOCK_TAG_OBJECT_INVALID".to_owned())
    );
}

#[test]
fn rejects_invalid_archive_and_license_evidence_digests() {
    let zero_archive = valid_lock().replace(
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(
        validate_text(&zero_archive),
        Err("SOURCE_LOCK_ARCHIVE_HASH_INVALID".to_owned())
    );

    let wrong_evidence = valid_lock().replace(EVIDENCE_SHA256, &"b".repeat(64));
    assert_eq!(
        validate_text(&wrong_evidence),
        Err("SOURCE_LOCK_LICENSE_EVIDENCE_INVALID".to_owned())
    );
}

#[test]
fn rejects_license_paths_outside_the_repository() {
    let traversal = valid_lock().replace("evidence/LICENSE.fixture", "../outside/LICENSE.fixture");
    assert_eq!(
        validate_text(&traversal),
        Err("SOURCE_LOCK_LICENSE_PATH_INVALID".to_owned())
    );

    let absolute = valid_lock().replace("evidence/LICENSE.fixture", "/tmp/LICENSE.fixture");
    assert_eq!(
        validate_text(&absolute),
        Err("SOURCE_LOCK_LICENSE_PATH_INVALID".to_owned())
    );
}

#[test]
fn rejects_unknown_fields_and_unreviewed_redistribution_values() {
    let unknown = valid_lock().replace(
        "profile_id = \"fedora-44-x86_64-8086-643e-candidate\"",
        "profile_id = \"fedora-44-x86_64-8086-643e-candidate\"\nunexpected = true",
    );
    assert_eq!(
        validate_text(&unknown),
        Err("SOURCE_LOCK_TOML_INVALID".to_owned())
    );

    let unreviewed = valid_lock().replace(
        "redistribution = \"allowed\"",
        "redistribution = \"unreviewed\"",
    );
    assert_eq!(
        validate_text(&unreviewed),
        Err("SOURCE_LOCK_TOML_INVALID".to_owned())
    );
}

#[test]
fn accepts_exactly_one_reviewed_gitlink_disposition() {
    let system = valid_lock().replace(
        "redistribution = \"allowed\"",
        r#"redistribution = "allowed"

[[sources.gitlinks]]
path = "third_party/yaml-cpp"
commit = "abcdef0123456789abcdef0123456789abcdef01"
disposition = "system"
packages = [
  { name = "gmock-devel", nevr = "0:1.17.0-2.fc44" },
  { name = "gtest-devel", nevr = "0:1.17.0-2.fc44" },
]"#,
    );
    let validated = validate_text(&system).expect("system replacement is explicit");
    assert_eq!(
        validated.sources[0].gitlinks[0].disposition,
        SourceGitlinkDisposition::System
    );
    assert_eq!(validated.sources[0].gitlinks[0].packages.len(), 2);

    let disabled = valid_lock().replace(
        "redistribution = \"allowed\"",
        r#"redistribution = "allowed"

[[sources.gitlinks]]
path = "src/plugins/intel_gpu/thirdparty/onednn_gpu"
commit = "abcdef0123456789abcdef0123456789abcdef01"
disposition = "disabled"
build_option = "ENABLE_INTEL_GPU=OFF""#,
    );
    let validated = validate_text(&disabled).expect("disabled source is explicit");
    assert_eq!(
        validated.sources[0].gitlinks[0].disposition,
        SourceGitlinkDisposition::Disabled
    );
}

#[test]
fn rejects_ambiguous_or_incomplete_gitlink_dispositions() {
    let incomplete = valid_lock().replace(
        "redistribution = \"allowed\"",
        r#"redistribution = "allowed"

[[sources.gitlinks]]
path = "third_party/yaml-cpp"
commit = "abcdef0123456789abcdef0123456789abcdef01"
disposition = "system"
packages = []"#,
    );
    assert_eq!(
        validate_text(&incomplete),
        Err("SOURCE_LOCK_GITLINK_INVALID".to_owned())
    );

    let ambiguous = valid_lock().replace(
        "redistribution = \"allowed\"",
        r#"redistribution = "allowed"

[[sources.gitlinks]]
path = "third_party/yaml-cpp"
commit = "abcdef0123456789abcdef0123456789abcdef01"
disposition = "system"
packages = [{ name = "yaml-cpp-devel", nevr = "0:0.8.0-5.fc44" }]
source = "yaml-cpp""#,
    );
    assert_eq!(
        validate_text(&ambiguous),
        Err("SOURCE_LOCK_GITLINK_INVALID".to_owned())
    );

    let enabled = valid_lock().replace(
        "redistribution = \"allowed\"",
        r#"redistribution = "allowed"

[[sources.gitlinks]]
path = "third_party/tests"
commit = "abcdef0123456789abcdef0123456789abcdef01"
disposition = "disabled"
build_option = "ENABLE_TESTS=ON""#,
    );
    assert_eq!(
        validate_text(&enabled),
        Err("SOURCE_LOCK_GITLINK_INVALID".to_owned())
    );
}

#[test]
fn repository_fixture_catalog_exercises_the_public_validator() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let fixture_root = repository_root.join("fixtures/source-lock");

    validate(&fixture_root.join("valid-fedora-44.toml"), &repository_root)
        .expect("valid repository fixture");

    for (filename, expected_code) in [
        (
            "invalid-duplicate-name.toml.invalid",
            "SOURCE_LOCK_NAME_INVALID",
        ),
        (
            "invalid-unpinned-git.toml.invalid",
            "SOURCE_LOCK_COMMIT_INVALID",
        ),
        (
            "invalid-license-evidence.toml.invalid",
            "SOURCE_LOCK_LICENSE_EVIDENCE_INVALID",
        ),
        (
            "invalid-redistribution.toml.invalid",
            "SOURCE_LOCK_TOML_INVALID",
        ),
    ] {
        let error = validate(&fixture_root.join(filename), &repository_root)
            .expect_err("invalid repository fixture");
        assert_eq!(error.code, expected_code, "fixture {filename}");
    }
}
