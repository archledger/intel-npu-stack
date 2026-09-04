// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use xtask::{ValidationFailure, validate_profiles_dir};

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture path has parent"))
        .expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}

fn valid_profile(id: &str) -> String {
    let mut components = String::new();
    for name in [
        "npu_firmware",
        "level_zero_loader",
        "npu_userspace_driver",
        "npu_compiler",
        "openvino_runtime",
        "openvino_npu_plugin",
    ] {
        components.push_str(&format!(
            "\n[components.{name}]\nversion = \"1.0.0\"\nsource = \"https://example.invalid/{name}\"\nsha256 = \"{HASH}\"\n\n[components.{name}.provider]\npackage = \"fixture-{name}\"\nversion = \"0:1.0.0-1.fc44\"\nactivation = \"immediate\"\n\n[[components.{name}.provider.files]]\npath = \"/usr/lib64/{name}.fixture.so\"\nsha256 = \"{HASH}\"\n\n[components.{name}.license]\nexpression = \"Apache-2.0\"\nredistribution = \"allowed\"\nevidence_sha256 = \"{HASH}\"\n"
        ));
    }
    format!(
        r#"schema_version = 1
id = "{id}"
stack_release = "0.1.0"
status = "qualified"
package_manager = "rpm"

[[conflicts]]
package = "fixture-conflicting-driver"
resolution = "remove"

[platform]
id = "testos"
version_id = "1"
arch = "x86_64"

[[hardware]]
vendor = "8086"
device = "abcd"

[kernel]
min = "6.10.0"
max_exclusive = "6.20.0"
module = "intel_vpu"
{components}
[qualification]
evidence_id = "fixture-only-not-hardware-evidence"
evidence_sha256 = "{HASH}"
qualified_at = "2026-09-03T19:00:00Z"
hardware_class = "fixture-lunar-lake-class"
test_suite_version = "fixture-suite-v1"
"#
    )
}

fn validate(fixture: &TempDir) -> (Result<(), ValidationFailure>, String) {
    let mut output = Vec::new();
    let result = validate_profiles_dir(fixture.path(), &mut output);
    (
        result,
        String::from_utf8(output).expect("validator output must be UTF-8"),
    )
}

#[test]
fn accepts_empty_production_directory() {
    let fixture = tempfile::tempdir().expect("create empty fixture");
    let (result, output) = validate(&fixture);
    assert_eq!(result, Ok(()));
    assert_eq!(output, "validated 0 profiles\n");
}

#[test]
fn accepts_sorted_unique_valid_profiles() {
    let fixture = tempfile::tempdir().expect("create valid fixture");
    write(fixture.path(), "z-last.toml", &valid_profile("profile-z"));
    write(fixture.path(), "a-first.toml", &valid_profile("profile-a"));

    let (result, output) = validate(&fixture);
    assert_eq!(result, Ok(()));
    assert_eq!(
        output,
        "ok a-first.toml profile-a\nok z-last.toml profile-z\nvalidated 2 profiles\n"
    );
}

#[test]
fn rejects_invalid_profile_with_filename_and_error_code() {
    let fixture = tempfile::tempdir().expect("create invalid fixture");
    write(fixture.path(), "broken.toml", "schema_version = 1\n");

    let (result, output) = validate(&fixture);
    assert_eq!(result, Err(ValidationFailure::InvalidProfiles));
    assert!(output.contains("error broken.toml PROFILE_TOML_INVALID"));
    assert!(output.ends_with("validation failed: 1 invalid profile\n"));
}

#[test]
fn rejects_duplicate_profile_id() {
    let fixture = tempfile::tempdir().expect("create duplicate fixture");
    write(fixture.path(), "a.toml", &valid_profile("duplicate"));
    write(fixture.path(), "b.toml", &valid_profile("duplicate"));

    let (result, output) = validate(&fixture);
    assert_eq!(result, Err(ValidationFailure::InvalidProfiles));
    assert!(output.contains("error b.toml DUPLICATE_PROFILE_ID"));
    assert!(output.contains("profile id duplicate already appeared in a.toml"));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_profile() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("create symlink fixture");
    let external = tempfile::NamedTempFile::new().expect("create external profile");
    fs::write(external.path(), valid_profile("external")).expect("write external profile");
    symlink(external.path(), fixture.path().join("linked.toml")).expect("create symlink");

    let (result, output) = validate(&fixture);
    assert_eq!(result, Err(ValidationFailure::InvalidProfiles));
    assert_eq!(
        output,
        "error linked.toml PROFILE_SYMLINK_REJECTED profile is a symlink\nvalidation failed: 1 invalid profile\n"
    );
}

#[test]
fn ignores_non_toml_direct_children() {
    let fixture = tempfile::tempdir().expect("create filtering fixture");
    write(fixture.path(), "notes.txt", "not a profile");
    write(fixture.path(), "draft.toml.invalid", "not a profile");

    let (result, output) = validate(&fixture);
    assert_eq!(result, Ok(()));
    assert_eq!(output, "validated 0 profiles\n");
}

#[test]
fn does_not_recurse_into_subdirectories() {
    let fixture = tempfile::tempdir().expect("create nested fixture");
    write(fixture.path(), "nested/broken.toml", "not valid TOML");

    let (result, output) = validate(&fixture);
    assert_eq!(result, Ok(()));
    assert_eq!(output, "validated 0 profiles\n");
}

#[test]
fn repository_fixtures_capture_valid_and_missing_component_contracts() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/profiles");
    for filename in ["valid-qualified.toml", "valid-experimental.toml"] {
        let input = fs::read_to_string(fixture_dir.join(filename))
            .unwrap_or_else(|error| panic!("read {filename}: {error}"));
        stack_schema::Profile::parse_toml(&input)
            .unwrap_or_else(|error| panic!("parse {filename}: {error}"));
    }

    let invalid = fs::read_to_string(fixture_dir.join("invalid-missing-component.toml.invalid"))
        .expect("read invalid fixture");
    let error = stack_schema::Profile::parse_toml(&invalid)
        .expect_err("missing-component fixture must be rejected");
    assert_eq!(error.code, "PROFILE_COMPONENT_MISSING");
}
