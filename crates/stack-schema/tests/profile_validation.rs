// SPDX-License-Identifier: Apache-2.0

use stack_schema::{KernelVersion, Profile, ProfileStatus};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const HASH_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const HASH_F: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn valid_profile_toml(status: &str) -> String {
    let qualification = if status == "qualified" {
        r#"
[qualification]
evidence_id = "fixture-evidence-001"
qualified_at = "2026-09-03T19:00:00Z"
"#
    } else {
        ""
    };

    format!(
        r#"schema_version = 1
id = "testos-1-x86_64-8086-abcd"
stack_release = "0.1.0"
status = "{status}"

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

[components.npu_firmware]
version = "1.0.0"
source = "https://example.invalid/npu-firmware"
sha256 = "{HASH_A}"

[components.level_zero_loader]
version = "1.0.0"
source = "https://example.invalid/level-zero-loader"
sha256 = "{HASH_B}"

[components.npu_userspace_driver]
version = "1.0.0"
source = "https://example.invalid/npu-userspace-driver"
sha256 = "{HASH_C}"

[components.npu_compiler]
version = "1.0.0"
source = "https://example.invalid/npu-compiler"
sha256 = "{HASH_D}"

[components.openvino_runtime]
version = "1.0.0"
source = "https://example.invalid/openvino-runtime"
sha256 = "{HASH_E}"

[components.openvino_npu_plugin]
version = "1.0.0"
source = "https://example.invalid/openvino-npu-plugin"
sha256 = "{HASH_F}"
{qualification}"#
    )
}

fn assert_error_code(input: &str, expected: &'static str) {
    let error = Profile::parse_toml(input).expect_err("profile must be rejected");
    assert_eq!(error.code, expected, "unexpected error: {error}");
}

#[test]
fn parse_valid_qualified_profile() {
    let profile = Profile::parse_toml(&valid_profile_toml("qualified"))
        .expect("qualified fixture must parse");

    assert_eq!(profile.schema_version, 1);
    assert_eq!(profile.id, "testos-1-x86_64-8086-abcd");
    assert_eq!(profile.status, ProfileStatus::Qualified);
    assert_eq!(profile.components.len(), 6);
    assert_eq!(
        profile
            .qualification
            .expect("qualified profile needs evidence")
            .evidence_id,
        "fixture-evidence-001"
    );
}

#[test]
fn reject_unknown_top_level_field() {
    let input = format!(
        "{}\nunknown_policy = true\n",
        valid_profile_toml("qualified")
    );
    assert_error_code(&input, "PROFILE_TOML_INVALID");
}

#[test]
fn reject_schema_version_other_than_one() {
    let input = valid_profile_toml("qualified").replace("schema_version = 1", "schema_version = 2");
    assert_error_code(&input, "PROFILE_SCHEMA_UNSUPPORTED");
}

#[test]
fn reject_non_https_component_source() {
    let input = valid_profile_toml("qualified").replace(
        "source = \"https://example.invalid/npu-firmware\"",
        "source = \"http://example.invalid/npu-firmware\"",
    );
    assert_error_code(&input, "PROFILE_FIELD_INVALID");
}

#[test]
fn reject_uppercase_or_wrong_length_sha256() {
    let uppercase = valid_profile_toml("qualified").replace(HASH_A, &"A".repeat(64));
    assert_error_code(&uppercase, "PROFILE_HASH_INVALID");

    let short = valid_profile_toml("qualified").replace(HASH_A, "abc123");
    assert_error_code(&short, "PROFILE_HASH_INVALID");
}

#[test]
fn reject_missing_required_component() {
    let block = format!(
        r#"
[components.openvino_npu_plugin]
version = "1.0.0"
source = "https://example.invalid/openvino-npu-plugin"
sha256 = "{HASH_F}"
"#
    );
    let input = valid_profile_toml("qualified").replace(&block, "\n");
    assert_error_code(&input, "PROFILE_COMPONENT_MISSING");
}

#[test]
fn reject_invalid_pci_hex() {
    let input = valid_profile_toml("qualified").replace("device = \"abcd\"", "device = \"ABC\"");
    assert_error_code(&input, "PROFILE_PCI_ID_INVALID");
}

#[test]
fn reject_reversed_kernel_range() {
    let input = valid_profile_toml("qualified")
        .replace("max_exclusive = \"6.20.0\"", "max_exclusive = \"6.9.0\"");
    assert_error_code(&input, "PROFILE_KERNEL_RANGE_INVALID");
}

#[test]
fn reject_qualified_without_evidence() {
    let input = valid_profile_toml("qualified")
        .split("\n[qualification]\n")
        .next()
        .expect("fixture has a qualification section")
        .to_owned();
    assert_error_code(&input, "PROFILE_QUALIFICATION_MISSING");
}

#[test]
fn accept_experimental_without_qualification() {
    let profile = Profile::parse_toml(&valid_profile_toml("experimental"))
        .expect("experimental fixture must parse without qualification");
    assert_eq!(profile.status, ProfileStatus::Experimental);
    assert!(profile.qualification.is_none());
}

#[test]
fn kernel_version_ignores_distribution_suffix() {
    let version = KernelVersion::parse_release("6.17.3-200.fc44.x86_64")
        .expect("distribution suffix must be ignored");
    assert_eq!((version.major, version.minor, version.patch), (6, 17, 3));
}

#[test]
fn kernel_version_rejects_missing_signed_whitespace_or_overflow_components() {
    for invalid in [
        "6.17",
        "+6.17.3",
        " 6.17.3",
        "6.17.3 ",
        "18446744073709551616.1.1",
    ] {
        let error = KernelVersion::parse_release(invalid).expect_err("kernel must be rejected");
        assert_eq!(error.code, "PROFILE_FIELD_INVALID", "input: {invalid}");
    }
}
