// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;

use stack_schema::{
    ActivationRequirement, KernelVersion, PackageManager, Profile, ProfileStatus,
    RedistributionVerdict,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const HASH_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const HASH_F: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn component(name: &str, hash: &str, package: &str, activation: &str, path: &str) -> String {
    format!(
        r#"
[components.{name}]
version = "1.0.0"
source = "https://example.invalid/{name}"
sha256 = "{hash}"

[components.{name}.provider]
package = "{package}"
version = "0:1.0.0-1.fc44"
activation = "{activation}"

[[components.{name}.provider.files]]
path = "{path}"
sha256 = "{hash}"

[components.{name}.license]
expression = "Apache-2.0"
redistribution = "allowed"
evidence_sha256 = "{hash}"
"#
    )
}

fn valid_profile_toml(status: &str) -> String {
    let qualification = if status == "qualified" {
        format!(
            r#"
[qualification]
evidence_id = "fixture-evidence-001"
evidence_sha256 = "{HASH_F}"
qualified_at = "2026-09-03T19:00:00Z"
hardware_class = "fixture-lunar-lake-class"
test_suite_version = "fixture-suite-v1"
"#
        )
    } else {
        String::new()
    };

    let components = [
        component(
            "npu_firmware",
            HASH_A,
            "fixture-npu-firmware",
            "reboot",
            "/usr/lib/firmware/fixture/npu.bin",
        ),
        component(
            "level_zero_loader",
            HASH_B,
            "fixture-level-zero-loader",
            "immediate",
            "/usr/lib64/libze_loader.fixture.so",
        ),
        component(
            "npu_userspace_driver",
            HASH_C,
            "fixture-npu-userspace-driver",
            "relogin",
            "/usr/lib64/libnpu_driver.fixture.so",
        ),
        component(
            "npu_compiler",
            HASH_D,
            "fixture-npu-compiler",
            "immediate",
            "/usr/libexec/intel-npu-stack/fixture-compiler",
        ),
        component(
            "openvino_runtime",
            HASH_E,
            "fixture-openvino-runtime",
            "immediate",
            "/usr/lib64/libopenvino.fixture.so",
        ),
        component(
            "openvino_npu_plugin",
            HASH_F,
            "fixture-openvino-npu-plugin",
            "immediate",
            "/usr/lib64/libopenvino_intel_npu_plugin.fixture.so",
        ),
    ]
    .join("");

    format!(
        r#"schema_version = 1
id = "testos-1-x86_64-8086-abcd"
stack_release = "0.1.0"
status = "{status}"
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
{components}{qualification}"#
    )
}

fn assert_error_code(input: &str, expected: &'static str) {
    let error = Profile::parse_toml(input).expect_err("profile must be rejected");
    assert_eq!(error.code, expected, "unexpected error: {error}");
}

#[test]
fn parse_complete_corrected_profile_v1() {
    let profile = Profile::parse_toml(&valid_profile_toml("qualified"))
        .expect("qualified fixture must parse");

    assert_eq!(profile.schema_version, 1);
    assert_eq!(profile.id, "testos-1-x86_64-8086-abcd");
    assert_eq!(profile.status, ProfileStatus::Qualified);
    assert_eq!(profile.package_manager, PackageManager::Rpm);
    assert_eq!(profile.conflicts.len(), 1);
    assert_eq!(profile.components.len(), 6);

    let firmware = profile
        .components
        .get("npu_firmware")
        .expect("firmware component exists");
    assert_eq!(firmware.provider.package, "fixture-npu-firmware");
    assert_eq!(firmware.provider.activation, ActivationRequirement::Reboot);
    assert_eq!(firmware.provider.files.len(), 1);
    assert_eq!(
        firmware.license.redistribution,
        RedistributionVerdict::Allowed
    );

    let qualification = profile
        .qualification
        .expect("qualified profile needs evidence");
    assert_eq!(qualification.evidence_id, "fixture-evidence-001");
    assert_eq!(qualification.evidence_sha256, HASH_F);
    assert_eq!(qualification.hardware_class, "fixture-lunar-lake-class");
    assert_eq!(qualification.test_suite_version, "fixture-suite-v1");
}

#[test]
fn reject_missing_native_provider() {
    let provider = r#"[components.npu_firmware.provider]
package = "fixture-npu-firmware"
version = "0:1.0.0-1.fc44"
activation = "reboot"

"#;
    let input = valid_profile_toml("qualified").replace(provider, "");
    assert_error_code(&input, "PROFILE_TOML_INVALID");
}

#[test]
fn reject_unsafe_package_name_or_version() {
    let unsafe_name =
        valid_profile_toml("qualified").replace("fixture-npu-firmware", "fixture npu;firmware");
    assert_error_code(&unsafe_name, "PROFILE_PACKAGE_INVALID");

    let unsafe_version = valid_profile_toml("qualified").replace("0:1.0.0-1.fc44", "1.0.0;remove");
    assert_error_code(&unsafe_version, "PROFILE_PACKAGE_INVALID");
}

#[test]
fn reject_non_normalized_or_unapproved_installed_path() {
    for invalid in [
        "usr/lib/firmware/fixture/npu.bin",
        "/opt/fixture/npu.bin",
        "/usr/lib/firmware//fixture/npu.bin",
        "/usr/lib/firmware/fixture/../npu.bin",
        "/usr/lib/firmware/fixture/npu.bin/",
    ] {
        let input =
            valid_profile_toml("qualified").replace("/usr/lib/firmware/fixture/npu.bin", invalid);
        assert_error_code(&input, "PROFILE_PATH_INVALID");
    }
}

#[test]
fn reject_installed_file_hash_with_wrong_shape() {
    let file_record =
        format!("path = \"/usr/lib/firmware/fixture/npu.bin\"\nsha256 = \"{HASH_A}\"");
    let input = valid_profile_toml("qualified").replace(
        &file_record,
        "path = \"/usr/lib/firmware/fixture/npu.bin\"\nsha256 = \"ABC123\"",
    );
    assert_error_code(&input, "PROFILE_HASH_INVALID");
}

#[test]
fn reject_unknown_activation_or_package_manager() {
    let manager = valid_profile_toml("qualified")
        .replace("package_manager = \"rpm\"", "package_manager = \"apk\"");
    assert_error_code(&manager, "PROFILE_TOML_INVALID");

    let activation = valid_profile_toml("qualified")
        .replace("activation = \"reboot\"", "activation = \"restart\"");
    assert_error_code(&activation, "PROFILE_TOML_INVALID");
}

#[test]
fn reject_unknown_conflict_action() {
    let input = valid_profile_toml("qualified")
        .replace("resolution = \"remove\"", "resolution = \"run_script\"");
    assert_error_code(&input, "PROFILE_TOML_INVALID");
}

#[test]
fn reject_unsorted_or_duplicate_conflicts() {
    let conflict =
        "[[conflicts]]\npackage = \"fixture-conflicting-driver\"\nresolution = \"remove\"\n";
    for replacement in [
        "[[conflicts]]\npackage = \"fixture-z\"\nresolution = \"remove\"\n[[conflicts]]\npackage = \"fixture-a\"\nresolution = \"remove\"\n",
        "[[conflicts]]\npackage = \"fixture-a\"\nresolution = \"remove\"\n[[conflicts]]\npackage = \"fixture-a\"\nresolution = \"remove\"\n",
    ] {
        let input = valid_profile_toml("qualified").replace(conflict, replacement);
        assert_error_code(&input, "PROFILE_PACKAGE_INVALID");
    }
}

#[test]
fn reject_component_without_critical_files() {
    let provider_files = format!(
        "activation = \"reboot\"\n\n[[components.npu_firmware.provider.files]]\npath = \"/usr/lib/firmware/fixture/npu.bin\"\nsha256 = \"{HASH_A}\""
    );
    let input = valid_profile_toml("qualified")
        .replace(&provider_files, "activation = \"reboot\"\nfiles = []");
    assert_error_code(&input, "PROFILE_RESOURCE_LIMIT");
}

#[test]
fn reject_invalid_component_license_evidence() {
    let evidence = format!(
        "[components.npu_firmware.license]\nexpression = \"Apache-2.0\"\nredistribution = \"allowed\"\nevidence_sha256 = \"{HASH_A}\""
    );
    let input = valid_profile_toml("qualified").replace(
        &evidence,
        "[components.npu_firmware.license]\nexpression = \"Apache-2.0\"\nredistribution = \"allowed\"\nevidence_sha256 = \"invalid\"",
    );
    assert_error_code(&input, "PROFILE_PROVENANCE_INVALID");
}

#[test]
fn reject_qualified_without_evidence_digest_hardware_or_suite() {
    let no_digest = valid_profile_toml("qualified").replace(
        &format!("evidence_sha256 = \"{HASH_F}\"\nqualified_at = \"2026-09-03T19:00:00Z\""),
        "evidence_sha256 = \"\"\nqualified_at = \"2026-09-03T19:00:00Z\"",
    );
    assert_error_code(&no_digest, "PROFILE_PROVENANCE_INVALID");

    for (field, value) in [
        ("hardware_class", "fixture-lunar-lake-class"),
        ("test_suite_version", "fixture-suite-v1"),
    ] {
        let input = valid_profile_toml("qualified").replace(
            &format!("{field} = \"{value}\""),
            &format!("{field} = \"\""),
        );
        assert_error_code(&input, "PROFILE_QUALIFICATION_MISSING");
    }
}

#[test]
fn reject_qualified_forbidden_redistribution() {
    let input = valid_profile_toml("qualified").replacen(
        "redistribution = \"allowed\"",
        "redistribution = \"forbidden\"",
        1,
    );
    assert_error_code(&input, "PROFILE_PROVENANCE_INVALID");
}

#[test]
fn reject_profile_resource_limits() {
    let oversized_input = format!(
        "{}\n#{}",
        valid_profile_toml("qualified"),
        "x".repeat(1_048_576)
    );
    assert_error_code(&oversized_input, "PROFILE_RESOURCE_LIMIT");

    let oversized_scalar = valid_profile_toml("qualified").replace(
        "id = \"testos-1-x86_64-8086-abcd\"",
        &format!("id = \"{}\"", "x".repeat(4097)),
    );
    assert_error_code(&oversized_scalar, "PROFILE_RESOURCE_LIMIT");

    let mut hardware = String::new();
    for index in 0..65 {
        writeln!(
            &mut hardware,
            "[[hardware]]\nvendor = \"8086\"\ndevice = \"{index:04x}\""
        )
        .expect("write hardware fixture");
    }
    let too_much_hardware = valid_profile_toml("qualified").replace(
        "[[hardware]]\nvendor = \"8086\"\ndevice = \"abcd\"\n",
        &hardware,
    );
    assert_error_code(&too_much_hardware, "PROFILE_RESOURCE_LIMIT");

    let mut conflicts = String::new();
    for index in 0..33 {
        writeln!(
            &mut conflicts,
            "[[conflicts]]\npackage = \"fixture-conflict-{index:02}\"\nresolution = \"remove\""
        )
        .expect("write conflict fixture");
    }
    let too_many_conflicts = valid_profile_toml("qualified").replace(
        "[[conflicts]]\npackage = \"fixture-conflicting-driver\"\nresolution = \"remove\"\n",
        &conflicts,
    );
    assert_error_code(&too_many_conflicts, "PROFILE_RESOURCE_LIMIT");

    let mut files = String::new();
    for index in 0..17 {
        writeln!(
            &mut files,
            "[[components.npu_firmware.provider.files]]\npath = \"/usr/lib/firmware/fixture/npu-{index:02}.bin\"\nsha256 = \"{HASH_A}\""
        )
        .expect("write critical-file fixture");
    }
    let too_many_files = valid_profile_toml("qualified").replace(
        &format!(
            "[[components.npu_firmware.provider.files]]\npath = \"/usr/lib/firmware/fixture/npu.bin\"\nsha256 = \"{HASH_A}\"\n"
        ),
        &files,
    );
    assert_error_code(&too_many_files, "PROFILE_RESOURCE_LIMIT");
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
fn reject_control_character_in_public_scalar() {
    let input = valid_profile_toml("qualified").replace(
        "id = \"testos-1-x86_64-8086-abcd\"",
        "id = \"testos\\nsecond-line\"",
    );
    assert_error_code(&input, "PROFILE_FIELD_INVALID");
}

#[test]
fn reject_schema_version_other_than_one() {
    let input = valid_profile_toml("qualified").replace("schema_version = 1", "schema_version = 2");
    assert_error_code(&input, "PROFILE_SCHEMA_UNSUPPORTED");
}

#[test]
fn reject_non_https_component_source() {
    let input = valid_profile_toml("qualified").replace(
        "source = \"https://example.invalid/npu_firmware\"",
        "source = \"http://example.invalid/npu_firmware\"",
    );
    assert_error_code(&input, "PROFILE_FIELD_INVALID");
}

#[test]
fn reject_uppercase_or_wrong_length_sha256() {
    let uppercase = valid_profile_toml("qualified").replacen(HASH_A, &"A".repeat(64), 1);
    assert_error_code(&uppercase, "PROFILE_HASH_INVALID");

    let short = valid_profile_toml("qualified").replacen(HASH_A, "abc123", 1);
    assert_error_code(&short, "PROFILE_HASH_INVALID");
}

#[test]
fn reject_missing_required_component() {
    let block = component(
        "openvino_npu_plugin",
        HASH_F,
        "fixture-openvino-npu-plugin",
        "immediate",
        "/usr/lib64/libopenvino_intel_npu_plugin.fixture.so",
    );
    let input = valid_profile_toml("qualified").replace(&block, "");
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
