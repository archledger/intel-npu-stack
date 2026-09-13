// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stack_install::ReleaseManifest;
use stack_schema::ProfileStatus;

const RELEASE: &[u8] = include_bytes!("fixtures/release.json");
const PROFILE: &[u8] = include_bytes!("fixtures/profile.toml");

fn input() -> Value {
    serde_json::from_slice(RELEASE).unwrap()
}

fn parse(value: &Value) -> Result<ReleaseManifest, stack_install::InstallError> {
    ReleaseManifest::parse_json(&serde_json::to_vec(value).unwrap())
}

#[test]
fn accepted_artifacts_bind_without_promoting_the_candidate() {
    let manifest = ReleaseManifest::parse_json(RELEASE).unwrap();
    let profile = manifest.bind_profile(PROFILE).unwrap();
    assert_eq!(profile.status, ProfileStatus::Candidate);
    assert_eq!(manifest.selected_packages(false, false).unwrap().len(), 14);
}

#[test]
fn altered_profile_is_rejected() {
    let manifest = ReleaseManifest::parse_json(RELEASE).unwrap();
    let mut profile = PROFILE.to_vec();
    profile.push(b'\n');
    assert_eq!(manifest.bind_profile(&profile).unwrap_err().exit_code, 20);
}

#[test]
fn missing_optional_capabilities_are_not_silently_ignored() {
    let manifest = ReleaseManifest::parse_json(RELEASE).unwrap();
    for (python, devel) in [(true, false), (false, true), (true, true)] {
        assert_eq!(
            manifest
                .selected_packages(python, devel)
                .unwrap_err()
                .exit_code,
            10
        );
    }
}

#[test]
fn requested_optional_packages_are_selected_deterministically() {
    let mut value = input();
    value["packages"].as_array_mut().unwrap().push(json!({
        "name": "openvino-devel", "nevr": "0:2026.2.0-1.intelnpu.fc44",
        "arch": "x86_64", "filename": "openvino-devel-2026.2.0-1.intelnpu.fc44.x86_64.rpm",
        "sha256": "e046d6e2b5d200b2aabbe83a8d6c8828f1e10fc0a1b2e412a8c6f0757e3c7c04",
        "role": "devel"
    }));
    let manifest = parse(&value).unwrap();
    assert_eq!(manifest.selected_packages(false, false).unwrap().len(), 14);
    let selected = manifest.selected_packages(false, true).unwrap();
    assert_eq!(selected.len(), 15);
    let names = selected.iter().map(|p| p.name.as_str()).collect::<Vec<_>>();
    assert!(names.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn malformed_manifest_fields_fail_closed() {
    for (pointer, replacement) in [
        ("/schema_version", json!(2)),
        ("/stack_release", json!("../0.1.0")),
        ("/profile_sha256", json!("A".repeat(64))),
        ("/profile_sha256", json!("a".repeat(63))),
        ("/repository/id", json!("--config=/tmp/evil")),
        ("/repository/repomd_sha256", json!("not-a-hash")),
        ("/packages/0/name", json!("--nogpgcheck")),
        ("/packages/0/nevr", json!("0:2026.2.0-1.fc43")),
        ("/packages/0/nevr", json!("0:2026.2.0-1.fc44;id")),
        ("/packages/0/nevr", json!("999999999999:2026.2.0-1.fc44")),
        ("/packages/0/arch", json!("aarch64")),
        ("/packages/0/filename", json!("../provider.rpm")),
        ("/packages/0/filename", json!("unrelated.rpm")),
        ("/packages/0/sha256", json!("z".repeat(64))),
        ("/packages/0/role", json!("shell")),
    ] {
        let mut value = input();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert_eq!(parse(&value).unwrap_err().exit_code, 20, "{pointer}");
    }
}

#[test]
fn unsafe_or_unversioned_repository_urls_are_rejected() {
    for url in [
        "http://example.invalid/0.1.0/",
        "https://user:secret@example.invalid/0.1.0/",
        "https://example.invalid/latest/",
        "https://example.invalid/0.1.0/../current/",
        "https://example.invalid/0.1.0/%2e%2e/",
        "https://example.invalid/0.1.0/?command=id",
        "https://example.invalid/0.1.0/#fragment",
        "https://example.invalid/0.1.0/\n",
        "https://example.invalid\\other/0.1.0/",
        "https://-bad.invalid/0.1.0/",
        "https:///0.1.0/",
        "https://example.invalid/0.1.01/",
        "https://example.invalid/0.1.0//",
    ] {
        let mut value = input();
        value["repository"]["base_url"] = json!(url);
        assert_eq!(parse(&value).unwrap_err().exit_code, 20, "{url:?}");
    }
}

#[test]
fn duplicate_and_unknown_fields_are_rejected() {
    let duplicate = String::from_utf8(RELEASE.to_vec()).unwrap().replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1, \"schema_version\": 1,",
        1,
    );
    assert!(ReleaseManifest::parse_json(duplicate.as_bytes()).is_err());
    for pointer in ["", "/repository", "/packages/0"] {
        let mut value = input();
        value.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert!(parse(&value).is_err(), "{pointer}");
    }
    let mut value = input();
    let first = value["packages"][0].clone();
    value["packages"].as_array_mut().unwrap().push(first);
    assert!(parse(&value).is_err());
}

#[test]
fn oversized_or_empty_metadata_is_rejected() {
    assert!(ReleaseManifest::parse_json(&vec![b' '; 1_048_577]).is_err());
    assert!(ReleaseManifest::parse_json(b"").is_err());
    let mut value = input();
    value["packages"] = json!([]);
    assert!(parse(&value).is_err());
    value["packages"] = json!(vec![input()["packages"][0].clone(); 129]);
    assert!(parse(&value).is_err());
}

#[test]
fn component_hash_version_and_runtime_membership_are_bound() {
    for change in ["hash", "version", "role", "missing"] {
        let mut value = input();
        let packages = value["packages"].as_array_mut().unwrap();
        let index = packages
            .iter()
            .position(|p| p["name"] == "intel-npu-driver")
            .unwrap();
        match change {
            "hash" => packages[index]["sha256"] = json!("b".repeat(64)),
            "version" => {
                packages[index]["nevr"] = json!("0:1.36.0-1.intelnpu.fc44");
                packages[index]["filename"] =
                    json!("intel-npu-driver-1.36.0-1.intelnpu.fc44.x86_64.rpm");
            }
            "role" => packages[index]["role"] = json!("devel"),
            "missing" => {
                packages.remove(index);
            }
            _ => unreachable!(),
        }
        let manifest = parse(&value).unwrap();
        assert_eq!(
            manifest.bind_profile(PROFILE).unwrap_err().exit_code,
            20,
            "{change}"
        );
    }
}

#[test]
fn tool_and_metapackage_are_required_runtime_inputs() {
    for name in ["intel-npu-stack", "intel-npu-stack-tools"] {
        let mut value = input();
        value["packages"]
            .as_array_mut()
            .unwrap()
            .retain(|p| p["name"] != name);
        assert_eq!(parse(&value).unwrap_err().exit_code, 20);
    }
}

#[test]
fn matching_digest_does_not_bypass_profile_semantics() {
    for (old, new) in [
        ("id = \"fedora\"", "id = \"other\""),
        ("stack_release = \"0.1.0\"", "stack_release = \"0.2.0\""),
    ] {
        let profile = String::from_utf8(PROFILE.to_vec())
            .unwrap()
            .replace(old, new);
        let mut value = input();
        value["profile_sha256"] = json!(format!("{:x}", Sha256::digest(profile.as_bytes())));
        assert_eq!(
            parse(&value)
                .unwrap()
                .bind_profile(profile.as_bytes())
                .unwrap_err()
                .exit_code,
            20
        );
    }
}
