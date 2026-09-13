// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use stack_install::{NativePlan, ReleaseManifest};

const NATIVE: &[u8] = include_bytes!("fixtures/dnf/install.json");
const RELEASE: &[u8] = include_bytes!("fixtures/release.json");

fn parse(bytes: &[u8]) -> Result<NativePlan, stack_install::InstallError> {
    let manifest = ReleaseManifest::parse_json(RELEASE).unwrap();
    let selected = manifest.selected_packages(false, false).unwrap();
    let inputs = selected
        .into_iter()
        .filter(|p| {
            matches!(
                p.name.as_str(),
                "intel-npu-stack" | "intel-npu-stack-tools" | "intel-npu-stack-firmware"
            )
        })
        .collect::<Vec<_>>();
    NativePlan::parse_install(bytes, &inputs)
}

fn altered(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(NATIVE).unwrap();
    edit(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn captured_native_plan_previews_exact_identities_and_digests() {
    let plan = parse(NATIVE).unwrap();
    assert_eq!(
        plan.preview(),
        concat!(
            "Install intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch sha256:8807d1bc9a140e011ee306c7e170729b20a4414809675875de6e0c9fd84bbb89\n",
            "Install intel-npu-stack-firmware-1.35.0-1.intelnpu.fc44.noarch sha256:8b2c0181293cb4d8373841decf15cc0dc251aba25181961371f6cef8baf39950\n",
            "Install intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64 sha256:a7a484f7a7d8ee76fa955a1f41aa27a7f8e702eba21d2378b8efb961537f3499\n"
        )
    );
}

#[test]
fn missing_or_extra_actions_cannot_become_an_approved_plan() {
    for bytes in [
        altered(|v| {
            v["rpms"].as_array_mut().unwrap().pop();
        }),
        altered(|v| {
            let row = v["rpms"][0].clone();
            v["rpms"].as_array_mut().unwrap().push(row);
        }),
        altered(|v| {
            v["rpms"][0]["nevra"] = "unexpected-1.0-1.fc44.x86_64".into();
        }),
    ] {
        assert_eq!(parse(&bytes).unwrap_err().exit_code, 30);
    }
}

#[test]
fn destructive_and_unobserved_native_actions_are_refused() {
    for action in [
        "Downgrade",
        "Remove",
        "Replaced",
        "Upgrade",
        "Reinstall",
        "Skipped",
        "",
    ] {
        assert_eq!(
            parse(&altered(|v| v["rpms"][0]["action"] = action.into()))
                .unwrap_err()
                .exit_code,
            30
        );
    }
}

#[test]
fn stored_paths_cannot_escape_or_alias_package_files() {
    for path in [
        "/tmp/tools.rpm",
        "./packages/../tools.rpm",
        "./packages/sub/tools.rpm",
        "./packages//tools.rpm",
        "./packages/..",
        "./packages/tools.rpm\n",
    ] {
        assert!(parse(&altered(|v| v["rpms"][0]["package_path"] = path.into())).is_err());
    }
    assert!(
        parse(&altered(
            |v| v["rpms"][0]["package_path"] = "./packages/meta.rpm".into()
        ))
        .is_err()
    );
}

#[test]
fn unknown_schema_repository_and_reason_are_refused() {
    for bytes in [
        altered(|v| v["version"] = "2.0".into()),
        altered(|v| v["groups"] = serde_json::json!([])),
        altered(|v| v["rpms"][0]["command"] = "id".into()),
        altered(|v| v["rpms"][0]["repo_id"] = "unreviewed".into()),
        altered(|v| v["rpms"][0]["reason"] = "unknown".into()),
    ] {
        assert!(parse(&bytes).is_err());
    }
    assert!(parse(br#"{"version":"1.0","version":"1.0","rpms":[]}"#).is_err());
    assert!(parse(&vec![b' '; 1_048_577]).is_err());
    assert!(parse(br#"{"version":"1.0","rpms":[]}"#).is_err());
}

#[test]
fn a_stored_plan_without_package_files_is_not_ready_for_replay() {
    let plan = parse(NATIVE).unwrap();
    let root = tempfile::tempdir().unwrap();
    assert_eq!(plan.verify_packages(root.path()).unwrap_err().exit_code, 20);
    std::fs::create_dir(root.path().join("packages")).unwrap();
    for filename in ["tools.rpm", "meta.rpm", "firmware.rpm"] {
        std::fs::write(root.path().join("packages").join(filename), b"changed").unwrap();
    }
    assert_eq!(plan.verify_packages(root.path()).unwrap_err().exit_code, 20);
}

#[test]
fn verified_content_and_symlink_refusal_use_real_files() {
    use sha2::{Digest, Sha256};
    let manifest = ReleaseManifest::parse_json(RELEASE).unwrap();
    let inputs = manifest.selected_packages(false, false).unwrap();
    let mut package = (*inputs
        .iter()
        .find(|p| p.name == "intel-npu-stack-tools")
        .unwrap())
    .clone();
    package.sha256 = format!("{:x}", Sha256::digest(b"fixture bytes"));
    let bytes = altered(|v| v["rpms"].as_array_mut().unwrap().truncate(1));
    let plan = NativePlan::parse_install(&bytes, &[&package]).unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("packages")).unwrap();
    let path = root.path().join("packages/tools.rpm");
    std::fs::write(&path, b"fixture bytes").unwrap();
    plan.verify_packages(root.path()).unwrap();
    std::fs::rename(&path, root.path().join("real.rpm")).unwrap();
    std::os::unix::fs::symlink(root.path().join("real.rpm"), &path).unwrap();
    assert!(plan.verify_packages(root.path()).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(root.path().join("packages")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("tools.rpm"), b"fixture bytes").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("packages")).unwrap();
    assert!(plan.verify_packages(root.path()).is_err());
}
