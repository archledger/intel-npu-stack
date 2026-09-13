// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use sha2::{Digest, Sha256};
use stack_install::{NativeInventory, NativePlan, ReleaseManifest};
use stack_runtime::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, Termination};
use std::{fs, path::Path};

const STATE: &[u8] = b"rpm|0:6.0.2-1.fc44|x86_64|0\n";
struct Query(&'static [u8]);
impl ProcessRunner for Query {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        assert_eq!(request.executable.to_str(), Some("/usr/bin/rpm"));
        assert!(request.args.iter().any(|x| x == "-qa"));
        Ok(ProcessOutput {
            termination: Termination::Exit(0),
            stdout: self.0.to_vec(),
            stdout_overflow: false,
            stderr_overflow: false,
        })
    }
}
struct MustNotRun;
impl ProcessRunner for MustNotRun {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("changed content must fail before state query")
    }
}
fn setup(root: &Path) -> NativePlan {
    let manifest = ReleaseManifest::parse_json(include_bytes!("fixtures/release.json")).unwrap();
    let mut inputs = manifest
        .selected_packages(false, false)
        .unwrap()
        .into_iter()
        .filter(|p| {
            matches!(
                p.name.as_str(),
                "intel-npu-stack" | "intel-npu-stack-tools" | "intel-npu-stack-firmware"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut native: Value =
        serde_json::from_slice(include_bytes!("fixtures/dnf/install.json")).unwrap();
    fs::create_dir(root.join("packages")).unwrap();
    for input in &mut inputs {
        let data = format!("test content {}", input.name);
        input.sha256 = format!("{:x}", Sha256::digest(data.as_bytes()));
        fs::write(root.join("packages").join(&input.filename), data).unwrap();
        for row in native["rpms"].as_array_mut().unwrap() {
            if row["nevra"].as_str().unwrap()
                == format!(
                    "{}-{}.{}",
                    input.name,
                    input.nevr.strip_prefix("0:").unwrap(),
                    input.arch
                )
            {
                row["package_path"] = format!("./packages/{}", input.filename).into();
            }
        }
    }
    let bytes = serde_json::to_vec(&native).unwrap();
    fs::write(root.join("transaction.json"), &bytes).unwrap();
    NativePlan::parse_update(
        Some(&bytes),
        &inputs.iter().collect::<Vec<_>>(),
        &NativeInventory::parse_query(STATE).unwrap(),
        "intel-npu-test",
        &MustNotRun,
    )
    .unwrap()
}
#[test]
fn exact_stored_bytes_packages_and_native_state_can_be_rechecked() {
    let root = tempfile::tempdir().unwrap();
    let plan = setup(root.path());
    plan.verify_stored(root.path(), &Query(STATE)).unwrap();
    assert_eq!(
        plan.transaction_sha256().unwrap(),
        format!(
            "{:x}",
            Sha256::digest(fs::read(root.path().join("transaction.json")).unwrap())
        )
    );
}
#[test]
fn changed_stored_json_or_symlink_is_refused_before_native_state_query() {
    for symlink in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let plan = setup(root.path());
        let file = root.path().join("transaction.json");
        if symlink {
            fs::rename(&file, root.path().join("original.json")).unwrap();
            std::os::unix::fs::symlink("original.json", &file).unwrap();
        } else {
            let mut bytes = fs::read(&file).unwrap();
            bytes.push(b' ');
            fs::write(&file, bytes).unwrap();
        }
        assert!(plan.verify_stored(root.path(), &MustNotRun).is_err());
    }
}
#[test]
fn changed_rpm_content_is_refused_before_native_state_query() {
    let root = tempfile::tempdir().unwrap();
    let plan = setup(root.path());
    let file = fs::read_dir(root.path().join("packages"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(file, b"changed").unwrap();
    assert!(plan.verify_stored(root.path(), &MustNotRun).is_err());
}
#[test]
fn changed_installed_inventory_invalidates_the_stored_plan() {
    let root = tempfile::tempdir().unwrap();
    let plan = setup(root.path());
    let changed = Query(b"rpm|0:6.0.2-1.fc44|x86_64|1\n");
    assert_eq!(
        plan.verify_stored(root.path(), &changed).unwrap_err().code,
        "INSTALL_STATE_CHANGED"
    );
}
