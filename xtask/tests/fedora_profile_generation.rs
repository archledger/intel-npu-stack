// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn candidate_generation_and_refusal_with_real_rpms() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let generated = temporary.path().join("candidate.toml");
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/test-profile-generation.py"))
        .arg(env!("CARGO_BIN_EXE_xtask"))
        .arg(&generated)
        .current_dir(root)
        .output()
        .expect("run real RPM candidate profile generation tests");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let profile =
        stack_schema::Profile::parse_toml(&std::fs::read_to_string(generated).unwrap()).unwrap();
    let facts = stack_platform::PlatformFacts {
        os_id: "fedora".into(),
        os_version_id: "44".into(),
        arch: "x86_64".into(),
        kernel: stack_schema::KernelVersion::parse_release("7.1.13-200.fc44.x86_64").unwrap(),
        pci_ids: vec![stack_schema::PciId {
            vendor: "8086".into(),
            device: "643e".into(),
        }],
        intel_vpu_loaded: true,
        accel_node_present: true,
        effective_root: false,
        boot_time_epoch: 1,
    };
    for channel in [
        stack_core::Channel::Stable,
        stack_core::Channel::Experimental,
    ] {
        let result = stack_core::select_profile(
            std::slice::from_ref(&profile),
            &facts,
            &stack_core::SelectionPolicy {
                channel,
                acknowledge_risk: channel == stack_core::Channel::Experimental,
            },
        );
        assert_eq!(result, Err(stack_core::SelectionError::NoCompatibleProfile));
    }
}
