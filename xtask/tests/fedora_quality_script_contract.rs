// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn provider_lint_preserves_raw_findings_and_checks_exact_notice_exceptions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/test-provider-lint.py"))
        .output()
        .expect("run provider lint evidence contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn provider_pair_gate_observes_offline_builds_and_propagates_failures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/test-package-gate.py"))
        .output()
        .expect("run package gate execution contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
