// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn bundled_provider_notices_bind_every_archive_before_compilation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/rpm/test-provider-notices.py"))
        .output()
        .expect("run provider notice preflight contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rpm_notice_payload_preserves_bytes_and_license_ownership() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/rpm/test-provider-notice-rpm.py"))
        .output()
        .expect("run real RPM notice transport contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
