// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn locked_vendor_integrity_and_license_layouts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/rpm/intel-npu-stack/test-vendor-licenses.py"))
        .output()
        .expect("run vendor license contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pinned_stdlib_source_notices_match_installed_toolchain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/rpm/intel-npu-stack/test-stdlib-notices.py"))
        .output()
        .expect("run Rust standard library notice contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
