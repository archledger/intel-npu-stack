// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn stack_rpm_contract_accepts_complete_packages_and_rejects_mutations() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../packaging/fedora/44/rpm/intel-npu-stack/test-package-contract.py");
    let result = Command::new("/usr/bin/python3")
        .arg(script)
        .output()
        .expect("execute real RPM package contract fixtures");
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
