// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn generated_bootstrap_download_and_execution_contracts_pass() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a repository parent");
    let output = Command::new("/usr/bin/python3")
        .arg(repository.join("install/test-bootstrap.py"))
        .arg("-v")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("execute the bootstrap behavior suite");
    assert!(
        output.status.success(),
        "bootstrap behavior suite failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
