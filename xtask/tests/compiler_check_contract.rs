// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn run_case(case: u8) -> bool {
    let root = TempDir::new().expect("fixture directory");
    let source = root.path().join("fixture.cpp");
    let executable = root.path().join("fixture");
    fs::write(
        &source,
        r#"#include <gtest/gtest.h>
#if CASE == 3
TEST(Functional, external_model) {}
#else
TEST(Functional, simple_function) {
#if CASE == 1
    GTEST_SKIP() << "exercise skipped-result rejection";
#elif CASE == 2
    FAIL() << "exercise failed-result rejection";
#endif
}
#endif
"#,
    )
    .expect("write real GoogleTest fixture");
    let output = Command::new("/usr/bin/g++")
        .arg(format!("-DCASE={case}"))
        .arg(&source)
        .args(["-lgtest_main", "-lgtest", "-pthread", "-o"])
        .arg(&executable)
        .output()
        .expect("compile fixture");
    assert!(
        output.status.success(),
        "fixture compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = root.path().join("config");
    fs::create_dir(&config).expect("fixture config directory");
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../packaging/fedora/44/rpm/openvino/check-compiler-tests.py");
    Command::new("/usr/bin/python3")
        .arg(script)
        .arg(executable)
        .arg(config)
        .arg(root.path().join("results"))
        .output()
        .expect("run production compiler check")
        .status
        .success()
}

#[test]
fn accepts_executed_passing_compiler_cases() {
    assert!(run_case(0));
}

#[test]
fn rejects_skipped_compiler_cases_even_when_gtest_returns_zero() {
    assert!(!run_case(1));
}

#[test]
fn rejects_failed_compiler_cases() {
    assert!(!run_case(2));
}

#[test]
fn rejects_empty_selection_even_when_gtest_returns_zero() {
    assert!(!run_case(3));
}
