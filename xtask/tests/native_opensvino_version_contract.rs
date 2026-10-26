// SPDX-License-Identifier: Apache-2.0

//! Regression contract for the native SDK probe's OpenVINO version acceptance.
//!
//! The tools package builds against the 2026.2.1-1 providers while local SDK
//! checks against an installed 0.1.1 stack resolve OpenVINO 2026.2.0, so the
//! native configure step must accept exactly those two versions and refuse
//! any other one instead of silently taking whatever the SDK ships.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sdk_fixture(root: &Path, version: &str, config_rel: &str) -> PathBuf {
    let sdk = root.join(format!("sdk-{version}"));
    fs::create_dir_all(sdk.join("include/level_zero")).expect("level zero include");
    fs::write(sdk.join("include/level_zero/ze_api.h"), "").expect("level zero header");
    fs::create_dir_all(sdk.join("lib64")).expect("lib64");
    fs::write(sdk.join("lib64/libze_loader.so"), "").expect("level zero loader");
    let runtime = sdk.join(format!("lib64/libopenvino.so.{version}"));
    fs::write(&runtime, "").expect("openvino runtime");
    let config_dir = sdk.join(config_rel);
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("OpenVINOConfig.cmake"),
        format!(
            "add_library(openvino::runtime SHARED IMPORTED)\n\
             set_target_properties(openvino::runtime PROPERTIES\n\
             IMPORTED_LOCATION \"{}\"\n\
             IMPORTED_LOCATION_RELEASE \"{}\")\n",
            runtime.display(),
            runtime.display()
        ),
    )
    .expect("openvino config");
    fs::write(
        config_dir.join("OpenVINOConfigVersion.cmake"),
        format!(
            "set(PACKAGE_VERSION \"{version}\")\n\
             if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)\n\
               set(PACKAGE_VERSION_COMPATIBLE TRUE)\n\
               set(PACKAGE_VERSION_EXACT TRUE)\n\
             else()\n\
               set(PACKAGE_VERSION_COMPATIBLE FALSE)\n\
             endif()\n"
        ),
    )
    .expect("openvino config version");
    sdk
}

fn configure_native(sdk: &Path) -> Output {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../native");
    let build = sdk.parent().expect("fixture parent").join(format!(
        "build-{}",
        sdk.file_name().expect("sdk name").to_string_lossy()
    ));
    Command::new("cmake")
        .arg("-S")
        .arg(&source)
        .arg("-B")
        .arg(&build)
        .arg(format!("-DINTEL_NPU_SDK_PREFIX={}", sdk.display()))
        .arg("-DBUILD_TESTING=OFF")
        .output()
        .expect("run cmake configure")
}

#[test]
fn accepts_both_supported_opensvino_versions() {
    for version in ["2026.2.1", "2026.2.0"] {
        let root = tempfile::tempdir().expect("fixture directory");
        let sdk = sdk_fixture(
            root.path(),
            version,
            &format!("lib64/cmake/openvino{version}"),
        );
        let output = configure_native(&sdk);
        assert!(
            output.status.success(),
            "configure must accept OpenVINO {version}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn refuses_unsupported_opensvino_version() {
    let root = tempfile::tempdir().expect("fixture directory");
    // openvino/cmake is a searched suffix, so the version gate itself must
    // reject this SDK rather than the directory-name gate hiding it.
    let sdk = sdk_fixture(root.path(), "2026.2.2", "openvino/cmake");
    let output = configure_native(&sdk);
    assert!(
        !output.status.success(),
        "configure must refuse OpenVINO 2026.2.2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("2026.2.1") && stderr.contains("2026.2.0"),
        "refusal must name the accepted versions\nstderr: {stderr}"
    );
}
