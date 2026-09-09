// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

const PLUGINS: &str = "usr/lib64/openvino-2026.2.0/";

fn write(root: &Path, relative: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create parent");
    fs::write(path, b"fixture").expect("write payload");
}

fn fixture() -> TempDir {
    let root = TempDir::new().expect("fixture root");
    for name in [
        "openvino",
        "openvino_c",
        "openvino_ir_frontend",
        "openvino_onnx_frontend",
        "openvino_paddle_frontend",
        "openvino_pytorch_frontend",
        "openvino_tensorflow_frontend",
        "openvino_tensorflow_lite_frontend",
    ] {
        for suffix in ["", ".2620", ".2026.2.0"] {
            if name != "openvino_ir_frontend" || !suffix.is_empty() {
                write(root.path(), &format!("usr/lib64/lib{name}.so{suffix}"));
            }
        }
    }
    for name in [
        "auto_plugin",
        "hetero_plugin",
        "intel_cpu_plugin",
        "intel_gpu_plugin",
        "intel_npu_plugin",
        "intel_npu_compiler",
        "intel_npu_compiler_loader",
    ] {
        write(root.path(), &format!("{PLUGINS}libopenvino_{name}.so"));
    }
    for name in [
        "libopenvino",
        "libopenvino-devel",
        "libopenvino-auto-plugin",
        "libopenvino-hetero-plugin",
        "libopenvino-intel-cpu-plugin",
        "libopenvino-intel-gpu-plugin",
        "libopenvino-ir-frontend",
        "libopenvino-onnx-frontend",
        "libopenvino-paddle-frontend",
        "libopenvino-pytorch-frontend",
        "libopenvino-tensorflow-frontend",
        "libopenvino-tensorflow-lite-frontend",
    ] {
        write(
            root.path(),
            &format!("usr/share/doc/{name}-2026.2.0/copyright"),
        );
    }
    for name in [
        "usr/include/npu_driver_compiler.h",
        "usr/include/openvino/openvino.hpp",
        "usr/lib64/pkgconfig/openvino.pc",
        "usr/lib64/cmake/openvino2026.2.0/OpenVINOConfig.cmake",
    ] {
        write(root.path(), name);
    }
    // Upstream installs tuning data beside the GPU plugin, which reads it there.
    write(root.path(), &format!("{PLUGINS}cache.json"));
    root
}

fn check(root: &Path) -> Output {
    Command::new("/usr/bin/python3")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../packaging/fedora/44/rpm/openvino/check-install-layout.py"),
        )
        .arg(root)
        .output()
        .expect("run staged layout check")
}

#[test]
fn accepts_complete_gpu_payload_with_tuning_data() {
    let root = fixture();
    let output = check(root.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_missing_gpu_tuning_data() {
    let root = fixture();
    fs::remove_file(root.path().join(format!("{PLUGINS}cache.json"))).expect("remove cache");
    let output = check(root.path());
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Missing staged paths:"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cache.json"));
}

#[test]
fn rejects_unexpected_file_beside_gpu_tuning_data() {
    let root = fixture();
    write(root.path(), &format!("{PLUGINS}unexpected.json"));
    let output = check(root.path());
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unexpected staged path:"));
}
