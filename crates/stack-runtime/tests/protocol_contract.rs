// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use stack_runtime::{
    ProbeErrorCode, ProbeKind, ProbeMode, ProbeObservations, ProbeOutcome, parse_probe_output,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/probes")
        .join(name);
    fs::read(path).expect("read protocol fixture")
}

fn assert_invalid(input: &[u8]) {
    let error = parse_probe_output(input, ProbeKind::OpenVino, ProbeMode::Infer)
        .expect_err("protocol input must be rejected");
    assert_eq!(error.code, "PROBE_OUTPUT_INVALID", "unexpected: {error}");
}

#[test]
fn parse_level_zero_success_fixture() {
    let report = parse_probe_output(
        &fixture("level-zero-success.json"),
        ProbeKind::LevelZero,
        ProbeMode::Enumerate,
    )
    .expect("parse Level Zero fixture");

    assert_eq!(report.schema_version, 1);
    assert_eq!(report.probe, ProbeKind::LevelZero);
    assert_eq!(report.mode, ProbeMode::Enumerate);
    assert_eq!(report.outcome, ProbeOutcome::Pass);
    assert_eq!(report.error_code, None);
    let ProbeObservations::LevelZero(observation) = report.observations else {
        panic!("expected Level Zero observations");
    };
    assert_eq!(observation.vpu_devices.len(), 1);
    assert_eq!(observation.vpu_devices[0].vendor_id, "8086");
    assert_eq!(observation.vpu_devices[0].device_id, "abcd");
    assert_eq!(observation.vpu_devices[0].driver_version, 65_536);
}

#[test]
fn parse_openvino_enumerate_success_fixture() {
    let report = parse_probe_output(
        &fixture("openvino-enumerate-success.json"),
        ProbeKind::OpenVino,
        ProbeMode::Enumerate,
    )
    .expect("parse OpenVINO enumeration fixture");

    let ProbeObservations::OpenVinoEnumerate(observation) = report.observations else {
        panic!("expected OpenVINO enumerate observations");
    };
    assert_eq!(observation.available_devices, ["CPU", "GPU.0", "NPU"]);
    assert_eq!(observation.runtime_version, "2026.2.0");
}

#[test]
fn parse_openvino_infer_success_fixture() {
    let report = parse_probe_output(
        &fixture("openvino-infer-success.json"),
        ProbeKind::OpenVino,
        ProbeMode::Infer,
    )
    .expect("parse OpenVINO inference fixture");

    let ProbeObservations::OpenVinoInfer(observation) = report.observations else {
        panic!("expected OpenVINO infer observations");
    };
    assert_eq!(observation.available_devices, ["CPU", "NPU"]);
    assert_eq!(observation.execution_devices, ["NPU"]);
    assert_eq!(observation.runtime_version, "2026.2.0");
    assert_eq!(observation.graph_id, "intel-npu-stack-neutral-v1");
    assert_eq!(observation.iterations, 8);
    assert_eq!(observation.tolerance, 0.001);
}

#[test]
fn reject_invalid_utf8_bom_trailing_data_and_oversize() {
    assert_invalid(&[0xff]);

    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend(fixture("openvino-infer-success.json"));
    assert_invalid(&bom);

    let mut trailing = fixture("openvino-infer-success.json");
    trailing.extend_from_slice(b"false");
    assert_invalid(&trailing);

    assert_invalid(&vec![b' '; 65_537]);
}

#[test]
fn reject_duplicate_key_at_every_object_depth() {
    for input in [
        r#"{"schema_version":1,"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":"OPENVINO_NO_NPU"}"#,
        r#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"pass","observations":{"vpu_devices":[{"vendor_id":"8086","vendor_id":"8086","device_id":"abcd","driver_version":1}]},"error_code":null}"#,
        r#"{"schema_version":1,"probe":"openvino","mode":"enumerate","outcome":"pass","observations":{"available_devices":["NPU"],"available_devices":["NPU"],"runtime_version":"2026.2.0"},"error_code":null}"#,
    ] {
        let expected = if input.contains("level_zero") {
            (ProbeKind::LevelZero, ProbeMode::Enumerate)
        } else if input.contains("\"mode\":\"enumerate\"") {
            (ProbeKind::OpenVino, ProbeMode::Enumerate)
        } else {
            (ProbeKind::OpenVino, ProbeMode::Infer)
        };
        let error = parse_probe_output(input.as_bytes(), expected.0, expected.1)
            .expect_err("duplicate object key must be rejected");
        assert_eq!(error.code, "PROBE_OUTPUT_INVALID");
    }
}

#[test]
fn reject_unknown_field_wrong_schema_probe_or_mode() {
    let unknown = String::from_utf8(fixture("openvino-infer-success.json"))
        .expect("fixture UTF-8")
        .replace("\"error_code\":null", "\"extra\":true,\"error_code\":null");
    assert_invalid(unknown.as_bytes());

    let wrong_schema = String::from_utf8(fixture("openvino-infer-success.json"))
        .expect("fixture UTF-8")
        .replace("\"schema_version\":1", "\"schema_version\":2");
    let error = parse_probe_output(
        wrong_schema.as_bytes(),
        ProbeKind::OpenVino,
        ProbeMode::Infer,
    )
    .expect_err("wrong schema must be rejected");
    assert_eq!(error.code, "PROBE_SCHEMA_UNSUPPORTED");

    let bytes = fixture("openvino-infer-success.json");
    for (probe, mode) in [
        (ProbeKind::LevelZero, ProbeMode::Infer),
        (ProbeKind::OpenVino, ProbeMode::Enumerate),
    ] {
        let error = parse_probe_output(&bytes, probe, mode).expect_err("identity mismatch");
        assert_eq!(error.code, "PROBE_OUTPUT_INVALID");
    }

    let invalid_level_zero_mode = br#"{"schema_version":1,"probe":"level_zero","mode":"infer","outcome":"fail","observations":{},"error_code":"LEVEL_ZERO_NO_VPU"}"#;
    let error = parse_probe_output(
        invalid_level_zero_mode,
        ProbeKind::LevelZero,
        ProbeMode::Infer,
    )
    .expect_err("Level Zero infer mode must be rejected");
    assert_eq!(error.code, "PROBE_OUTPUT_INVALID");
}

#[test]
fn reject_missing_required_top_level_key() {
    let missing_error_code = String::from_utf8(fixture("openvino-infer-success.json"))
        .expect("fixture UTF-8")
        .replace(",\"error_code\":null", "");
    assert_invalid(missing_error_code.as_bytes());
}

#[test]
fn reject_nonfinite_or_out_of_range_observations() {
    let huge_number = String::from_utf8(fixture("openvino-infer-success.json"))
        .expect("fixture UTF-8")
        .replace("\"tolerance\":0.001", "\"tolerance\":1e9999");
    assert_invalid(huge_number.as_bytes());

    let driver_overflow = r#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"pass","observations":{"vpu_devices":[{"vendor_id":"8086","device_id":"abcd","driver_version":4294967296}]},"error_code":null}"#;
    let error = parse_probe_output(
        driver_overflow.as_bytes(),
        ProbeKind::LevelZero,
        ProbeMode::Enumerate,
    )
    .expect_err("driver version overflow must be rejected");
    assert_eq!(error.code, "PROBE_OUTPUT_INVALID");
}

#[test]
fn reject_nonnormalized_device_names_or_pci_ids() {
    for invalid in ["npu", "NPU.x", "AUTO", "GPU.-1"] {
        let input = String::from_utf8(fixture("openvino-enumerate-success.json"))
            .expect("fixture UTF-8")
            .replace("\"NPU\"", &format!("\"{invalid}\""));
        let error = parse_probe_output(input.as_bytes(), ProbeKind::OpenVino, ProbeMode::Enumerate)
            .expect_err("device name must be normalized");
        assert_eq!(error.code, "PROBE_OUTPUT_INVALID");
    }

    for invalid in ["808", "808G", "ABCD", "00000"] {
        let input = String::from_utf8(fixture("level-zero-success.json"))
            .expect("fixture UTF-8")
            .replace("\"8086\"", &format!("\"{invalid}\""));
        let error =
            parse_probe_output(input.as_bytes(), ProbeKind::LevelZero, ProbeMode::Enumerate)
                .expect_err("PCI identifier must be normalized");
        assert_eq!(error.code, "PROBE_OUTPUT_INVALID");
    }
}

#[test]
fn require_error_code_exactly_when_outcome_is_fail() {
    let pass_with_error = String::from_utf8(fixture("openvino-infer-success.json"))
        .expect("fixture UTF-8")
        .replace("\"error_code\":null", "\"error_code\":\"OPENVINO_NO_NPU\"");
    assert_invalid(pass_with_error.as_bytes());

    let fail_without_error = br#"{"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":null}"#;
    assert_invalid(fail_without_error);

    let wrong_probe_code = br#"{"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"fail","observations":{},"error_code":"OPENVINO_NO_NPU"}"#;
    let error = parse_probe_output(wrong_probe_code, ProbeKind::LevelZero, ProbeMode::Enumerate)
        .expect_err("wrong probe error code must be rejected");
    assert_eq!(error.code, "PROBE_OUTPUT_INVALID");

    let valid_fail = br#"{"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":"OPENVINO_COMPILE_FAILED"}"#;
    let report = parse_probe_output(valid_fail, ProbeKind::OpenVino, ProbeMode::Infer)
        .expect("valid failure report must parse");
    assert_eq!(report.outcome, ProbeOutcome::Fail);
    assert_eq!(
        report.error_code,
        Some(ProbeErrorCode::OpenVinoCompileFailed)
    );
    assert_eq!(report.observations, ProbeObservations::Empty);
}

#[test]
fn serialize_protocol_deterministically() {
    for (name, probe, mode) in [
        (
            "level-zero-success.json",
            ProbeKind::LevelZero,
            ProbeMode::Enumerate,
        ),
        (
            "openvino-enumerate-success.json",
            ProbeKind::OpenVino,
            ProbeMode::Enumerate,
        ),
        (
            "openvino-infer-success.json",
            ProbeKind::OpenVino,
            ProbeMode::Infer,
        ),
    ] {
        let expected = fixture(name);
        let report = parse_probe_output(&expected, probe, mode).expect("parse fixture");
        let mut serialized = serde_json::to_vec(&report).expect("serialize report");
        serialized.push(b'\n');
        assert_eq!(serialized, expected);
    }
}
