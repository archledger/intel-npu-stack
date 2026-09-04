// SPDX-License-Identifier: Apache-2.0

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::strict_json::StrictValue;

pub const MAX_PROBE_STDOUT: usize = 65_536;
const MAX_OBSERVATIONS: usize = 64;
const MAX_OBSERVATION_STRING: usize = 256;
const PROBE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    LevelZero,
    #[serde(rename = "openvino")]
    OpenVino,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    Enumerate,
    Infer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeErrorCode {
    #[serde(rename = "LEVEL_ZERO_PERMISSION_DENIED")]
    LevelZeroPermissionDenied,
    #[serde(rename = "LEVEL_ZERO_DEPENDENCY_UNAVAILABLE")]
    LevelZeroDependencyUnavailable,
    #[serde(rename = "LEVEL_ZERO_NO_VPU")]
    LevelZeroNoVpu,
    #[serde(rename = "LEVEL_ZERO_ENUMERATION_FAILED")]
    LevelZeroEnumerationFailed,
    #[serde(rename = "LEVEL_ZERO_INTERNAL_FAILURE")]
    LevelZeroInternalFailure,
    #[serde(rename = "OPENVINO_NO_NPU")]
    OpenVinoNoNpu,
    #[serde(rename = "OPENVINO_ENUMERATION_FAILED")]
    OpenVinoEnumerationFailed,
    #[serde(rename = "OPENVINO_COMPILE_FAILED")]
    OpenVinoCompileFailed,
    #[serde(rename = "OPENVINO_WRONG_DEVICE")]
    OpenVinoWrongDevice,
    #[serde(rename = "OPENVINO_INFERENCE_FAILED")]
    OpenVinoInferenceFailed,
    #[serde(rename = "OPENVINO_OUTPUT_INVALID")]
    OpenVinoOutputInvalid,
    #[serde(rename = "OPENVINO_INTERNAL_FAILURE")]
    OpenVinoInternalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LevelZeroDevice {
    pub vendor_id: String,
    pub device_id: String,
    pub driver_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LevelZeroObservation {
    pub vpu_devices: Vec<LevelZeroDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVinoEnumerateObservation {
    pub available_devices: Vec<String>,
    pub runtime_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVinoInferObservation {
    pub available_devices: Vec<String>,
    pub execution_devices: Vec<String>,
    pub runtime_version: String,
    pub graph_id: String,
    pub iterations: u32,
    pub tolerance: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeObservations {
    Empty,
    LevelZero(LevelZeroObservation),
    OpenVinoEnumerate(OpenVinoEnumerateObservation),
    OpenVinoInfer(OpenVinoInferObservation),
}

impl Serialize for ProbeObservations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Empty => serializer.serialize_map(Some(0))?.end(),
            Self::LevelZero(value) => value.serialize(serializer),
            Self::OpenVinoEnumerate(value) => value.serialize(serializer),
            Self::OpenVinoInfer(value) => value.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub probe: ProbeKind,
    pub mode: ProbeMode,
    pub outcome: ProbeOutcome,
    pub observations: ProbeObservations,
    pub error_code: Option<ProbeErrorCode>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct ProtocolError {
    pub code: &'static str,
    message: String,
}

impl ProtocolError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "PROBE_OUTPUT_INVALID",
            message: message.into(),
        }
    }

    fn unsupported_schema(version: u64) -> Self {
        Self {
            code: "PROBE_SCHEMA_UNSUPPORTED",
            message: format!("unsupported probe schema version {version}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProbeReport {
    schema_version: u32,
    probe: ProbeKind,
    mode: ProbeMode,
    outcome: ProbeOutcome,
    observations: serde_json::Value,
    error_code: Option<ProbeErrorCode>,
}

/// Parses and validates one bounded helper report.
///
/// # Errors
///
/// Returns a stable protocol error when bytes, JSON structure, identity, or
/// probe-specific semantics violate protocol version one.
pub fn parse_probe_output(
    bytes: &[u8],
    expected_probe: ProbeKind,
    expected_mode: ProbeMode,
) -> Result<ProbeReport, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::invalid("probe output is empty"));
    }
    if bytes.len() > MAX_PROBE_STDOUT {
        return Err(ProtocolError::invalid("probe output exceeds 65536 bytes"));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(ProtocolError::invalid(
            "probe output starts with a byte-order mark",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProtocolError::invalid("probe output is not UTF-8"))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| ProtocolError::invalid("probe output is not strict JSON"))?;
    deserializer
        .end()
        .map_err(|_| ProtocolError::invalid("probe output has trailing data"))?;
    let value = serde_json::Value::from(strict);

    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::invalid("probe report must be an object"))?;
    const TOP_LEVEL_KEYS: [&str; 6] = [
        "schema_version",
        "probe",
        "mode",
        "outcome",
        "observations",
        "error_code",
    ];
    if object.len() != TOP_LEVEL_KEYS.len()
        || TOP_LEVEL_KEYS.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ProtocolError::invalid(
            "probe report top-level keys are invalid",
        ));
    }

    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ProtocolError::invalid("probe schema version is missing or invalid"))?;
    if schema_version != u64::from(PROBE_SCHEMA_VERSION) {
        return Err(ProtocolError::unsupported_schema(schema_version));
    }

    let raw: RawProbeReport = serde_json::from_value(value)
        .map_err(|_| ProtocolError::invalid("probe report shape is invalid"))?;
    if raw.schema_version != PROBE_SCHEMA_VERSION
        || raw.probe != expected_probe
        || raw.mode != expected_mode
        || (raw.probe == ProbeKind::LevelZero && raw.mode != ProbeMode::Enumerate)
    {
        return Err(ProtocolError::invalid("probe identity or mode is invalid"));
    }

    let observations = match raw.outcome {
        ProbeOutcome::Fail => {
            if !raw
                .observations
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
            {
                return Err(ProtocolError::invalid(
                    "failed probe observations must be empty",
                ));
            }
            let error_code = raw
                .error_code
                .ok_or_else(|| ProtocolError::invalid("failed probe has no error code"))?;
            validate_error_code(raw.probe, raw.mode, error_code)?;
            ProbeObservations::Empty
        }
        ProbeOutcome::Pass => {
            if raw.error_code.is_some() {
                return Err(ProtocolError::invalid(
                    "passing probe must not have an error code",
                ));
            }
            parse_success_observations(raw.probe, raw.mode, raw.observations)?
        }
    };

    Ok(ProbeReport {
        schema_version: raw.schema_version,
        probe: raw.probe,
        mode: raw.mode,
        outcome: raw.outcome,
        observations,
        error_code: raw.error_code,
    })
}

fn parse_success_observations(
    probe: ProbeKind,
    mode: ProbeMode,
    value: serde_json::Value,
) -> Result<ProbeObservations, ProtocolError> {
    match (probe, mode) {
        (ProbeKind::LevelZero, ProbeMode::Enumerate) => {
            let observation: LevelZeroObservation = deserialize_observation(value)?;
            validate_level_zero(&observation)?;
            Ok(ProbeObservations::LevelZero(observation))
        }
        (ProbeKind::OpenVino, ProbeMode::Enumerate) => {
            let observation: OpenVinoEnumerateObservation = deserialize_observation(value)?;
            validate_openvino_enumerate(&observation)?;
            Ok(ProbeObservations::OpenVinoEnumerate(observation))
        }
        (ProbeKind::OpenVino, ProbeMode::Infer) => {
            let observation: OpenVinoInferObservation = deserialize_observation(value)?;
            validate_openvino_infer(&observation)?;
            Ok(ProbeObservations::OpenVinoInfer(observation))
        }
        (ProbeKind::LevelZero, ProbeMode::Infer) => {
            Err(ProtocolError::invalid("Level Zero infer mode is invalid"))
        }
    }
}

fn deserialize_observation<T>(value: serde_json::Value) -> Result<T, ProtocolError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value)
        .map_err(|_| ProtocolError::invalid("probe observations are invalid"))
}

fn validate_level_zero(observation: &LevelZeroObservation) -> Result<(), ProtocolError> {
    if observation.vpu_devices.is_empty() || observation.vpu_devices.len() > MAX_OBSERVATIONS {
        return Err(ProtocolError::invalid("VPU device count is invalid"));
    }
    for device in &observation.vpu_devices {
        if !is_lower_hex_quad(&device.vendor_id) || !is_lower_hex_quad(&device.device_id) {
            return Err(ProtocolError::invalid("VPU PCI identifier is invalid"));
        }
    }
    if !observation.vpu_devices.windows(2).all(|pair| {
        let left = (
            pair[0].vendor_id.as_str(),
            pair[0].device_id.as_str(),
            pair[0].driver_version,
        );
        let right = (
            pair[1].vendor_id.as_str(),
            pair[1].device_id.as_str(),
            pair[1].driver_version,
        );
        left < right
    }) {
        return Err(ProtocolError::invalid(
            "VPU observations must be sorted and unique",
        ));
    }
    Ok(())
}

fn validate_openvino_enumerate(
    observation: &OpenVinoEnumerateObservation,
) -> Result<(), ProtocolError> {
    validate_device_list(&observation.available_devices, false)?;
    if !observation
        .available_devices
        .iter()
        .any(|device| is_npu_name(device))
    {
        return Err(ProtocolError::invalid(
            "passing OpenVINO enumeration has no NPU",
        ));
    }
    validate_runtime_version(&observation.runtime_version)
}

fn validate_openvino_infer(observation: &OpenVinoInferObservation) -> Result<(), ProtocolError> {
    validate_device_list(&observation.available_devices, false)?;
    if !observation
        .available_devices
        .iter()
        .any(|device| is_npu_name(device))
    {
        return Err(ProtocolError::invalid(
            "passing OpenVINO inference has no available NPU",
        ));
    }
    validate_device_list(&observation.execution_devices, true)?;
    validate_runtime_version(&observation.runtime_version)?;
    if observation.graph_id != "intel-npu-stack-neutral-v1"
        || observation.iterations != 8
        || observation.tolerance != 0.001
    {
        return Err(ProtocolError::invalid(
            "OpenVINO inference constants are invalid",
        ));
    }
    Ok(())
}

fn validate_device_list(devices: &[String], npu_only: bool) -> Result<(), ProtocolError> {
    if devices.is_empty() || devices.len() > MAX_OBSERVATIONS {
        return Err(ProtocolError::invalid("OpenVINO device count is invalid"));
    }
    for device in devices {
        if device.len() > MAX_OBSERVATION_STRING
            || !is_device_name(device)
            || (npu_only && !is_npu_name(device))
        {
            return Err(ProtocolError::invalid("OpenVINO device name is invalid"));
        }
    }
    if !devices.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ProtocolError::invalid(
            "OpenVINO devices must be sorted and unique",
        ));
    }
    Ok(())
}

fn validate_runtime_version(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_OBSERVATION_STRING
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
    {
        return Err(ProtocolError::invalid(
            "OpenVINO runtime version is invalid",
        ));
    }
    Ok(())
}

fn validate_error_code(
    probe: ProbeKind,
    mode: ProbeMode,
    code: ProbeErrorCode,
) -> Result<(), ProtocolError> {
    let valid = match probe {
        ProbeKind::LevelZero => matches!(
            code,
            ProbeErrorCode::LevelZeroPermissionDenied
                | ProbeErrorCode::LevelZeroDependencyUnavailable
                | ProbeErrorCode::LevelZeroNoVpu
                | ProbeErrorCode::LevelZeroEnumerationFailed
                | ProbeErrorCode::LevelZeroInternalFailure
        ),
        ProbeKind::OpenVino if mode == ProbeMode::Enumerate => matches!(
            code,
            ProbeErrorCode::OpenVinoNoNpu
                | ProbeErrorCode::OpenVinoEnumerationFailed
                | ProbeErrorCode::OpenVinoInternalFailure
        ),
        ProbeKind::OpenVino => matches!(
            code,
            ProbeErrorCode::OpenVinoNoNpu
                | ProbeErrorCode::OpenVinoEnumerationFailed
                | ProbeErrorCode::OpenVinoCompileFailed
                | ProbeErrorCode::OpenVinoWrongDevice
                | ProbeErrorCode::OpenVinoInferenceFailed
                | ProbeErrorCode::OpenVinoOutputInvalid
                | ProbeErrorCode::OpenVinoInternalFailure
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::invalid(
            "probe error code does not match probe mode",
        ))
    }
}

fn is_lower_hex_quad(value: &str) -> bool {
    value.len() == 4
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_device_name(value: &str) -> bool {
    ["CPU", "GPU", "NPU"].iter().any(|base| {
        value == *base
            || value
                .strip_prefix(&format!("{base}."))
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
    })
}

fn is_npu_name(value: &str) -> bool {
    value == "NPU"
        || value.strip_prefix("NPU.").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}
