// SPDX-License-Identifier: Apache-2.0

#include "openvino/probe.hpp"

#include "common/json_writer.hpp"
#include "common/protocol.hpp"

#include <openvino/openvino.hpp>
#include <openvino/opsets/opset13.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <stdexcept>

namespace intel_npu::native::openvino {
namespace {

constexpr std::string_view kProbe = "openvino";
constexpr std::string_view kInferMode = "infer";
constexpr std::string_view kGraphId = "intel-npu-stack-neutral-v1";
constexpr std::uint64_t kIterations = 8;
constexpr double kTolerance = 0.001;
constexpr std::array<float, 4> kExpectedOutput = {0.0F, 1.0F, 0.0F, 5.0F};

[[nodiscard]] ProbeResult failure(Error error) {
  return {
      .available_devices = {},
      .execution_devices = {},
      .runtime_version = {},
      .error = error,
  };
}

[[nodiscard]] bool is_device(std::string_view value) noexcept {
  constexpr std::array<std::string_view, 3> bases = {"CPU", "GPU", "NPU"};
  for (const std::string_view base : bases) {
    if (value == base) {
      return true;
    }
    if (value.size() > base.size() + 1 && value.starts_with(base) && value[base.size()] == '.') {
      const std::string_view suffix = value.substr(base.size() + 1);
      if (std::ranges::all_of(suffix, [](char byte) { return byte >= '0' && byte <= '9'; })) {
        return true;
      }
    }
  }
  return false;
}

[[nodiscard]] bool is_npu(std::string_view value) noexcept {
  return value == "NPU" ||
         (value.starts_with("NPU.") && value.size() > 4 &&
          std::ranges::all_of(
              value.substr(4), [](char byte) { return byte >= '0' && byte <= '9'; }));
}

[[nodiscard]] bool is_runtime_version(std::string_view value) noexcept {
  return !value.empty() && value.size() <= protocol::kMaxStringBytes &&
         std::ranges::all_of(value, [](unsigned char byte) {
           return std::isalnum(byte) != 0 || byte == '.' || byte == '+' || byte == '-' ||
                  byte == '_';
         });
}

void write_devices(json::Writer& writer, std::span<const std::string> devices) {
  writer.begin_array();
  for (const std::string& device : devices) {
    writer.string(device);
  }
  writer.end_array();
}

void begin_report(json::Writer& writer, std::string_view mode) {
  writer.begin_object();
  writer.key("schema_version");
  writer.unsigned_integer(protocol::kSchemaVersion);
  writer.key("probe");
  writer.string(kProbe);
  writer.key("mode");
  writer.string(mode);
}

void write_failure(json::Writer& writer, Error error) {
  writer.key("outcome");
  writer.string(protocol::kFailOutcome);
  writer.key("observations");
  writer.begin_object();
  writer.end_object();
  writer.key("error_code");
  writer.string(error_code(error));
}

void require_failure_invariant(const ProbeResult& result) {
  if (!result.available_devices.empty() || !result.execution_devices.empty() ||
      !result.runtime_version.empty()) {
    throw std::invalid_argument("failed OpenVINO result contains observations");
  }
}

void require_passing_enumeration(const ProbeResult& result) {
  const ProbeResult validated =
      validate_enumeration(result.available_devices, result.runtime_version);
  if (validated.error.has_value() || validated.available_devices != result.available_devices ||
      !result.execution_devices.empty()) {
    throw std::invalid_argument("passing OpenVINO enumeration result is invalid");
  }
}

}  // namespace

std::vector<std::string> normalize_devices(std::span<const std::string> devices) {
  std::vector<std::string> normalized;
  normalized.reserve(std::min(devices.size(), protocol::kMaxObservations));
  for (const std::string& device : devices) {
    if (device.size() <= protocol::kMaxStringBytes && is_device(device)) {
      normalized.push_back(device);
    }
  }
  std::sort(normalized.begin(), normalized.end());
  normalized.erase(std::unique(normalized.begin(), normalized.end()), normalized.end());
  return normalized;
}

std::optional<std::string> normalize_runtime_version(std::string_view version) {
  const auto end = std::ranges::find_if(version, [](unsigned char byte) {
    return std::isalnum(byte) == 0 && byte != '.' && byte != '+' && byte != '-' && byte != '_';
  });
  const std::size_t length = static_cast<std::size_t>(end - version.begin());
  if (length == 0 || length > protocol::kMaxStringBytes) {
    return std::nullopt;
  }
  return std::string(version.substr(0, length));
}

ProbeResult validate_enumeration(
    std::span<const std::string> devices,
    std::string_view runtime_version) {
  if (devices.size() > protocol::kMaxObservations || !is_runtime_version(runtime_version)) {
    return failure(Error::enumeration_failed);
  }
  std::vector<std::string> normalized = normalize_devices(devices);
  if (!std::ranges::any_of(normalized, is_npu)) {
    return failure(Error::no_npu);
  }
  return {
      .available_devices = std::move(normalized),
      .execution_devices = {},
      .runtime_version = std::string(runtime_version),
      .error = std::nullopt,
  };
}

std::optional<Error> validate_execution_devices(
    std::span<const std::string> devices) noexcept {
  if (devices.empty() || devices.size() > protocol::kMaxObservations ||
      !std::ranges::all_of(devices, [](const std::string& device) {
        return device.size() <= protocol::kMaxStringBytes && is_npu(device);
      })) {
    return Error::wrong_device;
  }
  return std::nullopt;
}

std::optional<Error> validate_neutral_output(
    std::span<const std::size_t> shape,
    std::span<const float> values) noexcept {
  if (shape.size() != 2 || shape[0] != 1 || shape[1] != kExpectedOutput.size() ||
      values.size() != kExpectedOutput.size()) {
    return Error::output_invalid;
  }
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (!std::isfinite(values[index]) ||
        std::fabs(static_cast<double>(values[index] - kExpectedOutput[index])) > kTolerance) {
      return Error::output_invalid;
    }
  }
  return std::nullopt;
}

std::string_view error_code(Error error) noexcept {
  switch (error) {
    case Error::no_npu:
      return "OPENVINO_NO_NPU";
    case Error::enumeration_failed:
      return "OPENVINO_ENUMERATION_FAILED";
    case Error::compile_failed:
      return "OPENVINO_COMPILE_FAILED";
    case Error::wrong_device:
      return "OPENVINO_WRONG_DEVICE";
    case Error::inference_failed:
      return "OPENVINO_INFERENCE_FAILED";
    case Error::output_invalid:
      return "OPENVINO_OUTPUT_INVALID";
    case Error::internal_failure:
      return "OPENVINO_INTERNAL_FAILURE";
  }
  return "OPENVINO_INTERNAL_FAILURE";
}

std::string render_enumerate_report(const ProbeResult& result) {
  json::Writer writer(protocol::kMaxOutputBytes, protocol::kMaxStringBytes);
  begin_report(writer, protocol::kEnumerateMode);
  if (result.error.has_value()) {
    require_failure_invariant(result);
    write_failure(writer, *result.error);
  } else {
    require_passing_enumeration(result);
    writer.key("outcome");
    writer.string(protocol::kPassOutcome);
    writer.key("observations");
    writer.begin_object();
    writer.key("available_devices");
    write_devices(writer, result.available_devices);
    writer.key("runtime_version");
    writer.string(result.runtime_version);
    writer.end_object();
    writer.key("error_code");
    writer.null_value();
  }
  writer.end_object();
  return writer.finish();
}

std::string render_infer_report(const ProbeResult& result) {
  json::Writer writer(protocol::kMaxOutputBytes, protocol::kMaxStringBytes);
  begin_report(writer, kInferMode);
  if (result.error.has_value()) {
    require_failure_invariant(result);
    write_failure(writer, *result.error);
  } else {
    const ProbeResult enumeration =
        validate_enumeration(result.available_devices, result.runtime_version);
    if (enumeration.error.has_value() || enumeration.available_devices != result.available_devices ||
        validate_execution_devices(result.execution_devices).has_value() ||
        normalize_devices(result.execution_devices) != result.execution_devices) {
      throw std::invalid_argument("passing OpenVINO inference result is invalid");
    }
    writer.key("outcome");
    writer.string(protocol::kPassOutcome);
    writer.key("observations");
    writer.begin_object();
    writer.key("available_devices");
    write_devices(writer, result.available_devices);
    writer.key("execution_devices");
    write_devices(writer, result.execution_devices);
    writer.key("runtime_version");
    writer.string(result.runtime_version);
    writer.key("graph_id");
    writer.string(kGraphId);
    writer.key("iterations");
    writer.unsigned_integer(kIterations);
    writer.key("tolerance");
    writer.decimal(kTolerance);
    writer.end_object();
    writer.key("error_code");
    writer.null_value();
  }
  writer.end_object();
  return writer.finish();
}

std::shared_ptr<ov::Model> build_neutral_model() {
  const auto parameter =
      std::make_shared<ov::opset13::Parameter>(ov::element::f32, ov::Shape{1, 4});
  const auto constant = ov::opset13::Constant::create(
      ov::element::f32,
      ov::Shape{1, 4},
      std::vector<float>{1.0F, -1.0F, 0.5F, 2.0F});
  const auto add = std::make_shared<ov::opset13::Add>(parameter, constant);
  const auto relu = std::make_shared<ov::opset13::Relu>(add);
  const auto result = std::make_shared<ov::opset13::Result>(relu);
  return std::make_shared<ov::Model>(
      ov::ResultVector{result}, ov::ParameterVector{parameter}, std::string(kGraphId));
}

ProbeResult enumerate() {
  try {
    ov::Core core;
    const ov::Version version = ov::get_openvino_version();
    if (version.buildNumber == nullptr) {
      return failure(Error::enumeration_failed);
    }
    const std::optional<std::string> normalized_version =
        normalize_runtime_version(version.buildNumber);
    if (!normalized_version.has_value()) {
      return failure(Error::enumeration_failed);
    }
    return validate_enumeration(core.get_available_devices(), *normalized_version);
  } catch (...) {
    return failure(Error::enumeration_failed);
  }
}

ProbeResult infer() {
  std::unique_ptr<ov::Core> core;
  ProbeResult discovery;
  try {
    core = std::make_unique<ov::Core>();
    const ov::Version version = ov::get_openvino_version();
    if (version.buildNumber == nullptr) {
      return failure(Error::enumeration_failed);
    }
    const std::optional<std::string> normalized_version =
        normalize_runtime_version(version.buildNumber);
    if (!normalized_version.has_value()) {
      return failure(Error::enumeration_failed);
    }
    discovery = validate_enumeration(core->get_available_devices(), *normalized_version);
  } catch (...) {
    return failure(Error::enumeration_failed);
  }
  if (discovery.error.has_value()) {
    return discovery;
  }

  ov::CompiledModel compiled;
  try {
    compiled = core->compile_model(build_neutral_model(), "NPU");
  } catch (...) {
    return failure(Error::compile_failed);
  }

  std::vector<std::string> execution_devices;
  try {
    const std::vector<std::string> raw_execution =
        compiled.get_property(ov::execution_devices);
    if (validate_execution_devices(raw_execution).has_value()) {
      return failure(Error::wrong_device);
    }
    execution_devices = normalize_devices(raw_execution);
  } catch (...) {
    return failure(Error::wrong_device);
  }

  ov::InferRequest request;
  try {
    request = compiled.create_infer_request();
    ov::Tensor input(ov::element::f32, ov::Shape{1, 4});
    constexpr std::array<float, 4> values = {-2.0F, 2.0F, -0.5F, 3.0F};
    std::ranges::copy(values, input.data<float>());
    request.set_input_tensor(input);

    for (std::uint64_t iteration = 0; iteration < kIterations; ++iteration) {
      request.infer();
      const ov::Tensor output = request.get_output_tensor();
      if (output.get_element_type() != ov::element::f32 ||
          validate_neutral_output(
              output.get_shape(),
              std::span<const float>(output.data<const float>(), output.get_size()))
              .has_value()) {
        return failure(Error::output_invalid);
      }
    }
  } catch (...) {
    return failure(Error::inference_failed);
  }

  return {
      .available_devices = std::move(discovery.available_devices),
      .execution_devices = std::move(execution_devices),
      .runtime_version = std::move(discovery.runtime_version),
      .error = std::nullopt,
  };
}

}  // namespace intel_npu::native::openvino
