// SPDX-License-Identifier: Apache-2.0

#include "openvino/probe.hpp"

#include <openvino/openvino.hpp>
#include <openvino/opsets/opset13.hpp>

#include <array>
#include <cmath>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace ov_probe = intel_npu::native::openvino;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

void normalize_only_cpu_gpu_and_npu_device_ids() {
  const std::vector<std::string> raw = {
      "NPU.2", "CPU", "AUTO", "GPU.0", "NPU", "npu", "GPU.0", "HETERO", "NPU.x"};
  require(
      ov_probe::normalize_devices(raw) ==
          std::vector<std::string>({"CPU", "GPU.0", "NPU", "NPU.2"}),
      "only normalized physical device identifiers must remain, sorted and unique");
}

void require_npu_for_enumeration_success() {
  const ov_probe::ProbeResult no_npu =
      ov_probe::validate_enumeration(std::vector<std::string>{"GPU.0", "CPU"}, "2026.2.0");
  require(no_npu.error == ov_probe::Error::no_npu, "CPU and GPU must not satisfy NPU discovery");
  require(no_npu.available_devices.empty(), "failure observations must remain empty");

  const ov_probe::ProbeResult npu = ov_probe::validate_enumeration(
      std::vector<std::string>{"NPU.1", "CPU", "NPU.1"}, "2026.2.0");
  require(!npu.error.has_value(), "a normalized NPU identifier must satisfy discovery");
  require(
      npu.available_devices == std::vector<std::string>({"CPU", "NPU.1"}),
      "passing enumeration devices must be normalized, sorted, and unique");
  require(npu.runtime_version == "2026.2.0", "the bounded runtime version must be retained");

  const ov_probe::ProbeResult excessive = ov_probe::validate_enumeration(
      std::vector<std::string>(65, "NPU"), "2026.2.0");
  require(
      excessive.error == ov_probe::Error::enumeration_failed,
      "native discovery input must be bounded before normalization");
}

void normalize_runtime_build_version_without_paths() {
  require(
      ov_probe::normalize_runtime_version(
          "2026.2.0-21903-52ddc073857-releases/2026/2") ==
          std::optional<std::string>("2026.2.0-21903-52ddc073857-releases"),
      "runtime version normalization must stop before path separators");
  require(
      !ov_probe::normalize_runtime_version("/plugin/path").has_value(),
      "a version without a safe prefix must be rejected");
}

void require_all_execution_devices_to_be_npu() {
  require(
      !ov_probe::validate_execution_devices(std::vector<std::string>{"NPU", "NPU.3"})
           .has_value(),
      "a nonempty all-NPU execution list must pass");
  for (const std::vector<std::string>& invalid : {
           std::vector<std::string>{},
           std::vector<std::string>{"CPU"},
           std::vector<std::string>{"NPU", "GPU.0"},
           std::vector<std::string>{"NPU.x"},
       }) {
    require(
        ov_probe::validate_execution_devices(invalid) == ov_probe::Error::wrong_device,
        "empty, malformed, or non-NPU execution lists must fail closed");
  }
}

void accept_exact_neutral_output_within_tolerance() {
  constexpr std::array<std::size_t, 2> shape = {1, 4};
  constexpr std::array<float, 4> exact = {0.0F, 1.0F, 0.0F, 5.0F};
  constexpr std::array<float, 4> near = {0.0009F, 0.9991F, -0.0009F, 5.0009F};
  require(
      !ov_probe::validate_neutral_output(shape, exact).has_value(),
      "the exact neutral graph output must pass");
  require(
      !ov_probe::validate_neutral_output(shape, near).has_value(),
      "finite values within absolute tolerance must pass");
}

void reject_wrong_shape_nonfinite_and_out_of_tolerance() {
  constexpr std::array<std::size_t, 2> shape = {1, 4};
  constexpr std::array<std::size_t, 2> wrong_shape = {2, 2};
  constexpr std::array<float, 4> exact = {0.0F, 1.0F, 0.0F, 5.0F};
  const std::array<float, 4> nonfinite = {
      0.0F, 1.0F, std::numeric_limits<float>::infinity(), 5.0F};
  constexpr std::array<float, 4> outside = {0.0F, 1.0F, 0.0F, 5.0011F};
  require(
      ov_probe::validate_neutral_output(wrong_shape, exact) == ov_probe::Error::output_invalid,
      "the output shape must be exactly [1,4]");
  require(
      ov_probe::validate_neutral_output(shape, nonfinite) == ov_probe::Error::output_invalid,
      "nonfinite output must fail");
  require(
      ov_probe::validate_neutral_output(shape, outside) == ov_probe::Error::output_invalid,
      "output beyond absolute tolerance must fail");
}

void emit_exact_graph_iterations_and_tolerance_constants() {
  const ov_probe::ProbeResult passing = {
      .available_devices = {"CPU", "NPU"},
      .execution_devices = {"NPU"},
      .runtime_version = "2026.2.0",
      .error = std::nullopt,
  };
  const std::string report = ov_probe::render_infer_report(passing);
  require(
      report ==
          R"({"schema_version":1,"probe":"openvino","mode":"infer","outcome":"pass","observations":{"available_devices":["CPU","NPU"],"execution_devices":["NPU"],"runtime_version":"2026.2.0","graph_id":"intel-npu-stack-neutral-v1","iterations":8,"tolerance":0.001},"error_code":null})",
      "passing inference must emit the exact neutral graph protocol constants");
  require(!report.ends_with('\n'), "report rendering must leave the one newline to main");
}

void build_exact_in_memory_neutral_graph() {
  const std::shared_ptr<ov::Model> model = ov_probe::build_neutral_model();
  require(model != nullptr, "the neutral graph must exist");
  require(model->get_friendly_name() == "intel-npu-stack-neutral-v1", "graph ID must be exact");
  require(model->inputs().size() == 1, "the neutral graph must have one input");
  require(model->outputs().size() == 1, "the neutral graph must have one output");
  require(model->input().get_element_type() == ov::element::f32, "input type must be f32");
  require(model->input().get_shape() == ov::Shape({1, 4}), "input shape must be [1,4]");
  require(model->output().get_shape() == ov::Shape({1, 4}), "output shape must be [1,4]");

  std::size_t parameters = 0;
  std::size_t constants = 0;
  std::size_t adds = 0;
  std::size_t relus = 0;
  std::size_t results = 0;
  std::vector<float> constant_values;
  for (const std::shared_ptr<ov::Node>& node : model->get_ordered_ops()) {
    if (std::dynamic_pointer_cast<ov::opset13::Parameter>(node) != nullptr) {
      ++parameters;
    }
    if (const auto constant = std::dynamic_pointer_cast<ov::opset13::Constant>(node)) {
      ++constants;
      constant_values = constant->cast_vector<float>();
    }
    if (std::dynamic_pointer_cast<ov::opset13::Add>(node) != nullptr) {
      ++adds;
    }
    if (std::dynamic_pointer_cast<ov::opset13::Relu>(node) != nullptr) {
      ++relus;
    }
    if (std::dynamic_pointer_cast<ov::opset13::Result>(node) != nullptr) {
      ++results;
    }
  }
  require(parameters == 1, "the graph must have exactly one Parameter");
  require(constants == 1, "the graph must have exactly one Constant");
  require(adds == 1, "the graph must have exactly one Add");
  require(relus == 1, "the graph must have exactly one ReLU");
  require(results == 1, "the graph must have exactly one Result");
  require(
      constant_values == std::vector<float>({1.0F, -1.0F, 0.5F, 2.0F}),
      "the graph Constant values must match the neutral contract");
}

void map_each_openvino_stage_to_fixed_error_code() {
  const std::vector<std::pair<ov_probe::Error, std::string_view>> errors = {
      {ov_probe::Error::no_npu, "OPENVINO_NO_NPU"},
      {ov_probe::Error::enumeration_failed, "OPENVINO_ENUMERATION_FAILED"},
      {ov_probe::Error::compile_failed, "OPENVINO_COMPILE_FAILED"},
      {ov_probe::Error::wrong_device, "OPENVINO_WRONG_DEVICE"},
      {ov_probe::Error::inference_failed, "OPENVINO_INFERENCE_FAILED"},
      {ov_probe::Error::output_invalid, "OPENVINO_OUTPUT_INVALID"},
      {ov_probe::Error::internal_failure, "OPENVINO_INTERNAL_FAILURE"},
  };
  for (const auto& [error, expected] : errors) {
    require(ov_probe::error_code(error) == expected, "every stage must have a fixed error code");
  }

  const ov_probe::ProbeResult failure = {
      .available_devices = {},
      .execution_devices = {},
      .runtime_version = {},
      .error = ov_probe::Error::compile_failed,
  };
  require(
      ov_probe::render_infer_report(failure) ==
          R"({"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":"OPENVINO_COMPILE_FAILED"})",
      "a failing stage must emit empty observations and only its stable error code");
}

}  // namespace

int main() {
  try {
    normalize_only_cpu_gpu_and_npu_device_ids();
    require_npu_for_enumeration_success();
    normalize_runtime_build_version_without_paths();
    require_all_execution_devices_to_be_npu();
    accept_exact_neutral_output_within_tolerance();
    reject_wrong_shape_nonfinite_and_out_of_tolerance();
    emit_exact_graph_iterations_and_tolerance_constants();
    build_exact_in_memory_neutral_graph();
    map_each_openvino_stage_to_fixed_error_code();
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
  return 0;
}
