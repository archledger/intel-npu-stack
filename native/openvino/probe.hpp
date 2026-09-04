// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ov {
class Model;
}

namespace intel_npu::native::openvino {

enum class Error {
  no_npu,
  enumeration_failed,
  compile_failed,
  wrong_device,
  inference_failed,
  output_invalid,
  internal_failure,
};

struct ProbeResult {
  std::vector<std::string> available_devices;
  std::vector<std::string> execution_devices;
  std::string runtime_version;
  std::optional<Error> error;
};

[[nodiscard]] std::vector<std::string> normalize_devices(
    std::span<const std::string> devices);
[[nodiscard]] std::optional<std::string> normalize_runtime_version(
    std::string_view version);
[[nodiscard]] ProbeResult validate_enumeration(
    std::span<const std::string> devices,
    std::string_view runtime_version);
[[nodiscard]] std::optional<Error> validate_execution_devices(
    std::span<const std::string> devices) noexcept;
[[nodiscard]] std::optional<Error> validate_neutral_output(
    std::span<const std::size_t> shape,
    std::span<const float> values) noexcept;
[[nodiscard]] std::string_view error_code(Error error) noexcept;
[[nodiscard]] std::string render_enumerate_report(const ProbeResult& result);
[[nodiscard]] std::string render_infer_report(const ProbeResult& result);
[[nodiscard]] std::shared_ptr<ov::Model> build_neutral_model();
[[nodiscard]] ProbeResult enumerate();
[[nodiscard]] ProbeResult infer();

}  // namespace intel_npu::native::openvino
