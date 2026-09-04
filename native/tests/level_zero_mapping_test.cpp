// SPDX-License-Identifier: Apache-2.0

#include "level_zero/probe.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace l0 = intel_npu::native::level_zero;
namespace protocol = intel_npu::native::protocol;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

void selects_all_vpus_after_enumerating_other_device_types() {
  const std::vector<l0::DriverRecord> drivers = {
      {9, {{ZE_DEVICE_TYPE_GPU, 0x8086, 0x1234}, {ZE_DEVICE_TYPE_VPU, 0x8086, 0x7d1d}}},
      {7, {{ZE_DEVICE_TYPE_CPU, 0x8086, 0x0001}, {ZE_DEVICE_TYPE_VPU, 0x123, 0xabc}}},
  };

  const l0::ProbeResult result = l0::map_devices(drivers);
  require(!result.error.has_value(), "VPU records must produce a passing result");
  require(result.vpu_devices.size() == 2, "all VPU records must be retained");
  require(
      result.vpu_devices[0] == l0::VpuDevice{"0123", "0abc", 7},
      "PCI identifiers must be normalized and results sorted");
  require(
      result.vpu_devices[1] == l0::VpuDevice{"8086", "7d1d", 9},
      "a non-VPU before a VPU must not stop enumeration");
}

void rejects_invalid_or_excessive_observations() {
  require(
      l0::map_devices({}).error == protocol::LevelZeroError::no_vpu,
      "zero drivers must map to no VPU");

  require(
      l0::map_devices(std::vector<l0::DriverRecord>(protocol::kMaxObservations + 1))
              .error == protocol::LevelZeroError::enumeration_failed,
      "the driver count must be bounded before mapping");

  require(
      l0::map_devices(std::vector<l0::DriverRecord>{
                          {1, std::vector<l0::DeviceRecord>(
                                  protocol::kMaxObservations + 1,
                                  {ZE_DEVICE_TYPE_GPU, 0x8086, 1})}})
              .error == protocol::LevelZeroError::enumeration_failed,
      "each native device count must be bounded before mapping");

  std::vector<l0::DeviceRecord> too_many;
  too_many.reserve(protocol::kMaxObservations + 1);
  for (std::size_t index = 0; index <= protocol::kMaxObservations; ++index) {
    too_many.push_back({ZE_DEVICE_TYPE_VPU, 0x8086, static_cast<std::uint32_t>(index)});
  }
  require(
      l0::map_devices(std::vector<l0::DriverRecord>{{1, too_many}}).error ==
          protocol::LevelZeroError::enumeration_failed,
      "more than 64 VPU observations must be rejected");

  require(
      l0::map_devices(std::vector<l0::DriverRecord>{
                          {1, {{ZE_DEVICE_TYPE_VPU, 0x1'0000, 1}}}})
          .error == protocol::LevelZeroError::enumeration_failed,
      "PCI identifiers wider than four hexadecimal digits must be rejected");
}

void maps_every_stable_error_code() {
  require(
      !l0::map_result(ZE_RESULT_SUCCESS).has_value(),
      "success must not map to an error");
  require(
      l0::map_result(ZE_RESULT_ERROR_INSUFFICIENT_PERMISSIONS) ==
          protocol::LevelZeroError::permission_denied,
      "permission failures must remain distinct");
  require(
      l0::map_result(ZE_RESULT_ERROR_DEPENDENCY_UNAVAILABLE) ==
          protocol::LevelZeroError::dependency_unavailable,
      "missing dependencies must remain distinct");
  require(
      l0::map_result(ZE_RESULT_ERROR_UNINITIALIZED) ==
          protocol::LevelZeroError::dependency_unavailable,
      "an unavailable driver must map to a dependency failure");
  require(
      l0::map_result(ZE_RESULT_ERROR_DEVICE_LOST) ==
          protocol::LevelZeroError::enumeration_failed,
      "other Level Zero failures must map to enumeration failure");

  require(
      protocol::error_code(protocol::LevelZeroError::permission_denied) ==
          "LEVEL_ZERO_PERMISSION_DENIED",
      "permission error spelling must be stable");
  require(
      protocol::error_code(protocol::LevelZeroError::dependency_unavailable) ==
          "LEVEL_ZERO_DEPENDENCY_UNAVAILABLE",
      "dependency error spelling must be stable");
  require(
      protocol::error_code(protocol::LevelZeroError::no_vpu) == "LEVEL_ZERO_NO_VPU",
      "no-VPU error spelling must be stable");
  require(
      protocol::error_code(protocol::LevelZeroError::enumeration_failed) ==
          "LEVEL_ZERO_ENUMERATION_FAILED",
      "enumeration error spelling must be stable");
  require(
      protocol::error_code(protocol::LevelZeroError::internal_failure) ==
          "LEVEL_ZERO_INTERNAL_FAILURE",
      "internal error spelling must be stable");
}

void renders_exact_bounded_protocol_variants_without_a_newline() {
  const std::vector<l0::DriverRecord> drivers = {
      {65'536, {{ZE_DEVICE_TYPE_VPU, 0x8086, 0xabcd}}},
  };
  const std::string passing = l0::render_report(l0::map_devices(drivers));
  require(
      passing ==
          R"({"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"pass","observations":{"vpu_devices":[{"vendor_id":"8086","device_id":"abcd","driver_version":65536}]},"error_code":null})",
      "passing report must match protocol version one exactly");
  require(!passing.ends_with('\n'), "report rendering must leave the one newline to main");

  const std::vector<std::pair<protocol::LevelZeroError, std::string_view>> failures = {
      {protocol::LevelZeroError::permission_denied, "LEVEL_ZERO_PERMISSION_DENIED"},
      {protocol::LevelZeroError::dependency_unavailable, "LEVEL_ZERO_DEPENDENCY_UNAVAILABLE"},
      {protocol::LevelZeroError::no_vpu, "LEVEL_ZERO_NO_VPU"},
      {protocol::LevelZeroError::enumeration_failed, "LEVEL_ZERO_ENUMERATION_FAILED"},
      {protocol::LevelZeroError::internal_failure, "LEVEL_ZERO_INTERNAL_FAILURE"},
  };
  for (const auto& [error, spelling] : failures) {
    const std::string expected =
        R"({"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"fail","observations":{},"error_code":")" +
        std::string(spelling) + R"("})";
    require(
        l0::render_report({.vpu_devices = {}, .error = error}) == expected,
        "failing report must contain only the stable error variant");
  }
}

}  // namespace

int main() {
  try {
    selects_all_vpus_after_enumerating_other_device_types();
    rejects_invalid_or_excessive_observations();
    maps_every_stable_error_code();
    renders_exact_bounded_protocol_variants_without_a_newline();
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
  return 0;
}
