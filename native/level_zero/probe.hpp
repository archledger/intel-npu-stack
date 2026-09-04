// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <level_zero/ze_api.h>

#include "common/protocol.hpp"

namespace intel_npu::native::level_zero {

struct DeviceRecord {
  ze_device_type_t type;
  std::uint32_t vendor_id;
  std::uint32_t device_id;
};

struct DriverRecord {
  std::uint32_t driver_version;
  std::vector<DeviceRecord> devices;
};

struct VpuDevice {
  std::string vendor_id;
  std::string device_id;
  std::uint32_t driver_version;

  friend bool operator==(const VpuDevice&, const VpuDevice&) = default;
};

struct ProbeResult {
  std::vector<VpuDevice> vpu_devices;
  std::optional<protocol::LevelZeroError> error;
};

[[nodiscard]] std::optional<protocol::LevelZeroError> map_result(ze_result_t result) noexcept;
[[nodiscard]] ProbeResult map_devices(std::span<const DriverRecord> drivers);
[[nodiscard]] ProbeResult enumerate();
[[nodiscard]] std::string render_report(const ProbeResult& result);

}  // namespace intel_npu::native::level_zero
