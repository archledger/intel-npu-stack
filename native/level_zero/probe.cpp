// SPDX-License-Identifier: Apache-2.0

#include "level_zero/probe.hpp"

#include "common/json_writer.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace intel_npu::native::level_zero {
namespace {

[[nodiscard]] ProbeResult failure(protocol::LevelZeroError error) {
  return {.vpu_devices = {}, .error = error};
}

[[nodiscard]] std::string hex_quad(std::uint32_t value) {
  if (value > 0xffffU) {
    throw std::out_of_range("PCI identifier exceeds 16 bits");
  }
  constexpr std::array<char, 16> hex = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string output(4, '0');
  for (std::size_t index = output.size(); index > 0; --index) {
    output[index - 1] = hex[value & 0x0fU];
    value >>= 4U;
  }
  return output;
}

[[nodiscard]] bool vpu_less(const VpuDevice& left, const VpuDevice& right) {
  if (left.vendor_id != right.vendor_id) {
    return left.vendor_id < right.vendor_id;
  }
  if (left.device_id != right.device_id) {
    return left.device_id < right.device_id;
  }
  return left.driver_version < right.driver_version;
}

[[nodiscard]] ProbeResult api_failure(ze_result_t result) {
  return failure(map_result(result).value_or(protocol::LevelZeroError::internal_failure));
}

}  // namespace

std::optional<protocol::LevelZeroError> map_result(ze_result_t result) noexcept {
  switch (result) {
    case ZE_RESULT_SUCCESS:
      return std::nullopt;
    case ZE_RESULT_ERROR_INSUFFICIENT_PERMISSIONS:
      return protocol::LevelZeroError::permission_denied;
    case ZE_RESULT_ERROR_DEPENDENCY_UNAVAILABLE:
    case ZE_RESULT_ERROR_UNINITIALIZED:
      return protocol::LevelZeroError::dependency_unavailable;
    default:
      return protocol::LevelZeroError::enumeration_failed;
  }
}

ProbeResult map_devices(std::span<const DriverRecord> drivers) {
  if (drivers.size() > protocol::kMaxObservations) {
    return failure(protocol::LevelZeroError::enumeration_failed);
  }

  std::vector<VpuDevice> devices;
  for (const DriverRecord& driver : drivers) {
    if (driver.devices.size() > protocol::kMaxObservations) {
      return failure(protocol::LevelZeroError::enumeration_failed);
    }
    for (const DeviceRecord& device : driver.devices) {
      if (device.type != ZE_DEVICE_TYPE_VPU) {
        continue;
      }
      try {
        devices.push_back({
            .vendor_id = hex_quad(device.vendor_id),
            .device_id = hex_quad(device.device_id),
            .driver_version = driver.driver_version,
        });
      } catch (const std::out_of_range&) {
        return failure(protocol::LevelZeroError::enumeration_failed);
      }
    }
  }

  std::sort(devices.begin(), devices.end(), vpu_less);
  devices.erase(std::unique(devices.begin(), devices.end()), devices.end());
  if (devices.empty()) {
    return failure(protocol::LevelZeroError::no_vpu);
  }
  if (devices.size() > protocol::kMaxObservations) {
    return failure(protocol::LevelZeroError::enumeration_failed);
  }
  return {.vpu_devices = std::move(devices), .error = std::nullopt};
}

ProbeResult enumerate() {
  ze_init_driver_type_desc_t descriptor{};
  descriptor.stype = ZE_STRUCTURE_TYPE_INIT_DRIVER_TYPE_DESC;
  descriptor.pNext = nullptr;
  descriptor.flags = std::numeric_limits<ze_init_driver_type_flags_t>::max();

  std::uint32_t driver_count = 0;
  ze_result_t result = zeInitDrivers(&driver_count, nullptr, &descriptor);
  if (result != ZE_RESULT_SUCCESS) {
    return api_failure(result);
  }
  if (driver_count > protocol::kMaxObservations) {
    return failure(protocol::LevelZeroError::enumeration_failed);
  }

  std::vector<ze_driver_handle_t> driver_handles(driver_count);
  if (driver_count != 0) {
    result = zeInitDrivers(&driver_count, driver_handles.data(), &descriptor);
    if (result != ZE_RESULT_SUCCESS) {
      return api_failure(result);
    }
    if (driver_count > driver_handles.size()) {
      return failure(protocol::LevelZeroError::enumeration_failed);
    }
    driver_handles.resize(driver_count);
  }

  std::vector<DriverRecord> drivers;
  drivers.reserve(driver_handles.size());
  for (const ze_driver_handle_t driver_handle : driver_handles) {
    ze_driver_properties_t driver_properties{};
    driver_properties.stype = ZE_STRUCTURE_TYPE_DRIVER_PROPERTIES;
    driver_properties.pNext = nullptr;
    result = zeDriverGetProperties(driver_handle, &driver_properties);
    if (result != ZE_RESULT_SUCCESS) {
      return api_failure(result);
    }

    std::uint32_t device_count = 0;
    result = zeDeviceGet(driver_handle, &device_count, nullptr);
    if (result != ZE_RESULT_SUCCESS) {
      return api_failure(result);
    }
    if (device_count > protocol::kMaxObservations) {
      return failure(protocol::LevelZeroError::enumeration_failed);
    }

    std::vector<ze_device_handle_t> device_handles(device_count);
    if (device_count != 0) {
      result = zeDeviceGet(driver_handle, &device_count, device_handles.data());
      if (result != ZE_RESULT_SUCCESS) {
        return api_failure(result);
      }
      if (device_count > device_handles.size()) {
        return failure(protocol::LevelZeroError::enumeration_failed);
      }
      device_handles.resize(device_count);
    }

    DriverRecord driver{.driver_version = driver_properties.driverVersion, .devices = {}};
    driver.devices.reserve(device_handles.size());
    for (const ze_device_handle_t device_handle : device_handles) {
      ze_device_properties_t device_properties{};
      device_properties.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
      device_properties.pNext = nullptr;
      result = zeDeviceGetProperties(device_handle, &device_properties);
      if (result != ZE_RESULT_SUCCESS) {
        return api_failure(result);
      }
      driver.devices.push_back({
          .type = device_properties.type,
          .vendor_id = device_properties.vendorId,
          .device_id = device_properties.deviceId,
      });
    }
    drivers.push_back(std::move(driver));
  }

  return map_devices(drivers);
}

std::string render_report(const ProbeResult& result) {
  if (result.error.has_value() == !result.vpu_devices.empty()) {
    throw std::invalid_argument("Level Zero probe result invariant is invalid");
  }

  json::Writer writer(protocol::kMaxOutputBytes, protocol::kMaxStringBytes);
  writer.begin_object();
  writer.key("schema_version");
  writer.unsigned_integer(protocol::kSchemaVersion);
  writer.key("probe");
  writer.string(protocol::kLevelZeroProbe);
  writer.key("mode");
  writer.string(protocol::kEnumerateMode);

  if (result.error.has_value()) {
    writer.key("outcome");
    writer.string(protocol::kFailOutcome);
    writer.key("observations");
    writer.begin_object();
    writer.end_object();
    writer.key("error_code");
    writer.string(protocol::error_code(*result.error));
  } else {
    if (result.vpu_devices.size() > protocol::kMaxObservations) {
      throw std::length_error("too many Level Zero observations");
    }
    writer.key("outcome");
    writer.string(protocol::kPassOutcome);
    writer.key("observations");
    writer.begin_object();
    writer.key("vpu_devices");
    writer.begin_array();
    for (const VpuDevice& device : result.vpu_devices) {
      writer.begin_object();
      writer.key("vendor_id");
      writer.string(device.vendor_id);
      writer.key("device_id");
      writer.string(device.device_id);
      writer.key("driver_version");
      writer.unsigned_integer(device.driver_version);
      writer.end_object();
    }
    writer.end_array();
    writer.end_object();
    writer.key("error_code");
    writer.null_value();
  }
  writer.end_object();
  return writer.finish();
}

}  // namespace intel_npu::native::level_zero
