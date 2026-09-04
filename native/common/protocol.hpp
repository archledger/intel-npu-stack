// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace intel_npu::native::protocol {

inline constexpr std::uint32_t kSchemaVersion = 1;
inline constexpr std::size_t kMaxObservations = 64;
inline constexpr std::size_t kMaxStringBytes = 256;
inline constexpr std::size_t kMaxOutputBytes = 65'536;

inline constexpr std::string_view kLevelZeroProbe = "level_zero";
inline constexpr std::string_view kEnumerateMode = "enumerate";
inline constexpr std::string_view kPassOutcome = "pass";
inline constexpr std::string_view kFailOutcome = "fail";

enum class LevelZeroError {
  permission_denied,
  dependency_unavailable,
  no_vpu,
  enumeration_failed,
  internal_failure,
};

[[nodiscard]] constexpr std::string_view error_code(LevelZeroError error) noexcept {
  switch (error) {
    case LevelZeroError::permission_denied:
      return "LEVEL_ZERO_PERMISSION_DENIED";
    case LevelZeroError::dependency_unavailable:
      return "LEVEL_ZERO_DEPENDENCY_UNAVAILABLE";
    case LevelZeroError::no_vpu:
      return "LEVEL_ZERO_NO_VPU";
    case LevelZeroError::enumeration_failed:
      return "LEVEL_ZERO_ENUMERATION_FAILED";
    case LevelZeroError::internal_failure:
      return "LEVEL_ZERO_INTERNAL_FAILURE";
  }
  return "LEVEL_ZERO_INTERNAL_FAILURE";
}

}  // namespace intel_npu::native::protocol
