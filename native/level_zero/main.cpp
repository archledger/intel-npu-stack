// SPDX-License-Identifier: Apache-2.0

#include "level_zero/probe.hpp"

#include <cstdio>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kInternalFailure =
    R"({"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"fail","observations":{},"error_code":"LEVEL_ZERO_INTERNAL_FAILURE"})";

void write_line(std::string_view value) noexcept {
  static_cast<void>(std::fwrite(value.data(), 1, value.size(), stdout));
  static_cast<void>(std::fputc('\n', stdout));
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2 || std::string_view(argv[1]) != intel_npu::native::protocol::kEnumerateMode) {
    return 64;
  }

  try {
    const std::string report = intel_npu::native::level_zero::render_report(
        intel_npu::native::level_zero::enumerate());
    write_line(report);
  } catch (...) {
    write_line(kInternalFailure);
  }
  return 0;
}
