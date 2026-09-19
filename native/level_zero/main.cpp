// SPDX-License-Identifier: Apache-2.0

#include "level_zero/probe.hpp"
#include "common/report_channel.hpp"

#include <string>
#include <string_view>

namespace {

constexpr std::string_view kInternalFailure =
    R"({"schema_version":1,"probe":"level_zero","mode":"enumerate","outcome":"fail","observations":{},"error_code":"LEVEL_ZERO_INTERNAL_FAILURE"})";

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2 || std::string_view(argv[1]) != intel_npu::native::protocol::kEnumerateMode) {
    return 64;
  }

  const intel_npu::native::ReportChannel channel;
  if (!channel.valid()) {
    return 74;
  }
  try {
    const std::string report = intel_npu::native::level_zero::render_report(
        intel_npu::native::level_zero::enumerate());
    return channel.write_line(report) ? 0 : 74;
  } catch (...) {
    return channel.write_line(kInternalFailure) ? 0 : 74;
  }
}
