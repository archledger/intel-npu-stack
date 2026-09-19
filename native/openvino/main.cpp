// SPDX-License-Identifier: Apache-2.0

#include "openvino/probe.hpp"
#include "common/report_channel.hpp"

#include <string>
#include <string_view>

namespace {

constexpr std::string_view kEnumerateInternalFailure =
    R"({"schema_version":1,"probe":"openvino","mode":"enumerate","outcome":"fail","observations":{},"error_code":"OPENVINO_INTERNAL_FAILURE"})";
constexpr std::string_view kInferInternalFailure =
    R"({"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":"OPENVINO_INTERNAL_FAILURE"})";

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2) {
    return 64;
  }
  const std::string_view mode = argv[1];
  if (mode != "enumerate" && mode != "infer") {
    return 64;
  }

  const intel_npu::native::ReportChannel channel;
  if (!channel.valid()) {
    return 74;
  }
  try {
    std::string report;
    if (mode == "enumerate") {
      report = intel_npu::native::openvino::render_enumerate_report(
          intel_npu::native::openvino::enumerate());
    } else {
      report = intel_npu::native::openvino::render_infer_report(
          intel_npu::native::openvino::infer());
    }
    return channel.write_line(report) ? 0 : 74;
  } catch (...) {
    return channel.write_line(mode == "enumerate" ? kEnumerateInternalFailure
                                                  : kInferInternalFailure) ? 0 : 74;
  }
}
