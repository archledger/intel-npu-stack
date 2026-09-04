// SPDX-License-Identifier: Apache-2.0

#include "openvino/probe.hpp"

#include <cstdio>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kEnumerateInternalFailure =
    R"({"schema_version":1,"probe":"openvino","mode":"enumerate","outcome":"fail","observations":{},"error_code":"OPENVINO_INTERNAL_FAILURE"})";
constexpr std::string_view kInferInternalFailure =
    R"({"schema_version":1,"probe":"openvino","mode":"infer","outcome":"fail","observations":{},"error_code":"OPENVINO_INTERNAL_FAILURE"})";

void write_line(std::string_view value) noexcept {
  static_cast<void>(std::fwrite(value.data(), 1, value.size(), stdout));
  static_cast<void>(std::fputc('\n', stdout));
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2) {
    return 64;
  }
  const std::string_view mode = argv[1];
  if (mode != "enumerate" && mode != "infer") {
    return 64;
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
    write_line(report);
  } catch (...) {
    write_line(mode == "enumerate" ? kEnumerateInternalFailure : kInferInternalFailure);
  }
  return 0;
}
