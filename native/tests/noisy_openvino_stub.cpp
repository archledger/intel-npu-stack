// SPDX-License-Identifier: Apache-2.0

#include "openvino/probe.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace intel_npu::native::openvino {
namespace {

ProbeResult noisy_probe() {
  std::atexit([] { std::puts("SDK shutdown warning"); });
  std::fputs("SDK buffered warning\n", stdout);
  std::cout << "SDK C++ warning\n";
  constexpr std::string_view message = "SDK descriptor warning\n";
  const ssize_t written = ::write(STDOUT_FILENO, message.data(), message.size());
  if (written != static_cast<ssize_t>(message.size())) {
    std::abort();
  }
  if (std::getenv("NOISY_PROBE_THROW") != nullptr) {
    throw std::runtime_error("simulated SDK failure");
  }
  return {};
}

}  // namespace

ProbeResult enumerate() { return noisy_probe(); }
ProbeResult infer() { return noisy_probe(); }

std::string render_enumerate_report(const ProbeResult&) {
  return R"({"mode":"enumerate","outcome":"pass"})";
}

std::string render_infer_report(const ProbeResult&) {
  return R"({"mode":"infer","outcome":"pass"})";
}

}  // namespace intel_npu::native::openvino
