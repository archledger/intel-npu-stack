// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cerrno>
#include <fcntl.h>
#include <string_view>
#include <unistd.h>

namespace intel_npu::native {

// Keep the protocol pipe separate from SDK stdout, including late shutdown logs.
// The redirected stdout intentionally remains stderr until process exit.
class ReportChannel final {
 public:
  ReportChannel() noexcept : descriptor_(::fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3)) {
    if (descriptor_ < 0) {
      return;
    }
    int result;
    do {
      result = ::dup2(STDERR_FILENO, STDOUT_FILENO);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
      static_cast<void>(::close(descriptor_));
      descriptor_ = -1;
    }
  }

  ~ReportChannel() {
    if (descriptor_ >= 0) {
      static_cast<void>(::close(descriptor_));
    }
  }

  ReportChannel(const ReportChannel&) = delete;
  ReportChannel& operator=(const ReportChannel&) = delete;

  [[nodiscard]] bool valid() const noexcept { return descriptor_ >= 0; }

  [[nodiscard]] bool write_line(std::string_view report) const noexcept {
    return valid() && write_all(report) && write_all("\n");
  }

 private:
  [[nodiscard]] bool write_all(std::string_view remaining) const noexcept {
    while (!remaining.empty()) {
      const ssize_t written = ::write(descriptor_, remaining.data(), remaining.size());
      if (written > 0) {
        remaining.remove_prefix(static_cast<std::size_t>(written));
      } else if (written == 0 || errno != EINTR) {
        return false;
      }
    }
    return true;
  }

  int descriptor_;
};

}  // namespace intel_npu::native
