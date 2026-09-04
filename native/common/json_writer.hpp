// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace intel_npu::native::json {

class Writer final {
 public:
  explicit Writer(std::size_t max_output_bytes, std::size_t max_string_bytes);
  ~Writer();

  Writer(const Writer&) = delete;
  Writer& operator=(const Writer&) = delete;
  Writer(Writer&&) noexcept;
  Writer& operator=(Writer&&) noexcept;

  void begin_object();
  void end_object();
  void begin_array();
  void end_array();
  void key(std::string_view value);
  void null_value();
  void boolean(bool value);
  void unsigned_integer(std::uint64_t value);
  void decimal(double value);
  void string(std::string_view value);

  [[nodiscard]] std::string finish();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace intel_npu::native::json
