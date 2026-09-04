// SPDX-License-Identifier: Apache-2.0

#include "common/json_writer.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <stdexcept>
#include <utility>
#include <vector>

namespace intel_npu::native::json {
namespace {

[[nodiscard]] bool is_continuation(unsigned char byte) noexcept {
  return (byte & 0xc0U) == 0x80U;
}

[[nodiscard]] bool is_valid_utf8(std::string_view value) noexcept {
  std::size_t index = 0;
  while (index < value.size()) {
    const auto first = static_cast<unsigned char>(value[index]);
    if (first <= 0x7fU) {
      ++index;
      continue;
    }

    if (first >= 0xc2U && first <= 0xdfU) {
      if (index + 1 >= value.size() ||
          !is_continuation(static_cast<unsigned char>(value[index + 1]))) {
        return false;
      }
      index += 2;
      continue;
    }

    if (first >= 0xe0U && first <= 0xefU) {
      if (index + 2 >= value.size()) {
        return false;
      }
      const auto second = static_cast<unsigned char>(value[index + 1]);
      const auto third = static_cast<unsigned char>(value[index + 2]);
      const bool valid_second =
          (first == 0xe0U && second >= 0xa0U && second <= 0xbfU) ||
          (first == 0xedU && second >= 0x80U && second <= 0x9fU) ||
          (((first >= 0xe1U && first <= 0xecU) || (first >= 0xeeU && first <= 0xefU)) &&
           is_continuation(second));
      if (!valid_second || !is_continuation(third)) {
        return false;
      }
      index += 3;
      continue;
    }

    if (first >= 0xf0U && first <= 0xf4U) {
      if (index + 3 >= value.size()) {
        return false;
      }
      const auto second = static_cast<unsigned char>(value[index + 1]);
      const auto third = static_cast<unsigned char>(value[index + 2]);
      const auto fourth = static_cast<unsigned char>(value[index + 3]);
      const bool valid_second =
          (first == 0xf0U && second >= 0x90U && second <= 0xbfU) ||
          (first == 0xf4U && second >= 0x80U && second <= 0x8fU) ||
          (first >= 0xf1U && first <= 0xf3U && is_continuation(second));
      if (!valid_second || !is_continuation(third) || !is_continuation(fourth)) {
        return false;
      }
      index += 4;
      continue;
    }

    return false;
  }
  return true;
}

}  // namespace

struct Writer::Impl {
  enum class Container { object, array };

  struct Frame {
    Container container;
    bool first = true;
    bool expects_key = true;
  };

  std::size_t max_output_bytes;
  std::size_t max_string_bytes;
  std::string output;
  std::vector<Frame> frames;
  bool root_written = false;
  bool finished = false;

  Impl(std::size_t output_bound, std::size_t string_bound)
      : max_output_bytes(output_bound), max_string_bytes(string_bound) {}

  void append(std::string_view value) {
    if (value.size() > max_output_bytes - output.size()) {
      throw std::length_error("JSON output exceeds its configured bound");
    }
    output.append(value);
  }

  void append(char value) {
    if (output.size() == max_output_bytes) {
      throw std::length_error("JSON output exceeds its configured bound");
    }
    output.push_back(value);
  }

  void require_active() const {
    if (finished) {
      throw std::logic_error("JSON writer is already finished");
    }
  }

  void before_value() {
    require_active();
    if (frames.empty()) {
      if (root_written) {
        throw std::logic_error("JSON writer accepts exactly one root value");
      }
      root_written = true;
      return;
    }

    Frame& frame = frames.back();
    if (frame.container == Container::object) {
      if (frame.expects_key) {
        throw std::logic_error("an object value requires a key");
      }
      frame.expects_key = true;
      return;
    }

    if (!frame.first) {
      append(',');
    }
    frame.first = false;
  }

  void append_quoted(std::string_view value) {
    if (value.size() > max_string_bytes) {
      throw std::length_error("JSON string exceeds its configured bound");
    }
    if (!is_valid_utf8(value)) {
      throw std::invalid_argument("JSON string is not valid UTF-8");
    }

    constexpr std::array<char, 16> hex = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    append('"');
    for (const char character : value) {
      const auto byte = static_cast<unsigned char>(character);
      switch (byte) {
        case '"':
          append("\\\"");
          break;
        case '\\':
          append("\\\\");
          break;
        case '\b':
          append("\\b");
          break;
        case '\f':
          append("\\f");
          break;
        case '\n':
          append("\\n");
          break;
        case '\r':
          append("\\r");
          break;
        case '\t':
          append("\\t");
          break;
        default:
          if (byte < 0x20U) {
            const std::array<char, 6> escaped = {
                '\\', 'u', '0', '0', hex[byte >> 4U], hex[byte & 0x0fU]};
            append(std::string_view(escaped.data(), escaped.size()));
          } else {
            append(character);
          }
          break;
      }
    }
    append('"');
  }
};

Writer::Writer(std::size_t max_output_bytes, std::size_t max_string_bytes)
    : impl_(std::make_unique<Impl>(max_output_bytes, max_string_bytes)) {
  if (max_output_bytes == 0 || max_string_bytes == 0) {
    throw std::invalid_argument("JSON bounds must be nonzero");
  }
}

Writer::~Writer() = default;
Writer::Writer(Writer&&) noexcept = default;
Writer& Writer::operator=(Writer&&) noexcept = default;

void Writer::begin_object() {
  impl_->before_value();
  impl_->append('{');
  impl_->frames.push_back({Impl::Container::object});
}

void Writer::end_object() {
  impl_->require_active();
  if (impl_->frames.empty() || impl_->frames.back().container != Impl::Container::object ||
      !impl_->frames.back().expects_key) {
    throw std::logic_error("JSON object is incomplete or mismatched");
  }
  impl_->frames.pop_back();
  impl_->append('}');
}

void Writer::begin_array() {
  impl_->before_value();
  impl_->append('[');
  impl_->frames.push_back({Impl::Container::array, true, false});
}

void Writer::end_array() {
  impl_->require_active();
  if (impl_->frames.empty() || impl_->frames.back().container != Impl::Container::array) {
    throw std::logic_error("JSON array is incomplete or mismatched");
  }
  impl_->frames.pop_back();
  impl_->append(']');
}

void Writer::key(std::string_view value) {
  impl_->require_active();
  if (impl_->frames.empty() || impl_->frames.back().container != Impl::Container::object ||
      !impl_->frames.back().expects_key) {
    throw std::logic_error("JSON key is not valid in the current state");
  }
  Impl::Frame& frame = impl_->frames.back();
  if (!frame.first) {
    impl_->append(',');
  }
  frame.first = false;
  impl_->append_quoted(value);
  impl_->append(':');
  frame.expects_key = false;
}

void Writer::null_value() {
  impl_->before_value();
  impl_->append("null");
}

void Writer::boolean(bool value) {
  impl_->before_value();
  impl_->append(value ? "true" : "false");
}

void Writer::unsigned_integer(std::uint64_t value) {
  impl_->before_value();
  std::array<char, 32> buffer{};
  const auto [end, error] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (error != std::errc{}) {
    throw std::runtime_error("cannot format JSON unsigned integer");
  }
  impl_->append(std::string_view(buffer.data(), static_cast<std::size_t>(end - buffer.data())));
}

void Writer::decimal(double value) {
  if (!std::isfinite(value)) {
    throw std::invalid_argument("JSON decimal must be finite");
  }
  impl_->before_value();
  if (value == 0.0) {
    impl_->append('0');
    return;
  }
  std::array<char, 64> buffer{};
  const auto [end, error] = std::to_chars(
      buffer.data(), buffer.data() + buffer.size(), value, std::chars_format::general);
  if (error != std::errc{}) {
    throw std::runtime_error("cannot format JSON decimal");
  }
  impl_->append(std::string_view(buffer.data(), static_cast<std::size_t>(end - buffer.data())));
}

void Writer::string(std::string_view value) {
  impl_->before_value();
  impl_->append_quoted(value);
}

std::string Writer::finish() {
  impl_->require_active();
  if (!impl_->root_written || !impl_->frames.empty()) {
    throw std::logic_error("JSON document is incomplete");
  }
  impl_->finished = true;
  return impl_->output;
}

}  // namespace intel_npu::native::json
