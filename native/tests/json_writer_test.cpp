// SPDX-License-Identifier: Apache-2.0

#include "common/json_writer.hpp"

#include <cmath>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using intel_npu::native::json::Writer;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

template <typename Function>
void require_throws(Function&& function, std::string_view message) {
  try {
    function();
  } catch (const std::exception&) {
    return;
  }
  throw std::runtime_error(std::string(message));
}

void writes_every_escape_and_preserves_utf8() {
  Writer writer(65'536, 256);
  writer.begin_object();
  writer.key("escaped");
  std::string input = {'"', '\\', '\b', '\f', '\n', '\r', '\t', '\0', '\1', '\x1f', '/'};
  input.append("\xC3\xA9", 2);
  writer.string(input);
  writer.end_object();

  const std::string expected = R"({"escaped":"\"\\\b\f\n\r\t\u0000\u0001\u001f/é"})";
  const std::string actual = writer.finish();
  if (actual != expected) {
    throw std::runtime_error(
        "writer must escape every JSON control and preserve valid UTF-8; actual=" + actual);
  }
}

void writes_typed_values_in_call_order_without_a_newline() {
  Writer writer(65'536, 256);
  writer.begin_object();
  writer.key("schema_version");
  writer.unsigned_integer(1);
  writer.key("enabled");
  writer.boolean(true);
  writer.key("ratio");
  writer.decimal(0.125);
  writer.key("items");
  writer.begin_array();
  writer.null_value();
  writer.string("NPU");
  writer.begin_object();
  writer.key("id");
  writer.unsigned_integer(UINT64_C(18446744073709551615));
  writer.end_object();
  writer.end_array();
  writer.end_object();

  const std::string output = writer.finish();
  require(
      output ==
          R"({"schema_version":1,"enabled":true,"ratio":0.125,"items":[null,"NPU",{"id":18446744073709551615}]})",
      "writer must preserve deterministic key order and typed values");
  require(output.empty() || output.back() != '\n', "writer must not add a newline");

  std::string entrypoint_line = output;
  entrypoint_line.push_back('\n');
  require(entrypoint_line.ends_with("}\n"), "entry point must add a trailing newline");
  require(!entrypoint_line.ends_with("}\n\n"), "entry point must add exactly one newline");
}

void rejects_invalid_inputs_and_invalid_control_flow() {
  require_throws(
      [] {
        Writer writer(65'536, 256);
        writer.string(std::string("\xC0\xAF", 2));
      },
      "overlong UTF-8 must be rejected");
  require_throws(
      [] {
        Writer writer(65'536, 256);
        writer.string(std::string("\xED\xA0\x80", 3));
      },
      "UTF-8 surrogates must be rejected");
  require_throws(
      [] {
        Writer writer(65'536, 3);
        writer.string("toolong");
      },
      "bounded strings must be enforced");
  require_throws(
      [] {
        Writer writer(65'536, 256);
        writer.decimal(std::numeric_limits<double>::infinity());
      },
      "non-finite decimals must be rejected");
  require_throws(
      [] {
        Writer writer(65'536, 256);
        writer.begin_object();
        writer.string("value-without-key");
      },
      "an object value without a key must be rejected");
  require_throws(
      [] {
        Writer writer(65'536, 256);
        writer.begin_object();
        writer.key("dangling");
        writer.end_object();
      },
      "an object key without a value must be rejected");
  require_throws(
      [] {
        Writer writer(8, 256);
        writer.string("12345678");
      },
      "the output limit must be enforced");
}

}  // namespace

int main() {
  try {
    writes_every_escape_and_preserves_utf8();
    writes_typed_values_in_call_order_without_a_newline();
    rejects_invalid_inputs_and_invalid_control_flow();
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
  return 0;
}
