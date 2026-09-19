// SPDX-License-Identifier: Apache-2.0

#include <openvino/openvino.hpp>
#include <openvino/opsets/opset13.hpp>
#include <openvino/pass/serialize.hpp>

#include <filesystem>
#include <iostream>
#include <string>

// Standalone, opt-in compiler reproducer. No application models or input data.
int main(int argc, char* argv[]) {
  if (argc < 3 || argc > 4) {
    std::cerr << "usage: npu-reshape-bounds static|bounded|unbounded CPU|NPU [output-prefix]\n";
    return 64;
  }
  const std::string mode = argv[1];
  const std::string device = argv[2];
  if ((mode != "static" && mode != "bounded" && mode != "unbounded") ||
      (device != "CPU" && device != "NPU")) {
    return 64;
  }

  try {
    using namespace ov::opset13;
    const ov::Dimension batch = mode == "static"    ? ov::Dimension(1)
                                : mode == "bounded" ? ov::Dimension(1, 4)
                                                    : ov::Dimension::dynamic();
    const auto input = std::make_shared<Parameter>(ov::element::f32, ov::PartialShape{batch, 2});
    const auto axes = Constant::create(ov::element::i64, ov::Shape{1}, {1});
    const auto mean = std::make_shared<ReduceMean>(input, axes, false);
    mean->set_friendly_name("mean");
    const auto pattern = Constant::create(ov::element::i64, ov::Shape{2}, {-1, 1});
    const auto reshape = std::make_shared<Reshape>(mean, pattern, false);
    reshape->set_friendly_name("reshape");
    const auto model = std::make_shared<ov::Model>(
        ov::ResultVector{std::make_shared<Result>(reshape)},
        ov::ParameterVector{input}, "reduce_reshape_bounds");

    std::cout << "INPUT " << input->get_partial_shape()
              << " OUTPUT " << reshape->get_output_partial_shape(0) << std::endl;
    if (argc == 4) {
      const std::string prefix = argv[3];
      const auto exists = [](const std::string& path) {
        return std::filesystem::exists(path) || std::filesystem::is_symlink(path);
      };
      if (exists(prefix + ".xml") || exists(prefix + ".bin")) {
        std::cerr << "output already exists\n";
        return 64;
      }
      ov::serialize(model, prefix + ".xml", prefix + ".bin");
    }

    ov::Core core;
    const auto compiled = core.compile_model(model, device);
    std::cout << "COMPILE_OK\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "EXCEPTION " << error.what() << '\n';
    return 1;
  }
}
