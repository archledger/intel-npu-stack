// SPDX-License-Identifier: Apache-2.0

#include <openvino/openvino.hpp>
#include <openvino/opsets/opset13.hpp>
#include <openvino/pass/serialize.hpp>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <string>

// Standalone, opt-in compiler reproducer. No application models or input data.
// The -layout modes name the tensors and give the input a batch layout, so the NPU plugin can reshape the model to
// batch 1 before compilation; they then run one inference with a batch of 3.
int main(int argc, char* argv[]) {
  if (argc < 3 || argc > 4) {
    std::cerr << "usage: npu-reshape-bounds static|bounded|unbounded|bounded-layout|unbounded-layout CPU|NPU "
                 "[output-prefix]\n";
    return 64;
  }
  std::string mode = argv[1];
  const std::string device = argv[2];
  const bool layout = mode == "bounded-layout" || mode == "unbounded-layout";
  if (layout) mode.resize(mode.size() - std::string("-layout").size());
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
    if (layout) {
      // Imported models name their tensors; the plugin's batch handling needs the names.
      input->output(0).set_names({"input"});
      reshape->output(0).set_names({"output"});
      input->set_layout(ov::Layout("N..."));
    }

    std::cout << "INPUT " << input->get_partial_shape()
              << " OUTPUT " << reshape->get_output_partial_shape(0) << std::endl;
    if (layout) {
      // Copies: the name sets belong to the tensors, but output(0) returns a temporary handle.
      const auto input_names = input->output(0).get_names();
      const auto output_names = reshape->output(0).get_names();
      std::cout << "LAYOUT " << input->get_layout().to_string() << " INPUT_NAMES";
      for (const auto& name : input_names) std::cout << ' ' << name;
      std::cout << " OUTPUT_NAMES";
      for (const auto& name : output_names) std::cout << ' ' << name;
      std::cout << std::endl;
    }
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
    auto compiled = core.compile_model(model, device);
    std::cout << "COMPILE_OK\n";
    if (layout) {
      ov::Tensor data(ov::element::f32, ov::Shape{3, 2});
      const float values[] = {1, 3, -2, 2, 0.5f, 1.5f};
      std::copy(std::begin(values), std::end(values), data.data<float>());
      auto request = compiled.create_infer_request();
      request.set_input_tensor(data);
      request.infer();
      const auto output = request.get_output_tensor();
      std::cout << "INFER_OK " << output.get_shape();
      for (size_t i = 0; i < output.get_size(); ++i) std::cout << ' ' << output.data<const float>()[i];
      std::cout << '\n';
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "EXCEPTION " << error.what() << '\n';
    return 1;
  }
}
