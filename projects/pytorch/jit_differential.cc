// Copyright 2025 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ###############################################################################

#include <cstdlib>
#include <exception>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>

#include <ATen/core/jit_type.h>
#include <c10/core/ScalarType.h>
#include <torch/csrc/jit/api/function_impl.h>
#include <torch/csrc/jit/backends/backend.h>
#include <torch/csrc/jit/backends/backend_detail.h>
#include <torch/csrc/jit/backends/backend_preprocess.h>
#include <torch/csrc/jit/ir/irparser.h>
#include <torch/csrc/jit/mobile/nnc/aot_compiler.h>
#include <torch/csrc/jit/passes/concat_opt.h>
#include <torch/csrc/jit/passes/dead_code_elimination.h>
#include <torch/csrc/jit/passes/freeze_module.h>
#include <torch/csrc/jit/passes/variadic_ops.h>
#include <torch/csrc/jit/runtime/interpreter.h>
#include <torch/csrc/jit/serialization/export.h>
#include <torch/csrc/jit/serialization/import.h>
#include <torch/csrc/jit/tensorexpr/graph_opt.h>
#include <torch/csrc/jit/tensorexpr/kernel.h>
#include <torch/csrc/jit/testing/file_check.h>
#include <torch/script.h>

bool exactlyEqual(const at::Tensor &a, const at::Tensor &b) {
  return torch::equal(a, b) || (at::isnan(a).any().item<bool>() && at::isnan(b).any().item<bool>());
}

bool exactlyEqual(const std::vector<at::Tensor> &a,
                  const std::vector<at::Tensor> &b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    if (!exactlyEqual(a[i], b[i])) {
      return false;
    }
  }
  return true;
}

std::vector<at::Tensor> runGraph(std::shared_ptr<torch::jit::Graph> graph,
                                 const std::vector<at::Tensor> &inputs) {
  std::vector<torch::jit::IValue> stack =
      torch::jit::fmap<torch::jit::IValue>(inputs);
  torch::jit::Code code(graph, "test");
  torch::jit::InterpreterState(code).run(stack);
  // Graph outputs that are handled below:
  //   * A list of Tensors.
  //   * 1 Tensor.
  if (stack.front().isTensorList()) {
    return stack.front().toTensorVector();
  }
  return {stack.front().toTensor()};
}

std::string CreateIrCode(const uint8_t *data, size_t size) {
  std::string graph_body = std::string((const char *)data, size);

  const std::string templ1 =
      R"IR(
        graph(%0: Float(3, 3, 3, strides=[9, 3, 1], requires_grad=0, device=cpu)):
          %2 : int = prim::Constant[value=2]()
          %1 : int = prim::Constant[value=1]()
          %5 : int? = prim::Constant()
          %7 : Device? = prim::Constant()
          %15: bool = prim::Constant[value=0]()
          %3 : int[] = prim::ListConstruct(%1, %2)
          %res : Tensor = aten::tensor(%3, %5, %7, %15)
        )IR";
  const std::string templ2 =
      R"IR(
          return (%res)
      )IR";

  return templ1 + graph_body + templ2;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    auto graph = std::make_shared<torch::jit::Graph>();
    const std::string input = CreateIrCode(data, size);
    torch::jit::parseIR(input, graph.get());

    std::vector<at::Tensor> inputs = {at::rand({3, 3, 3}, at::kCPU)};
    std::vector<at::Tensor> inputs_copy = {inputs[0].detach().clone()};
    auto orig_outputs = runGraph(graph, inputs);

    torch::jit::preoptimizeGraph(graph);
    graph->lint();
    auto opt_outputs = runGraph(graph, inputs_copy);

    if (!exactlyEqual(orig_outputs, opt_outputs)) {
      throw std::logic_error("Result differs!");
    }

  } catch (const c10::Error &e) {
    return 0;
  } catch (const torch::jit::ErrorReport &e) {
    return 0;
  } catch (const std::runtime_error &e) {
    return 0;
  }
  return 0;
}
