// Copyright 2022 ISP RAS
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

#include <sstream>
#include <string>
#include <unistd.h>

#include <c10/util/Flags.h>
#include <torch/csrc/jit/api/module.h>
#include <torch/csrc/jit/mobile/module.h>
#include <torch/csrc/jit/runtime/instruction.h>
#include <torch/csrc/jit/serialization/import.h>

namespace torch {
namespace jit {
void dump_opnames(const Module &m, std::unordered_set<std::string> &opnames) {
  auto methods = m.get_methods();
  for (const auto &method : methods) {
    const auto &func = method.function();
    auto graph = toGraphFunction(func).graph()->copy();
    torch::jit::Code code(graph, "");
    for (size_t i = 0; i < code.instructions().size(); ++i) {
      auto ins = code.instructions()[i];
      auto node = code.instructions_source()[i];
      if (ins.op == OpCode::OP) {
        auto opname = node->schema().operator_name();
        std::string namestr = opname.name;
        if (!opname.overload_name.empty())
          namestr += "." + opname.overload_name;
        opnames.emplace(namestr);
      }
    }
  }
  for (const auto &sub_m : m.children()) {
    dump_opnames(sub_m, opnames);
  }
}
} // namespace jit
} // namespace torch

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  torch::jit::Module m;
  std::unordered_set<std::string> opnames;

  std::stringstream ss;
  std::copy((char *)data, (char *)data + size,
            std::ostreambuf_iterator<char>(ss));

  try {
    m = torch::jit::load(ss);
  } catch (const c10::Error &e) {
    return 0;
  } catch (const torch::jit::ErrorReport &e) {
    return 0;
  } catch (const std::runtime_error &e) {
    return 0;
  }

  torch::jit::dump_opnames(m, opnames);

  return 0;
}
