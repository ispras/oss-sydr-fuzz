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

#include <sstream>
#include <string>
#include <unistd.h>

#include "torch/csrc/jit/api/module.h"
#include "torch/csrc/jit/passes/metal_rewrite.h"
#include "torch/csrc/jit/passes/vulkan_rewrite.h"
#include "torch/csrc/jit/passes/xnnpack_rewrite.h"
#include "torch/csrc/jit/serialization/export.h"
#include "torch/csrc/jit/serialization/import.h"
#include "torch/script.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::stringstream ss;
  std::copy((char *)data, (char *)data + size,
            std::ostreambuf_iterator<char>(ss));
  torch::jit::Module m;
  try {
    m = torch::jit::load(ss);
  } catch (const c10::Error &e) {
    return 0;
  } catch (const torch::jit::ErrorReport &e) {
    return 0;
  } catch (const std::runtime_error &e) {
    return 0;
  }

  torch::jit::Module optimized_module = torch::jit::optimizeForMobile(m);

  return 0;
}
