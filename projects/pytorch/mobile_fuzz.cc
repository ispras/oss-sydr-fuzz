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
//###############################################################################

#include <unistd.h>

#include <string>
#include <sstream>
#include "torch/script.h"
#include "torch/csrc/jit/api/module.h"
#include <torch/csrc/jit/passes/metal_rewrite.h>
#include "torch/csrc/jit/passes/vulkan_rewrite.h"
#include "torch/csrc/jit/passes/xnnpack_rewrite.h"
#include "torch/csrc/jit/serialization/import.h"
#include "torch/csrc/jit/serialization/export.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char name[] = "/tmp/torch-fuzz-XXXXXX";
    char *dir = mktemp(name);

    std::ofstream fp;
    fp.open(dir, std::ios::out | std::ios::binary);
    fp.write((char *) data, size);
    fp.close();
    torch::jit::Module m;
    try {
        m = torch::jit::load(dir);
    } catch (const c10::Error &e) {
        unlink(dir);
        return 0;
    } catch (const torch::jit::ErrorReport &e) {
        unlink(dir);
        return 0;
    } catch(const std::runtime_error &e) {
        unlink(dir);
        return 0;
    } catch(const std::out_of_range &e) {
        std::string err = e.what();
        unlink(dir);
        if (err.find("Argument passed to at() was not in the map.") != std::string::npos) {
            return 0;
        }
        abort();
    }

    unlink(dir);
 
    torch::jit::Module optimized_module = torch::jit::optimizeForMobile(m);
    
    return 0;
}
