// Copyright 2023 ISP RAS
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
#include <sstream>
#include <stdexcept>
#include <string>

#include "onnx/common/status.h"
#include "onnx/defs/parser.h"
#include "onnx/proto_utils.h"

namespace ONNX_NAMESPACE {

using namespace ONNX_NAMESPACE::Common;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    GraphProto proto{};
    try {
        if (size && strnlen((const char*)data, size) < size) {
            onnx::OnnxParser parser((const char*)data);
            auto status = parser.Parse(proto);
        }
    } catch (const std::runtime_error &e) {
        return 0;
    }

    return 0;
}

} // namespace ONNX_NAMESPACE

