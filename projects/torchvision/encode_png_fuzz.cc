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

#include "common_png.h"
#include "encode_png.h"
#include "torch/script.h"
#include "torch/torch.h"
#include "torch/types.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size <= 0) {
    return 0;
  }

  torch::Tensor input_data;
  torch::from_blob((void *)data, size, torch::kU8);

  if (input_data.dim() != 3 || input_data.numel() <= 0) {
    return 0;
  }

  try {
    // compression values in the range 0 - 9
    // default compression level = 6
    // BEST_SPEED = 1
    // NO_COMPRESSION = 0
    torch::Tensor out_tensor = vision::image::encode_png(
        input_data, 6 /* compression level */ );
  } catch (const c10::Error &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    if (err.find("The number of channels") != std::string::npos ||
        err.find("Input tensor") != std::string::npos) {
      return 0;
    }
    abort();
  }

  return 0;
}
