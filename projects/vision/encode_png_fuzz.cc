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
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char name[] = "/tmp/torch-fuzz-XXXXXX";
  char *dir = mktemp(name);
  std::ofstream fp;
  fp.open(dir, std::ios::out | std::ios::binary);
  fp.write((char *)data, size);
  fp.close();

  if (size <= 0) {
    unlink(dir);
    return 0;
  }

  torch::Tensor input_data;
  try {
    torch::load(input_data, dir);
  } catch (const c10::Error &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    if (err.find("PytorchStreamReader") != std::string::npos ||
        err.find("Unpickler found") != std::string::npos ||
        err.find("Expected") != std::string::npos ||
        err.find("false") != std::string::npos ||
        err.find("Unknown") != std::string::npos) {
      unlink(dir);
      return 0;
    }
    unlink(dir);
    abort();
  } catch (const std::runtime_error &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    unlink(dir);
    return 0;
  } catch (const torch::jit::ErrorReport &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    unlink(dir);
    return 0;
  }

  if (input_data.dim() != 3 || input_data.numel() <= 0) {
    unlink(dir);
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
      unlink(dir);
      return 0;
    }
    unlink(dir);
    abort();
  }

  unlink(dir);

  return 0;
}
