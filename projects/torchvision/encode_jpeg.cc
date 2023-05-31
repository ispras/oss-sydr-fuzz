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

#include "encode_jpeg.h"
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
    unlink(dir);
    return 0;
  } catch (const std::exception &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    unlink(dir);
    return 0;
  } catch (const torch::jit::ErrorReport &e) {
    unlink(dir);
    return 0;
  }

  if (input_data.dim() != 3 || input_data.numel() <= 0) {
    unlink(dir);
    return 0;
  }

  try {
    torch::Tensor out_tensor = vision::image::encode_jpeg(
        input_data, 100 /* quality level: 0-100 */ );
  } catch (const c10::Error &e) {
    unlink(dir);
    return 0;
  }

  unlink(dir);

  return 0;
}
