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
#include "decode_png.h"
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) { return 0; }
  size_t size_i = size - 1;

  auto input_data =
      torch::from_blob((char *)(data + 1), /*size=*/size_i, torch::kU8);
  if (input_data.dim() != 1 || input_data.numel() <= 0) {
    return 0;
  }

  int mode = (int)data[0] % 5;

  try {
    torch::Tensor out_tensor = vision::image::decode_png(
        input_data, mode /* ImageReadMode */ );
  } catch (const c10::Error &e) {
    return 0;
  }

  return 0;
}
