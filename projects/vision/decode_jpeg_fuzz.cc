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

#include "decode_jpeg.h"
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 2) { return 0; }
  size_t size_i = size - 1;
  char name[] = "/tmp/torch-fuzz-XXXXXX";
  char *dir = mktemp(name);
  std::ofstream fp;
  fp.open(dir, std::ios::out | std::ios::binary);
  fp.write((char *)(data + 1), size_i);
  fp.close();

  if (size <= 0) {
    unlink(dir);
    return 0;
  }

  auto input_data =
      torch::from_file(dir, /*shared=*/false, /*size=*/size_i, torch::kU8);
  if (input_data.dim() != 1 || input_data.numel() <= 0) {
    unlink(dir);
    return 0;
  }

  int mode = (int)data[0] % 5;

  try {
    torch::Tensor out_tensor = vision::image::decode_jpeg(
        input_data, mode /* ImageReadMode */ );
  } catch (const c10::Error &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    if (err.find("data precision") != std::string::npos ||
        err.find("Unsupported marker type") != std::string::npos ||
        err.find("Bogus") != std::string::npos ||
        err.find("Invalid") != std::string::npos ||
        err.find("Image is incomplete or truncated") != std::string::npos ||
        err.find("Unsupported JPEG process") != std::string::npos ||
        err.find("Didn't expect more than one scan") != std::string::npos ||
        err.find("Not a JPEG file") != std::string::npos ||
        err.find("JPEG datastream contains no image") != std::string::npos ||
        err.find("Quantization table") != std::string::npos ||
        err.find("Empty JPEG image") != std::string::npos ||
        err.find("Huffman") != std::string::npos ||
        err.find("Fractional sampling") != std::string::npos ||
        err.find("Maximum supported image dimension") != std::string::npos ||
        err.find("Sampling factors") != std::string::npos ||
        err.find("The provided mode is not supported") != std::string::npos ||
        err.find("Unsupported color conversion request") != std::string::npos ||
        err.find("Corrupt JPEG data") != std::string::npos ||
        err.find("unknown JFIF revision") != std::string::npos) {
      unlink(dir);
      return 0;
    }
    unlink(dir);
    abort();
  }

  unlink(dir);

  return 0;
}
