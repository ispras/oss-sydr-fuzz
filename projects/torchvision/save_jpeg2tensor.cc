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
#include <sys/stat.h>
#include <torch/script.h>
#include <torch/torch.h>

int main(int argc, char **argv) {

  const std::string &filename = argv[1];
  struct stat stat_buf;
  int rc = stat(filename.c_str(), &stat_buf);
  if (rc != 0) {
    return 0;
  }

  int64_t size = stat_buf.st_size;

  if (size <= 0) {
    return 0;
  }

  auto input_data =
      torch::from_file(filename, /*shared=*/false, /*size=*/size, torch::kU8);
  try {
    torch::Tensor out_tensor =
        vision::image::decode_jpeg(input_data,
                                   /* IMAGE_READ_MODE_UNCHANGED */
                                   0);
    std::string postfix = ".tensor";
    std::string prefix = filename + postfix;
    torch::save(out_tensor, prefix);
  } catch (const c10::Error &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    abort();
  }
  return 0;
}
