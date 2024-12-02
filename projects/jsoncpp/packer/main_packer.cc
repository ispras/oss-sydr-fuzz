// Copyright 2024 ISP RAS.
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
////////////////////////////////////////////////////////////////////////////////

#include "json.pb.h"
#include "json_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "packer_macro.h"


#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <stdint.h>

extern int PackPb2Data(std::string data, char *fout);
extern int PackData2Pb(std::string data, char *fout);

int main(int argc, char **argv) {
  if (argc < 4) return 1;
  bool data2pb = false;
  if (strncmp(argv[3], "--to-proto", 10) == 0)
  {
    data2pb = true;
  }
  else if (strncmp(argv[3], "--from-proto", 12) != 0)
  {
    std::cout << "Unknown conversion type" << std::endl;
    return 1;
  }

  // Read data bytes from file
  FILE *f = fopen(argv[1], "r");
  assert(f);
  fseek(f, 0, SEEK_END);
  size_t len = ftell(f);
  if (len == 0) {
    std::cout << "Failed: empty input file" << std::endl;
    return 0;
  }
  fseek(f, 0, SEEK_SET);
  unsigned char *buf = (unsigned char*)malloc(len);
  size_t n_read = fread(buf, 1, len, f);
  fclose(f);
  assert(n_read == len);
  std::string data = {reinterpret_cast<const char*>(buf), len};

  int res = 0;
  if (data2pb)
  {
    res = PackData2Pb(data, argv[2]);
  }
  else
  {
    res = PackPb2Data(data, argv[2]);
  }

  free(buf);
  return res;
}
