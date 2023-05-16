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
// ###############################################################################

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char *argv[]) {
  LLVMFuzzerInitialize(&argc, &argv);

  FILE *fd = fopen(argv[1], "rb");

  if (fd == NULL)
    return 1;
  fseek(fd, 0, SEEK_END);
  int fsize = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  char *buffer = (char *)malloc(sizeof(char) * fsize);
  fread(buffer, 1, fsize, fd);
  fclose(fd);

  return LLVMFuzzerTestOneInput((const uint8_t *)buffer, fsize);
}
