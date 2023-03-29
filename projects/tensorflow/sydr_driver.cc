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
////////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

extern "C" int LLVMFuzzerRunDriver(int *argc, char ***argv,
		  int (*UserCb)(const uint8_t *data, size_t size))
{
    FILE *f = fopen((*argv)[*argc - 1], "r");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char*)malloc(len);
    size_t n_read = fread(buf, 1, len, f);
    fclose(f);
    UserCb(buf, len);
    free(buf);
    return 0;
}
