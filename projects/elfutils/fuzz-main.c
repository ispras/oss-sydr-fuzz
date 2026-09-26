/*
# Copyright 2026 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }

    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }

    rewind(f);

    size_t size = (size_t)len;
    uint8_t *data = malloc(size ? size : 1);

    if (!data) {
        fclose(f);
        return 1;
    }

    if (size && fread(data, 1, size, f) != size) {
        perror("fread");
        free(data);
        fclose(f);
        return 1;
    }

    fclose(f);

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    return 0;
}
