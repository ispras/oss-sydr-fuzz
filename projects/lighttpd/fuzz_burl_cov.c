/* Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "burl.h"
#include "buffer.h"

void run_burl_normalize (buffer *psrc, buffer *ptmp, 
						int flags, int line, const char *in, 
						size_t in_len) {
    int qs;
    buffer_copy_string_len(psrc, in, in_len);
    qs = burl_normalize(psrc, ptmp, flags);
}

int LLVMFuzzerTestOneInput(const char *filename) {
    int fd = open(filename, O_RDONLY, 0666);
    int size = lseek(fd, 0, SEEK_END);
    char* data = malloc(size);
    lseek(fd, 0, SEEK_SET);
    read(fd, data, size);
    close(fd);

    if (size <= 4) {
        return 0;
    }
    int flags = ((int*)data)[0];
    data += 4;
    size -= 4;
    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
        return 0;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\0';

    /* main fuzzer entrypoint for library */
    buffer *psrc = buffer_init();
    buffer *ptmp = buffer_init();
    run_burl_normalize(psrc, ptmp, flags, __LINE__, new_str, size);
    buffer_urldecode_path(psrc);

    buffer_free(psrc);
    buffer_free(ptmp);
    free(new_str);
    return 0;     
}

int main(int argc, char **argv) {
  return LLVMFuzzerTestOneInput(argv[1]);
}