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
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv) {
#if defined(FUZZER) && defined(TARGET)
    size_t len = strlen("--fuzz=") + strlen(TARGET) + 1;
    char *target_arg = calloc(len, sizeof(*target_arg));
    snprintf(target_arg, len, "--fuzz=%s", TARGET);
 
    char **args = calloc(argc + 2, sizeof(*args));
    args[0] = FUZZER;
    args[1] = target_arg;
    args[2] = "--";
    for (size_t i = 1, j = 3; i < argc; ++i, ++j) {
        args[j] = argv[i];
    }

    execv(FUZZER, args);
#endif
    free(target_arg);
    free(args);
    return 0;
}
