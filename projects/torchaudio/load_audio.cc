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
//###############################################################################

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "io.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char audio_path[24] = {0};
    strcpy(audio_path, "/tmp/audio-XXXXXX");
    int fd = mkstemp(audio_path);
    if (fd == -1) {
        return 0;
    }

    write(fd, data, size);

    try {
        torchaudio::sox::load_audio_file(audio_path, 0, -1, true, true, c10::nullopt);
    } catch (const std::runtime_error &e) {
        goto out;
    } catch (const c10::Error &e) {
        goto out;
    }

out:
    unlink(audio_path);
    close(fd);
    return 0;
}
