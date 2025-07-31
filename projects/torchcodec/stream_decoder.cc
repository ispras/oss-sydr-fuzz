// Copyright 2025 ISP RAS
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "src/torchcodec/_core/SingleStreamDecoder.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char video_path[24] = {0};
    strcpy(video_path, "/tmp/video-XXXXXX");
    int fd = mkstemp(video_path);
    if (fd == -1) {
        return 0;
    }

    write(fd, data, size);
    facebook::torchcodec::SingleStreamDecoder decoder = facebook::torchcodec::SingleStreamDecoder(video_path);

    auto value = decoder.getKeyFrameIndices();

    unlink(video_path);
    close(fd);
    return 0;
}
