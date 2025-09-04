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
#include "torch/types.h"
#include <torch/csrc/jit/frontend/error_report.h>
#include "src/torchcodec/_core/SingleStreamDecoder.h"
#include "src/torchcodec/_core/CpuDeviceInterface.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char video_path[24] = {0};
    strcpy(video_path, "/tmp/video-XXXXXX");
    int fd = mkstemp(video_path);
    if (fd == -1) {
        unlink(video_path);
        return 0;
    }
    if (size < 4){
        unlink(video_path);
        return 0;
    }
    write(fd, data, size);
    close(fd);
    try{
        facebook::torchcodec::SingleStreamDecoder decoder = facebook::torchcodec::SingleStreamDecoder(video_path, facebook::torchcodec::SingleStreamDecoder::SeekMode::approximate);

        facebook::torchcodec::AudioStreamOptions options;
        
        options.bitRate = 128;
        options.numChannels = 1;
        options.sampleRate = 1;

        static bool g_cpu = facebook::torchcodec::registerDeviceInterface(
        torch::kCPU,
        [](const torch::Device& device) { return new facebook::torchcodec::CpuDeviceInterface(device); });

        decoder.addAudioStream(0, options);
            
        auto out = decoder.getFramesPlayedInRangeAudio(0);

    } catch (const c10::Error &e) {

    } catch (const torch::jit::ErrorReport &e) {

    } catch (const std::runtime_error &e) {

    }

    unlink(video_path);
    return 0;
}
