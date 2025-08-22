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
#include <torch/torch.h>
#include <fstream>
#include "src/torchcodec/_core/Encoder.h"
#include "src/torchcodec/_core/StreamOptions.h"
#include <torch/csrc/jit/frontend/error_report.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char name[] = "/tmp/torch-fuzz-XXXXXX";
    char *dir = mktemp(name);
    std::ofstream fp;
    fp.open(dir, std::ios::out | std::ios::binary);
    fp.write((char *)data, size);
    fp.close();

    if (size <= 0) {
        unlink(dir);
        return 0;
    }

    
    
    //if (input_data.dim() != 1 || input_data.numel() <= 0) {
    //    return 0;
    //}

    try {

        torch::Tensor input_data;
        torch::load(input_data, dir);
        std::cout << input_data.dtype() << ' ' 
              << input_data.dim() << ' ' 
              << input_data.numel() << std::endl;
        std::cout << input_data << std::endl;


        int mode = (int)data[0] % 5;
        facebook::torchcodec::AudioStreamOptions aso;
        aso.bitRate = mode;
        aso.numChannels = 1;
        aso.sampleRate = 1;
        std::string fileName = "tmp";


        facebook::torchcodec::AudioEncoder encoder = facebook::torchcodec::AudioEncoder(
        input_data, mode, fileName, aso);

        auto result = encoder.encodeToTensor(); 

    } catch (const c10::Error &e) {
        return 0;
    } catch (const torch::jit::ErrorReport &e) {
        return 0;
    } catch (const std::runtime_error &e) {
        return 0;
    }

    return 0;
}
