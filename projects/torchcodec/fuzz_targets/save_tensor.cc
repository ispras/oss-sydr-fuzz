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
//###############################################################################

#include "src/torchcodec/_core/SingleStreamDecoder.h"
#include "src/torchcodec/_core/CpuDeviceInterface.h"
#include <sys/stat.h>
#include <torch/torch.h>
#include <torch/csrc/jit/frontend/error_report.h>

int main(int argc, char **argv) {

  const std::string &filename = argv[1];
  struct stat stat_buf;
  int rc = stat(filename.c_str(), &stat_buf);
  if (rc != 0) {
    return 0;
  }

  int64_t size = stat_buf.st_size;

  if (size <= 0) {
    return 0;
  }

  
  try {

    facebook::torchcodec::SingleStreamDecoder decoder = facebook::torchcodec::SingleStreamDecoder(filename, 
      facebook::torchcodec::SingleStreamDecoder::SeekMode::approximate);

    facebook::torchcodec::AudioStreamOptions options;
    options.bitRate = 128;
    options.numChannels = 1;
    options.sampleRate = 1;

   static const auto cpu_key = facebook::torchcodec::DeviceInterfaceKey{torch::kCPU, ""};
   static bool g_cpu = facebook::torchcodec::registerDeviceInterface(
     cpu_key,
     [](const torch::Device& device) { return new facebook::torchcodec::CpuDeviceInterface(device); });
    
    decoder.addAudioStream(0, options);
        
    auto out = decoder.getFramesPlayedInRangeAudio(0);
    auto out_tensor = out.data;

    std::cout << out_tensor.dtype() << ' ' << out_tensor.dim() << ' ' << out_tensor.numel() << std::endl;
    std::cout << out_tensor << std::endl;

    std::string postfix = ".tensor";
    std::string prefix = filename + postfix;
    torch::save(out_tensor, prefix);

  } catch (const c10::Error &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    abort();

  } catch (const torch::jit::ErrorReport &e) {
    std::string err = e.what();
    std::cout << "Catch exception: " << err << std::endl;
    abort();
    
  }
  
  return 0;
}
