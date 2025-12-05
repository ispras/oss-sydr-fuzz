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

#include <iostream>
#include <string>

#include <rlottie.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const std::string json((char *)data, size);
    //try {
        auto player = rlottie::Animation::loadFromData(json, {}, {}, false);
        if (!player) {
           return 0;
        }
    
        // Defaults from rlottie/example/lottie2gif.cpp
        size_t w = 200;
        size_t h = 200;
        auto buffer = std::unique_ptr<uint32_t[]>(new uint32_t[w * h]);
	size_t frameCount = player->totalFrame();
        for (size_t i = 0; i < frameCount ; i++) {
            rlottie::Surface surface(buffer.get(), w, h, w * 4);
            player->renderSync(i, surface);
        }
    //}
    //catch (const std::exception& e) {
    //    std::cout << "Catch exception on render: " << typeid(e).name() << ": " << e.what() << std::endl;
    //}
    //catch (...) {
    //    std::cout << "Unknown non-standard exception caught on render!" << std::endl;
    //}

    return 0;
}
