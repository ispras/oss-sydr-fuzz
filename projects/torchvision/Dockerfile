# Copyright 2022 ISP RAS
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

FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Kirill Parhomenko

# Install build dependencies.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cmake cffi \
    typing_extensions 

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    libpng-dev libjpeg-dev ffmpeg libavformat-dev libswscale-dev python-is-python3 nasm

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch_fuzz
RUN cd /pytorch_fuzz && \
    git checkout 664058fa83f1d8eede5d66418abff6e20bd76ca8 && \
    git submodule update --init --recursive --jobs 0

RUN git clone https://github.com/pytorch/vision.git vision_fuzz/
RUN cd /vision_fuzz && \
    git checkout c3ec69482a5b9359306c58f0f5c587e1b3bb11cb

# Patch torchvision CMakeLists to build static
RUN sed -i 's/add_library(${PROJECT_NAME} SHARED ${ALL_SOURCES})/add_library(${PROJECT_NAME} STATIC ${ALL_SOURCES})/' /vision_fuzz/CMakeLists.txt && \
    sed -i 's/target_link_libraries(${PROJECT_NAME} PRIVATE ${TORCH_LIBRARIES} ${PNG_LIBRARY} ${JPEG_LIBRARIES})/add_definitions(-DJPEG_FOUND -DPNG_FOUND)/' /vision_fuzz/CMakeLists.txt

# Install OpenCV
RUN cd / && mkdir cv && cd cv/ && \
    wget -O opencv.zip https://github.com/opencv/opencv/archive/4.x.zip && \
    unzip opencv.zip && mkdir -p build && cd build && \
    cmake -DBUILD_TESTS=OFF ../opencv-4.x && \
    cmake --build . -j$(nproc) && \
    make install && cd /

# Copy build script and targets.
COPY build_*.sh \
     *_fuzz.cc \
     afl.cc \
     main.cc \
     save_jpeg2tensor.cc \
     save_png2tensor.cc \
     *.toml \
     /

# Copy for different targets.
RUN cp -r /pytorch_fuzz/ /pytorch_sydr/
RUN cp -r /pytorch_fuzz/ /pytorch_cov/
RUN cp -r vision_fuzz/ vision_sydr/
RUN cp -r vision_fuzz/ vision_cov/
RUN cp -r vision_fuzz/ vision_fuzz_afl/

# Build fuzz targets.
RUN bash build_fuzz.sh
RUN bash build_sydr.sh
RUN bash build_cov.sh

# Copy corpus and tensor
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git
RUN mkdir /jpeg_corpus/ && mkdir /png_corpus/ && mkdir /jpeg_tensor/ && mkdir /png_tensor/
RUN cp -rn /fuzzing-corpus/jpg/*/* /jpeg_corpus/ && cp -rn /fuzzing-corpus/png/*/* /png_corpus/

RUN bash build_corpus.sh
