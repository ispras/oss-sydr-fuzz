# Copyright 2023 ISP RAS
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

FROM sydr/ubuntu20.04-sydr-fuzz

MAINTAINER Kobrin Eli

# Install build dependencies.
RUN pip3 install astunparse numpy ninja pyyaml mkl mkl-include setuptools cmake cffi \
    typing_extensions

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    libpng-dev libjpeg-dev ffmpeg libavformat-dev libswscale-dev python-is-python3 nasm

# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch_fuzz
RUN cd /pytorch_fuzz && \
    git checkout 0f1621df1a0a73956c7ce4e2f72f069e610e0137 && \
    git submodule update --init --recursive --jobs 0

RUN git clone https://github.com/pytorch/vision.git vision_fuzz/
RUN cd /vision_fuzz && \
    git checkout 9d0a93eee90bf7c401b74ebf9c8be80346254f15

# Install OpenCV
RUN cd / && mkdir cv && cd cv/ && \
    wget -O opencv.zip https://github.com/opencv/opencv/archive/4.x.zip && \
    unzip opencv.zip && mkdir -p build && cd build && \
    cmake -DBUILD_TESTS=OFF ../opencv-4.x && \
    cmake --build . -j$(nproc) && \
    make install && cd /

# Copy torch for different instrumentations.
RUN cp -r /pytorch_fuzz/ /pytorch_afl/
RUN cp -r /pytorch_fuzz/ /pytorch_sydr/
RUN cp -r /pytorch_fuzz/ /pytorch_cov/

# Build torch libraries.
COPY build_torch.sh /
RUN CONFIGS="libfuzzer afl sydr coverage" /build_torch.sh

# Copy corpus and tensor
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git

# Remove empty files from corpus.
RUN find fuzzing-corpus -type f -size 0c | xargs -I {} rm {}

RUN mkdir /jpeg_corpus/ && mkdir /png_corpus/ && \
    mkdir /jpeg_tensor/ && mkdir /png_tensor/
RUN cp -rn /fuzzing-corpus/jpg/*/* /jpeg_corpus/ && \
    cp -rn /fuzzing-corpus/png/*/* /png_corpus/

# Copy build script, targets and patch vision build.
COPY *.cc /vision_fuzz/
COPY build_vision.sh CMakeLists.patch /
RUN cd /vision_fuzz && git apply /CMakeLists.patch

# Copy vision for different instrumentations.
RUN cp -r /vision_fuzz/ /vision_afl/
RUN cp -r /vision_fuzz/ /vision_sydr/
RUN cp -r /vision_fuzz/ /vision_cov/

# Build torchvision
RUN CONFIGS="libfuzzer afl sydr coverage" /build_vision.sh
