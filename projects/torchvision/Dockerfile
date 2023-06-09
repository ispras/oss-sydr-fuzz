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
RUN git clone https://github.com/pytorch/pytorch.git pytorch
RUN cd /pytorch && \
    git checkout 0f1621df1a0a73956c7ce4e2f72f069e610e0137 && \
    git submodule update --init --recursive --jobs 0

RUN git clone https://github.com/pytorch/vision.git vision
RUN cd /vision && \
    git checkout 9d0a93eee90bf7c401b74ebf9c8be80346254f15

# Install OpenCV
RUN cd / && mkdir cv && cd cv/ && \
    wget -O opencv.zip https://github.com/opencv/opencv/archive/4.x.zip && \
    unzip opencv.zip && mkdir -p build && cd build && \
    cmake -DBUILD_TESTS=OFF ../opencv-4.x && \
    cmake --build . -j$(nproc) && \
    make install && cd /

# Download jpeg, png, zlib and ffmpeg sources.
RUN wget http://download.sourceforge.net/libpng/libpng-1.6.37.tar.gz && \
    tar -xvzf libpng-1.6.37.tar.gz && rm libpng-1.6.37.tar.gz
RUN wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/2.1.3.tar.gz && \
    tar -xvzf 2.1.3.tar.gz && rm 2.1.3.tar.gz
RUN git clone https://github.com/madler/zlib.git zlib && cd zlib && \
    git checkout v1.2.13
RUN git clone https://github.com/FFmpeg/FFmpeg.git ffmpeg && cd ffmpeg && \
    git checkout cbb1760afab867bf269e4c4f5b7bb63b8c58abc7

# Copy corpus and tensor
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git

# Remove empty files from corpus.
RUN find fuzzing-corpus -type f -size 0c | xargs -I {} rm {}

RUN mkdir /jpeg_corpus/ && mkdir /png_corpus/ && \
    mkdir /jpeg_tensor/ && mkdir /png_tensor/ && \
    mkdir /mp4_corpus/
RUN cp -rn /fuzzing-corpus/jpg/*/* /jpeg_corpus/ && \
    cp -rn /fuzzing-corpus/png/*/* /png_corpus/ && \
    cp -rn /fuzzing-corpus/mp4/*/* /mp4_corpus/ 

# Copy build script, targets and patch vision build.
COPY *.cc /vision/
COPY build.sh CMakeLists.patch /
RUN cd /vision && git apply /CMakeLists.patch

# Build torchvision
RUN CONFIGS="libfuzzer afl" /build.sh
RUN CONFIGS="sydr coverage" /build.sh
