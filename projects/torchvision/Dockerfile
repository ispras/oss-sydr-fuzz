# Copyright 2025 ISP RAS
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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE
ARG CMAKE_VERSION=3.27.6

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    libbrotli-dev \
    libtool \
    make \
    mercurial \
    pkg-config \
    yasm \
    zlib1g-dev \
    ninja-build

WORKDIR /opt
RUN wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz && \
    tar -xzf cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz && \
    mv cmake-${CMAKE_VERSION}-linux-x86_64 /opt/cmake && \
    ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake && \
    rm cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz

# Copy build script, patch vision.
COPY build.sh /

WORKDIR /    
# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch
RUN cd /pytorch && \
    git checkout 19ae5afdaa3a59135e6adbaea197b7a2456f1865 && \
    git submodule sync && \
    git submodule update --init --recursive --jobs 0 && \
    pip install -r requirements.txt

COPY torchvision.patch /    
RUN git clone https://github.com/pytorch/vision.git vision
RUN cd /vision && \
    git checkout b818d320a14a2e6d9d9f28853e9e7beae703e52e && \
    git apply /torchvision.patch
RUN rm torchvision.patch


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
    mkdir /jpeg_raw/ && mkdir /png_raw/ && \
    mkdir /jpeg_tensor/ && mkdir /png_tensor/ && \
    mkdir /mp4_corpus/
RUN cp -rn /fuzzing-corpus/jpg/*/* /jpeg_raw/ && \
    cp -rn /fuzzing-corpus/png/*/* /png_raw/ && \
    cp -rn /fuzzing-corpus/mp4/*/* /mp4_corpus/ 

# Copy targets
COPY *.cc /vision/


# Build torchvision

RUN CONFIGS="sydr" /build.sh
RUN CONFIGS="libfuzzer" /build.sh
RUN CONFIGS="coverage" /build.sh
RUN CONFIGS="afl" /build.sh
