# Copyright 2023 Google LLC
# Modifications copyright (C) 2026 ISP RAS
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

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libx11-xcb-dev \
    libxkbcommon-dev \
    libxrandr-dev

WORKDIR /
RUN git clone https://github.com/khronosgroup/Vulkan-Headers vulkan-headers
RUN git clone https://github.com/khronosgroup/Vulkan-Loader vulkan-loader

WORKDIR /vulkan-loader
RUN git checkout 1bf213b2a90181553fff35aeb6fa5c468dcfd35d

WORKDIR /
COPY fuzzers/*.h fuzzers/*_fuzzer.c *.sh vulkan-keywords.dict *.diff ./

RUN cd /vulkan-loader && git apply --ignore-space-change --ignore-whitespace /fuzz-patch.diff && sed -i 's/fput/\/\/fput/g' /vulkan-loader/loader/log.c || true

RUN TARGET=libfuzzer /build.sh
RUN TARGET=coverage /build.sh
RUN TARGET=sydr /build.sh
RUN TARGET=afl /build.sh

RUN mkdir /corpus && \
    cp -r /vulkan-loader/tests/corpus/* /corpus/
