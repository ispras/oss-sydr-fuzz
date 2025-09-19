#!/bin/bash
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

ARG BASE_IMAGE="sydr/ubuntu20.04-riscv64-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && apt-get install -y nano libprotobuf-dev protobuf-compiler libomp-18-dev libopencv-dev

WORKDIR /

RUN git clone https://github.com/Tencent/ncnn.git

WORKDIR /ncnn

RUN git checkout 86efe80b50408bfeca79761edcb3fa4b4e513331 && \
    git submodule update --init

COPY build.sh fuzzer_temp_file.h \
         ./
COPY *.cc /

RUN TARGET="sydr" ./build.sh
RUN TARGET="fuzz" ./build.sh
RUN TARGET="afl"  ./build.sh
RUN TARGET="cov"  ./build.sh

WORKDIR /

RUN mkdir -p /corpus_darknet && find /ncnn -name "*.cfg" -exec cp "{}" "/corpus_darknet/" \;
RUN mkdir -p /corpus_imread && find /ncnn -name "*.png" -exec cp "{}" "/corpus_imread/" \;
RUN mkdir -p /corpus_mxnet && find /ncnn -name "*.json" -exec cp "{}" "/corpus_mxnet/" \;
