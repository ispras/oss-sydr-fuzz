#!/bin/bash -eu
# Copyright 2019 Google Inc.
# Modifications copyright (C) 2021 ISP RAS
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

MAINTAINER Andrey Fedotov

# Install build dependencies.
RUN apt-get update && apt-get install -y cmake

# Clone target from GitHub.
RUN git clone https://github.com/DaveGamble/cJSON.git cjson

WORKDIR cjson

# Checkout specified commit. It could be updated later.
RUN git checkout b45f48e600671feade0b6bd65d1c69de7899f2be

# Copy build script and fuzz targets for libFuzzer and Sydr.
COPY build.sh cjson_read_sydr.c ./fuzzing/

# Build fuzz targets.
RUN ./fuzzing/build.sh

WORKDIR /corpus

# Prepare seed corpus.
RUN cp -r /cjson/fuzzing/inputs/* .
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git /go-fuzz-corpus && \
    cp /go-fuzz-corpus/json/corpus/* . && rm -rf /go-fuzz-corpus

WORKDIR /
