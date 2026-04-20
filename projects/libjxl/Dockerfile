# Copyright 2021 Google Inc.
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


# Install build dependencies
RUN apt-get update && \ 
  apt-get install -y cmake ninja-build pkg-config libjpeg-dev

# Clone target from GitHub and checkout specific commit, as it can be updated later

RUN git clone https://github.com/libjxl/libjxl.git && \
    cd /libjxl && \
    git checkout 37bbfd09b4fd42554940ac2c0b72a1121cfa6d8a

# We only need these sub-projects for the fuzzers.
RUN git -C libjxl submodule update --init --recommend-shallow \
  third_party/brotli \
  third_party/highway \
  third_party/libjpeg-turbo \
  third_party/skcms

RUN git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora

COPY build.sh /build.sh

RUN TARGET="fuzzer" /build.sh
RUN TARGET="afl" /build.sh
RUN TARGET="sydr" /build.sh
RUN TARGET="cov" /build.sh
