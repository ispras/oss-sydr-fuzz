# Copyright 2025 Google Inc.
# Modifications copyright (C) 2022 ISP RAS
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

RUN git clone https://github.com/Samsung/rlottie.git

WORKDIR /rlottie

RUN git checkout 671c561130ead1c6e44805a7ec1263573a3440fd

COPY build.sh *_fuzz.cpp ./

RUN TARGET="fuzz" ./build.sh
RUN TARGET="afl" ./build.sh
RUN TARGET="sydr" ./build.sh
RUN TARGET="cov" ./build.sh

WORKDIR /

RUN mkdir /corpus && \
    find /rlottie -name "*.json" -exec cp {} /corpus/ \;
