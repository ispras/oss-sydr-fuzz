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

RUN apt-get update && apt-get install -y make autoconf automake libtool libomp-dev libgomp1

RUN git clone https://github.com/google/XNNPACK /xnnpack \
    && cd /xnnpack \
    && git checkout cbd072c2f11237064f77d87f68d1b191dbcb380a

WORKDIR /xnnpack

COPY build.sh *.cc /xnnpack/

COPY corpus.zip /
RUN unzip /corpus.zip -d /

RUN chmod +x        /xnnpack/build.sh
RUN TARGET=fuzzer   /xnnpack/build.sh
RUN TARGET=afl      /xnnpack/build.sh
RUN TARGET=sydr     /xnnpack/build.sh
RUN TARGET=cov      /xnnpack/build.sh