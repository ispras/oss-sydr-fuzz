# Copyright 2016 Google Inc.
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

RUN git clone https://github.com/google/brotli.git /brotli \
    && cd /brotli \
    && git checkout ab685df8343d8046226ece980408e958c10f9085

WORKDIR /brotli
COPY build.sh /brotli/

RUN unzip /brotli/java/org/brotli/integration/fuzz_data.zip -d /corpus

RUN TARGET=libfuzzer ./build.sh
RUN TARGET=cov ./build.sh
RUN TARGET=sydr ./build.sh
RUN TARGET=afl ./build.sh
